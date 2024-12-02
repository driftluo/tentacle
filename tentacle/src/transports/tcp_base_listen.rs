use std::{
    collections::{hash_map::Entry, HashMap},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use futures::{
    channel::mpsc::{self, Receiver, Sender},
    SinkExt, Stream,
};
use log::debug;

#[cfg(any(feature = "ws", feature = "tls"))]
use crate::multiaddr::Protocol;
#[cfg(feature = "ws")]
use {crate::transports::ws::WsStream, tokio_tungstenite::accept_async};
#[cfg(feature = "tls")]
use {
    crate::{service::TlsConfig, transports::parse_tls_domain_name},
    std::borrow::Cow,
    tokio_rustls::{
        rustls::{server::ResolvesServerCertUsingSni, ServerConfig},
        TlsAcceptor,
    },
};

use crate::{
    multiaddr::Multiaddr,
    runtime::{TcpListener, TcpStream},
    service::config::TcpSocketConfig,
    transports::{tcp_listen, MultiStream, Result, TcpListenMode, TransportErrorKind},
    utils::{multiaddr_to_socketaddr, socketaddr_to_multiaddr},
};

pub enum TcpBaseListenerEnum {
    Upgrade,
    New(TcpBaseListener),
}

/// Tcp listen bind
pub async fn bind(
    address: impl Future<Output = Result<Multiaddr>>,
    tcp_config: TcpSocketConfig,
    listen_mode: TcpListenMode,
    #[cfg(feature = "tls")] config: TlsConfig,
    global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    timeout: Duration,
) -> Result<(Multiaddr, TcpBaseListenerEnum)> {
    let addr = address.await?;
    let upgrade_mode: UpgradeMode = listen_mode.into();
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let (local_addr, tcp) = if socket_address.port() == 0 {
                // this branch must be unique address
                let (local_addr, tcp) = tcp_listen(socket_address, tcp_config).await?;
                global
                    .clone()
                    .lock()
                    .insert(local_addr, upgrade_mode.clone());
                (local_addr, tcp)
            } else {
                // Global register global listener upgrade mode
                match global.clone().lock().entry(socket_address) {
                    Entry::Occupied(v) => {
                        #[allow(unused_mut)]
                        let mut tcp_base_addr: Multiaddr = socketaddr_to_multiaddr(socket_address);
                        let listen_addr = match listen_mode {
                            TcpListenMode::Tcp => tcp_base_addr,
                            #[cfg(feature = "ws")]
                            TcpListenMode::Ws => {
                                tcp_base_addr.push(Protocol::Ws);
                                tcp_base_addr
                            }
                            #[cfg(feature = "tls")]
                            TcpListenMode::Tls => {
                                match parse_tls_domain_name(&addr) {
                                    None => return Err(TransportErrorKind::NotSupported(addr)),
                                    Some(d) => {
                                        tcp_base_addr.push(Protocol::Tls(Cow::Owned(d)));
                                    }
                                }
                                tcp_base_addr
                            }
                        };
                        v.get().combine(listen_mode.into());
                        return Ok((listen_addr, TcpBaseListenerEnum::Upgrade));
                    }
                    Entry::Vacant(v) => {
                        v.insert(upgrade_mode.clone());
                    }
                }
                tcp_listen(socket_address, tcp_config).await?
            };
            #[allow(unused_mut)]
            let mut tcp_base_addr: Multiaddr = socketaddr_to_multiaddr(local_addr);
            let listen_addr = match listen_mode {
                TcpListenMode::Tcp => tcp_base_addr,
                #[cfg(feature = "ws")]
                TcpListenMode::Ws => {
                    tcp_base_addr.push(Protocol::Ws);
                    tcp_base_addr
                }
                #[cfg(feature = "tls")]
                TcpListenMode::Tls => {
                    match parse_tls_domain_name(&addr) {
                        None => return Err(TransportErrorKind::NotSupported(addr)),
                        Some(d) => {
                            tcp_base_addr.push(Protocol::Tls(Cow::Owned(d)));
                        }
                    }
                    tcp_base_addr
                }
            };
            #[cfg(feature = "tls")]
            let tls_server_config = config.tls_server_config.unwrap_or(
                // if enable tls but not set tls config, it will use a empty server config
                Arc::new(
                    ServerConfig::builder()
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new())),
                ),
            );

            Ok((
                listen_addr,
                TcpBaseListenerEnum::New({
                    let tcp_listen =
                        TcpBaseListener::new(timeout, tcp, local_addr, upgrade_mode, global);
                    #[cfg(feature = "tls")]
                    let tcp_listen = tcp_listen.tls_config(tls_server_config);
                    tcp_listen
                }),
            ))
        }
        None => Err(TransportErrorKind::NotSupported(addr)),
    }
}

#[derive(Clone)]
pub(crate) struct UpgradeMode {
    inner: Arc<AtomicU8>,
}

impl UpgradeMode {
    pub fn combine(&self, other: UpgradeModeEnum) {
        let other = other as u8;
        self.inner.fetch_or(other, Ordering::AcqRel);
    }

    pub fn to_enum(&self) -> UpgradeModeEnum {
        self.inner.load(Ordering::Acquire).into()
    }
}

impl From<UpgradeModeEnum> for UpgradeMode {
    fn from(value: UpgradeModeEnum) -> Self {
        Self {
            inner: Arc::new(AtomicU8::from(value as u8)),
        }
    }
}

impl From<TcpListenMode> for UpgradeMode {
    fn from(value: TcpListenMode) -> Self {
        match value {
            TcpListenMode::Tcp => UpgradeModeEnum::OnlyTcp.into(),
            #[cfg(feature = "tls")]
            TcpListenMode::Tls => UpgradeModeEnum::OnlyTls.into(),
            #[cfg(feature = "ws")]
            TcpListenMode::Ws => UpgradeModeEnum::OnlyWs.into(),
        }
    }
}

impl From<TcpListenMode> for UpgradeModeEnum {
    fn from(value: TcpListenMode) -> Self {
        match value {
            TcpListenMode::Tcp => UpgradeModeEnum::OnlyTcp,
            #[cfg(feature = "tls")]
            TcpListenMode::Tls => UpgradeModeEnum::OnlyTls,
            #[cfg(feature = "ws")]
            TcpListenMode::Ws => UpgradeModeEnum::OnlyWs,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum UpgradeModeEnum {
    OnlyTcp = 0b1,
    #[cfg(feature = "ws")]
    OnlyWs = 0b10,
    #[cfg(feature = "tls")]
    OnlyTls = 0b100,
    #[cfg(feature = "ws")]
    TcpAndWs = 0b11,
    #[cfg(feature = "tls")]
    TcpAndTls = 0b101,
    #[cfg(all(feature = "ws", feature = "tls"))]
    All = 0b111,
}

impl From<u8> for UpgradeModeEnum {
    fn from(value: u8) -> Self {
        match value {
            0b1 => UpgradeModeEnum::OnlyTcp,
            #[cfg(feature = "ws")]
            0b10 => UpgradeModeEnum::OnlyWs,
            #[cfg(feature = "ws")]
            0b11 => UpgradeModeEnum::TcpAndWs,
            #[cfg(feature = "tls")]
            0b100 => UpgradeModeEnum::OnlyTls,
            #[cfg(feature = "tls")]
            0b101 => UpgradeModeEnum::TcpAndTls,
            #[cfg(all(feature = "ws", feature = "tls"))]
            0b111 => UpgradeModeEnum::All,
            _ => unreachable!(),
        }
    }
}

pub struct TcpBaseListener {
    inner: TcpListener,
    upgrade_mode: UpgradeMode,
    timeout: Duration,
    local_addr: SocketAddr,
    sender: Sender<(Multiaddr, MultiStream)>,
    pending_stream: Receiver<(Multiaddr, MultiStream)>,
    global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    #[cfg(feature = "tls")]
    tls_config: Arc<ServerConfig>,
}

impl Drop for TcpBaseListener {
    fn drop(&mut self) {
        self.global.lock().remove(&self.local_addr);
    }
}

impl TcpBaseListener {
    fn new(
        timeout: Duration,
        inner: TcpListener,
        local_addr: SocketAddr,
        upgrade_mode: UpgradeMode,
        global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(128);

        Self {
            inner,
            timeout,
            upgrade_mode,
            local_addr,
            global,
            sender: tx,
            pending_stream: rx,
            #[cfg(feature = "tls")]
            tls_config: Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new())),
            ),
        }
    }

    #[cfg(feature = "tls")]
    fn tls_config(mut self, tls_config: Arc<ServerConfig>) -> Self {
        self.tls_config = tls_config;
        self
    }

    fn poll_pending(&mut self, cx: &mut Context) -> Poll<(Multiaddr, MultiStream)> {
        match Pin::new(&mut self.pending_stream).as_mut().poll_next(cx) {
            Poll::Ready(Some(res)) => Poll::Ready(res),
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }

    fn poll_listen(&mut self, cx: &mut Context) -> Poll<std::result::Result<(), io::Error>> {
        match self.inner.poll_accept(cx)? {
            Poll::Ready((stream, _)) => {
                // Why can't get the peer address of the connected stream ?
                // Error will be "Transport endpoint is not connected",
                // so why incoming will appear unconnected stream ?
                match stream.peer_addr() {
                    Ok(remote_address) => {
                        let timeout = self.timeout;
                        let sender = self.sender.clone();
                        let upgrade_mode = self.upgrade_mode.to_enum();
                        #[cfg(feature = "tls")]
                        let acceptor = TlsAcceptor::from(Arc::clone(&self.tls_config));
                        crate::runtime::spawn(protocol_select(
                            stream,
                            timeout,
                            upgrade_mode,
                            sender,
                            remote_address,
                            #[cfg(feature = "tls")]
                            acceptor,
                        ));
                    }
                    Err(err) => {
                        debug!("stream get peer address error: {:?}", err);
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Stream for TcpBaseListener {
    type Item = std::result::Result<(Multiaddr, MultiStream), io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(res) = self.poll_pending(cx) {
            return Poll::Ready(Some(Ok(res)));
        }

        loop {
            let is_pending = self.poll_listen(cx)?.is_pending();
            match self.poll_pending(cx) {
                Poll::Ready(res) => return Poll::Ready(Some(Ok(res))),
                Poll::Pending => {
                    if is_pending {
                        break;
                    }
                }
            }
        }
        Poll::Pending
    }
}

async fn protocol_select(
    stream: TcpStream,
    timeout: Duration,
    #[allow(unused_mut)] mut upgrade_mode: UpgradeModeEnum,
    mut sender: Sender<(Multiaddr, MultiStream)>,
    remote_address: SocketAddr,
    #[cfg(feature = "tls")] acceptor: TlsAcceptor,
) {
    let mut peek_buf = [0u8; 16];
    let now = std::time::Instant::now();
    loop {
        match stream.peek(&mut peek_buf).await {
            Ok(n) => {
                if n != 16 {
                    if now.elapsed() > timeout {
                        debug!(
                            "In the timeout range, stream can't read more than 16 byte data, 
                        We need to give up this suspected offensive stream"
                        );
                        return;
                    } else {
                        continue;
                    }
                }
                break;
            }
            Err(e) => {
                debug!("stream encountered err: {}, close unexpectedly", e);
                return;
            }
        }
    }

    loop {
        match upgrade_mode {
            UpgradeModeEnum::OnlyTcp => {
                if sender
                    .send((
                        socketaddr_to_multiaddr(remote_address),
                        MultiStream::Tcp(stream),
                    ))
                    .await
                    .is_err()
                {
                    debug!("receiver closed unexpectedly")
                }
                return;
            }
            #[cfg(feature = "ws")]
            UpgradeModeEnum::OnlyWs => {
                match crate::runtime::timeout(timeout, accept_async(stream)).await {
                    Err(_) => debug!("accept websocket stream timeout"),
                    Ok(res) => match res {
                        Ok(stream) => {
                            let mut addr = socketaddr_to_multiaddr(remote_address);
                            addr.push(Protocol::Ws);
                            if sender
                                .send((addr, MultiStream::Ws(Box::new(WsStream::new(stream)))))
                                .await
                                .is_err()
                            {
                                debug!("receiver closed unexpectedly")
                            }
                        }
                        Err(err) => {
                            debug!("accept websocket stream err: {:?}", err);
                        }
                    },
                }
                return;
            }
            #[cfg(feature = "tls")]
            UpgradeModeEnum::OnlyTls => {
                match crate::runtime::timeout(timeout, acceptor.accept(stream)).await {
                    Err(_) => debug!("accept tls server stream timeout"),
                    Ok(res) => match res {
                        Ok(stream) => {
                            let mut addr = socketaddr_to_multiaddr(remote_address);
                            addr.push(Protocol::Tls(Cow::Borrowed("")));
                            if sender
                                .send((addr, MultiStream::Tls(Box::new(stream))))
                                .await
                                .is_err()
                            {
                                debug!("receiver closed unexpectedly")
                            }
                        }
                        Err(err) => {
                            debug!("accept tls server stream err: {:?}", err);
                        }
                    },
                }
                return;
            }
            #[cfg(feature = "tls")]
            UpgradeModeEnum::TcpAndTls => {
                // The first sixteen bytes of secio's Propose message's mode is fixed
                // it's bytes like follow:
                //
                // | 4 byte | 4 byte | 4 byte | 4 byte | 4 byte |...
                // |--|--|--|--|--|
                // | LengthDelimitedCodec header| molecule propose header | rand start | rand end/pubkey start | pubkey end/exchange start |...
                //
                // LengthDelimitedCodec header is big-end total len
                // molecule propose header is little-end total len
                // rand start offset is 24 = (5(feild count) + 1(total len))* 4
                let length_delimited_header =
                    u32::from_be_bytes(TryInto::<[u8; 4]>::try_into(&peek_buf[..4]).unwrap());
                let molecule_header =
                    u32::from_le_bytes(TryInto::<[u8; 4]>::try_into(&peek_buf[4..8]).unwrap());
                let rand_start =
                    u32::from_le_bytes(TryInto::<[u8; 4]>::try_into(&peek_buf[8..12]).unwrap());
                let rand_end =
                    u32::from_le_bytes(TryInto::<[u8; 4]>::try_into(&peek_buf[12..16]).unwrap());

                // The first twelve bytes of yamux's message's mode is fixed
                // it's bytes like follow:
                // | byte | byte | 2 byte | 4 byte | 4 byte | ...
                // |--|--|--|--|--|
                // | version | type | flags(big-end) | steam_id(big-end) | header_len(big-end) |...
                //
                // yamux version is fixed = 0x0
                // open window message type = 0x1, ping message type = 0x2
                // flags is Syn = 0x1
                // open window message stream id = 0x1(client standard implementation, but does not check, but can't be zero), ping message steam id = 0x0
                // header_len is not a fixed value.
                // It may be the ping_id or the window length value expressed in windowupdate.
                let yamux_version = peek_buf[0];
                let yamux_ty = peek_buf[1];
                let yamux_flags =
                    u16::from_be_bytes(TryInto::<[u8; 2]>::try_into(&peek_buf[2..4]).unwrap());
                let yamux_stream_id =
                    u32::from_be_bytes(TryInto::<[u8; 4]>::try_into(&peek_buf[4..8]).unwrap());

                if (length_delimited_header == molecule_header
                    && rand_start == 24
                    && rand_start < rand_end
                    && rand_end < molecule_header)
                    || (yamux_version == 0
                        && ((yamux_ty == 0x1 && yamux_stream_id != 0)
                            || (yamux_ty == 0x2 && yamux_stream_id == 0))
                        && yamux_flags == 0x1)
                {
                    upgrade_mode = UpgradeModeEnum::OnlyTcp;
                    continue;
                } else {
                    upgrade_mode = UpgradeModeEnum::OnlyTls;
                    continue;
                }
            }
            #[cfg(feature = "ws")]
            UpgradeModeEnum::TcpAndWs => {
                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut req = httparse::Request::new(&mut headers);

                match req.parse(&peek_buf) {
                    Ok(_) => {
                        upgrade_mode = UpgradeModeEnum::OnlyWs;
                        continue;
                    }
                    Err(_) => {
                        upgrade_mode = UpgradeModeEnum::OnlyTcp;
                        continue;
                    }
                }
            }
            #[cfg(all(feature = "ws", feature = "tls"))]
            UpgradeModeEnum::All => {
                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut req = httparse::Request::new(&mut headers);

                match req.parse(&peek_buf) {
                    Ok(_) => {
                        upgrade_mode = UpgradeModeEnum::OnlyWs;
                        continue;
                    }
                    Err(_) => {
                        upgrade_mode = UpgradeModeEnum::TcpAndTls;
                        continue;
                    }
                }
            }
        }
    }
}
