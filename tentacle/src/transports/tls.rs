use super::Result;
use futures::{future::ok, SinkExt, Stream, TryFutureExt};
use log::{debug, warn};
use std::{
    borrow::Cow,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use crate::runtime::TcpListener;
use crate::service::TlsConfig;
use crate::{
    error::TransportErrorKind,
    multiaddr::{Multiaddr, Protocol},
    service::config::TcpSocketConfig,
    session::AsyncRw,
    transports::{tcp_dial, tcp_listen, Transport, TransportFuture},
    utils::{dns::DnsResolver, multiaddr_to_socketaddr, socketaddr_to_multiaddr},
};
use futures::channel::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use tokio::io;
use tokio_rustls::rustls::{ServerConfig, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub type TlsStream = Box<dyn AsyncRw + Send + Unpin + 'static>;

/// Tls listen bind
async fn bind(
    address: impl Future<Output = Result<Multiaddr>>,
    timeout: Duration,
    config: TlsConfig,
    domain_name: String,
    tcp_config: TcpSocketConfig,
) -> Result<(Multiaddr, TlsListener)> {
    let addr = address.await?;
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let (local_addr, tcp) = tcp_listen(socket_address, tcp_config).await?;
            let tls_server_config = config.tls_server_config.ok_or_else(|| {
                TransportErrorKind::TlsError("server config not found".to_string())
            })?;
            let mut listen_addr = socketaddr_to_multiaddr(local_addr);
            listen_addr.push(Protocol::Tls(Cow::Owned(domain_name)));
            Ok((
                listen_addr,
                TlsListener::new(timeout, tcp, tls_server_config),
            ))
        }
        None => Err(TransportErrorKind::NotSupported(addr)),
    }
}

/// Tls connect
async fn connect(
    address: impl Future<Output = Result<Multiaddr>>,
    timeout: Duration,
    original: Option<Multiaddr>,
    config: TlsConfig,
    domain_name: String,
    tcp_config: TcpSocketConfig,
) -> Result<(Multiaddr, TlsStream)> {
    let tls_client_config = config
        .tls_client_config
        .ok_or_else(|| TransportErrorKind::TlsError("client config not found".to_string()))?;

    let addr = address.await?;
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let stream = tcp_dial(socket_address, tcp_config, timeout).await?;

            let domain_name = ServerName::try_from(domain_name.as_str())
                .map_err(|_| TransportErrorKind::TlsError("invalid dnsname".to_string()))?;
            let connector = TlsConnector::from(tls_client_config);
            Ok((
                original.unwrap_or(addr),
                Box::new(
                    connector
                        .connect(domain_name, stream)
                        .await
                        .map_err(TransportErrorKind::Io)?,
                ),
            ))
        }
        None => Err(TransportErrorKind::NotSupported(original.unwrap_or(addr))),
    }
}

pub struct TlsListener {
    inner: TcpListener,
    timeout: Duration,
    sender: Sender<(Multiaddr, TlsStream)>,
    pending_stream: Receiver<(Multiaddr, TlsStream)>,
    tls_config: Arc<ServerConfig>,
}

impl TlsListener {
    fn new(timeout: Duration, listen: TcpListener, tls_config: Arc<ServerConfig>) -> Self {
        let (sender, rx) = channel(24);
        TlsListener {
            inner: listen,
            timeout,
            sender,
            pending_stream: rx,
            tls_config,
        }
    }

    fn poll_pending(&mut self, cx: &mut Context) -> Poll<(Multiaddr, TlsStream)> {
        match Pin::new(&mut self.pending_stream).as_mut().poll_next(cx) {
            Poll::Ready(Some(res)) => Poll::Ready(res),
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }

    fn poll_listen(&mut self, cx: &mut Context) -> Poll<std::result::Result<(), io::Error>> {
        match self.inner.poll_accept(cx)? {
            Poll::Ready((stream, _)) => {
                match stream.peer_addr() {
                    Ok(remote_address) => {
                        let timeout = self.timeout;
                        let mut sender = self.sender.clone();
                        let acceptor = TlsAcceptor::from(Arc::clone(&self.tls_config));
                        crate::runtime::spawn(async move {
                            match crate::runtime::timeout(timeout, acceptor.accept(stream)).await {
                                Err(_) => warn!("accept tls server stream timeout"),
                                Ok(res) => match res {
                                    Ok(stream) => {
                                        let mut addr = socketaddr_to_multiaddr(remote_address);
                                        addr.push(Protocol::Tls(Cow::Borrowed("")));
                                        if sender.send((addr, Box::new(stream))).await.is_err() {
                                            debug!("receiver closed unexpectedly")
                                        }
                                    }
                                    Err(err) => {
                                        warn!("accept tls server stream err: {:?}", err);
                                    }
                                },
                            }
                        });
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

impl Stream for TlsListener {
    type Item = std::result::Result<(Multiaddr, TlsStream), io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
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

fn parse_tls_domain_name(addr: &Multiaddr) -> Option<String> {
    let mut iter = addr.iter();

    iter.find_map(|proto| {
        if let Protocol::Tls(s) = proto {
            Some(s.to_string())
        } else {
            None
        }
    })
}

/// Tcp transport
pub struct TlsTransport {
    timeout: Duration,
    config: TlsConfig,
    tcp_config: TcpSocketConfig,
}

impl TlsTransport {
    pub fn new(timeout: Duration, config: TlsConfig, tcp_config: TcpSocketConfig) -> Self {
        TlsTransport {
            timeout,
            config,
            tcp_config,
        }
    }
}

pub type TlsListenFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TlsListener)>> + Send>>>;
pub type TlsDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TlsStream)>> + Send>>>;

impl Transport for TlsTransport {
    type ListenFuture = TlsListenFuture;
    type DialFuture = TlsDialFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
        if let Some(domain_name) = parse_tls_domain_name(&address) {
            match DnsResolver::new(address.clone()) {
                Some(dns) => {
                    let task = bind(
                        dns.map_err(|(multiaddr, io_error)| {
                            TransportErrorKind::DnsResolverError(multiaddr, io_error)
                        }),
                        self.timeout,
                        self.config,
                        domain_name,
                        self.tcp_config,
                    );
                    Ok(TransportFuture::new(Box::pin(task)))
                }
                None => {
                    let task = bind(
                        ok(address),
                        self.timeout,
                        self.config,
                        domain_name,
                        self.tcp_config,
                    );
                    Ok(TransportFuture::new(Box::pin(task)))
                }
            }
        } else {
            Err(TransportErrorKind::NotSupported(address))
        }
    }

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
        if let Some(domain_name) = parse_tls_domain_name(&address) {
            match DnsResolver::new(address.clone()) {
                Some(dns) => {
                    // Why do this?
                    // Because here need to save the original address as an index to open the specified protocol.
                    let task = connect(
                        dns.map_err(|(multiaddr, io_error)| {
                            TransportErrorKind::DnsResolverError(multiaddr, io_error)
                        }),
                        self.timeout,
                        Some(address),
                        self.config,
                        domain_name,
                        self.tcp_config,
                    );
                    Ok(TransportFuture::new(Box::pin(task)))
                }
                None => {
                    let dial = connect(
                        ok(address),
                        self.timeout,
                        None,
                        self.config,
                        domain_name,
                        self.tcp_config,
                    );
                    Ok(TransportFuture::new(Box::pin(dial)))
                }
            }
        } else {
            Err(TransportErrorKind::NotSupported(address))
        }
    }
}
