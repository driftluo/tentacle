use futures::{channel::mpsc, prelude::*};
use log::{debug, error, trace};
use multiaddr::Multiaddr;
use secio::{KeyProvider, handshake::Config};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use yamux::session::SessionType as YamuxType;

use crate::{
    error::{HandshakeErrorKind, TransportErrorKind},
    service::{HandshakeType, future_task::BoxedFutureTask},
    session::SessionEvent,
    transports::MultiIncoming,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    /// Event from user
    External,
    /// Event from session
    Internal,
}

/// Indicates the session type
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SessionType {
    /// Representing yourself as the active party means that you are the client side
    Outbound,
    /// Representing yourself as a passive recipient means that you are the server side
    Inbound,
}

impl SessionType {
    /// is outbound
    #[inline]
    pub fn is_outbound(self) -> bool {
        match self {
            SessionType::Outbound => true,
            SessionType::Inbound => false,
        }
    }

    /// is inbound
    #[inline]
    pub fn is_inbound(self) -> bool {
        !self.is_outbound()
    }
}

impl From<YamuxType> for SessionType {
    #[inline]
    fn from(ty: YamuxType) -> Self {
        match ty {
            YamuxType::Client => SessionType::Outbound,
            YamuxType::Server => SessionType::Inbound,
        }
    }
}

impl From<SessionType> for YamuxType {
    #[inline]
    fn from(ty: SessionType) -> YamuxType {
        match ty {
            SessionType::Outbound => YamuxType::Client,
            SessionType::Inbound => YamuxType::Server,
        }
    }
}

pub(crate) struct HandshakeContext<K> {
    pub(crate) handshake_type: HandshakeType<K>,
    pub(crate) event_sender: mpsc::Sender<SessionEvent>,
    pub(crate) max_frame_length: usize,
    pub(crate) timeout: Duration,
    pub(crate) ty: SessionType,
    pub(crate) remote_address: Multiaddr,
    pub(crate) listen_address: Option<Multiaddr>,
}

impl<K> HandshakeContext<K>
where
    K: KeyProvider,
{
    pub async fn handshake<H>(mut self, socket: H)
    where
        H: AsyncRead + AsyncWrite + Send + 'static + Unpin,
    {
        match self.handshake_type {
            HandshakeType::Secio(key_provider) => {
                let result = crate::runtime::timeout(
                    self.timeout,
                    Config::new(key_provider)
                        .max_frame_length(self.max_frame_length)
                        .handshake(socket),
                )
                .await;

                let event = match result {
                    Err(error) => {
                        debug!(
                            "Handshake with {} failed, error: {:?}",
                            self.remote_address, error
                        );
                        // time out error
                        SessionEvent::HandshakeError {
                            ty: self.ty,
                            error: HandshakeErrorKind::Timeout(error.to_string()),
                            address: self.remote_address,
                        }
                    }
                    Ok(res) => match res {
                        Ok((handle, public_key, _)) => SessionEvent::HandshakeSuccess {
                            handle: Box::new(handle),
                            public_key: Some(public_key),
                            address: self.remote_address,
                            ty: self.ty,
                            listen_address: self.listen_address,
                        },
                        Err(error) => {
                            debug!(
                                "Handshake with {} failed, error: {:?}",
                                self.remote_address, error
                            );
                            SessionEvent::HandshakeError {
                                ty: self.ty,
                                error: HandshakeErrorKind::SecioError(error),
                                address: self.remote_address,
                            }
                        }
                    },
                };
                if let Err(err) = self.event_sender.send(event).await {
                    error!("handshake result send back error: {:?}", err);
                }
            }
            HandshakeType::Noop => {
                let event = SessionEvent::HandshakeSuccess {
                    handle: Box::new(socket),
                    public_key: None,
                    address: self.remote_address,
                    ty: self.ty,
                    listen_address: self.listen_address,
                };
                if let Err(err) = self.event_sender.send(event).await {
                    error!("handshake result send back error: {:?}", err);
                }
            }
        }
    }
}

#[cfg(not(target_family = "wasm"))]
pub struct Listener<K> {
    pub(crate) inner: MultiIncoming,
    pub(crate) handshake_type: HandshakeType<K>,
    pub(crate) event_sender: mpsc::Sender<SessionEvent>,
    pub(crate) max_frame_length: usize,
    pub(crate) timeout: Duration,
    pub(crate) listen_addr: Multiaddr,
    pub(crate) future_task_sender: mpsc::Sender<BoxedFutureTask>,
    pub(crate) listens_upgrade_modes: std::sync::Arc<
        crate::lock::Mutex<
            std::collections::HashMap<
                std::net::SocketAddr,
                crate::transports::tcp_base_listen::UpgradeMode,
            >,
        >,
    >,
}

#[cfg(not(target_family = "wasm"))]
impl<K> Listener<K>
where
    K: KeyProvider,
{
    fn close(&self, io_err: io::Error) {
        let mut event_sender = self.event_sender.clone();
        let mut future_sender = self.future_task_sender.clone();
        let address = self.listen_addr.clone();
        let mode = {
            use crate::utils::multiaddr_to_socketaddr;

            let global = self.listens_upgrade_modes.lock();
            match multiaddr_to_socketaddr(&address) {
                Some(net_addr) => global.get(&net_addr).map(|u| u.to_enum()),
                None => None,
            }
        };
        #[cfg(any(feature = "ws", feature = "tls"))]
        use crate::multiaddr::Protocol;
        use crate::transports::tcp_base_listen::UpgradeModeEnum;
        let report_task = async move {
            match mode {
                None => {
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address,
                            error: TransportErrorKind::Io(io_err),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                }
                Some(UpgradeModeEnum::OnlyTcp) => {
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address,
                            error: TransportErrorKind::Io(io_err),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                }
                #[cfg(feature = "ws")]
                Some(UpgradeModeEnum::OnlyWs) => {
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address,
                            error: TransportErrorKind::Io(io_err),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                }
                #[cfg(feature = "tls")]
                Some(UpgradeModeEnum::OnlyTls) => {
                    let clear_addr = address
                        .into_iter()
                        .map(|p| {
                            if let Protocol::Tls(_) = p {
                                Protocol::Tls(Default::default())
                            } else {
                                p
                            }
                        })
                        .collect::<Multiaddr>();
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address: clear_addr,
                            error: TransportErrorKind::Io(io_err),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                }
                #[cfg(feature = "tls")]
                Some(UpgradeModeEnum::TcpAndTls) => {
                    let base_net: Multiaddr = address
                        .iter()
                        .filter_map(|p| {
                            if matches!(p, Protocol::Tls(_)) {
                                None
                            } else {
                                Some(p)
                            }
                        })
                        .collect();
                    let mut tls_net = base_net.clone();
                    tls_net.push(Protocol::Tls(Default::default()));
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address: base_net,
                            error: TransportErrorKind::Io(std::io::Error::new(
                                io_err.kind(),
                                io_err.to_string(),
                            )),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address: tls_net,
                            error: TransportErrorKind::Io(io_err),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                }
                #[cfg(feature = "ws")]
                Some(UpgradeModeEnum::TcpAndWs) => {
                    let base_net: Multiaddr = address
                        .iter()
                        .filter_map(|p| {
                            if matches!(p, Protocol::Ws) {
                                None
                            } else {
                                Some(p)
                            }
                        })
                        .collect();
                    let mut ws_net = base_net.clone();
                    ws_net.push(Protocol::Ws);
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address: base_net,
                            error: TransportErrorKind::Io(std::io::Error::new(
                                io_err.kind(),
                                io_err.to_string(),
                            )),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address: ws_net,
                            error: TransportErrorKind::Io(io_err),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                }
                #[cfg(all(feature = "ws", feature = "tls"))]
                Some(UpgradeModeEnum::All) => {
                    let base_net: Multiaddr = address
                        .iter()
                        .filter_map(|p| {
                            if matches!(p, Protocol::Ws | Protocol::Tls(_)) {
                                None
                            } else {
                                Some(p)
                            }
                        })
                        .collect();
                    let mut ws_net = base_net.clone();
                    let mut tls_net = base_net.clone();
                    ws_net.push(Protocol::Ws);
                    tls_net.push(Protocol::Tls(Default::default()));
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address: base_net,
                            error: TransportErrorKind::Io(std::io::Error::new(
                                io_err.kind(),
                                io_err.to_string(),
                            )),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address: ws_net,
                            error: TransportErrorKind::Io(std::io::Error::new(
                                io_err.kind(),
                                io_err.to_string(),
                            )),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                    if let Err(err) = event_sender
                        .send(SessionEvent::ListenError {
                            address: tls_net,
                            error: TransportErrorKind::Io(io_err),
                        })
                        .await
                    {
                        error!("Listen address result send back error: {:?}", err);
                    }
                }
            }
        };
        crate::runtime::spawn(async move {
            if future_sender.send(Box::pin(report_task)).await.is_err() {
                trace!("Listen address result send to future manager error");
            }
        });
    }

    fn handshake<H>(&self, socket: H, remote_address: Multiaddr)
    where
        H: AsyncRead + AsyncWrite + Send + 'static + Unpin,
    {
        let handshake_task = HandshakeContext {
            ty: SessionType::Inbound,
            remote_address,
            listen_address: Some(self.listen_addr.clone()),
            handshake_type: self.handshake_type.clone(),
            event_sender: self.event_sender.clone(),
            max_frame_length: self.max_frame_length,
            timeout: self.timeout,
        }
        .handshake(socket);

        let mut future_task_sender = self.future_task_sender.clone();

        crate::runtime::spawn(async move {
            if future_task_sender
                .send(Box::pin(handshake_task))
                .await
                .is_err()
            {
                trace!("handshake send err")
            }
        });
    }
}

#[cfg(not(target_family = "wasm"))]
impl<K> Unpin for Listener<K> {}

#[cfg(not(target_family = "wasm"))]
impl<K> Stream for Listener<K>
where
    K: KeyProvider,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok((remote_address, socket)))) => {
                self.handshake(socket, remote_address);
                Poll::Ready(Some(()))
            }
            Poll::Ready(None) => {
                self.close(io::ErrorKind::BrokenPipe.into());
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(err))) => {
                self.close(err);
                Poll::Ready(None)
            }
        }
    }
}
