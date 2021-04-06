use futures::{channel::mpsc, prelude::*};
use log::{debug, error, trace};
use multiaddr::Multiaddr;
use secio::handshake::Config;
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
    service::future_task::BoxedFutureTask,
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

pub(crate) struct HandshakeContext {
    pub(crate) key_pair: Option<secio::SecioKeyPair>,
    pub(crate) event_sender: mpsc::Sender<SessionEvent>,
    pub(crate) max_frame_length: usize,
    pub(crate) timeout: Duration,
    pub(crate) ty: SessionType,
    pub(crate) remote_address: Multiaddr,
    pub(crate) listen_address: Option<Multiaddr>,
}

impl HandshakeContext {
    pub async fn handshake<H>(mut self, socket: H)
    where
        H: AsyncRead + AsyncWrite + Send + 'static + Unpin,
    {
        match self.key_pair {
            Some(key_pair) => {
                let result = crate::runtime::timeout(
                    self.timeout,
                    Config::new(key_pair)
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
            None => {
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

#[cfg(not(target_arch = "wasm32"))]
pub struct Listener {
    pub(crate) inner: MultiIncoming,
    pub(crate) key_pair: Option<secio::SecioKeyPair>,
    pub(crate) event_sender: mpsc::Sender<SessionEvent>,
    pub(crate) max_frame_length: usize,
    pub(crate) timeout: Duration,
    pub(crate) listen_addr: Multiaddr,
    pub(crate) future_task_sender: mpsc::Sender<BoxedFutureTask>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Listener {
    fn close(&self, io_err: io::Error) {
        let mut event_sender = self.event_sender.clone();
        let mut future_sender = self.future_task_sender.clone();
        let address = self.listen_addr.clone();
        let report_task = async move {
            if let Err(err) = event_sender
                .send(SessionEvent::ListenError {
                    address,
                    error: TransportErrorKind::Io(io_err),
                })
                .await
            {
                error!("Listen address result send back error: {:?}", err);
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
            key_pair: self.key_pair.clone(),
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

#[cfg(not(target_arch = "wasm32"))]
impl Stream for Listener {
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
