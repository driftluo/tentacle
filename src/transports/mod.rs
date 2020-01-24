use crate::{multiaddr::Multiaddr, utils::socketaddr_to_multiaddr};

use futures::{prelude::Stream, FutureExt};
use log::debug;
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    prelude::{AsyncRead, AsyncWrite},
};

use self::tcp::{TcpDialFuture, TcpListenFuture, TcpTransport};

mod tcp;

/// Transport Error
pub enum TransportError {
    /// Protocol not support
    NotSupport(Multiaddr),
    /// Dns resolver error
    DNSResolverError((Multiaddr, io::Error)),
    /// Io error
    Io(io::Error),
}

impl Into<io::Error> for TransportError {
    fn into(self) -> io::Error {
        match self {
            TransportError::Io(err) => err,
            _ => io::ErrorKind::InvalidData.into(),
        }
    }
}

/// Definition of transport protocol behavior
pub trait Transport {
    type ListenFuture;
    type DialFuture;

    /// Transport listen
    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture, TransportError>;
    /// Transport dial
    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture, TransportError>;
}

#[derive(Clone, Copy)]
pub struct MultiTransport {
    timeout: Duration,
}

impl MultiTransport {
    pub fn new(timeout: Duration) -> Self {
        MultiTransport { timeout }
    }
}

impl Transport for MultiTransport {
    type ListenFuture = MultiListenFuture;
    type DialFuture = MultiDialFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture, TransportError> {
        match TcpTransport::new(self.timeout).listen(address) {
            Ok(future) => Ok(MultiListenFuture::Tcp(future)),
            Err(e) => Err(e),
        }
    }

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture, TransportError> {
        match TcpTransport::new(self.timeout).dial(address) {
            Ok(res) => Ok(MultiDialFuture::Tcp(res)),
            Err(e) => Err(e),
        }
    }
}

pub enum MultiListenFuture {
    Tcp(TcpListenFuture),
}

impl Future for MultiListenFuture {
    type Output = Result<(Multiaddr, MultiIncoming), TransportError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            MultiListenFuture::Tcp(inner) => {
                Pin::new(&mut inner.map(|res| res.map(|res| (res.0, MultiIncoming::Tcp(res.1)))))
                    .poll(cx)
            }
        }
    }
}

pub enum MultiDialFuture {
    Tcp(TcpDialFuture),
}

impl Future for MultiDialFuture {
    type Output = Result<(Multiaddr, MultiStream), TransportError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            MultiDialFuture::Tcp(inner) => {
                Pin::new(&mut inner.map(|res| res.map(|res| (res.0, MultiStream::Tcp(res.1)))))
                    .poll(cx)
            }
        }
    }
}

pub enum MultiStream {
    Tcp(TcpStream),
}

impl fmt::Debug for MultiStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MultiStream::Tcp(_) => write!(f, "Tcp stream"),
        }
    }
}

impl AsyncRead for MultiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MultiStream::Tcp(inner) => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MultiStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MultiStream::Tcp(inner) => Pin::new(inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MultiStream::Tcp(inner) => Pin::new(inner).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MultiStream::Tcp(inner) => Pin::new(inner).poll_shutdown(cx),
        }
    }
}

#[derive(Debug)]
pub enum MultiIncoming {
    Tcp(TcpListener),
}

impl Stream for MultiIncoming {
    type Item = Result<(Multiaddr, MultiStream), io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            MultiIncoming::Tcp(inner) => match inner.accept().boxed_local().poll_unpin(cx)? {
                // Why can't get the peer address of the connected stream ?
                // Error will be "Transport endpoint is not connected",
                // so why incoming will appear unconnected stream ?
                Poll::Ready((stream, _)) => match stream.peer_addr() {
                    Ok(remote_address) => Poll::Ready(Some(Ok((
                        socketaddr_to_multiaddr(remote_address),
                        MultiStream::Tcp(stream),
                    )))),
                    Err(err) => {
                        debug!("stream get peer address error: {:?}", err);
                        Poll::Pending
                    }
                },
                Poll::Pending => Poll::Pending,
            },
        }
    }
}
