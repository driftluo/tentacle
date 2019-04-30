use crate::{multiaddr::Multiaddr, utils::socketaddr_to_multiaddr};

use futures::prelude::{Async, Future, Poll, Stream};
use log::debug;
use std::{
    fmt,
    io::{self, Read, Write},
    time::Duration,
};
use tokio::{
    net::{tcp::Incoming, TcpStream},
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
    fn listen(self, address: Multiaddr) -> Result<(Self::ListenFuture, Multiaddr), TransportError>;
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

    fn listen(self, address: Multiaddr) -> Result<(Self::ListenFuture, Multiaddr), TransportError> {
        match TcpTransport::new(self.timeout).listen(address) {
            Ok(res) => Ok((MultiListenFuture::Tcp(res.0), res.1)),
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
    type Item = (Multiaddr, MultiIncoming);
    type Error = TransportError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            MultiListenFuture::Tcp(inner) => {
                inner.map(|res| (res.0, MultiIncoming::Tcp(res.1))).poll()
            }
        }
    }
}

pub enum MultiDialFuture {
    Tcp(TcpDialFuture),
}

impl Future for MultiDialFuture {
    type Item = (Multiaddr, MultiStream);
    type Error = TransportError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            MultiDialFuture::Tcp(inner) => inner.map(|res| (res.0, MultiStream::Tcp(res.1))).poll(),
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

impl Read for MultiStream {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self {
            MultiStream::Tcp(inner) => inner.read(buf),
        }
    }
}

impl Write for MultiStream {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self {
            MultiStream::Tcp(inner) => inner.write(buf),
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), io::Error> {
        match self {
            MultiStream::Tcp(inner) => inner.flush(),
        }
    }
}

impl AsyncRead for MultiStream {
    #[inline]
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        match self {
            MultiStream::Tcp(inner) => inner.prepare_uninitialized_buffer(buf),
        }
    }
}

impl AsyncWrite for MultiStream {
    #[inline]
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match self {
            MultiStream::Tcp(inner) => inner.shutdown(),
        }
    }
}

#[derive(Debug)]
pub enum MultiIncoming {
    Tcp(Incoming),
}

impl Stream for MultiIncoming {
    type Item = (Multiaddr, MultiStream);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self {
            MultiIncoming::Tcp(inner) => match inner.poll()? {
                // Why can't get the peer address of the connected stream ?
                // Error will be "Transport endpoint is not connected",
                // so why incoming will appear unconnected stream ?
                Async::Ready(Some(stream)) => match stream.peer_addr() {
                    Ok(remote_address) => Ok(Async::Ready(Some((
                        socketaddr_to_multiaddr(remote_address),
                        MultiStream::Tcp(stream),
                    )))),
                    Err(err) => {
                        debug!("stream get peer address error: {:?}", err);
                        Ok(Async::NotReady)
                    }
                },
                Async::Ready(None) => Ok(Async::Ready(None)),
                Async::NotReady => Ok(Async::NotReady),
            },
        }
    }
}
