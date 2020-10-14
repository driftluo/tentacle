use super::Result;
use futures::{future::ok, TryFutureExt};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    error::TransportErrorKind,
    multiaddr::Multiaddr,
    runtime::{TcpListener, TcpStream},
    transports::{tcp_dial, tcp_listen, Transport},
    utils::{dns::DNSResolver, multiaddr_to_socketaddr, socketaddr_to_multiaddr},
};

/// Tcp listen bind
async fn bind(
    address: impl Future<Output = Result<Multiaddr>>,
    reuse: bool,
) -> Result<(Multiaddr, TcpListener)> {
    let addr = address.await?;
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let (local_addr, tcp) = tcp_listen(socket_address, reuse).await?;

            let listen_addr = socketaddr_to_multiaddr(local_addr);

            Ok((listen_addr, tcp))
        }
        None => Err(TransportErrorKind::NotSupported(addr)),
    }
}

/// Tcp connect
async fn connect(
    address: impl Future<Output = Result<Multiaddr>>,
    timeout: Duration,
    original: Option<Multiaddr>,
    bind_addr: Option<SocketAddr>,
) -> Result<(Multiaddr, TcpStream)> {
    let addr = address.await?;
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let stream = tcp_dial(socket_address, bind_addr, timeout).await?;
            Ok((original.unwrap_or(addr), stream))
        }
        None => Err(TransportErrorKind::NotSupported(original.unwrap_or(addr))),
    }
}

/// Tcp transport
#[derive(Default)]
pub struct TcpTransport {
    timeout: Duration,
    bind_addr: Option<SocketAddr>,
}

impl TcpTransport {
    pub fn new(timeout: Duration, bind_addr: Option<SocketAddr>) -> Self {
        TcpTransport { timeout, bind_addr }
    }
}

impl Transport for TcpTransport {
    type ListenFuture = TcpListenFuture;
    type DialFuture = TcpDialFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
        match DNSResolver::new(address.clone()) {
            Some(dns) => {
                let task = bind(
                    dns.map_err(|(multiaddr, io_error)| {
                        TransportErrorKind::DNSResolverError(multiaddr, io_error)
                    }),
                    self.bind_addr.is_some(),
                );
                Ok(TcpListenFuture::new(task))
            }
            None => {
                let task = bind(ok(address), self.bind_addr.is_some());
                Ok(TcpListenFuture::new(task))
            }
        }
    }

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
        match DNSResolver::new(address.clone()) {
            Some(dns) => {
                // Why do this?
                // Because here need to save the original address as an index to open the specified protocol.
                let task = connect(
                    dns.map_err(|(multiaddr, io_error)| {
                        TransportErrorKind::DNSResolverError(multiaddr, io_error)
                    }),
                    self.timeout,
                    Some(address),
                    self.bind_addr,
                );
                Ok(TcpDialFuture::new(task))
            }
            None => {
                let dial = connect(ok(address), self.timeout, None, self.bind_addr);
                Ok(TcpDialFuture::new(dial))
            }
        }
    }
}

type TcpListenFutureInner = Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpListener)>> + Send>>;

/// Tcp listen future
pub struct TcpListenFuture {
    executed: TcpListenFutureInner,
}

impl TcpListenFuture {
    fn new<T>(executed: T) -> Self
    where
        T: Future<Output = Result<(Multiaddr, TcpListener)>> + 'static + Send,
    {
        TcpListenFuture {
            executed: Box::pin(executed),
        }
    }
}

impl Future for TcpListenFuture {
    type Output = Result<(Multiaddr, TcpListener)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.executed.as_mut().poll(cx)
    }
}

type TcpDialFutureInner = Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpStream)>> + Send>>;

/// Tcp dial future
pub struct TcpDialFuture {
    executed: TcpDialFutureInner,
}

impl TcpDialFuture {
    fn new<T>(executed: T) -> Self
    where
        T: Future<Output = Result<(Multiaddr, TcpStream)>> + 'static + Send,
    {
        TcpDialFuture {
            executed: Box::pin(executed),
        }
    }
}

impl Future for TcpDialFuture {
    type Output = Result<(Multiaddr, TcpStream)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.executed.as_mut().poll(cx)
    }
}
