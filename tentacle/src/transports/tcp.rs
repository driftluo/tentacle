use super::Result;
use futures::{future::ok, TryFutureExt};
use std::{future::Future, pin::Pin, time::Duration};

use crate::{
    error::TransportErrorKind,
    multiaddr::Multiaddr,
    runtime::{TcpListener, TcpStream},
    service::config::TcpSocketConfig,
    transports::{tcp_dial, tcp_listen, Transport, TransportFuture},
    utils::{dns::DnsResolver, multiaddr_to_socketaddr, socketaddr_to_multiaddr},
};

/// Tcp listen bind
async fn bind(
    address: impl Future<Output = Result<Multiaddr>>,
    tcp_config: TcpSocketConfig,
) -> Result<(Multiaddr, TcpListener)> {
    let addr = address.await?;
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let (local_addr, tcp) = tcp_listen(socket_address, tcp_config).await?;

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
    tcp_config: TcpSocketConfig,
) -> Result<(Multiaddr, TcpStream)> {
    let addr = address.await?;
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let stream = tcp_dial(socket_address, tcp_config, timeout).await?;
            Ok((original.unwrap_or(addr), stream))
        }
        None => Err(TransportErrorKind::NotSupported(original.unwrap_or(addr))),
    }
}

/// Tcp transport
pub struct TcpTransport {
    timeout: Duration,
    tcp_config: TcpSocketConfig,
}

impl TcpTransport {
    pub fn new(timeout: Duration, tcp_config: TcpSocketConfig) -> Self {
        TcpTransport {
            timeout,
            tcp_config,
        }
    }
}

// If `Existence type` is available, `Pin<Box<...>>` will no longer be needed here, and the signature is `TransportFuture<impl Future<Output=xxx>>`
pub type TcpListenFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpListener)>> + Send>>>;
pub type TcpDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpStream)>> + Send>>>;

impl Transport for TcpTransport {
    type ListenFuture = TcpListenFuture;
    type DialFuture = TcpDialFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
        match DnsResolver::new(address.clone()) {
            Some(dns) => {
                let task = bind(
                    dns.map_err(|(multiaddr, io_error)| {
                        TransportErrorKind::DnsResolverError(multiaddr, io_error)
                    }),
                    self.tcp_config,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
            None => {
                let task = bind(ok(address), self.tcp_config);
                Ok(TransportFuture::new(Box::pin(task)))
            }
        }
    }

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
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
                    self.tcp_config,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
            None => {
                let dial = connect(ok(address), self.timeout, None, self.tcp_config);
                Ok(TransportFuture::new(Box::pin(dial)))
            }
        }
    }
}
