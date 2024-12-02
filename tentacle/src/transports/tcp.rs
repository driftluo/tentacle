use futures::{future::ok, TryFutureExt};
use std::{
    collections::HashMap, future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

#[cfg(feature = "tls")]
use crate::service::TlsConfig;
use crate::{
    error::TransportErrorKind,
    multiaddr::Multiaddr,
    runtime::TcpStream,
    service::config::TcpSocketConfig,
    transports::{
        tcp_base_listen::{bind, TcpBaseListenerEnum, UpgradeMode},
        tcp_dial, Result, TcpListenMode, TransportDial, TransportFuture, TransportListen,
    },
    utils::{dns::DnsResolver, multiaddr_to_socketaddr},
};

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
    listen_mode: TcpListenMode,
    global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    #[cfg(feature = "tls")]
    tls_config: TlsConfig,
}

impl TcpTransport {
    pub fn new(timeout: Duration, tcp_config: TcpSocketConfig) -> Self {
        Self {
            timeout,
            tcp_config,
            listen_mode: TcpListenMode::Tcp,
            global: Arc::new(crate::lock::Mutex::new(Default::default())),
            #[cfg(feature = "tls")]
            tls_config: Default::default(),
        }
    }

    pub fn from_multi_transport(
        multi_transport: super::MultiTransport,
        listen_mode: TcpListenMode,
    ) -> Self {
        Self {
            timeout: multi_transport.timeout,
            tcp_config: match listen_mode {
                TcpListenMode::Tcp => multi_transport.tcp_config.tcp,
                #[cfg(feature = "ws")]
                TcpListenMode::Ws => multi_transport.tcp_config.ws,
                #[cfg(feature = "tls")]
                TcpListenMode::Tls => multi_transport.tcp_config.tls,
            },
            listen_mode,
            global: multi_transport.listens_upgrade_modes,
            #[cfg(feature = "tls")]
            tls_config: multi_transport.tls_config.unwrap_or_default(),
        }
    }
}

// If `Existence type` is available, `Pin<Box<...>>` will no longer be needed here, and the signature is `TransportFuture<impl Future<Output=xxx>>`
pub type TcpListenFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpBaseListenerEnum)>> + Send>>>;
pub type TcpDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpStream)>> + Send>>>;

impl TransportListen for TcpTransport {
    type ListenFuture = TcpListenFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
        match DnsResolver::new(address.clone()) {
            Some(dns) => {
                let task = bind(
                    dns.map_err(|(multiaddr, io_error)| {
                        TransportErrorKind::DnsResolverError(multiaddr, io_error)
                    }),
                    self.tcp_config,
                    self.listen_mode,
                    #[cfg(feature = "tls")]
                    self.tls_config,
                    self.global,
                    self.timeout,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
            None => {
                let task = bind(
                    ok(address),
                    self.tcp_config,
                    self.listen_mode,
                    #[cfg(feature = "tls")]
                    self.tls_config,
                    self.global,
                    self.timeout,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
        }
    }
}

impl TransportDial for TcpTransport {
    type DialFuture = TcpDialFuture;

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
