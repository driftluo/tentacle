use futures::{TryFutureExt, future::ok};
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
        Result, TcpListenMode, TransportDial, TransportFuture, TransportListen,
        tcp_base_listen::{TcpBaseListenerEnum, UpgradeMode, bind},
        tcp_dial,
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
    /// Trusted proxy addresses for HAProxy PROXY protocol and X-Forwarded-For header parsing.
    trusted_proxies: Arc<Vec<std::net::IpAddr>>,
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
            trusted_proxies: Arc::new(Vec::new()),
        }
    }

    pub fn from_multi_transport(
        multi_transport: super::MultiTransport,
        listen_mode: TcpListenMode,
    ) -> Self {
        Self {
            timeout: multi_transport.timeout.timeout,
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
            trusted_proxies: multi_transport.trusted_proxies,
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
                    self.trusted_proxies,
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
                    self.trusted_proxies,
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
