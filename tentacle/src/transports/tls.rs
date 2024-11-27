use super::Result;
use futures::{future::ok, TryFutureExt};
use std::{future::Future, pin::Pin, time::Duration};

use crate::service::TlsConfig;
use crate::{
    error::TransportErrorKind,
    multiaddr::Multiaddr,
    service::config::TcpSocketConfig,
    session::AsyncRw,
    transports::{parse_tls_domain_name, tcp_dial, TransportDial, TransportFuture},
    utils::{dns::DnsResolver, multiaddr_to_socketaddr},
};

use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

pub type TlsStream = Box<dyn AsyncRw + Send + Unpin + 'static>;

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

            let domain_name = ServerName::try_from(domain_name)
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

pub type TlsDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TlsStream)>> + Send>>>;

impl TransportDial for TlsTransport {
    type DialFuture = TlsDialFuture;

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
