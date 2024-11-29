use crate::{
    multiaddr::Multiaddr,
    runtime::TcpStream,
    service::config::TcpSocketConfig,
    transports::{Result, TransportDial, TransportFuture, onion_dial},
};
use futures::future::ok;
use std::{future::Future, pin::Pin, time::Duration};

/// Onion connect
async fn connect(
    onion_address: impl Future<Output = Result<Multiaddr>>,
    timeout: Duration,
    tcp_config: TcpSocketConfig,
) -> Result<(Multiaddr, TcpStream)> {
    let onion_addr = onion_address.await?;
    let stream = onion_dial(onion_addr.clone(), tcp_config, timeout).await?;
    Ok((onion_addr, stream))
}

/// Onion transport
pub struct OnionTransport {
    timeout: Duration,
    tcp_config: TcpSocketConfig,
}

impl OnionTransport {
    pub fn new(timeout: Duration, tcp_config: TcpSocketConfig) -> Self {
        Self {
            timeout,
            tcp_config,
        }
    }
}

pub type OnionDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpStream)>> + Send>>>;

impl TransportDial for OnionTransport {
    type DialFuture = OnionDialFuture;

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
        let dial = connect(ok(address), self.timeout, self.tcp_config);
        Ok(TransportFuture::new(Box::pin(dial)))
    }
}
