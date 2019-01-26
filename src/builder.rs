use secio::SecioKeyPair;
use std::collections::HashMap;
use std::sync::Arc;
use std::{error, io, time::Duration};
use tokio::codec::{Decoder, Encoder};
use yamux::Config;

use crate::{
    service::Service,
    traits::{ProtocolMeta, ServiceHandle},
};

/// Builder for Service
pub struct ServiceBuilder<U> {
    inner: HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>,
    key_pair: Option<SecioKeyPair>,
    forever: bool,
    timeout: Duration,
    yamux_config: Config,
    max_frame_length: usize,
}

impl<U> ServiceBuilder<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error + Into<io::Error>,
    <U as Encoder>::Error: error::Error + Into<io::Error>,
{
    /// New a default empty builder
    pub fn new() -> Self {
        Default::default()
    }

    /// Combine the configuration of this builder with service handle to create a Service.
    pub fn build<H>(self, handle: H) -> Service<H, U>
    where
        H: ServiceHandle,
    {
        Service::new(
            Arc::new(self.inner),
            handle,
            self.key_pair,
            self.forever,
            self.timeout,
        )
        .max_frame_length(self.max_frame_length)
        .yamux_config(self.yamux_config)
    }

    /// Insert a custom protocol
    pub fn insert_protocol<T>(mut self, protocol: T) -> Self
    where
        T: ProtocolMeta<U> + Send + Sync + 'static,
    {
        self.inner.insert(
            protocol.name(),
            Box::new(protocol) as Box<dyn ProtocolMeta<_> + Send + Sync>,
        );
        self
    }

    /// Enable encrypted communication mode.
    ///
    /// If you do not need encrypted communication, you do not need to call this method
    pub fn key_pair(mut self, key_pair: SecioKeyPair) -> Self {
        self.key_pair = Some(key_pair);
        self
    }

    /// When the service has no tasks, it will be turned off by default.
    /// If you do not want to close service, set it to true.
    pub fn forever(mut self, forever: bool) -> Self {
        self.forever = forever;
        self
    }

    /// Timeout for handshake and connect
    ///
    /// Default 10 second
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Yamux config for service
    ///
    /// Panic when max_frame_length < yamux_max_window_size
    pub fn yamux_config(mut self, config: Config) -> Self {
        assert!(self.max_frame_length as u32 >= config.max_stream_window_size);
        self.yamux_config = config;
        self
    }

    /// Secio max frame length
    ///
    /// Panic when max_frame_length < yamux_max_window_size
    pub fn max_frame_length(mut self, size: usize) -> Self {
        assert!(size as u32 >= self.yamux_config.max_stream_window_size);
        self.max_frame_length = size;
        self
    }

    /// Clear all protocols
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl<U> Default for ServiceBuilder<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error + Into<io::Error>,
    <U as Encoder>::Error: error::Error + Into<io::Error>,
{
    fn default() -> Self {
        ServiceBuilder {
            inner: HashMap::new(),
            key_pair: None,
            forever: false,
            timeout: Duration::from_secs(10),
            yamux_config: Config::default(),
            max_frame_length: 1024 * 1024 * 8,
        }
    }
}
