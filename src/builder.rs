use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    secio::SecioKeyPair,
    service::{config::ServiceConfig, Service},
    traits::{ProtocolMeta, ServiceHandle},
    yamux::Config,
};

/// Builder for Service
pub struct ServiceBuilder {
    inner: HashMap<String, Box<dyn ProtocolMeta + Send + Sync>>,
    key_pair: Option<SecioKeyPair>,
    forever: bool,
    config: ServiceConfig,
}

impl ServiceBuilder {
    /// New a default empty builder
    pub fn new() -> Self {
        Default::default()
    }

    /// Combine the configuration of this builder with service handle to create a Service.
    pub fn build<H>(self, handle: H) -> Service<H>
    where
        H: ServiceHandle,
    {
        Service::new(
            Arc::new(self.inner),
            handle,
            self.key_pair,
            self.forever,
            self.config,
        )
    }

    /// Insert a custom protocol
    pub fn insert_protocol<T>(mut self, protocol: T) -> Self
    where
        T: ProtocolMeta + Send + Sync + 'static,
    {
        if protocol.session_handle().has_event() || protocol.service_handle().has_event() {
            self.config.event.insert(protocol.id());
        }

        self.inner.insert(
            protocol.name(),
            Box::new(protocol) as Box<dyn ProtocolMeta + Send + Sync>,
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
        self.config.timeout = timeout;
        self
    }

    /// Yamux config for service
    ///
    /// Panic when max_frame_length < yamux_max_window_size
    pub fn yamux_config(mut self, config: Config) -> Self {
        assert!(self.config.max_frame_length as u32 >= config.max_stream_window_size);
        self.config.yamux_config = config;
        self
    }

    /// Secio max frame length
    ///
    /// Panic when max_frame_length < yamux_max_window_size
    pub fn max_frame_length(mut self, size: usize) -> Self {
        assert!(size as u32 >= self.config.yamux_config.max_stream_window_size);
        self.config.max_frame_length = size;
        self
    }

    /// Clear all protocols
    pub fn clear(&mut self) {
        self.inner.clear();
        self.config.event.clear();
    }
}

impl Default for ServiceBuilder {
    fn default() -> Self {
        ServiceBuilder {
            inner: HashMap::new(),
            key_pair: None,
            forever: false,
            config: ServiceConfig::default(),
        }
    }
}
