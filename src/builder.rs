use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::codec::LengthDelimitedCodec;

use crate::{
    secio::SecioKeyPair,
    service::{config::ServiceConfig, ProtocolHandle, ProtocolMeta, Service},
    traits::{Codec, ServiceHandle, ServiceProtocol, SessionProtocol},
    yamux::Config,
    ProtocolId,
};

/// Builder for Service
pub struct ServiceBuilder {
    inner: HashMap<String, ProtocolMeta>,
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
    pub fn insert_protocol(mut self, protocol: ProtocolMeta) -> Self {
        if protocol.session_handle().has_event() || protocol.service_handle().has_event() {
            self.config.event.insert(protocol.id());
        }

        self.inner.insert(protocol.name(), protocol);
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

/// Builder for protocol meta
pub struct MetaBuilder {
    id: ProtocolId,
    name: Box<Fn(&ProtocolMeta) -> String + Send + Sync>,
    support_versions: Vec<String>,
    codec: Box<Fn(&ProtocolMeta) -> Box<dyn Codec + Send + 'static> + Send + Sync>,
    service_handle: Box<Fn(&ProtocolMeta) -> ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static>> + Send + Sync>,
    session_handle: Box<Fn(&ProtocolMeta) -> ProtocolHandle<Box<dyn SessionProtocol + Send + 'static>> + Send + Sync>,
}

impl MetaBuilder {
    /// New a default builder
    pub fn new() -> Self {
        Default::default()
    }

    /// Define protocol id
    pub fn id(mut self, id: ProtocolId) -> Self {
        self.id = id;
        self
    }

    /// Define protocol name
    pub fn name<T: Fn(&ProtocolMeta) -> String + 'static + Send + Sync>(mut self, name: T) -> Self {
        self.name = Box::new(name);
        self
    }

    /// Define protocol support versions
    pub fn support_versions(mut self, versions: Vec<String>) -> Self {
        self.support_versions = versions;
        self
    }

    /// Define protocol codec
    pub fn codec<T: Fn(&ProtocolMeta) -> Box<dyn Codec + Send + 'static> + 'static + Send + Sync>(mut self, codec: T) -> Self {
        self.codec = Box::new(codec);
        self
    }

    /// Define protocol service handle
    pub fn service_handle<T: Fn(&ProtocolMeta) -> ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static>> + 'static + Sync + Send>(
        mut self,
        service_handle: T,
    ) -> Self {
        self.service_handle = Box::new(service_handle);
        self
    }

    /// Define protocol session handle
    pub fn session_handle<T: Fn(&ProtocolMeta) -> ProtocolHandle<Box<dyn SessionProtocol + Send + 'static>> + 'static + Send + Sync>(
        mut self,
        session_handle: T,
    ) -> Self {
        self.session_handle = Box::new(session_handle);
        self
    }

    /// Combine the configuration of this builder to create a ProtocolMeta
    pub fn build(self) -> ProtocolMeta {
        ProtocolMeta {
            id: self.id,
            name: self.name,
            support_versions: self.support_versions,
            codec: self.codec,
            service_handle: self.service_handle,
            session_handle: self.session_handle,
        }
    }
}

impl Default for MetaBuilder {
    fn default() -> Self {
        MetaBuilder {
            id: 0,
            name: Box::new(|meta| format!("/p2p/{}", meta.id)),
            support_versions: vec!["0.0.1".to_owned()],
            codec: Box::new(|_| Box::new(LengthDelimitedCodec::new())),
            service_handle: Box::new(|_| ProtocolHandle::Neither),
            session_handle: Box::new(|_| ProtocolHandle::Neither),
        }
    }
}
