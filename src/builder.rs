use secio::SecioKeyPair;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::{error, io};
use tokio::codec::{Decoder, Encoder};

use crate::{
    service::{Service, ServiceHandle},
    session::ProtocolMeta,
};

/// Builder for Service
pub struct ServiceBuilder<T, U> {
    inner: HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>,
    key_pair: Option<SecioKeyPair>,
    phantom: PhantomData<T>,
}

impl<T, U> ServiceBuilder<T, U>
where
    T: ProtocolMeta<U> + Send + Sync + 'static,
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
        Service::new(Arc::new(self.inner), handle, self.key_pair)
    }

    /// Insert a custom protocol
    pub fn insert_protocol(mut self, protocol: T) -> Self {
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

    /// Clear all protocols
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl<T, U> Default for ServiceBuilder<T, U>
where
    T: ProtocolMeta<U> + Send + Sync + 'static,
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error + Into<io::Error>,
    <U as Encoder>::Error: error::Error + Into<io::Error>,
{
    fn default() -> Self {
        ServiceBuilder {
            inner: HashMap::new(),
            key_pair: None,
            phantom: PhantomData,
        }
    }
}
