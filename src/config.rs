use std::collections::HashMap;
use std::sync::Arc;
use std::{error, io};
use tokio::codec::{Decoder, Encoder};

use crate::session::ProtocolMeta;

pub struct ConfigBuilder<U> {
    inner: HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>,
}

impl<U> ConfigBuilder<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error + Into<io::Error>,
    <U as Encoder>::Error: error::Error + Into<io::Error>,
{
    pub fn new() -> Self {
        Default::default()
    }

    pub fn build(self) -> Arc<HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>> {
        Arc::new(self.inner)
    }

    pub fn push<T>(mut self, protocol: T) -> Self
    where
        T: ProtocolMeta<U> + Send + Sync + 'static,
    {
        self.inner.insert(
            protocol.name(),
            Box::new(protocol) as Box<dyn ProtocolMeta<_> + Send + Sync>,
        );
        self
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl<U> Default for ConfigBuilder<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error + Into<io::Error>,
    <U as Encoder>::Error: error::Error + Into<io::Error>,
{
    fn default() -> Self {
        ConfigBuilder {
            inner: HashMap::new(),
        }
    }
}
