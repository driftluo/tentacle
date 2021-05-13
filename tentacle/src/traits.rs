use std::{io, sync::Arc};
use tokio_util::codec::{Decoder, Encoder};

use crate::service::ServiceAsyncControl;
use crate::{
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext, SessionContext},
    service::{ServiceError, ServiceEvent},
    substream::SubstreamReadPart,
};

/// Service handle
///
/// #### Note
///
/// All functions on this trait will block the entire server running, do not insert long-time tasks,
/// you can use the futures task instead.
///
/// #### Behavior
///
/// The handle that exists when the Service is created.
///
/// Mainly handle some Service-level errors thrown at runtime, such as listening errors.
///
/// At the same time, the session establishment and disconnection messages will also be perceived here.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait ServiceHandle: Send {
    /// Handling runtime errors
    async fn handle_error(&mut self, _control: &mut ServiceContext, _error: ServiceError) {}
    /// Handling session establishment and disconnection events
    async fn handle_event(&mut self, _control: &mut ServiceContext, _event: ServiceEvent) {}
}

/// Service level protocol handle
///
/// #### Note
///
/// All functions on this trait will block the entire server running, do not insert long-time tasks,
/// you can use the futures task instead.
///
/// #### Behavior
///
/// Define the behavior of each custom protocol in each state.
///
/// Depending on whether the user defines a service handle or a session exclusive handle,
/// the runtime has different performance.
///
/// The **important difference** is that some state values are allowed in the service handle,
/// and the handle exclusive to the session is "stateless", relative to the service handle,
/// it can only retain the information between a protocol stream on and off.
///
/// The opening and closing of the protocol will create and clean up the handle exclusive
/// to the session, but the service handle will remain in the state until the service is closed.
///
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait ServiceProtocol: Send {
    /// This function is called when the service start.
    ///
    /// The service handle will only be called once
    async fn init(&mut self, context: &mut ProtocolContext);
    /// Called when opening protocol
    async fn connected(&mut self, _context: ProtocolContextMutRef<'_>, _version: &str) {}
    /// Called when closing protocol
    async fn disconnected(&mut self, _context: ProtocolContextMutRef<'_>) {}
    /// Called when the corresponding protocol message is received
    async fn received(&mut self, _context: ProtocolContextMutRef<'_>, _data: bytes::Bytes) {}
    /// Called when the Service receives the notify task
    async fn notify(&mut self, _context: &mut ProtocolContext, _token: u64) {}
    /// Behave like `Stream::poll_next`, but nothing output
    /// if ready with Some, it will continue poll immediately
    /// if ready with None, it will don't try to call the function again
    #[inline]
    async fn poll(&mut self, _context: &mut ProtocolContext) -> Option<()> {
        None
    }
}

/// Session level protocol handle
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait SessionProtocol: Send {
    /// Called when opening protocol
    async fn connected(&mut self, _context: ProtocolContextMutRef<'_>, _version: &str) {}
    /// Called when closing protocol
    async fn disconnected(&mut self, _context: ProtocolContextMutRef<'_>) {}
    /// Called when the corresponding protocol message is received
    async fn received(&mut self, _context: ProtocolContextMutRef<'_>, _data: bytes::Bytes) {}
    /// Called when the session receives the notify task
    async fn notify(&mut self, _context: ProtocolContextMutRef<'_>, _token: u64) {}
    /// Behave like `Stream::poll_next`, but nothing output
    /// if ready with Some, it will continue poll immediately
    /// if ready with None, it will don't try to call the function again
    #[inline]
    async fn poll(&mut self, _context: ProtocolContextMutRef<'_>) -> Option<()> {
        None
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ServiceHandle for Box<dyn ServiceHandle + Send + 'static> {
    async fn handle_error(&mut self, control: &mut ServiceContext, error: ServiceError) {
        (&mut **self).handle_error(control, error).await
    }

    async fn handle_event(&mut self, control: &mut ServiceContext, event: ServiceEvent) {
        (&mut **self).handle_event(control, event).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ServiceHandle for Box<dyn ServiceHandle + Send + Sync + 'static> {
    async fn handle_error(&mut self, control: &mut ServiceContext, error: ServiceError) {
        (&mut **self).handle_error(control, error).await
    }

    async fn handle_event(&mut self, control: &mut ServiceContext, event: ServiceEvent) {
        (&mut **self).handle_event(control, event).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ServiceHandle for () {}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ServiceProtocol for Box<dyn ServiceProtocol + Send + 'static + Unpin> {
    async fn init(&mut self, context: &mut ProtocolContext) {
        (&mut **self).init(context).await
    }

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, version: &str) {
        (&mut **self).connected(context, version).await
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        (&mut **self).disconnected(context).await
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        (&mut **self).received(context, data).await
    }

    async fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        (&mut **self).notify(context, token).await
    }

    #[inline]
    async fn poll(&mut self, context: &mut ProtocolContext) -> Option<()> {
        (&mut **self).poll(context).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ServiceProtocol for Box<dyn ServiceProtocol + Send + Sync + 'static + Unpin> {
    async fn init(&mut self, context: &mut ProtocolContext) {
        (&mut **self).init(context).await
    }

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, version: &str) {
        (&mut **self).connected(context, version).await
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        (&mut **self).disconnected(context).await
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        (&mut **self).received(context, data).await
    }

    async fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        (&mut **self).notify(context, token).await
    }

    #[inline]
    async fn poll(&mut self, context: &mut ProtocolContext) -> Option<()> {
        (&mut **self).poll(context).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SessionProtocol for Box<dyn SessionProtocol + Send + 'static + Unpin> {
    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, version: &str) {
        (&mut **self).connected(context, version).await
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        (&mut **self).disconnected(context).await
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        (&mut **self).received(context, data).await
    }

    async fn notify(&mut self, context: ProtocolContextMutRef<'_>, token: u64) {
        (&mut **self).notify(context, token).await
    }

    #[inline]
    async fn poll(&mut self, context: ProtocolContextMutRef<'_>) -> Option<()> {
        (&mut **self).poll(context).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SessionProtocol for Box<dyn SessionProtocol + Send + Sync + 'static + Unpin> {
    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, version: &str) {
        (&mut **self).connected(context, version).await
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        (&mut **self).disconnected(context).await
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        (&mut **self).received(context, data).await
    }

    async fn notify(&mut self, context: ProtocolContextMutRef<'_>, token: u64) {
        (&mut **self).notify(context, token).await
    }

    #[inline]
    async fn poll(&mut self, context: ProtocolContextMutRef<'_>) -> Option<()> {
        (&mut **self).poll(context).await
    }
}

/// When the negotiation is completed and the agreement is opened, will call the implementation,
/// allow users to implement the read processing of the protocol by themselves
///
/// Implementing this trait means that streaming reading directly from the underlying substream
/// will become possible, and at the same time, async methods that cannot be used due to Rust's
/// temporary lack of support on async trait will also become possible
///
/// This trait implementation and the callback implementation are mutually exclusive, and will be
/// checked during construction, if both exist, it will panic
#[cfg_attr(not(feature = "unstable"), doc(hidden))]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub trait ProtocolSpawn {
    /// Call on protocol opened
    fn spawn(
        &self,
        context: Arc<SessionContext>,
        control: &ServiceAsyncControl,
        read_part: SubstreamReadPart,
    );
}

/// A trait can define codec, just wrapper `Decoder` and `Encoder`
pub trait Codec:
    Decoder<Item = bytes::BytesMut, Error = io::Error> + Encoder<bytes::Bytes, Error = io::Error>
{
}

impl<T> Codec for T where
    T: Decoder<Item = bytes::BytesMut, Error = io::Error>
        + Encoder<bytes::Bytes, Error = io::Error>
{
}

impl Decoder for Box<dyn Codec + Send + 'static> {
    type Item = bytes::BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Decoder::decode(&mut **self, src)
    }
}

impl Encoder<bytes::Bytes> for Box<dyn Codec + Send + 'static> {
    type Error = io::Error;

    fn encode(&mut self, item: bytes::Bytes, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        Encoder::encode(&mut **self, item, dst)
    }
}
