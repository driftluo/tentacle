use std::{io, pin::Pin, task::Context};
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    service::{ProtocolEvent, ServiceError, ServiceEvent},
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
pub trait ServiceHandle {
    /// Handling runtime errors
    fn handle_error(&mut self, _control: &mut ServiceContext, _error: ServiceError) {}
    /// Handling session establishment and disconnection events
    fn handle_event(&mut self, _control: &mut ServiceContext, _event: ServiceEvent) {}
    /// Handling all protocol events
    ///
    /// ---
    ///
    /// **Note** that this is a compatibility mode interface.
    ///
    /// If the handle of the protocol has event, then its events will be placed here.
    /// If there is no event handle in the protocol, this interface will not be called.
    fn handle_proto(&mut self, _control: &mut ServiceContext, _event: ProtocolEvent) {}
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
pub trait ServiceProtocol {
    /// This function is called when the protocol is opened.
    ///
    /// The service handle will only be called once
    fn init(&mut self, context: &mut ProtocolContext);
    /// Called when opening protocol
    fn connected(&mut self, _context: ProtocolContextMutRef, _version: &str) {}
    /// Called when closing protocol
    fn disconnected(&mut self, _context: ProtocolContextMutRef) {}
    /// Called when the corresponding protocol message is received
    fn received(&mut self, _context: ProtocolContextMutRef, _data: bytes::Bytes) {}
    /// Called when the Service receives the notify task
    fn notify(&mut self, _context: &mut ProtocolContext, _token: u64) {}
    /// Behave like `Stream::poll`, but nothing output
    #[inline]
    fn poll(self: Pin<&mut Self>, _cx: &mut Context, _context: &mut ProtocolContext) {}
}

/// Session level protocol handle
pub trait SessionProtocol {
    /// Called when opening protocol
    fn connected(&mut self, _context: ProtocolContextMutRef, _version: &str) {}
    /// Called when closing protocol
    fn disconnected(&mut self, _context: ProtocolContextMutRef) {}
    /// Called when the corresponding protocol message is received
    fn received(&mut self, _context: ProtocolContextMutRef, _data: bytes::Bytes) {}
    /// Called when the session receives the notify task
    fn notify(&mut self, _context: ProtocolContextMutRef, _token: u64) {}
    /// Behave like `Stream::poll`, but nothing output, shutdown when session close
    #[inline]
    fn poll(self: Pin<&mut Self>, _cx: &mut Context, _context: ProtocolContextMutRef) {}
}

/// A trait can define codec, just wrapper `Decoder` and `Encoder`
pub trait Codec:
    Decoder<Item = bytes::BytesMut, Error = io::Error> + Encoder<Item = bytes::Bytes, Error = io::Error>
{
}

impl<T> Codec for T where
    T: Decoder<Item = bytes::BytesMut, Error = io::Error>
        + Encoder<Item = bytes::Bytes, Error = io::Error>
{
}

impl Decoder for Box<dyn Codec + Send + 'static> {
    type Item = bytes::BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Decoder::decode(&mut **self, src)
    }
}

impl Encoder for Box<dyn Codec + Send + 'static> {
    type Item = bytes::Bytes;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        Encoder::encode(&mut **self, item, dst)
    }
}

impl ServiceHandle for Box<dyn ServiceHandle + Send + 'static> {
    fn handle_error(&mut self, control: &mut ServiceContext, error: ServiceError) {
        (&mut **self).handle_error(control, error)
    }

    fn handle_event(&mut self, control: &mut ServiceContext, event: ServiceEvent) {
        (&mut **self).handle_event(control, event)
    }

    fn handle_proto(&mut self, control: &mut ServiceContext, event: ProtocolEvent) {
        (&mut **self).handle_proto(control, event)
    }
}

impl ServiceHandle for Box<dyn ServiceHandle + Send + Sync + 'static> {
    fn handle_error(&mut self, control: &mut ServiceContext, error: ServiceError) {
        (&mut **self).handle_error(control, error)
    }

    fn handle_event(&mut self, control: &mut ServiceContext, event: ServiceEvent) {
        (&mut **self).handle_event(control, event)
    }

    fn handle_proto(&mut self, control: &mut ServiceContext, event: ProtocolEvent) {
        (&mut **self).handle_proto(control, event)
    }
}

impl ServiceHandle for () {}

impl ServiceProtocol for Box<dyn ServiceProtocol + Send + 'static + Unpin> {
    fn init(&mut self, context: &mut ProtocolContext) {
        (&mut **self).init(context)
    }

    fn connected(&mut self, context: ProtocolContextMutRef, version: &str) {
        (&mut **self).connected(context, version)
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        (&mut **self).disconnected(context)
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        (&mut **self).received(context, data)
    }

    fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        (&mut **self).notify(context, token)
    }

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context, context: &mut ProtocolContext) {
        Pin::new(&mut **self).poll(cx, context)
    }
}

impl ServiceProtocol for Box<dyn ServiceProtocol + Send + Sync + 'static + Unpin> {
    fn init(&mut self, context: &mut ProtocolContext) {
        (&mut **self).init(context)
    }

    fn connected(&mut self, context: ProtocolContextMutRef, version: &str) {
        (&mut **self).connected(context, version)
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        (&mut **self).disconnected(context)
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        (&mut **self).received(context, data)
    }

    fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        (&mut **self).notify(context, token)
    }

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context, context: &mut ProtocolContext) {
        Pin::new(&mut **self).poll(cx, context)
    }
}

impl SessionProtocol for Box<dyn SessionProtocol + Send + 'static + Unpin> {
    fn connected(&mut self, context: ProtocolContextMutRef, version: &str) {
        (&mut **self).connected(context, version)
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        (&mut **self).disconnected(context)
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        (&mut **self).received(context, data)
    }

    fn notify(&mut self, context: ProtocolContextMutRef, token: u64) {
        (&mut **self).notify(context, token)
    }

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context, context: ProtocolContextMutRef) {
        Pin::new(&mut **self).as_mut().poll(cx, context)
    }
}

impl SessionProtocol for Box<dyn SessionProtocol + Send + Sync + 'static + Unpin> {
    fn connected(&mut self, context: ProtocolContextMutRef, version: &str) {
        (&mut **self).connected(context, version)
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        (&mut **self).disconnected(context)
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        (&mut **self).received(context, data)
    }

    fn notify(&mut self, context: ProtocolContextMutRef, token: u64) {
        (&mut **self).notify(context, token)
    }

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context, context: ProtocolContextMutRef) {
        Pin::new(&mut **self).as_mut().poll(cx, context)
    }
}
