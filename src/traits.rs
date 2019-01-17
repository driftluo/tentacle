use std::{error, io};
use tokio::codec::{Decoder, Encoder};

use crate::{
    context::{ServiceContext, SessionContext},
    service::ServiceEvent,
    ProtocolId,
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
    fn handle_error(&mut self, _control: &mut ServiceContext, _error: ServiceEvent) {}
    /// Handling session establishment and disconnection events
    fn handle_event(&mut self, _control: &mut ServiceContext, _event: ServiceEvent) {}
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
    fn init(&mut self, service: &mut ServiceContext);
    /// Called when opening protocol
    fn connected(
        &mut self,
        _service: &mut ServiceContext,
        _session: &SessionContext,
        _version: &str,
    ) {
    }
    /// Called when closing protocol
    fn disconnected(&mut self, _service: &mut ServiceContext, _session: &SessionContext) {}
    /// Called when the corresponding protocol message is received
    fn received(
        &mut self,
        _service: &mut ServiceContext,
        _session: &SessionContext,
        _data: Vec<u8>,
    ) {
    }
    /// Called when the Service receives the notify task
    fn notify(&mut self, _service: &mut ServiceContext, _token: u64) {}
}

/// Session level protocol handle
pub trait SessionProtocol {
    /// Called when opening protocol
    fn connected(
        &mut self,
        _service: &mut ServiceContext,
        _session: &SessionContext,
        _version: &str,
    ) {
    }
    /// Called when closing protocol
    fn disconnected(&mut self, _service: &mut ServiceContext) {}
    /// Called when the corresponding protocol message is received
    fn received(&mut self, _service: &mut ServiceContext, _data: Vec<u8>) {}
    /// Called when the session receives the notify task
    fn notify(&mut self, _service: &mut ServiceContext, _token: u64) {}
}

/// Define the minimum data required for a custom protocol
pub trait ProtocolMeta<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error + Into<io::Error>,
    <U as Encoder>::Error: error::Error + Into<io::Error>,
{
    /// Protocol id
    fn id(&self) -> ProtocolId;

    /// Protocol name, default is "/p2p/protocol_id"
    #[inline]
    fn name(&self) -> String {
        format!("/p2p/{}", self.id())
    }

    /// Protocol supported version
    fn support_versions(&self) -> Vec<String> {
        vec!["0.0.1".to_owned()]
    }

    /// The codec used by the custom protocol, such as `LengthDelimitedCodec` by tokio
    fn codec(&self) -> U;

    /// A service level callback handle for a protocol.
    ///
    /// ---
    ///
    /// #### Behavior
    ///
    /// This function is called when the protocol is first opened in the service
    /// and remains in memory until the entire service is closed.
    fn service_handle(&self) -> Option<Box<dyn ServiceProtocol + Send + 'static>> {
        None
    }

    /// A session level callback handle for a protocol.
    ///
    /// ---
    ///
    /// #### Behavior
    ///
    /// When a session is opened, whenever the protocol of the session is opened,
    /// the function will be called again to generate the corresponding exclusive handle.
    ///
    /// Correspondingly, whenever the protocol is closed, the corresponding exclusive handle is cleared.
    fn session_handle(&self) -> Option<Box<dyn SessionProtocol + Send + 'static>> {
        None
    }
}

impl ServiceHandle for Box<dyn ServiceHandle + Send + 'static> {
    fn handle_error(&mut self, control: &mut ServiceContext, error: ServiceEvent) {
        (&mut **self).handle_error(control, error)
    }

    fn handle_event(&mut self, control: &mut ServiceContext, event: ServiceEvent) {
        (&mut **self).handle_event(control, event)
    }
}

impl ServiceHandle for Box<dyn ServiceHandle + Send + Sync + 'static> {
    fn handle_error(&mut self, control: &mut ServiceContext, error: ServiceEvent) {
        (&mut **self).handle_error(control, error)
    }

    fn handle_event(&mut self, control: &mut ServiceContext, event: ServiceEvent) {
        (&mut **self).handle_event(control, event)
    }
}
