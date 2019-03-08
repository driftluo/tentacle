use crate::{
    traits::{Codec, ServiceProtocol, SessionProtocol},
    yamux::config::Config as YamuxConfig,
    ProtocolId,
};
use std::collections::HashSet;
use std::time::Duration;

pub(crate) struct ServiceConfig {
    pub timeout: Duration,
    pub yamux_config: YamuxConfig,
    pub max_frame_length: usize,
    /// event output or callback output
    pub event: HashSet<ProtocolId>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            timeout: Duration::from_secs(10),
            yamux_config: YamuxConfig::default(),
            max_frame_length: 1024 * 1024 * 8,
            event: HashSet::default(),
        }
    }
}

/// When dial, specify which protocol want to open
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum DialProtocol {
    /// Try open all protocol
    All,
    /// Try open one protocol
    Single(ProtocolId),
    /// Try open some protocol
    Multi(Vec<ProtocolId>),
}

/// Define the minimum data required for a custom protocol
pub struct ProtocolMeta {
    pub(crate) id: ProtocolId,
    pub(crate) name: Box<Fn(&ProtocolMeta) -> String + Send + Sync + 'static>,
    pub(crate) support_versions: Vec<String>,
    pub(crate) codec: Box<Fn(&ProtocolMeta) -> Box<dyn Codec + Send + 'static> + Send + Sync + 'static>,
    pub(crate) service_handle: Box<Fn(&ProtocolMeta) -> ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static>> + Send + Sync + 'static>,
    pub(crate) session_handle: Box<Fn(&ProtocolMeta) -> ProtocolHandle<Box<dyn SessionProtocol + Send + 'static>> + Send + Sync + 'static>,
}

impl ProtocolMeta {
    /// Protocol id
    #[inline]
    pub fn id(&self) -> ProtocolId {
        self.id
    }

    /// Protocol name, default is "/p2p/protocol_id"
    #[inline]
    pub fn name(&self) -> String {
        (self.name)(&self)
    }

    /// Protocol supported version
    #[inline]
    pub fn support_versions(&self) -> Vec<String> {
        self.support_versions.clone()
    }

    /// The codec used by the custom protocol, such as `LengthDelimitedCodec` by tokio
    #[inline]
    pub fn codec(&self) -> Box<dyn Codec + Send + 'static> {
        (self.codec)(&self)
    }

    /// A service level callback handle for a protocol.
    ///
    /// ---
    ///
    /// #### Behavior
    ///
    /// This function is called when the protocol is first opened in the service
    /// and remains in memory until the entire service is closed.
    #[inline]
    pub fn service_handle(&self) -> ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static>> {
        (self.service_handle)(&self)
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
    #[inline]
    pub fn session_handle(&self) -> ProtocolHandle<Box<dyn SessionProtocol + Send + 'static>> {
        (self.session_handle)(&self)
    }
}

/// Protocol handle
pub enum ProtocolHandle<T: Sized> {
    /// No operation
    Neither,
    /// Event output
    Event,
    /// Both event and callback
    Both(T),
    /// Callback handle
    Callback(T),
}

impl<T> ProtocolHandle<T> {
    /// Returns true if the enum is a callback value.
    #[inline]
    pub fn is_callback(&self) -> bool {
        if let ProtocolHandle::Callback(_) = self {
            true
        } else {
            false
        }
    }

    /// Returns true if the enum is a empty value.
    #[inline]
    pub fn is_neither(&self) -> bool {
        if let ProtocolHandle::Neither = self {
            true
        } else {
            false
        }
    }

    /// Returns true if the enum is a event value.
    #[inline]
    pub fn is_event(&self) -> bool {
        if let ProtocolHandle::Event = self {
            true
        } else {
            false
        }
    }

    /// Returns true if the enum is a both value.
    #[inline]
    pub fn is_both(&self) -> bool {
        if let ProtocolHandle::Both(_) = self {
            true
        } else {
            false
        }
    }

    /// Returns true if the enum is a both value.
    #[inline]
    pub fn has_event(&self) -> bool {
        self.is_event() || self.is_both()
    }
}
