#[cfg(feature = "tls")]
use crate::utils::multiaddr_to_socketaddr;
use crate::{
    builder::{BeforeReceiveFn, CodecFn, NameFn, SelectVersionFn, SessionHandleFn},
    traits::{Codec, ProtocolSpawn, ServiceProtocol, SessionProtocol},
    yamux::config::Config as YamuxConfig,
    ProtocolId, SessionId,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
#[cfg(feature = "tls")]
use tokio_rustls::rustls::{ClientConfig, ServerConfig};

/// Default max buffer size
const MAX_BUF_SIZE: usize = 24 * 1024 * 1024;

pub(crate) struct ServiceConfig {
    pub timeout: Duration,
    pub session_config: SessionConfig,
    pub max_frame_length: usize,
    pub keep_buffer: bool,
    #[cfg(all(not(target_arch = "wasm32"), feature = "upnp"))]
    pub upnp: bool,
    pub max_connection_number: usize,
    pub tcp_bind_addr: Option<SocketAddr>,
    #[cfg(feature = "ws")]
    pub ws_bind_addr: Option<SocketAddr>,
    #[cfg(feature = "tls")]
    pub tls_config: Option<TlsConfig>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            timeout: Duration::from_secs(10),
            session_config: SessionConfig::default(),
            max_frame_length: 1024 * 1024 * 8,
            keep_buffer: false,
            #[cfg(all(not(target_arch = "wasm32"), feature = "upnp"))]
            upnp: false,
            max_connection_number: 65535,
            tcp_bind_addr: None,
            #[cfg(feature = "ws")]
            ws_bind_addr: None,
            #[cfg(feature = "tls")]
            tls_config: None,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SessionConfig {
    pub yamux_config: YamuxConfig,
    /// default is 24Mb
    pub send_buffer_size: usize,
    /// default is 24Mb
    pub recv_buffer_size: usize,
}

impl SessionConfig {
    /// see https://github.com/rust-lang/rust/issues/57563
    /// can't use `if` to filter out 0, so add one to avoid this case
    pub const fn recv_event_size(&self) -> usize {
        (self.recv_buffer_size / self.yamux_config.max_stream_window_size as usize) + 1
    }

    /// see https://github.com/rust-lang/rust/issues/57563
    /// can't use `if` to filter out 0, so add one to avoid this case
    pub const fn send_event_size(&self) -> usize {
        (self.send_buffer_size / self.yamux_config.max_stream_window_size as usize) + 1
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            recv_buffer_size: MAX_BUF_SIZE,
            send_buffer_size: MAX_BUF_SIZE,
            yamux_config: YamuxConfig::default(),
        }
    }
}

/// tls config wrap for server setup
#[derive(Clone, Default)]
#[cfg(feature = "tls")]
pub struct TlsConfig {
    /// tls server end config
    pub(crate) tls_server_config: Option<Arc<ServerConfig>>,
    /// tls client end config
    pub(crate) tls_client_config: Option<Arc<ClientConfig>>,
    /// tls bind socket address
    pub(crate) tls_bind: Option<SocketAddr>,
}

#[cfg(feature = "tls")]
impl TlsConfig {
    /// new TlsConfig
    pub fn new(server_config: Option<ServerConfig>, client_config: Option<ClientConfig>) -> Self {
        let tls_server_config = server_config.map(Arc::new);
        let tls_client_config = client_config.map(Arc::new);
        TlsConfig {
            tls_server_config,
            tls_client_config,
            tls_bind: None,
        }
    }

    /// bind tls address
    pub fn tls_bind(mut self, addr: multiaddr::Multiaddr) -> Self {
        self.tls_bind = multiaddr_to_socketaddr(&addr);
        self
    }
}

/// When dial, specify which protocol want to open
pub enum TargetProtocol {
    /// Try open all protocol
    All,
    /// Try open one protocol
    Single(ProtocolId),
    /// Try open some protocol, if return true, open it
    Filter(Box<dyn Fn(&ProtocolId) -> bool + Send>),
}

impl From<ProtocolId> for TargetProtocol {
    fn from(id: ProtocolId) -> Self {
        TargetProtocol::Single(id)
    }
}

impl From<usize> for TargetProtocol {
    fn from(id: usize) -> Self {
        TargetProtocol::Single(id.into())
    }
}

/// When sending a message, select the specified session
pub enum TargetSession {
    /// Try broadcast
    All,
    /// Try send to only one
    Single(SessionId),
    /// Try send to some session, if return true, send to it
    Filter(Box<dyn Fn(&SessionId) -> bool + Send>),
}

impl From<SessionId> for TargetSession {
    fn from(id: SessionId) -> Self {
        TargetSession::Single(id)
    }
}

impl From<usize> for TargetSession {
    fn from(id: usize) -> Self {
        TargetSession::Single(id.into())
    }
}

/// Define the minimum data required for a custom protocol
pub struct ProtocolMeta {
    pub(crate) inner: Arc<Meta>,
    pub(crate) service_handle: ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static + Unpin>>,
    pub(crate) session_handle: SessionHandleFn,
    pub(crate) before_send: Option<Box<dyn Fn(bytes::Bytes) -> bytes::Bytes + Send + 'static>>,
    pub(crate) flag: BlockingFlag,
}

impl ProtocolMeta {
    /// Protocol id
    #[inline]
    pub fn id(&self) -> ProtocolId {
        self.inner.id
    }

    /// Protocol name, default is "/p2p/protocol_id"
    #[inline]
    pub fn name(&self) -> String {
        (self.inner.name)(self.inner.id)
    }

    /// Protocol supported version
    #[inline]
    pub fn support_versions(&self) -> Vec<String> {
        self.inner.support_versions.clone()
    }

    /// The codec used by the custom protocol, such as `LengthDelimitedCodec` by tokio
    #[inline]
    pub fn codec(&self) -> Box<dyn Codec + Send + 'static> {
        (self.inner.codec)()
    }

    /// A service level callback handle for a protocol.
    ///
    /// ---
    ///
    /// #### Behavior
    ///
    /// This function is called when the protocol is first opened in the service
    /// and remains in memory until the entire service is closed.
    ///
    /// #### Warning
    ///
    /// Only can be called once, and will return `ProtocolHandle::None` or later.
    #[inline]
    pub fn service_handle(
        &mut self,
    ) -> ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static + Unpin>> {
        ::std::mem::replace(&mut self.service_handle, ProtocolHandle::None)
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
    pub fn session_handle(
        &mut self,
    ) -> ProtocolHandle<Box<dyn SessionProtocol + Send + 'static + Unpin>> {
        (self.session_handle)()
    }

    /// Control whether the protocol handle method requires blocking to run
    pub fn blocking_flag(&self) -> BlockingFlag {
        self.flag
    }
}

pub(crate) struct Meta {
    pub(crate) id: ProtocolId,
    pub(crate) name: NameFn,
    pub(crate) support_versions: Vec<String>,
    pub(crate) codec: CodecFn,
    pub(crate) select_version: SelectVersionFn,
    pub(crate) before_receive: BeforeReceiveFn,
    pub(crate) spawn: Option<Box<dyn ProtocolSpawn + Send + Sync + 'static>>,
}

/// Protocol handle Contains four modes, each of which has a corresponding behavior,
/// please carefully consider which mode should be used in the protocol
pub enum ProtocolHandle<T: Sized> {
    /// No operation: Receive messages, but do not process, silently discard
    None,
    /// Callback handle: The behavior of receiving the protocol through the corresponding
    /// `ServiceProtocol` or `SessionProtocol`, according to the registered trait, has different
    /// behaviors, each has its own advantages and disadvantages, please carefully consider.
    /// This is also the recommended way to use this crate.
    Callback(T),
}

impl<T> ProtocolHandle<T> {
    /// Returns true if the enum is a callback value.
    #[inline]
    pub fn is_callback(&self) -> bool {
        matches!(self, ProtocolHandle::Callback(_))
    }

    /// Returns true if the enum is a empty value.
    #[inline]
    pub fn is_none(&self) -> bool {
        matches!(self, ProtocolHandle::None)
    }
}

/// Control whether the protocol handle method requires blocking to run
/// default is 0b1111, all function use blocking
///
/// flag & 0b1000 > 0 means `connected` use blocking
/// flag & 0b0100 > 0 means `disconnected` use blocking
/// flag & 0b0010 > 0 means `received` use blocking
/// flag & 0b0001 > 0 means `notify` use blocking
#[derive(Copy, Clone, Debug)]
pub struct BlockingFlag(u8);

impl BlockingFlag {
    /// connected don't use blocking
    #[inline]
    pub fn disable_connected(&mut self) {
        self.0 &= 0b0111
    }

    /// disconnected don't use blocking
    #[inline]
    pub fn disable_disconnected(&mut self) {
        self.0 &= 0b1011
    }

    /// received don't use blocking
    #[inline]
    pub fn disable_received(&mut self) {
        self.0 &= 0b1101
    }

    /// notify don't use blocking
    pub fn disable_notify(&mut self) {
        self.0 &= 0b1110
    }

    /// all function use blocking
    #[inline]
    pub fn enable_all(&mut self) {
        self.0 |= 0b1111
    }

    /// all function don't use blocking
    #[inline]
    pub fn disable_all(&mut self) {
        self.0 &= 0b0000
    }

    /// return true if connected enable
    #[inline]
    pub const fn connected(self) -> bool {
        self.0 & 0b1000 > 0
    }

    /// return true if disconnected enable
    #[inline]
    pub const fn disconnected(self) -> bool {
        self.0 & 0b0100 > 0
    }

    /// return true if received enable
    #[inline]
    pub const fn received(self) -> bool {
        self.0 & 0b0010 > 0
    }

    /// return true if notify enable
    #[inline]
    pub const fn notify(self) -> bool {
        self.0 & 0b0001 > 0
    }
}

impl Default for BlockingFlag {
    fn default() -> Self {
        BlockingFlag(0b1111)
    }
}

impl From<u8> for BlockingFlag {
    fn from(inner: u8) -> BlockingFlag {
        BlockingFlag(inner)
    }
}

/// Service state
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum State {
    /// Calculate the number of connection requests that need to be sent externally
    Running(usize),
    Forever,
    PreShutdown,
}

impl State {
    /// new
    pub fn new(forever: bool) -> Self {
        if forever {
            State::Forever
        } else {
            State::Running(0)
        }
    }

    /// Can it be shutdown?
    #[inline]
    pub fn is_shutdown(&self) -> bool {
        match self {
            State::Running(num) if num == &0 => true,
            State::PreShutdown => true,
            State::Running(_) | State::Forever => false,
        }
    }

    /// Convert to pre shutdown state
    #[inline]
    pub fn pre_shutdown(&mut self) {
        *self = State::PreShutdown
    }

    /// Add one task count
    #[inline]
    pub fn increase(&mut self) {
        match self {
            State::Running(num) => *num += 1,
            State::PreShutdown | State::Forever => (),
        }
    }

    /// Reduce one task count
    #[inline]
    pub fn decrease(&mut self) {
        match self {
            State::Running(num) => *num -= 1,
            State::PreShutdown | State::Forever => (),
        }
    }

    #[inline]
    pub fn into_inner(self) -> Option<usize> {
        match self {
            State::Running(num) => Some(num),
            State::PreShutdown | State::Forever => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{BlockingFlag, State};

    #[test]
    fn test_state_no_forever() {
        let mut state = State::new(false);
        state.increase();
        state.increase();
        assert_eq!(state, State::Running(2));
        state.decrease();
        state.decrease();
        assert_eq!(state, State::Running(0));
        state.increase();
        state.increase();
        state.increase();
        state.increase();
        state.pre_shutdown();
        assert_eq!(state, State::PreShutdown);
    }

    #[test]
    fn test_state_forever() {
        let mut state = State::new(true);
        state.increase();
        state.increase();
        assert_eq!(state, State::Forever);
        state.decrease();
        state.decrease();
        assert_eq!(state, State::Forever);
        state.increase();
        state.increase();
        state.increase();
        state.increase();
        state.pre_shutdown();
        assert_eq!(state, State::PreShutdown);
    }

    #[test]
    fn test_proto_flag() {
        let mut p = BlockingFlag::default();

        assert_eq!(p.connected(), true);
        assert_eq!(p.disconnected(), true);
        assert_eq!(p.received(), true);
        assert_eq!(p.notify(), true);

        p.disable_connected();
        assert_eq!(p.connected(), false);
        p.disable_disconnected();
        assert_eq!(p.disconnected(), false);
        p.disable_received();
        assert_eq!(p.received(), false);
        p.disable_notify();
        assert_eq!(p.notify(), false);

        p.enable_all();
        p.disable_all();
        assert_eq!(p.connected(), false);
        assert_eq!(p.disconnected(), false);
        assert_eq!(p.received(), false);
        assert_eq!(p.notify(), false);
    }
}
