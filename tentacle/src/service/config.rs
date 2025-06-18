use crate::{
    ProtocolId, SessionId,
    builder::{BeforeReceiveFn, CodecFn, NameFn, SelectVersionFn, SessionHandleFn},
    traits::{Codec, ProtocolSpawn, ServiceProtocol, SessionProtocol},
    yamux::config::Config as YamuxConfig,
};
#[cfg(windows)]
use std::os::windows::io::{
    AsRawSocket, AsSocket, BorrowedSocket, FromRawSocket, IntoRawSocket, RawSocket,
};
#[cfg(unix)]
use std::os::{
    fd::AsFd,
    unix::io::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, RawFd},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
#[cfg(feature = "tls")]
use tokio_rustls::rustls::{ClientConfig, ServerConfig};

/// Default max buffer size
const MAX_BUF_SIZE: usize = 24 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct ServiceTimeout {
    pub timeout: Duration,
    pub onion_timeout: Duration,
}

impl Default for ServiceTimeout {
    fn default() -> Self {
        ServiceTimeout {
            timeout: Duration::from_secs(10),
            onion_timeout: Duration::from_secs(120),
        }
    }
}

pub(crate) struct ServiceConfig {
    pub timeout: ServiceTimeout,
    pub session_config: SessionConfig,
    pub max_frame_length: usize,
    pub keep_buffer: bool,
    #[cfg(all(not(target_family = "wasm"), feature = "upnp"))]
    pub upnp: bool,
    pub max_connection_number: usize,
    pub tcp_config: TcpConfig,
    #[cfg(feature = "tls")]
    pub tls_config: Option<TlsConfig>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            timeout: ServiceTimeout::default(),
            session_config: SessionConfig::default(),
            max_frame_length: 1024 * 1024 * 8,
            keep_buffer: false,
            #[cfg(all(not(target_family = "wasm"), feature = "upnp"))]
            upnp: false,
            max_connection_number: 65535,
            tcp_config: Default::default(),
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
    /// defautl is 128
    pub channel_size: usize,
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
            channel_size: 128,
            yamux_config: YamuxConfig::default(),
        }
    }
}

/// This enum's purpose is to let socket_transformer know how the socket is created
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum SocketState {
    /// listen
    Listen,
    /// dial
    Dial,
}

/// in socket_transformer
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct TransformerContext {
    /// dial or listen
    pub state: SocketState,
    /// if dial, remote address; if listen, local address
    pub address: SocketAddr,
}

impl TransformerContext {
    /// crate a listen context
    pub fn new_listen(address: SocketAddr) -> Self {
        TransformerContext {
            state: SocketState::Listen,
            address,
        }
    }

    /// create a dial context
    pub fn new_dial(address: SocketAddr) -> Self {
        TransformerContext {
            state: SocketState::Dial,
            address,
        }
    }
}

pub(crate) type TcpSocketTransformer = Arc<
    dyn Fn(TcpSocket, TransformerContext) -> Result<TcpSocket, std::io::Error>
        + Send
        + Sync
        + 'static,
>;

#[derive(Clone)]
pub(crate) struct TcpSocketConfig {
    pub(crate) socket_transformer: TcpSocketTransformer,
    pub(crate) proxy_url: Option<url::Url>,
    pub(crate) onion_url: Option<url::Url>,
    /// generates unique SOCKS credentials for proxy connection. Default: true
    /// If the proxy_server is tor server, this prevents connection correlation,
    /// and enhances privacy by forcing different Tor circuits.
    /// see IsolateSOCKSAuth section in https://2019.www.torproject.org/docs/tor-manual.html.en
    pub(crate) proxy_random_auth: bool,
}

impl Default for TcpSocketConfig {
    fn default() -> Self {
        Self {
            socket_transformer: Arc::new(|tcp_socket, _| Ok(tcp_socket)),
            proxy_url: None,
            onion_url: None,
            proxy_random_auth: true,
        }
    }
}

/// This config Allow users to set various underlying parameters of TCP
#[derive(Clone, Default)]
pub(crate) struct TcpConfig {
    /// When dial/listen on tcp, tentacle will call it allow user to set all tcp socket config
    pub tcp: TcpSocketConfig,
    /// When dial/listen on ws, tentacle will call it allow user to set all tcp socket config
    #[cfg(feature = "ws")]
    pub ws: TcpSocketConfig,
    /// When dial/listen on tls, tentacle will call it allow user to set all tcp socket config
    #[cfg(feature = "tls")]
    pub tls: TcpSocketConfig,
}

/// A TCP socket that has not yet been converted to a `TcpStream` or
/// `TcpListener`.
///
/// `TcpSocket` wraps an operating system socket and enables the caller to
/// configure the socket before establishing a TCP connection or accepting
/// inbound connections. The caller is able to set socket option and explicitly
/// bind the socket with a socket address.
pub struct TcpSocket {
    #[cfg(not(target_family = "wasm"))]
    pub(crate) inner: socket2::Socket,
}

#[cfg(unix)]
impl AsRawFd for TcpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(unix)]
impl FromRawFd for TcpSocket {
    /// Converts a `RawFd` to a `TcpSocket`.
    unsafe fn from_raw_fd(fd: RawFd) -> TcpSocket {
        let inner = unsafe { socket2::Socket::from_raw_fd(fd) };
        TcpSocket { inner }
    }
}

#[cfg(unix)]
impl IntoRawFd for TcpSocket {
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

#[cfg(unix)]
impl AsFd for TcpSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(windows)]
impl IntoRawSocket for TcpSocket {
    fn into_raw_socket(self) -> RawSocket {
        self.inner.into_raw_socket()
    }
}

#[cfg(windows)]
impl AsRawSocket for TcpSocket {
    fn as_raw_socket(&self) -> RawSocket {
        self.inner.as_raw_socket()
    }
}

#[cfg(windows)]
impl FromRawSocket for TcpSocket {
    /// Converts a `RawSocket` to a `TcpStream`.
    unsafe fn from_raw_socket(socket: RawSocket) -> TcpSocket {
        let inner = socket2::Socket::from_raw_socket(socket);
        TcpSocket { inner }
    }
}

#[cfg(windows)]
impl AsSocket for TcpSocket {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        unsafe { BorrowedSocket::borrow_raw(self.as_raw_socket()) }
    }
}

/// tls config wrap for server setup
#[derive(Clone, Default)]
#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub struct TlsConfig {
    /// tls server end config
    pub(crate) tls_server_config: Option<Arc<ServerConfig>>,
    /// tls client end config
    pub(crate) tls_client_config: Option<Arc<ClientConfig>>,
}

#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
impl TlsConfig {
    /// new TlsConfig
    pub fn new(server_config: Option<ServerConfig>, client_config: Option<ClientConfig>) -> Self {
        let tls_server_config = server_config.map(Arc::new);
        let tls_client_config = client_config.map(Arc::new);
        TlsConfig {
            tls_server_config,
            tls_client_config,
        }
    }
}

/// When dial, specify which protocol want to open
pub enum TargetProtocol {
    /// Try open all protocol
    All,
    /// Try open one protocol
    Single(ProtocolId),
    /// Try open some protocol, if return true, open it
    Filter(Box<dyn Fn(&ProtocolId) -> bool + Sync + Send + 'static>),
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
    /// Try send to some determined session
    Multi(Box<dyn Iterator<Item = SessionId> + Send + 'static>),
    /// Try send to some session, if return true, send to it
    Filter(Box<dyn FnMut(&SessionId) -> bool + Send + 'static>),
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

/// Handshake encryption layer protocol selection
#[non_exhaustive]
pub enum HandshakeType<T> {
    /// Enable secio
    Secio(T),
    /// Disable all built-in encryption layer
    Noop,
}

impl<K> From<K> for HandshakeType<K>
where
    K: secio::KeyProvider,
{
    fn from(value: K) -> Self {
        HandshakeType::Secio(value)
    }
}

impl<T> Clone for HandshakeType<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        match self {
            HandshakeType::Secio(s) => HandshakeType::Secio(s.clone()),
            HandshakeType::Noop => HandshakeType::Noop,
        }
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
    use super::State;

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
}
