use std::{io, sync::Arc, time::Duration};

use nohash_hasher::IntMap;
use tokio_util::codec::LengthDelimitedCodec;

#[cfg(feature = "tls")]
use crate::service::config::TlsConfig;
use crate::{
    protocol_select::SelectFn,
    secio::SecioKeyPair,
    service::{
        config::{Meta, ServiceConfig},
        ProtocolHandle, ProtocolMeta, Service, TcpSocket,
    },
    traits::{Codec, ProtocolSpawn, ServiceHandle, ServiceProtocol, SessionProtocol},
    yamux::Config,
    ProtocolId,
};

/// Builder for Service
#[derive(Default)]
pub struct ServiceBuilder {
    inner: IntMap<ProtocolId, ProtocolMeta>,
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
        H: ServiceHandle + Unpin,
    {
        Service::new(self.inner, handle, self.key_pair, self.forever, self.config)
    }

    /// Insert a custom protocol
    pub fn insert_protocol(mut self, protocol: ProtocolMeta) -> Self {
        self.inner.insert(protocol.id(), protocol);
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
        self.config.session_config.yamux_config = config;
        self
    }

    /// Secio max frame length
    ///
    /// Panic when max_frame_length < yamux_max_window_size
    pub fn max_frame_length(mut self, size: usize) -> Self {
        assert!(
            size as u32
                >= self
                    .config
                    .session_config
                    .yamux_config
                    .max_stream_window_size
        );
        self.config.max_frame_length = size;
        self
    }

    /// Tentacle use lots of bound channel, default channel size is 128
    pub fn set_channel_size(mut self, size: usize) -> Self {
        self.config.session_config.channel_size = size;
        self
    }

    /// Set send buffer size, default is 24Mb
    pub fn set_send_buffer_size(mut self, size: usize) -> Self {
        self.config.session_config.send_buffer_size = size;
        self
    }

    /// Set receive buffer size, default is 24Mb
    pub fn set_recv_buffer_size(mut self, size: usize) -> Self {
        self.config.session_config.recv_buffer_size = size;
        self
    }

    /// If session is close by remote, did you want to keep unreceived message as more as possible
    /// default is false
    pub fn keep_buffer(mut self, keep: bool) -> Self {
        self.config.keep_buffer = keep;
        self
    }

    /// Whether to allow tentative registration upnp, default is disable(false)
    ///
    /// upnp: https://en.wikipedia.org/wiki/Universal_Plug_and_Play
    ///
    /// Upnp is a simple solution to nat penetration, which requires routing support for registration mapping.
    ///
    /// The function provided here is that if the external ip of the query route is a public network,
    /// then an attempt is made to register the local listener port into the mapping so that it can
    /// receive the access request of the external network, and if the external ip of the route is not the public network,
    /// Then do nothing
    #[cfg(all(not(target_arch = "wasm32"), feature = "upnp"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "upnp")))]
    pub fn upnp(mut self, enable: bool) -> Self {
        self.config.upnp = enable;
        self
    }

    /// The limit of max open connection(file descriptors)
    /// If not limited, service will try to serve as many connections as possible until it exhausts system resources(os error),
    /// and then close the listener, no longer accepting new connection requests, and the established connections remain working
    ///
    /// Default is 65535
    pub fn max_connection_number(mut self, number: usize) -> Self {
        self.config.max_connection_number = number;
        self
    }

    /// Users can make their own custom configuration for all tcp socket at the bottom of Tentacle according to their own needs,
    /// for example, use reuse port to try to build nat penetration
    ///
    /// In this way, any actively connected outbound connection is potentially connectable. Through this setting,
    /// the device after NAT can have the opportunity to be connected to the public network.
    ///
    /// TCP Hole Punching: http://bford.info/pub/net/p2pnat/
    /// STUN: https://tools.ietf.org/html/rfc5389
    ///
    /// for example, set all tcp bind to `127.0.0.1:1080`, set keepalive:
    ///
    /// ```rust
    ///  use socket2;
    ///  use tentacle::{service::TcpSocket, builder::ServiceBuilder};
    ///  #[cfg(unix)]
    ///  use std::os::unix::io::{FromRawFd, IntoRawFd};
    ///  #[cfg(windows)]
    ///  use std::os::windows::io::{FromRawSocket, IntoRawSocket};
    ///  use std::net::SocketAddr;
    ///
    ///  let mut server = ServiceBuilder::new();
    ///  server.tcp_config(|socket: TcpSocket| {
    ///      let socket = unsafe {
    ///         #[cfg(unix)]
    ///         let socket = socket2::Socket::from_raw_fd(socket.into_raw_fd());
    ///         #[cfg(windows)]
    ///         let socket = socket2::Socket::from_raw_socket(socket.into_raw_socket());
    ///         socket
    ///      };
    ///      #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    ///      socket.set_reuse_port(true)?;
    ///
    ///      socket.set_reuse_address(true)?;
    ///      socket.bind(&"127.0.0.1:1080".parse::<SocketAddr>().unwrap().into())?;
    ///      socket.set_keepalive(true)?;
    ///      let socket = unsafe {
    ///         #[cfg(unix)]
    ///         let socket = TcpSocket::from_raw_fd(socket.into_raw_fd());
    ///         #[cfg(windows)]
    ///         let socket = TcpSocket::from_raw_socket(socket.into_raw_socket());
    ///         socket
    ///      };
    ///      Ok(socket)
    /// });
    /// ```
    ///
    /// ## Note
    ///
    /// User use `listen(2)` or `connect(2)` on this closure will cause abnormal behavior
    #[cfg(not(target_arch = "wasm32"))]
    pub fn tcp_config<F>(mut self, f: F) -> Self
    where
        F: Fn(TcpSocket) -> Result<TcpSocket, std::io::Error> + Send + Sync + 'static,
    {
        self.config.tcp_config.tcp = Arc::new(f);
        self
    }

    /// The same as tcp config, but use on ws transport
    #[cfg(feature = "ws")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ws")))]
    pub fn tcp_config_on_ws<F>(mut self, f: F) -> Self
    where
        F: Fn(TcpSocket) -> Result<TcpSocket, std::io::Error> + Send + Sync + 'static,
    {
        self.config.tcp_config.ws = Arc::new(f);
        self
    }

    /// Clear all protocols
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// set rustls ServerConfig, default is NoClientAuth
    #[cfg(feature = "tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    pub fn tls_config(mut self, config: TlsConfig) -> Self {
        self.config.tls_config = Some(config);
        self
    }

    /// The same as tcp config, but use on tls transport
    #[cfg(feature = "tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    pub fn tcp_config_on_tls<F>(mut self, f: F) -> Self
    where
        F: Fn(TcpSocket) -> Result<TcpSocket, std::io::Error> + Send + Sync + 'static,
    {
        self.config.tcp_config.tls = Arc::new(f);
        self
    }
}

pub(crate) type NameFn = Box<dyn Fn(ProtocolId) -> String + Send + Sync>;
pub(crate) type CodecFn = Box<dyn Fn() -> Box<dyn Codec + Send + 'static> + Send + Sync>;
pub(crate) type SessionHandleFn =
    Box<dyn FnMut() -> ProtocolHandle<Box<dyn SessionProtocol + Send + 'static + Unpin>> + Send>;
pub(crate) type SelectVersionFn = Box<dyn Fn() -> Option<SelectFn<String>> + Send + Sync + 'static>;
pub(crate) type BeforeReceiveFn = Box<dyn Fn() -> Option<BeforeReceive> + Send + Sync + 'static>;
pub(crate) type BeforeReceive =
    Box<dyn Fn(bytes::BytesMut) -> Result<bytes::Bytes, io::Error> + Send + 'static>;

/// Builder for protocol meta
pub struct MetaBuilder {
    id: ProtocolId,
    name: NameFn,
    support_versions: Vec<String>,
    codec: CodecFn,
    service_handle: ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static + Unpin>>,
    session_handle: SessionHandleFn,
    select_version: SelectVersionFn,
    before_send: Option<Box<dyn Fn(bytes::Bytes) -> bytes::Bytes + Send + 'static>>,
    before_receive: BeforeReceiveFn,
    spawn: Option<Box<dyn ProtocolSpawn + Send + Sync + 'static>>,
}

impl MetaBuilder {
    /// New a default builder
    pub fn new() -> Self {
        Default::default()
    }

    /// Define protocol id
    ///
    /// It is just an internal index of the system that
    /// identifies the open/close and message transfer for the specified protocol.
    pub fn id(mut self, id: ProtocolId) -> Self {
        self.id = id;
        self
    }

    /// Define protocol name, default is "/p2p/protocol_id"
    ///
    /// Used to interact with the remote service to determine whether the protocol is supported.
    ///
    /// If not found, the protocol connection(not session just sub stream) will be closed,
    /// and return a `ProtocolSelectError` event.
    pub fn name<T: Fn(ProtocolId) -> String + 'static + Send + Sync>(mut self, name: T) -> Self {
        self.name = Box::new(name);
        self
    }

    /// Define protocol support versions, default is `vec!["0.0.1".to_owned()]`
    ///
    /// Used to interact with the remote service to confirm that both parties
    /// open the same version of the protocol.
    ///
    /// If not found, the protocol connection(not session just sub stream) will be closed,
    /// and return a `ProtocolSelectError` event.
    pub fn support_versions(mut self, versions: Vec<String>) -> Self {
        self.support_versions = versions;
        self
    }

    /// Define protocol codec, default is LengthDelimitedCodec
    pub fn codec<T: Fn() -> Box<dyn Codec + Send + 'static> + 'static + Send + Sync>(
        mut self,
        codec: T,
    ) -> Self {
        self.codec = Box::new(codec);
        self
    }

    /// Define protocol service handle, default is neither
    pub fn service_handle<
        T: FnOnce() -> ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static + Unpin>>,
    >(
        mut self,
        service_handle: T,
    ) -> Self {
        self.service_handle = service_handle();
        self
    }

    /// Define protocol session handle, default is neither
    pub fn session_handle<
        T: FnMut() -> ProtocolHandle<Box<dyn SessionProtocol + Send + 'static + Unpin>>
            + Send
            + 'static,
    >(
        mut self,
        session_handle: T,
    ) -> Self {
        self.session_handle = Box::new(session_handle);
        self
    }

    /// Define the spawn process of the protocol read part
    ///
    /// Mutually exclusive with protocol handle
    #[cfg(feature = "unstable")]
    #[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
    pub fn protocol_spawn<T: ProtocolSpawn + Send + Sync + 'static>(mut self, spawn: T) -> Self {
        self.spawn = Some(Box::new(spawn));
        self
    }

    /// Protocol version selection rule, default is [select_version](../protocol_select/fn.select_version.html)
    pub fn select_version<T>(mut self, f: T) -> Self
    where
        T: Fn() -> Option<SelectFn<String>> + Send + Sync + 'static,
    {
        self.select_version = Box::new(f);
        self
    }

    /// Unified processing of messages before they are sent
    pub fn before_send<T>(mut self, f: T) -> Self
    where
        T: Fn(bytes::Bytes) -> bytes::Bytes + 'static + Send,
    {
        self.before_send = Some(Box::new(f));
        self
    }

    /// Unified processing of messages before user received
    pub fn before_receive<T>(mut self, f: T) -> Self
    where
        T: Fn() -> Option<BeforeReceive> + Send + Sync + 'static,
    {
        self.before_receive = Box::new(f);
        self
    }

    /// Combine the configuration of this builder to create a ProtocolMeta
    pub fn build(mut self) -> ProtocolMeta {
        if self.spawn.is_some() {
            assert!(self.service_handle.is_none());
            assert!((self.session_handle)().is_none());
        }
        let meta = Meta {
            id: self.id,
            name: self.name,
            support_versions: self.support_versions,
            codec: self.codec,
            select_version: self.select_version,
            before_receive: self.before_receive,
            spawn: self.spawn,
        };
        ProtocolMeta {
            inner: Arc::new(meta),
            service_handle: self.service_handle,
            session_handle: self.session_handle,
            before_send: self.before_send,
        }
    }
}

impl Default for MetaBuilder {
    fn default() -> Self {
        MetaBuilder {
            id: ProtocolId::new(0),
            name: Box::new(|id| format!("/p2p/{}", id.value())),
            support_versions: vec!["0.0.1".to_owned()],
            codec: Box::new(|| Box::new(LengthDelimitedCodec::new())),
            service_handle: ProtocolHandle::None,
            session_handle: Box::new(|| ProtocolHandle::None),
            select_version: Box::new(|| None),
            before_send: None,
            before_receive: Box::new(|| None),
            spawn: None,
        }
    }
}
