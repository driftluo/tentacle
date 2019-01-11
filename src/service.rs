use futures::{prelude::*, sync::mpsc};
use log::{debug, error, trace, warn};
use secio::{handshake::Config, PublicKey, SecioKeyPair};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{
    error::{self, Error},
    io,
    time::{Duration, Instant},
};
use tokio::net::{
    tcp::{ConnectFuture, Incoming},
    TcpListener, TcpStream,
};
use tokio::timer::{self, Interval};
use tokio::{
    codec::{Decoder, Encoder},
    prelude::{AsyncRead, AsyncWrite, FutureExt},
};
use yamux::session::SessionType;

use crate::protocol_select::ProtocolInfo;
use crate::session::{ProtocolId, Session, SessionEvent, SessionId, SessionMeta};

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
    fn connected(&mut self, _service: &mut ServiceContext, _session: &SessionContext) {}
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
    fn connected(&mut self, _service: &mut ServiceContext, _session: &SessionContext) {}
    /// Called when closing protocol
    fn disconnected(&mut self, _service: &mut ServiceContext) {}
    /// Called when the corresponding protocol message is received
    fn received(&mut self, _service: &mut ServiceContext, _data: Vec<u8>) {}
    /// Called when the session receives the notify task
    fn notify(&mut self, _service: &mut ServiceContext, _token: u64) {}
}

/// Protocol handle value
pub enum ProtocolHandle {
    /// Service level protocol
    Service(Box<dyn ServiceProtocol + Send + 'static>),
    /// Session level protocol
    Session(Box<dyn SessionProtocol + Send + 'static>),
}

impl ProtocolHandle {
    /// Check if this is a session level protocol
    pub fn is_session(&self) -> bool {
        match self {
            ProtocolHandle::Session(_) => true,
            _ => false,
        }
    }
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
    fn session_handle(&self) -> Option<Box<dyn SessionProtocol + Send + 'static>> {
        None
    }
}

// TODO: maybe remote this struct later?
/// Protocol message
///
/// > The structure may be adjusted in the future
#[derive(Debug)]
pub struct Message {
    /// This field is used to indicate from
    /// which session the message was received,
    /// but this field is useless when sending a message.
    pub session_id: SessionId,
    /// Protocol id
    pub proto_id: ProtocolId,
    /// Data
    pub data: Vec<u8>,
}

/// Session context
pub struct SessionContext {
    /// Session's ID
    pub id: SessionId,
    /// Remote socket address
    pub address: SocketAddr,
    /// Session type (server or client)
    pub ty: SessionType,
    // TODO: use reference?
    /// Remote public key
    pub remote_pubkey: Option<PublicKey>,
    // TODO: use reference?
    /// Selected protocol version
    pub version: String,
}

/// The Service runtime can send some instructions to the inside of the handle.
/// This is the sending channel.
// TODO: Need to maintain the network topology map here?
#[derive(Clone)]
pub struct ServiceContext {
    service_task_sender: mpsc::Sender<ServiceTask>,
    proto_infos: Arc<HashMap<ProtocolId, ProtocolInfo>>,
    listens: Vec<SocketAddr>,
}

impl ServiceContext {
    /// New
    fn new(
        service_task_sender: mpsc::Sender<ServiceTask>,
        proto_infos: HashMap<ProtocolId, ProtocolInfo>,
    ) -> Self {
        ServiceContext {
            service_task_sender,
            proto_infos: Arc::new(proto_infos),
            listens: Vec::new(),
        }
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&mut self, address: SocketAddr) {
        self.send(ServiceTask::Dial { address })
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(&mut self, session_id: SessionId) {
        self.send(ServiceTask::Disconnect { session_id })
    }

    /// Send message
    #[inline]
    pub fn send_message(&mut self, session_ids: Option<Vec<SessionId>>, message: Message) {
        self.send(ServiceTask::ProtocolMessage {
            session_ids,
            message,
        })
    }

    /// Send a future task
    #[inline]
    pub fn future_task<T>(&mut self, task: T)
    where
        T: Future<Item = (), Error = ()> + 'static + Send,
    {
        self.send(ServiceTask::FutureTask {
            task: Box::new(task),
        })
    }

    /// Set a notify token
    pub fn set_notify(&mut self, proto_id: ProtocolId, interval: Duration, token: u64) {
        let mut interval_sender = self.sender().clone();
        let fut = Interval::new(Instant::now(), interval)
            .for_each(move |_| {
                interval_sender
                    .try_send(ServiceTask::ProtocolNotify { proto_id, token })
                    .map_err(|err| {
                        debug!("interval error: {:?}", err);
                        timer::Error::shutdown()
                    })
            })
            .map_err(|err| warn!("{}", err));
        self.future_task(fut);
    }

    /// Get the internal channel sender side handle
    #[inline]
    pub fn sender(&mut self) -> &mut mpsc::Sender<ServiceTask> {
        &mut self.service_task_sender
    }

    /// Get service protocol message, Map(ID, Name), but can't modify
    #[inline]
    pub fn protocols(&self) -> &Arc<HashMap<ProtocolId, ProtocolInfo>> {
        &self.proto_infos
    }

    /// Get service listen address list
    #[inline]
    pub fn listens(&self) -> &Vec<SocketAddr> {
        &self.listens
    }

    /// Real send function
    #[inline]
    fn send(&mut self, event: ServiceTask) {
        let _ = self.service_task_sender.try_send(event);
    }

    /// Update listen list
    #[inline]
    fn update_listens(&mut self, address_list: Vec<SocketAddr>) {
        self.listens = address_list;
    }
}

/// Event generated by the Service
#[derive(Debug)]
pub enum ServiceEvent {
    /// When dial remote error
    DialerError {
        /// Remote address
        address: SocketAddr,
        /// Io error
        error: io::Error,
    },
    /// When listen error
    ListenError {
        /// Listen address
        address: SocketAddr,
        /// Io error
        error: io::Error,
    },
    /// A session close
    SessionClose {
        /// Session id
        id: SessionId,
    },
    /// A session open
    SessionOpen {
        /// Session id
        id: SessionId,
        /// Remote address
        address: SocketAddr,
        /// Outbound or Inbound
        ty: SessionType,
        /// Remote public key
        public_key: Option<PublicKey>,
    },
}

/// Task received by the Service.
///
/// An instruction that the outside world can send to the service
pub enum ServiceTask {
    /// Send protocol data task
    ProtocolMessage {
        /// Specify which sessions to send to,
        /// None means broadcast
        session_ids: Option<Vec<SessionId>>,
        /// data
        message: Message,
    },
    /// Service-level notify task
    ProtocolNotify {
        /// Protocol id
        proto_id: ProtocolId,
        /// Notify token
        token: u64,
    },
    /// Session-level notify task
    ProtocolSessionNotify {
        /// Session id
        session_id: SessionId,
        /// Protocol id
        proto_id: ProtocolId,
        /// Notify token
        token: u64,
    },
    /// Future task
    FutureTask {
        /// Future
        task: Box<dyn Future<Item = (), Error = ()> + 'static + Send>,
    },
    /// Disconnect task
    Disconnect {
        /// Session id
        session_id: SessionId,
    },
    /// Dial task
    Dial {
        /// Remote address
        address: SocketAddr,
    },
}

/// An abstraction of p2p service, currently only supports TCP protocol
pub struct Service<T, U> {
    protocol_configs: Arc<HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>>,

    sessions: HashMap<SessionId, mpsc::Sender<SessionEvent>>,

    listens: Vec<(SocketAddr, Incoming)>,

    dial: Vec<(SocketAddr, ConnectFuture)>,
    /// Calculate the number of connection requests that need to be sent externally,
    /// if run forever, it will default to 1, else it default to 0
    task_count: usize,

    next_session: SessionId,

    key_pair: Option<SecioKeyPair>,

    remote_pubkeys: HashMap<SessionId, PublicKey>,

    /// Can be upgrade to list service level protocols
    handle: T,

    session_contexts: HashMap<SessionId, SessionContext>,

    service_proto_handles: HashMap<ProtocolId, Box<dyn ServiceProtocol + Send + 'static>>,

    session_proto_handles:
        HashMap<SessionId, HashMap<ProtocolId, Box<dyn SessionProtocol + Send + 'static>>>,

    /// Send events to service, clone to session
    session_event_sender: mpsc::Sender<SessionEvent>,
    /// Receive event from service
    session_event_receiver: mpsc::Receiver<SessionEvent>,

    /// External event is passed in from this
    service_context: ServiceContext,
    /// External event receiver
    service_task_receiver: mpsc::Receiver<ServiceTask>,
}

impl<T, U> Service<T, U>
where
    T: ServiceHandle,
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error + Into<io::Error>,
    <U as Encoder>::Error: error::Error + Into<io::Error>,
{
    /// New a Service
    pub fn new(
        protocol_configs: Arc<HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>>,
        handle: T,
        key_pair: Option<SecioKeyPair>,
        forever: bool,
    ) -> Self {
        let (session_event_sender, session_event_receiver) = mpsc::channel(256);
        let (service_task_sender, service_task_receiver) = mpsc::channel(256);
        let proto_infos = protocol_configs
            .values()
            .map(|meta| {
                let proto_info = ProtocolInfo::new(&meta.name(), meta.support_versions());
                (meta.id(), proto_info)
            })
            .collect();

        Service {
            protocol_configs,
            handle,
            key_pair,
            sessions: HashMap::default(),
            remote_pubkeys: HashMap::new(),
            session_contexts: HashMap::default(),
            service_proto_handles: HashMap::default(),
            session_proto_handles: HashMap::default(),
            listens: Vec::new(),
            dial: Vec::new(),
            task_count: if forever { 1 } else { 0 },
            next_session: 0,
            session_event_sender,
            session_event_receiver,
            service_context: ServiceContext::new(service_task_sender, proto_infos),
            service_task_receiver,
        }
    }

    /// Listen on the given address.
    pub fn listen(&mut self, address: SocketAddr) -> Result<(), io::Error> {
        let tcp = TcpListener::bind(&address)?;
        self.listens.push((address, tcp.incoming()));
        Ok(())
    }

    /// Dial the given address, doesn't actually make a request, just generate a future
    pub fn dial(mut self, address: SocketAddr) -> Self {
        let dial = TcpStream::connect(&address);
        self.dial.push((address, dial));
        self.task_count += 1;
        self
    }

    /// Get service current protocol configure
    pub fn get_protocol_configs(
        &self,
    ) -> &Arc<HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>> {
        &self.protocol_configs
    }

    /// Send data to the specified protocol for the specified session.
    ///
    /// Valid after Service starts
    #[inline]
    pub fn send_message(&mut self, message: Message) {
        if let Some(sender) = self.sessions.get_mut(&message.session_id) {
            let _ = sender.try_send(SessionEvent::ProtocolMessage {
                id: message.session_id,
                proto_id: message.proto_id,
                data: message.data.into(),
            });
        }
    }

    /// Send data to the specified protocol for the specified sessions.
    ///
    /// Valid after Service starts
    #[inline]
    pub fn filter_broadcast(&mut self, ids: Option<Vec<SessionId>>, message: Message) {
        match ids {
            None => self.broadcast(message),
            Some(ids) => {
                let proto_id = message.proto_id;
                let data: bytes::Bytes = message.data.into();
                self.sessions.iter_mut().for_each(|(id, send)| {
                    if ids.contains(id) {
                        let _ = send.try_send(SessionEvent::ProtocolMessage {
                            id: *id,
                            proto_id,
                            data: data.clone(),
                        });
                    }
                });
            }
        }
    }

    /// Broadcast data for a specified protocol.
    ///
    /// Valid after Service starts
    #[inline]
    pub fn broadcast(&mut self, message: Message) {
        debug!(
            "broadcast message, peer count: {}, proto_id: {}",
            self.sessions.len(),
            message.proto_id
        );
        let proto_id = message.proto_id;
        let data: bytes::Bytes = message.data.into();
        self.sessions.iter_mut().for_each(|(id, send)| {
            let _ = send.try_send(SessionEvent::ProtocolMessage {
                id: *id,
                proto_id,
                data: data.clone(),
            });
        });
    }

    /// Get the callback handle of the specified protocol
    #[inline]
    fn get_proto_handle(&self, session: bool, proto_id: ProtocolId) -> Option<ProtocolHandle> {
        let handle = self
            .protocol_configs
            .values()
            .filter(|proto| proto.id() == proto_id)
            .map(|proto| {
                if session {
                    proto.session_handle().map(ProtocolHandle::Session)
                } else {
                    proto.service_handle().map(ProtocolHandle::Service)
                }
            })
            .find(Option::is_some)
            .unwrap_or(None);

        if handle.is_none() {
            debug!(
                "can't find proto [{}] {} handle",
                proto_id,
                if session { "session" } else { "service" }
            );
        }

        handle
    }

    /// Handshake
    #[inline]
    fn handshake(&mut self, socket: TcpStream, ty: SessionType) {
        let address = socket.peer_addr().unwrap();
        if let Some(ref key_pair) = self.key_pair {
            let key_pair = key_pair.clone();
            let mut success_sender = self.session_event_sender.clone();
            let mut fail_sender = self.session_event_sender.clone();

            let task = Config::new(key_pair)
                .handshake(socket)
                .and_then(move |(handle, public_key, _)| {
                    let _ = success_sender.try_send(SessionEvent::HandshakeSuccess {
                        handle,
                        public_key,
                        address,
                        ty,
                    });
                    Ok(())
                })
                .timeout(Duration::from_secs(10))
                .map_err(move |err| {
                    error!(
                        "Handshake with {} failed, error: {:?}",
                        address,
                        err.description()
                    );
                    let _ = fail_sender.try_send(SessionEvent::HandshakeFail {
                        ty,
                        error: io::Error::new(io::ErrorKind::TimedOut, err.description()),
                    });
                });

            tokio::spawn(task);
        } else {
            self.session_open(socket, None, address, ty);
            if ty == SessionType::Client {
                self.task_count -= 1;
            }
        }
    }

    /// Session open
    #[inline]
    fn session_open<H>(
        &mut self,
        mut handle: H,
        public_key: Option<PublicKey>,
        address: SocketAddr,
        ty: SessionType,
    ) where
        H: AsyncRead + AsyncWrite + Send + 'static,
    {
        if let Some(ref key) = public_key {
            // If the public key exists, the connection has been established
            // and then the useless connection needs to be closed.
            if self
                .remote_pubkeys
                .values()
                .any(|current_key| current_key == key)
            {
                let _ = handle.shutdown();
            } else {
                self.next_session += 1;
                self.remote_pubkeys.insert(self.next_session, key.clone());
            }
        } else {
            self.next_session += 1;
        }

        let (service_event_sender, service_event_receiver) = mpsc::channel(256);
        let meta = SessionMeta::new(self.next_session, ty, address, public_key.clone())
            .protocol(self.protocol_configs.clone());
        let mut session = Session::new(
            handle,
            self.session_event_sender.clone(),
            service_event_receiver,
            meta,
        );

        if ty == SessionType::Client {
            self.protocol_configs
                .keys()
                .for_each(|name| session.open_proto_stream(name));
        }
        self.sessions
            .insert(self.next_session, service_event_sender);

        tokio::spawn(session.for_each(|_| Ok(())).map_err(|_| ()));

        self.handle.handle_event(
            &mut self.service_context,
            ServiceEvent::SessionOpen {
                id: self.next_session,
                address,
                ty: SessionType::Server,
                public_key,
            },
        );
    }

    /// Close the specified session, clean up the handle
    #[inline]
    fn session_close(&mut self, id: SessionId) {
        debug!("service session [{}] close", id);
        self.remote_pubkeys.remove(&id);
        if let Some(mut session_sender) = self.sessions.remove(&id) {
            let _ = session_sender.try_send(SessionEvent::SessionClose { id });
        }

        // Service handle processing flow
        self.handle
            .handle_event(&mut self.service_context, ServiceEvent::SessionClose { id });

        // Session proto handle processing flow
        let mut close_proto_ids = Vec::new();
        if let Some(handles) = self.session_proto_handles.remove(&id) {
            for (proto_id, mut handle) in handles {
                handle.disconnected(&mut self.service_context);
                close_proto_ids.push(proto_id);
            }
        }

        debug!("session [{}] close proto [{:?}]", id, close_proto_ids);
        // Service proto handle processing flow
        //
        // You must first confirm that the protocol is open in the session,
        // otherwise a false positive will occur.
        close_proto_ids.into_iter().for_each(|proto_id| {
            let session_context = self.session_contexts.get(&id);
            let service_handle = self.service_proto_handles.get_mut(&proto_id);
            if let (Some(handle), Some(session_context)) = (service_handle, session_context) {
                handle.disconnected(&mut self.service_context, session_context);
            }
        });
        self.session_contexts.remove(&id);
    }

    /// Open the handle corresponding to the protocol
    #[inline]
    fn protocol_open(
        &mut self,
        id: SessionId,
        proto_id: ProtocolId,
        address: SocketAddr,
        ty: SessionType,
        remote_pubkey: &Option<PublicKey>,
        version: &str,
    ) {
        debug!("service session [{}] proto [{}] open", id, proto_id);

        let session_context = SessionContext {
            id,
            address,
            ty,
            remote_pubkey: remote_pubkey.clone(),
            version: version.to_owned(),
        };

        // Service proto handle processing flow
        if !self.service_proto_handles.contains_key(&proto_id) {
            if let Some(ProtocolHandle::Service(mut handle)) =
                self.get_proto_handle(false, proto_id)
            {
                debug!("init service [{}] level proto [{}] handle", id, proto_id);
                handle.init(&mut self.service_context);
                self.service_proto_handles.insert(proto_id, handle);
            }
        }
        if let Some(handle) = self.service_proto_handles.get_mut(&proto_id) {
            handle.connected(&mut self.service_context, &session_context);
        }

        // Session proto handle processing flow
        // Regardless of the existence of the session level handle,
        // you **must record** which protocols are opened for each session.
        if let Some(ProtocolHandle::Session(mut handle)) = self.get_proto_handle(true, proto_id) {
            debug!("init session [{}] level proto [{}] handle", id, proto_id);
            handle.connected(&mut self.service_context, &session_context);
            self.session_proto_handles
                .entry(id)
                .or_default()
                .insert(proto_id, handle);
        }

        self.session_contexts.insert(id, session_context);
    }

    /// Processing the received data
    #[inline]
    fn protocol_message(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: &bytes::Bytes,
    ) {
        debug!(
            "service receive session [{}] proto [{}] data: {:?}",
            session_id, proto_id, data
        );

        // Service proto handle processing flow
        let service_handle = self.service_proto_handles.get_mut(&proto_id);
        let session_context = self.session_contexts.get_mut(&session_id);
        if let (Some(handle), Some(session_context)) = (service_handle, session_context) {
            handle.received(&mut self.service_context, &session_context, data.to_vec());
        }

        // Session proto handle processing flow
        if let Some(handles) = self.session_proto_handles.get_mut(&session_id) {
            if let Some(handle) = handles.get_mut(&proto_id) {
                handle.received(&mut self.service_context, data.to_vec());
            }
        }
    }

    /// Protocol stream is closed, clean up data
    #[inline]
    fn protocol_close(&mut self, session_id: SessionId, proto_id: ProtocolId) {
        debug!(
            "service session [{}] proto [{}] close",
            session_id, proto_id
        );

        // Service proto handle processing flow
        let service_handle = self.service_proto_handles.get_mut(&proto_id);
        let session_context = self.session_contexts.get_mut(&session_id);
        if let (Some(handle), Some(session_context)) = (service_handle, session_context) {
            handle.disconnected(&mut self.service_context, &session_context);
        }

        // Session proto handle processing flow
        if let Some(handles) = self.session_proto_handles.get_mut(&session_id) {
            if let Some(mut handle) = handles.remove(&proto_id) {
                handle.disconnected(&mut self.service_context);
            }
        }
    }

    /// Handling various events uploaded by the session
    fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::SessionClose { id } => self.session_close(id),
            SessionEvent::HandshakeSuccess {
                handle,
                public_key,
                address,
                ty,
            } => {
                self.session_open(handle, Some(public_key), address, ty);
                if ty == SessionType::Client {
                    self.task_count -= 1;
                }
            }
            SessionEvent::HandshakeFail { ty, .. } => {
                if ty == SessionType::Client {
                    self.task_count -= 1;
                }
            }
            SessionEvent::ProtocolMessage { id, proto_id, data } => {
                self.protocol_message(id, proto_id, &data)
            }
            SessionEvent::ProtocolOpen {
                id,
                proto_id,
                remote_address,
                remote_public_key,
                ty,
                version,
                ..
            } => self.protocol_open(
                id,
                proto_id,
                remote_address,
                ty,
                &remote_public_key,
                &version,
            ),
            SessionEvent::ProtocolClose { id, proto_id, .. } => self.protocol_close(id, proto_id),
        }
    }

    /// Handling various tasks sent externally
    fn handle_service_task(&mut self, event: ServiceTask) {
        match event {
            ServiceTask::ProtocolMessage {
                session_ids,
                message,
            } => self.filter_broadcast(session_ids, message),
            ServiceTask::Dial { address } => {
                if !self.dial.iter().any(|(addr, _)| addr == &address) {
                    let dial = TcpStream::connect(&address);
                    self.dial.push((address, dial));
                }
            }
            ServiceTask::Disconnect { session_id } => self.session_close(session_id),
            ServiceTask::FutureTask { task } => {
                tokio::spawn(task);
            }
            ServiceTask::ProtocolNotify { proto_id, token } => {
                if let Some(handle) = self.service_proto_handles.get_mut(&proto_id) {
                    handle.notify(&mut self.service_context, token);
                }
            }
            ServiceTask::ProtocolSessionNotify {
                session_id,
                proto_id,
                token,
            } => {
                if let Some(handles) = self.session_proto_handles.get_mut(&session_id) {
                    if let Some(handle) = handles.get_mut(&proto_id) {
                        handle.notify(&mut self.service_context, token);
                    }
                }
            }
        }
    }

    /// Poll client requests
    #[inline]
    fn client_poll(&mut self) {
        for (address, mut dialer) in self.dial.split_off(0) {
            match dialer.poll() {
                Ok(Async::Ready(socket)) => {
                    self.handshake(socket, SessionType::Client);
                }
                Ok(Async::NotReady) => {
                    trace!("client not ready");
                    self.dial.push((address, dialer));
                }
                Err(err) => {
                    self.task_count -= 1;
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceEvent::DialerError {
                            address,
                            error: err,
                        },
                    );
                }
            }
        }
    }

    /// Poll listen connections
    #[inline]
    fn listen_poll(&mut self) {
        for (address, mut listen) in self.listens.split_off(0) {
            match listen.poll() {
                Ok(Async::Ready(Some(socket))) => {
                    self.handshake(socket, SessionType::Server);
                    self.listens.push((address, listen));
                }
                Ok(Async::Ready(None)) => (),
                Ok(Async::NotReady) => {
                    self.listens.push((address, listen));
                }
                Err(err) => {
                    // TODO: need push back?
                    self.listens.push((address, listen));
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceEvent::ListenError {
                            address,
                            error: err,
                        },
                    );
                }
            }
        }

        self.service_context
            .update_listens(self.listens.iter().map(|(address, _)| *address).collect());
    }
}

impl<T, U> Stream for Service<T, U>
where
    T: ServiceHandle,
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error + Into<io::Error>,
    <U as Encoder>::Error: error::Error + Into<io::Error>,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if self.listens.is_empty() && self.task_count == 0 && self.sessions.is_empty() {
            return Ok(Async::Ready(None));
        }

        self.client_poll();

        self.listen_poll();

        loop {
            match self.session_event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_session_event(event),
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("receive session error: {:?}", err);
                    break;
                }
            }
        }

        loop {
            match self.service_task_receiver.poll() {
                Ok(Async::Ready(Some(task))) => self.handle_service_task(task),
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("receive service task error: {:?}", err);
                    break;
                }
            }
        }

        // Double check service state
        if self.listens.is_empty() && self.task_count == 0 && self.sessions.is_empty() {
            return Ok(Async::Ready(None));
        }
        debug!(
            "listens count: {}, task_count: {}, sessions count: {}",
            self.listens.len(),
            self.task_count,
            self.sessions.len()
        );

        Ok(Async::NotReady)
    }
}
