use futures::{prelude::*, sync::mpsc};
use log::{debug, error, trace, warn};
use secio::{handshake::Config, PublicKey, SecioKeyPair};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{error, io};
use tokio::net::{
    tcp::{ConnectFuture, Incoming},
    TcpListener, TcpStream,
};
use tokio::{
    codec::{Decoder, Encoder},
    prelude::{AsyncRead, AsyncWrite},
};
use yamux::session::SessionType;

use crate::session::{ProtocolId, ProtocolMeta, Session, SessionEvent, SessionId, SessionMeta};

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

/// Protocol handle
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
/// Depending on whether the user defines a global handle or a session exclusive handle,
/// the runtime has different performance.
///
/// The **important difference** is that some state values are allowed in the global handle,
/// and the handle exclusive to the session is "stateless", relative to the global handle,
/// it can only retain the information between a protocol stream on and off.
///
/// The opening and closing of the protocol will create and clean up the handle exclusive
/// to the session, but the global handle will remain in the state until the service is closed.
///
pub trait ProtocolHandle {
    /// This function is called when the protocol is opened.
    ///
    /// The global handle will only be called once, and the session exclusive handle will be called each time it is opened.
    fn init(&mut self, _control: &mut ServiceContext) {}
    /// Called when the corresponding protocol message is received
    ///
    /// Session exclusive handle can only receive messages from the own session
    fn received(&mut self, _control: &mut ServiceContext, _data: Message) {}
    /// Called when opening protocol
    fn connected(
        &mut self,
        _control: &mut ServiceContext,
        _session_id: SessionId,
        _address: SocketAddr,
        _ty: SessionType,
    ) {
    }
    /// Called when closing protocol
    fn disconnected(&mut self, _control: &mut ServiceContext, _session_id: SessionId) {}
    /// Called when the Service receives the notify task
    ///
    /// Similarly, session notify and notify correspond to session exclusive handle and global handle respectively.
    fn notify(&mut self, _control: &mut ServiceContext, _token: u64) {}
}

/// Protocol message
///
/// > The structure may be adjusted in the future
#[derive(Debug)]
pub struct Message {
    /// This field is used to indicate from
    /// which session the message was received,
    /// but this field is useless when sending a message.
    pub id: SessionId,
    /// Protocol id
    pub proto_id: ProtocolId,
    /// Data
    pub data: Vec<u8>,
}

impl Default for Message {
    fn default() -> Self {
        Message {
            id: 0,
            proto_id: 0,
            data: Vec::new(),
        }
    }
}

/// The Service runtime can send some instructions to the inside of the handle.
/// This is the sending channel.
// TODO: Need to maintain the network topology map here?
#[derive(Clone)]
pub struct ServiceContext {
    service_task_sender: mpsc::Sender<ServiceTask>,
    proto_message: Arc<HashMap<ProtocolId, String>>,
}

impl ServiceContext {
    /// New
    fn new(
        service_task_sender: mpsc::Sender<ServiceTask>,
        proto_message: HashMap<ProtocolId, String>,
    ) -> Self {
        ServiceContext {
            service_task_sender,
            proto_message: Arc::new(proto_message),
        }
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&mut self, address: SocketAddr) {
        self.send(ServiceTask::Dial { address })
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(&mut self, id: SessionId) {
        self.send(ServiceTask::Disconnect { id })
    }

    /// Send message
    #[inline]
    pub fn send_message(&mut self, ids: Option<Vec<SessionId>>, message: Message) {
        self.send(ServiceTask::ProtocolMessage { ids, message })
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

    /// Get the internal channel sender side handle
    #[inline]
    pub fn sender(&mut self) -> &mut mpsc::Sender<ServiceTask> {
        &mut self.service_task_sender
    }

    /// Get service protocol message, Map(ID, Name), but can't modify
    #[inline]
    pub fn get_protocols(&self) -> &Arc<HashMap<ProtocolId, String>> {
        &self.proto_message
    }

    /// Real send function
    #[inline]
    fn send(&mut self, event: ServiceTask) {
        let _ = self.service_task_sender.try_send(event);
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
        ids: Option<Vec<SessionId>>,
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
        id: SessionId,
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
        id: SessionId,
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
    /// Calculate the number of connection requests that need to be sent externally
    need_dial: usize,

    next_session: SessionId,

    key_pair: Option<SecioKeyPair>,

    /// Can be upgrade to list service level protocols
    handle: T,

    proto_handles: HashMap<ProtocolId, Box<dyn ProtocolHandle + Send + 'static>>,

    proto_session_handles:
        HashMap<SessionId, HashMap<ProtocolId, Option<Box<dyn ProtocolHandle + Send + 'static>>>>,

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
    ) -> Self {
        let (session_event_sender, session_event_receiver) = mpsc::channel(256);
        let (service_task_sender, service_task_receiver) = mpsc::channel(256);
        let protocol_message = protocol_configs
            .values()
            .map(|meta| (meta.id(), meta.name()))
            .collect::<HashMap<ProtocolId, String>>();

        Service {
            protocol_configs,
            handle,
            key_pair,
            sessions: HashMap::default(),
            proto_handles: HashMap::default(),
            proto_session_handles: HashMap::default(),
            listens: Vec::new(),
            dial: Vec::new(),
            need_dial: 0,
            next_session: 0,
            session_event_sender,
            session_event_receiver,
            service_context: ServiceContext::new(service_task_sender, protocol_message),
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
        self.need_dial += 1;
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
        if let Some(sender) = self.sessions.get_mut(&message.id) {
            let _ = sender.try_send(SessionEvent::ProtocolMessage {
                id: message.id,
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
    fn get_proto_handle(
        &self,
        session: bool,
        proto_id: ProtocolId,
    ) -> Option<Box<dyn ProtocolHandle + Send + 'static>> {
        let handle = self
            .protocol_configs
            .values()
            .map(|proto| {
                if proto.id() == proto_id {
                    if session {
                        proto.session_handle()
                    } else {
                        proto.handle()
                    }
                } else {
                    None
                }
            })
            .filter(|handle| handle.is_some())
            .collect::<Vec<Option<Box<dyn ProtocolHandle + Send + 'static>>>>()
            .pop();

        if let Some(Some(handle)) = handle {
            Some(handle)
        } else {
            trace!("can't find proto [{}] handle", proto_id);
            None
        }
    }

    /// Session open
    #[inline]
    fn session_open<H>(
        &mut self,
        handle: H,
        public_key: Option<PublicKey>,
        address: SocketAddr,
        ty: SessionType,
    ) where
        H: AsyncRead + AsyncWrite + Send + 'static,
    {
        self.next_session += 1;
        let (service_event_sender, service_event_receiver) = mpsc::channel(256);
        let meta = SessionMeta::new(self.next_session, ty, address)
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
                .for_each(|name| session.open_proto_stream(name.to_owned()));
        }
        self.sessions
            .insert(self.next_session, service_event_sender);

        let mut fail_sender = self.session_event_sender.clone();
        let fail_id = self.next_session;

        tokio::spawn(session.for_each(|_| Ok(())).map_err(move |err| {
            error!("session error: {}", err);
            let _ = fail_sender.try_send(SessionEvent::SessionClose { id: fail_id });
        }));

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
        if let Some(mut session_sender) = self.sessions.remove(&id) {
            let _ = session_sender.try_send(SessionEvent::SessionClose { id });
        }

        // Service handle processing flow
        self.handle
            .handle_event(&mut self.service_context, ServiceEvent::SessionClose { id });

        // Session proto handle processing flow
        let mut close_proto_ids = Vec::new();
        if let Some(handles) = self.proto_session_handles.remove(&id) {
            for (proto_id, handle) in handles {
                if let Some(mut handle) = handle {
                    handle.disconnected(&mut self.service_context, id);
                }
                close_proto_ids.push(proto_id);
            }
        }

        debug!("session [{}] close proto [{:?}]", id, close_proto_ids);
        // Global proto handle processing flow
        //
        // You must first confirm that the protocol is open in the session,
        // otherwise a false positive will occur.
        close_proto_ids.into_iter().for_each(|proto_id| {
            if let Some(handle) = self.proto_handles.get_mut(&proto_id) {
                handle.disconnected(&mut self.service_context, id);
            }
        });
    }

    /// Open the handle corresponding to the protocol
    #[inline]
    fn protocol_open(
        &mut self,
        id: SessionId,
        proto_id: ProtocolId,
        address: SocketAddr,
        ty: SessionType,
    ) {
        debug!("service session [{}] proto [{}] open", id, proto_id);

        // Global proto handle processing flow
        if let Some(handle) = self.proto_handles.get_mut(&proto_id) {
            handle.connected(&mut self.service_context, id, address, ty);
        } else if let Some(mut handle) = self.get_proto_handle(false, proto_id) {
            handle.init(&mut self.service_context);
            handle.connected(&mut self.service_context, id, address, ty);
            self.proto_handles.insert(proto_id, handle);
        }

        // Session proto handle processing flow
        // Regardless of the existence of the session level handle,
        // you **must record** which protocols are opened for each session.
        let session_level_handle = match self.get_proto_handle(true, proto_id) {
            Some(mut handle) => {
                debug!("init session [{}] level proto [{}] handle", id, proto_id);
                handle.init(&mut self.service_context);
                handle.connected(&mut self.service_context, id, address, ty);
                Some(handle)
            }
            None => None,
        };

        self.proto_session_handles
            .entry(id)
            .or_default()
            .insert(proto_id, session_level_handle);
    }

    /// Processing the received data
    #[inline]
    fn protocol_message(&mut self, id: SessionId, proto_id: ProtocolId, data: &bytes::Bytes) {
        debug!(
            "service receive session [{}] proto [{}] data: {:?}",
            id, proto_id, data
        );

        // Global proto handle processing flow
        if let Some(handle) = self.proto_handles.get_mut(&proto_id) {
            handle.received(
                &mut self.service_context,
                Message {
                    id,
                    proto_id,
                    data: data.to_vec(),
                },
            );
        }

        // Session proto handle processing flow
        if let Some(handles) = self.proto_session_handles.get_mut(&id) {
            if let Some(Some(handle)) = handles.get_mut(&proto_id) {
                handle.received(
                    &mut self.service_context,
                    Message {
                        id,
                        proto_id,
                        data: data.to_vec(),
                    },
                );
            }
        }
    }

    /// Protocol stream is closed, clean up data
    #[inline]
    fn protocol_close(&mut self, id: SessionId, proto_id: ProtocolId) {
        debug!("service session [{}] proto [{}] close", id, proto_id);

        // Global proto handle processing flow
        if let Some(handle) = self.proto_handles.get_mut(&proto_id) {
            handle.disconnected(&mut self.service_context, id);
        }

        // Session proto handle processing flow
        if let Some(handles) = self.proto_session_handles.get_mut(&id) {
            if let Some(Some(mut handle)) = handles.remove(&proto_id) {
                handle.disconnected(&mut self.service_context, id);
            }
        }
    }

    /// Handling various events uploaded by the session
    fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::SessionClose { id } => self.session_close(id),
            SessionEvent::SessionOpen {
                handle,
                public_key,
                address,
                ty,
                error,
            } => {
                if error.is_none() {
                    self.session_open(handle.unwrap(), public_key, address.unwrap(), ty)
                }
                if ty == SessionType::Client {
                    self.need_dial -= 1;
                }
            }
            SessionEvent::ProtocolMessage { id, proto_id, data } => {
                self.protocol_message(id, proto_id, &data)
            }
            SessionEvent::ProtocolOpen {
                id,
                proto_id,
                remote_address,
                ty,
                ..
            } => self.protocol_open(id, proto_id, remote_address, ty),
            SessionEvent::ProtocolClose { id, proto_id, .. } => self.protocol_close(id, proto_id),
        }
    }

    /// Handling various tasks sent externally
    fn handle_service_task(&mut self, event: ServiceTask) {
        match event {
            ServiceTask::ProtocolMessage { ids, message } => self.filter_broadcast(ids, message),
            ServiceTask::Dial { address } => {
                let dial = TcpStream::connect(&address);
                self.dial.push((address, dial));
            }
            ServiceTask::Disconnect { id } => self.session_close(id),
            ServiceTask::FutureTask { task } => {
                tokio::spawn(task);
            }
            ServiceTask::ProtocolNotify { proto_id, token } => {
                if let Some(handle) = self.proto_handles.get_mut(&proto_id) {
                    handle.notify(&mut self.service_context, token);
                }
            }
            ServiceTask::ProtocolSessionNotify {
                id,
                proto_id,
                token,
            } => {
                if let Some(handles) = self.proto_session_handles.get_mut(&id) {
                    if let Some(Some(handle)) = handles.get_mut(&proto_id) {
                        handle.notify(&mut self.service_context, token);
                    }
                }
            }
        }
    }

    /// Poll client requests
    #[inline]
    fn client_poll(&mut self) {
        let mut no_ready_client = Vec::new();
        while let Some((address, mut dialer)) = self.dial.pop() {
            match dialer.poll() {
                Ok(Async::Ready(socket)) => {
                    let address = socket.peer_addr().unwrap();
                    if self.key_pair.is_some() {
                        let key_pair = self.key_pair.clone().unwrap();
                        let mut success_sender = self.session_event_sender.clone();
                        let mut fail_sender = self.session_event_sender.clone();

                        let task = Config::new(key_pair)
                            .handshake(socket)
                            .and_then(move |(handle, public_key, _)| {
                                let _ = success_sender.try_send(SessionEvent::SessionOpen {
                                    handle: Some(handle),
                                    public_key: Some(public_key),
                                    address: Some(address),
                                    ty: SessionType::Client,
                                    error: None,
                                });
                                Ok(())
                            })
                            .map_err(move |err| {
                                error!("Handshake with {} failed, error: {:?}", address, err);
                                let _ = fail_sender.try_send(SessionEvent::SessionOpen {
                                    handle: None,
                                    public_key: None,
                                    address: None,
                                    ty: SessionType::Client,
                                    error: Some(err.into()),
                                });
                            });

                        tokio::spawn(task);
                    } else {
                        self.session_open(socket, None, address, SessionType::Client);
                    }
                }
                Ok(Async::NotReady) => {
                    trace!("client not ready");
                    no_ready_client.push((address, dialer));
                }
                Err(err) => {
                    self.need_dial -= 1;
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
        self.dial = no_ready_client;
    }

    /// Poll listen connections
    #[inline]
    fn listen_poll(&mut self) -> Poll<Option<()>, ()> {
        if self.listens.is_empty() && self.need_dial == 0 && self.sessions.is_empty() {
            return Ok(Async::Ready(None));
        }

        let mut listen_len = self.listens.len();
        let mut no_ready_len = listen_len;

        for (address, mut listen) in self.listens.split_off(0) {
            match listen.poll() {
                Ok(Async::Ready(Some(socket))) => {
                    let address = socket.peer_addr().unwrap();
                    if self.key_pair.is_some() {
                        let key_pair = self.key_pair.clone().unwrap();
                        let mut success_sender = self.session_event_sender.clone();
                        let mut fail_sender = self.session_event_sender.clone();

                        let task = Config::new(key_pair)
                            .handshake(socket)
                            .and_then(move |(handle, public_key, _)| {
                                let _ = success_sender.try_send(SessionEvent::SessionOpen {
                                    handle: Some(handle),
                                    public_key: Some(public_key),
                                    address: Some(address),
                                    ty: SessionType::Server,
                                    error: None,
                                });
                                Ok(())
                            })
                            .map_err(move |err| {
                                error!("Handshake with {} failed, error: {:?}", address, err);
                                let _ = fail_sender.try_send(SessionEvent::SessionOpen {
                                    handle: None,
                                    public_key: None,
                                    address: None,
                                    ty: SessionType::Server,
                                    error: Some(err.into()),
                                });
                            });

                        tokio::spawn(task);
                    } else {
                        self.session_open(socket, None, address, SessionType::Server);
                    }
                    self.listens.push((address, listen));
                }
                Ok(Async::Ready(None)) => {
                    if self.sessions.is_empty() {
                        listen_len -= 1;
                    }
                }
                Ok(Async::NotReady) => {
                    no_ready_len -= 1;
                    self.listens.push((address, listen));
                }
                Err(err) => {
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

        // If all listens return NotReady, then it is NotReady
        if no_ready_len == 0 {
            return Ok(Async::NotReady);
        }

        // If all listens return None and the count of sessions is 0, then it returns None
        // others will return Some(())
        if listen_len == 0 {
            Ok(Async::Ready(None))
        } else {
            Ok(Async::Ready(Some(())))
        }
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
        self.client_poll();

        if let Ok(Async::Ready(None)) = self.listen_poll() {
            return Ok(Async::Ready(None));
        }

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
        if self.listens.is_empty() && self.need_dial == 0 && self.sessions.is_empty() {
            return Ok(Async::Ready(None));
        }

        Ok(Async::NotReady)
    }
}
