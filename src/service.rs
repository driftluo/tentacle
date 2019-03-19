use futures::{
    prelude::*,
    sync::mpsc,
    task::{self, Task},
};
use log::{debug, error, trace, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::{error::Error as ErrorTrait, io};
use tokio::net::{
    tcp::{ConnectFuture, Incoming},
    TcpListener, TcpStream,
};
use tokio::{
    prelude::{AsyncRead, AsyncWrite, FutureExt},
    timer::Timeout,
};

use crate::{
    context::{ServiceContext, SessionContext},
    error::Error,
    multiaddr::{multihash::Multihash, Multiaddr, Protocol, ToMultiaddr},
    protocol_handle_stream::{
        ServiceProtocolEvent, ServiceProtocolStream, SessionProtocolEvent, SessionProtocolStream,
    },
    protocol_select::ProtocolInfo,
    secio::{handshake::Config, PublicKey, SecioKeyPair},
    service::config::ServiceConfig,
    session::{Session, SessionEvent, SessionMeta},
    traits::{ServiceHandle, ServiceProtocol, SessionProtocol},
    utils::{dns::DNSResolver, extract_peer_id, multiaddr_to_socketaddr},
    yamux::{session::SessionType, Config as YamuxConfig},
    ProtocolId, SessionId,
};

pub(crate) mod config;
mod control;
mod event;

pub use crate::service::{
    config::{DialProtocol, ProtocolHandle, ProtocolMeta},
    control::ServiceControl,
    event::{ProtocolEvent, ServiceError, ServiceEvent, ServiceTask},
};

/// Protocol handle value
pub(crate) enum InnerProtocolHandle {
    /// Service level protocol
    Service(Box<dyn ServiceProtocol + Send + 'static>),
    /// Session level protocol
    Session(Box<dyn SessionProtocol + Send + 'static>),
}

/// An abstraction of p2p service, currently only supports TCP protocol
pub struct Service<T> {
    protocol_configs: HashMap<String, ProtocolMeta>,

    sessions: HashMap<SessionId, SessionContext>,

    listens: Vec<(Multiaddr, Incoming)>,

    dial: Vec<(Multiaddr, Timeout<ConnectFuture>)>,
    dial_protocols: HashMap<Multiaddr, DialProtocol>,
    config: ServiceConfig,
    /// Calculate the number of connection requests that need to be sent externally,
    /// if run forever, it will default to 1, else it default to 0
    task_count: usize,

    next_session: SessionId,

    /// Can be upgrade to list service level protocols
    handle: T,

    /// The buffer which will distribute to sessions
    write_buf: VecDeque<(SessionId, SessionEvent)>,
    /// The buffer which will distribute to service protocol handle
    read_service_buf: VecDeque<(ProtocolId, ServiceProtocolEvent)>,
    /// The buffer which will distribute to session protocol handle
    read_session_buf: VecDeque<(SessionId, ProtocolId, SessionProtocolEvent)>,

    // The service protocols open with the session
    session_service_protos: HashMap<SessionId, HashSet<ProtocolId>>,

    service_proto_handles: HashMap<ProtocolId, mpsc::Sender<ServiceProtocolEvent>>,

    session_proto_handles: HashMap<(SessionId, ProtocolId), mpsc::Sender<SessionProtocolEvent>>,

    /// Send events to service, clone to session
    session_event_sender: mpsc::Sender<SessionEvent>,
    /// Receive event from service
    session_event_receiver: mpsc::Receiver<SessionEvent>,

    /// External event is passed in from this
    service_context: ServiceContext,
    /// External event receiver
    service_task_receiver: mpsc::Receiver<ServiceTask>,

    notify: Option<Task>,
}

impl<T> Service<T>
where
    T: ServiceHandle,
{
    /// New a Service
    pub(crate) fn new(
        protocol_configs: HashMap<String, ProtocolMeta>,
        handle: T,
        key_pair: Option<SecioKeyPair>,
        forever: bool,
        config: ServiceConfig,
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
            sessions: HashMap::default(),
            session_service_protos: HashMap::default(),
            service_proto_handles: HashMap::default(),
            session_proto_handles: HashMap::default(),
            listens: Vec::new(),
            dial: Vec::new(),
            dial_protocols: HashMap::default(),
            config,
            task_count: if forever { 1 } else { 0 },
            next_session: 0,
            write_buf: VecDeque::default(),
            read_service_buf: VecDeque::default(),
            read_session_buf: VecDeque::default(),
            session_event_sender,
            session_event_receiver,
            service_context: ServiceContext::new(service_task_sender, proto_infos, key_pair),
            service_task_receiver,
            notify: None,
        }
    }

    /// Yamux config for service
    ///
    /// Panic when max_frame_length < yamux_max_window_size
    pub fn yamux_config(mut self, config: YamuxConfig) -> Self {
        assert!(self.config.max_frame_length as u32 >= config.max_stream_window_size);
        self.config.yamux_config = config;
        self
    }

    /// Secio max frame length
    ///
    /// Panic when max_frame_length < yamux_max_window_size
    pub fn max_frame_length(mut self, size: usize) -> Self {
        assert!(size as u32 >= self.config.yamux_config.max_stream_window_size);
        self.config.max_frame_length = size;
        self
    }

    /// Listen on the given address.
    ///
    /// Return really listen multiaddr, but if use `/dns4/localhost/tcp/80`,
    /// it will return original value, and create a future task to DNS resolver later.
    pub fn listen(&mut self, address: Multiaddr) -> Result<Multiaddr, io::Error> {
        let listen_addr = if let Some(socket_address) = multiaddr_to_socketaddr(&address) {
            let tcp = TcpListener::bind(&socket_address)?;
            let listen_addr = tcp.local_addr()?.to_multiaddr().unwrap();
            self.listens.push((listen_addr.clone(), tcp.incoming()));
            listen_addr
        } else {
            let dns = DNSResolver::new(address.clone())
                .ok_or_else::<io::Error, _>(|| io::ErrorKind::InvalidInput.into())?;
            let sender = self.session_event_sender.clone();
            let future_task = dns.then(move |result| match result {
                Ok(address) => tokio::spawn(
                    sender
                        .send(SessionEvent::DNSResolverSuccess {
                            ty: SessionType::Server,
                            address,
                            target: DialProtocol::All,
                        })
                        .map(|_| ())
                        .map_err(|err| {
                            error!("Listen address success send back error: {:?}", err);
                        }),
                ),
                Err((address, error)) => tokio::spawn(
                    sender
                        .send(SessionEvent::ListenError { address, error })
                        .map(|_| ())
                        .map_err(|err| {
                            error!("Listen address fail send back error: {:?}", err);
                        }),
                ),
            });
            self.service_context
                .pending_tasks
                .push_back(ServiceTask::FutureTask {
                    task: Box::new(future_task),
                });
            self.task_count += 1;
            address
        };
        Ok(listen_addr)
    }

    /// Dial the given address, doesn't actually make a request, just generate a future
    pub fn dial(
        &mut self,
        address: Multiaddr,
        target: DialProtocol,
    ) -> Result<&mut Self, io::Error> {
        self.dial_inner(address, target)?;
        Ok(self)
    }

    /// Use by inner
    #[inline(always)]
    fn dial_inner(&mut self, address: Multiaddr, target: DialProtocol) -> Result<(), io::Error> {
        if let Some(socket_address) = multiaddr_to_socketaddr(&address) {
            let dial = TcpStream::connect(&socket_address).timeout(self.config.timeout);
            self.dial_protocols.insert(address.clone(), target);
            self.dial.push((address, dial));
            self.task_count += 1;
        } else {
            let dns = DNSResolver::new(address)
                .ok_or_else::<io::Error, _>(|| io::ErrorKind::InvalidInput.into())?;
            let sender = self.session_event_sender.clone();
            let future_task = dns.then(move |result| match result {
                Ok(address) => tokio::spawn(
                    sender
                        .send(SessionEvent::DNSResolverSuccess {
                            ty: SessionType::Client,
                            address,
                            target,
                        })
                        .map(|_| ())
                        .map_err(|err| {
                            error!("dial address success send back error: {:?}", err);
                        }),
                ),
                Err((address, error)) => tokio::spawn(
                    sender
                        .send(SessionEvent::DialError { address, error })
                        .map(|_| ())
                        .map_err(|err| {
                            error!("dial address fail send back error: {:?}", err);
                        }),
                ),
            });
            self.service_context
                .pending_tasks
                .push_back(ServiceTask::FutureTask {
                    task: Box::new(future_task),
                });
            self.task_count += 1;
        }

        Ok(())
    }

    /// Get service current protocol configure
    pub fn protocol_configs(&self) -> &HashMap<String, ProtocolMeta> {
        &self.protocol_configs
    }

    /// Get service control, control can send tasks externally to the runtime inside
    pub fn control(&mut self) -> &mut ServiceControl {
        self.service_context.control()
    }

    /// Distribute event to sessions
    #[inline]
    fn distribute_to_session(&mut self) {
        for (id, event) in self.write_buf.split_off(0) {
            if let Some(session) = self.sessions.get_mut(&id) {
                if let Err(e) = session.event_sender.try_send(event) {
                    if e.is_full() {
                        debug!("session [{}] is full", id);
                        self.write_buf.push_back((id, e.into_inner()));
                        self.notify();
                    } else {
                        error!("channel shutdown, message can't send")
                    }
                }
            } else {
                debug!("Can't find session {} to send data", id);
            }
        }
    }

    /// Distribute event to user level
    #[inline(always)]
    fn distribute_to_user_level(&mut self) {
        for (proto_id, event) in self.read_service_buf.split_off(0) {
            if let Some(sender) = self.service_proto_handles.get_mut(&proto_id) {
                if let Err(e) = sender.try_send(event) {
                    if e.is_full() {
                        debug!("service proto [{}] handle is full", proto_id);
                        self.read_service_buf.push_back((proto_id, e.into_inner()));
                        self.notify();
                    } else {
                        error!(
                            "channel shutdown, proto [{}] message can't send to user",
                            proto_id
                        )
                    }
                }
            }
        }

        for (session_id, proto_id, event) in self.read_session_buf.split_off(0) {
            if let Some(sender) = self.session_proto_handles.get_mut(&(session_id, proto_id)) {
                if let Err(e) = sender.try_send(event) {
                    if e.is_full() {
                        debug!(
                            "session [{}] proto [{}] handle is full",
                            session_id, proto_id
                        );
                        self.read_session_buf
                            .push_back((session_id, proto_id, e.into_inner()));
                        self.notify();
                    } else {
                        error!(
                            "channel shutdown, proto [{}] session [{}] message can't send to user",
                            proto_id, session_id
                        )
                    }
                }
            }
        }
    }

    /// Send data to the specified protocol for the specified session.
    ///
    /// Valid after Service starts
    #[inline]
    pub fn send_message(&mut self, session_id: SessionId, proto_id: ProtocolId, data: &[u8]) {
        self.write_buf.push_back((
            session_id,
            SessionEvent::ProtocolMessage {
                id: session_id,
                proto_id,
                data: data.into(),
            },
        ));
        self.distribute_to_session();
    }

    /// Send data to the specified protocol for the specified sessions.
    ///
    /// Valid after Service starts
    #[inline]
    pub fn filter_broadcast(
        &mut self,
        ids: Option<Vec<SessionId>>,
        proto_id: ProtocolId,
        data: &[u8],
    ) {
        match ids {
            None => self.broadcast(proto_id, data),
            Some(ids) => {
                let data: bytes::Bytes = data.into();
                for id in self.sessions.keys() {
                    if ids.contains(id) {
                        debug!(
                            "send message to session [{}], proto [{}], data len: {}",
                            id,
                            proto_id,
                            data.len()
                        );
                        self.write_buf.push_back((
                            *id,
                            SessionEvent::ProtocolMessage {
                                id: *id,
                                proto_id,
                                data: data.clone(),
                            },
                        ));
                    }
                }
                self.distribute_to_session();
            }
        }
    }

    /// Broadcast data for a specified protocol.
    ///
    /// Valid after Service starts
    #[inline]
    pub fn broadcast(&mut self, proto_id: ProtocolId, data: &[u8]) {
        debug!(
            "broadcast message, peer count: {}, proto_id: {}, data len: {}",
            self.sessions.len(),
            proto_id,
            data.len()
        );
        let data: bytes::Bytes = data.into();
        for id in self.sessions.keys() {
            self.write_buf.push_back((
                *id,
                SessionEvent::ProtocolMessage {
                    id: *id,
                    proto_id,
                    data: data.clone(),
                },
            ));
        }
        self.distribute_to_session();
    }

    /// Get the callback handle of the specified protocol
    #[inline]
    fn proto_handle(&self, session: bool, proto_id: ProtocolId) -> Option<InnerProtocolHandle> {
        let handle = self.protocol_configs.values().find_map(|proto| {
            if proto.id() == proto_id {
                if session {
                    match proto.session_handle() {
                        ProtocolHandle::Callback(handle) | ProtocolHandle::Both(handle) => {
                            Some(InnerProtocolHandle::Session(handle))
                        }
                        _ => None,
                    }
                } else {
                    match proto.service_handle() {
                        ProtocolHandle::Callback(handle) | ProtocolHandle::Both(handle) => {
                            Some(InnerProtocolHandle::Service(handle))
                        }
                        _ => None,
                    }
                }
            } else {
                None
            }
        });

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
    fn handshake<H>(&mut self, socket: H, ty: SessionType, remote_address: Multiaddr)
    where
        H: AsyncRead + AsyncWrite + Send + 'static,
    {
        if let Some(key_pair) = self.service_context.key_pair() {
            let key_pair = key_pair.clone();
            let sender = self.session_event_sender.clone();

            let task = Config::new(key_pair)
                .max_frame_length(self.config.max_frame_length)
                .handshake(socket)
                .timeout(self.config.timeout)
                .then(move |result| {
                    let send_task = match result {
                        Ok((handle, public_key, _)) => {
                            sender.send(SessionEvent::HandshakeSuccess {
                                handle,
                                public_key,
                                address: remote_address,
                                ty,
                            })
                        }
                        Err(err) => {
                            let error = if err.is_timer() {
                                // tokio timer error
                                io::Error::new(io::ErrorKind::Other, err.description()).into()
                            } else if err.is_elapsed() {
                                // time out error
                                io::Error::new(io::ErrorKind::TimedOut, err.description()).into()
                            } else {
                                // dialer error
                                err.into_inner().unwrap().into()
                            };

                            debug!(
                                "Handshake with {} failed, error: {:?}",
                                remote_address, error
                            );

                            sender.send(SessionEvent::HandshakeFail {
                                ty,
                                error,
                                address: remote_address,
                            })
                        }
                    };

                    tokio::spawn(send_task.map(|_| ()).map_err(|err| {
                        error!("handshake result send back error: {:?}", err);
                    }));

                    Ok(())
                });

            tokio::spawn(task);
        } else {
            self.session_open(socket, None, remote_address, ty);
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
        remote_pubkey: Option<PublicKey>,
        mut address: Multiaddr,
        ty: SessionType,
    ) where
        H: AsyncRead + AsyncWrite + Send + 'static,
    {
        let target = self
            .dial_protocols
            .remove(&address)
            .unwrap_or_else(|| DialProtocol::All);
        if let Some(ref key) = remote_pubkey {
            // If the public key exists, the connection has been established
            // and then the useless connection needs to be closed.
            match self
                .sessions
                .values()
                .find(|&context| context.remote_pubkey.as_ref() == Some(key))
            {
                Some(context) => {
                    trace!("Connected to the connected node");
                    let _ = handle.shutdown();
                    if ty == SessionType::Client {
                        self.handle.handle_error(
                            &mut self.service_context,
                            ServiceError::DialerError {
                                error: Error::RepeatedConnection(context.id),
                                address,
                            },
                        );
                    } else {
                        self.handle.handle_error(
                            &mut self.service_context,
                            ServiceError::ListenError {
                                error: Error::RepeatedConnection(context.id),
                                address,
                            },
                        );
                    }
                    return;
                }
                None => {
                    // if peer id doesn't match return an error
                    if let Some(peer_id) = extract_peer_id(&address) {
                        if key.peer_id() != peer_id {
                            trace!("Peer id not match");
                            self.handle.handle_error(
                                &mut self.service_context,
                                ServiceError::DialerError {
                                    error: Error::PeerIdNotMatch,
                                    address,
                                },
                            );
                            return;
                        }
                    } else {
                        address.append(Protocol::P2p(
                            Multihash::from_bytes(key.peer_id().into_bytes())
                                .expect("Invalid peer id"),
                        ))
                    }

                    self.next_session += 1
                }
            }
        } else {
            self.next_session += 1;
        }

        let (service_event_sender, service_event_receiver) = mpsc::channel(32);
        let session_context = SessionContext {
            event_sender: service_event_sender,
            id: self.next_session,
            address,
            ty,
            remote_pubkey,
        };

        let meta = SessionMeta::new(self.next_session, ty, self.config.timeout)
            .protocol(
                self.protocol_configs
                    .iter()
                    .map(|(key, value)| (key.clone(), value.inner.clone()))
                    .collect(),
            )
            .config(self.config.yamux_config);

        let mut session = Session::new(
            handle,
            self.session_event_sender.clone(),
            service_event_receiver,
            meta,
        );

        if ty == SessionType::Client {
            match target {
                DialProtocol::All => {
                    self.protocol_configs
                        .keys()
                        .for_each(|name| session.open_proto_stream(name));
                }
                DialProtocol::Single(proto_id) => {
                    self.protocol_configs
                        .values()
                        .find(|meta| meta.id() == proto_id)
                        .and_then(|meta| {
                            session.open_proto_stream(&meta.name());
                            Some(())
                        });
                }
                DialProtocol::Multi(proto_ids) => self
                    .protocol_configs
                    .values()
                    .filter(|meta| proto_ids.contains(&meta.id()))
                    .for_each(|meta| session.open_proto_stream(&meta.name())),
            }
        }

        tokio::spawn(session.for_each(|_| Ok(())).map_err(|_| ()));

        self.handle.handle_event(
            &mut self.service_context,
            ServiceEvent::SessionOpen {
                session_context: &session_context,
            },
        );

        self.sessions.insert(session_context.id, session_context);
    }

    /// Close the specified session, clean up the handle
    #[inline]
    fn session_close(&mut self, id: SessionId, source: Source) {
        if source == Source::External {
            debug!("try close service session [{}] ", id);
            self.write_buf
                .push_back((id, SessionEvent::SessionClose { id }));
            self.distribute_to_session();
            return;
        }

        debug!("close service session [{}]", id);

        // Close all open proto
        let close_proto_ids = self.session_service_protos.remove(&id).unwrap_or_default();
        debug!("session [{}] close proto [{:?}]", id, close_proto_ids);

        close_proto_ids.into_iter().for_each(|proto_id| {
            self.protocol_close(id, proto_id, Source::Internal);
        });

        if let Some(session_context) = self.sessions.remove(&id) {
            // Service handle processing flow
            self.handle.handle_event(
                &mut self.service_context,
                ServiceEvent::SessionClose { session_context },
            );
        }
    }

    /// Open the handle corresponding to the protocol
    #[inline]
    fn protocol_open(
        &mut self,
        id: SessionId,
        proto_id: ProtocolId,
        version: String,
        source: Source,
    ) {
        if source == Source::External {
            debug!("try open session [{}] proto [{}]", id, proto_id);
            self.write_buf.push_back((
                id,
                SessionEvent::ProtocolOpen {
                    id,
                    proto_id,
                    version,
                },
            ));
            self.distribute_to_session();
            return;
        }

        debug!("service session [{}] proto [{}] open", id, proto_id);
        let session_context = self
            .sessions
            .get(&id)
            .expect("Protocol open without session open");

        // Regardless of the existence of the session level handle,
        // you **must record** which protocols are opened for each session.
        self.session_service_protos
            .entry(id)
            .or_default()
            .insert(proto_id);

        if self.config.event.contains(&proto_id) {
            // event output
            self.handle.handle_proto(
                &mut self.service_context,
                ProtocolEvent::Connected {
                    session_context,
                    proto_id,
                    version: version.clone(),
                },
            );
        }

        // callback output
        // Service proto handle processing flow
        if !self.service_proto_handles.contains_key(&proto_id) {
            if let Some(InnerProtocolHandle::Service(handle)) = self.proto_handle(false, proto_id) {
                debug!("init service level [{}] proto handle", proto_id);
                let (sender, receiver) = mpsc::channel(32);
                let stream = ServiceProtocolStream::new(
                    handle,
                    self.service_context.clone_self(),
                    receiver,
                    proto_id,
                );

                self.service_proto_handles.insert(proto_id, sender);

                tokio::spawn(stream.for_each(|_| Ok(())).map_err(|_| ()));

                self.read_service_buf
                    .push_back((proto_id, ServiceProtocolEvent::Init));
            }
        }

        if self.service_proto_handles.contains_key(&proto_id) {
            self.read_service_buf.push_back((
                proto_id,
                ServiceProtocolEvent::Connected {
                    session: session_context.clone(),
                    version: version.clone(),
                },
            ));
        }

        // Session proto handle processing flow
        if let Some(InnerProtocolHandle::Session(handle)) = self.proto_handle(true, proto_id) {
            debug!("init session [{}] level proto [{}] handle", id, proto_id);
            let (sender, receiver) = mpsc::channel(32);
            let stream = SessionProtocolStream::new(
                handle,
                self.service_context.clone_self(),
                session_context.clone(),
                receiver,
                proto_id,
            );

            tokio::spawn(stream.for_each(|_| Ok(())).map_err(|_| ()));

            self.session_proto_handles
                .entry((id, proto_id))
                .or_insert(sender);

            self.read_session_buf.push_back((
                id,
                proto_id,
                SessionProtocolEvent::Connected { version },
            ));
        }

        self.distribute_to_user_level();
    }

    /// Processing the received data
    #[inline]
    fn protocol_message(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: bytes::Bytes,
    ) {
        debug!(
            "service receive session [{}] proto [{}] data len: {}",
            session_id,
            proto_id,
            data.len()
        );

        if self.config.event.contains(&proto_id) {
            if let Some(session_context) = self.sessions.get(&session_id) {
                // event output
                self.handle.handle_proto(
                    &mut self.service_context,
                    ProtocolEvent::Received {
                        session_context,
                        proto_id,
                        data: data.clone(),
                    },
                );
            }
        }

        // callback output
        // Service proto handle processing flow
        if self.service_proto_handles.contains_key(&proto_id) {
            self.read_service_buf.push_back((
                proto_id,
                ServiceProtocolEvent::Received {
                    id: session_id,
                    data: data.clone(),
                },
            ));
        }

        // Session proto handle processing flow
        if self
            .session_proto_handles
            .contains_key(&(session_id, proto_id))
        {
            self.read_session_buf.push_back((
                session_id,
                proto_id,
                SessionProtocolEvent::Received { data },
            ));
        }

        self.distribute_to_user_level();
    }

    /// Protocol stream is closed, clean up data
    #[inline]
    fn protocol_close(&mut self, session_id: SessionId, proto_id: ProtocolId, source: Source) {
        if source == Source::External {
            debug!("try close session [{}] proto [{}]", session_id, proto_id);
            self.write_buf.push_back((
                session_id,
                SessionEvent::ProtocolClose {
                    id: session_id,
                    proto_id,
                },
            ));
            self.distribute_to_session();
            return;
        }

        debug!(
            "service session [{}] proto [{}] close",
            session_id, proto_id
        );

        if self.config.event.contains(&proto_id) {
            if let Some(session_context) = self.sessions.get(&session_id) {
                self.handle.handle_proto(
                    &mut self.service_context,
                    ProtocolEvent::DisConnected {
                        proto_id,
                        session_context,
                    },
                )
            }
        }

        // Service proto handle processing flow
        if self.service_proto_handles.contains_key(&proto_id) {
            self.read_service_buf.push_back((
                proto_id,
                ServiceProtocolEvent::Disconnected { id: session_id },
            ));
            self.distribute_to_user_level();
        }

        // Session proto handle processing flow
        if let Some(sender) = self.session_proto_handles.remove(&(session_id, proto_id)) {
            let send_task = sender.send(SessionProtocolEvent::Disconnected);
            tokio::spawn(send_task.map(|_| ()).map_err(|err| {
                error!(
                    "service session close event send to session handle error: {:?}",
                    err
                );
            }));
        }

        // Session proto info remove
        if let Some(infos) = self.session_service_protos.get_mut(&session_id) {
            infos.remove(&proto_id);
        }

        // Close notify sender
        self.service_context
            .remove_session_notify_senders(session_id, proto_id);
    }

    #[inline(always)]
    fn send_pending_task(&mut self) {
        while let Some(task) = self.service_context.pending_tasks.pop_front() {
            self.handle_service_task(task);
        }
    }

    /// When listen update, call here
    #[inline]
    fn update_listens(&mut self) {
        let new_listens = self
            .listens
            .iter()
            .map(|(address, _)| address.clone())
            .collect::<Vec<Multiaddr>>();
        self.service_context.update_listens(new_listens.clone());

        for proto_id in self.service_proto_handles.keys() {
            self.read_service_buf.push_back((
                *proto_id,
                ServiceProtocolEvent::Update {
                    listen_addrs: new_listens.clone(),
                },
            ));
        }

        for (session_id, proto_id) in self.session_proto_handles.keys() {
            self.read_session_buf.push_back((
                *session_id,
                *proto_id,
                SessionProtocolEvent::Update {
                    listen_addrs: new_listens.clone(),
                },
            ));
        }

        self.distribute_to_user_level();
    }

    /// Handling various events uploaded by the session
    fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::SessionClose { id } => self.session_close(id, Source::Internal),
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
            SessionEvent::HandshakeFail { ty, error, address } => {
                if ty == SessionType::Client {
                    self.task_count -= 1;
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::DialerError { error, address },
                    )
                }
            }
            SessionEvent::ProtocolMessage { id, proto_id, data } => {
                self.protocol_message(id, proto_id, data)
            }
            SessionEvent::ProtocolOpen {
                id,
                proto_id,
                version,
            } => self.protocol_open(id, proto_id, version, Source::Internal),
            SessionEvent::ProtocolClose { id, proto_id } => {
                self.protocol_close(id, proto_id, Source::Internal)
            }
            SessionEvent::ProtocolSelectError { id, proto_name } => {
                if let Some(session_context) = self.sessions.get(&id) {
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::ProtocolSelectError {
                            proto_name,
                            session_context,
                        },
                    )
                }
            }
            SessionEvent::ProtocolError {
                id,
                proto_id,
                error,
            } => self.handle.handle_error(
                &mut self.service_context,
                ServiceError::ProtocolError {
                    id,
                    proto_id,
                    error,
                },
            ),
            SessionEvent::DialError { address, error } => self.handle.handle_error(
                &mut self.service_context,
                ServiceError::DialerError { address, error },
            ),
            SessionEvent::ListenError { address, error } => self.handle.handle_error(
                &mut self.service_context,
                ServiceError::ListenError { address, error },
            ),
            SessionEvent::SessionTimeout { id } => {
                if let Some(session_context) = self.sessions.get(&id) {
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::SessionTimeout { session_context },
                    )
                }
            }
            SessionEvent::DNSResolverSuccess {
                ty,
                address,
                target,
            } => {
                self.task_count -= 1;
                match ty {
                    SessionType::Server => {
                        self.handle_service_task(ServiceTask::Listen { address })
                    }
                    SessionType::Client => {
                        self.handle_service_task(ServiceTask::Dial { address, target })
                    }
                }
            }
            SessionEvent::MuxerError { id, error } => {
                if let Some(session_context) = self.sessions.get(&id) {
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::MuxerError {
                            session_context,
                            error,
                        },
                    )
                }
            }
        }
    }

    /// Handling various tasks sent externally
    fn handle_service_task(&mut self, event: ServiceTask) {
        match event {
            ServiceTask::ProtocolMessage {
                session_ids,
                proto_id,
                data,
            } => self.filter_broadcast(session_ids, proto_id, &data),
            ServiceTask::Dial { address, target } => {
                if !self.dial.iter().any(|(addr, _)| addr == &address) {
                    if let Err(e) = self.dial_inner(address.clone(), target) {
                        self.handle.handle_error(
                            &mut self.service_context,
                            ServiceError::DialerError {
                                address,
                                error: e.into(),
                            },
                        );
                    }
                }
                if !self.dial.is_empty() {
                    self.client_poll();
                }
            }
            ServiceTask::Listen { address } => {
                if !self.listens.iter().any(|(addr, _)| addr == &address) {
                    match self.listen(address.clone()) {
                        Ok(_) => {
                            self.update_listens();
                            self.listen_poll();
                        }
                        Err(e) => {
                            self.handle.handle_error(
                                &mut self.service_context,
                                ServiceError::ListenError {
                                    address,
                                    error: e.into(),
                                },
                            );
                        }
                    }
                }
            }
            ServiceTask::Disconnect { session_id } => {
                self.session_close(session_id, Source::External)
            }
            ServiceTask::FutureTask { task } => {
                tokio::spawn(task);
            }
            ServiceTask::ProtocolNotify { proto_id, token } => {
                if self.config.event.contains(&proto_id) {
                    // event output
                    self.handle.handle_proto(
                        &mut self.service_context,
                        ProtocolEvent::ProtocolNotify { proto_id, token },
                    )
                } else if self.service_proto_handles.contains_key(&proto_id) {
                    // callback output
                    self.read_service_buf
                        .push_back((proto_id, ServiceProtocolEvent::Notify { token }));
                    self.distribute_to_user_level();
                }
            }
            ServiceTask::ProtocolSessionNotify {
                session_id,
                proto_id,
                token,
            } => {
                if self
                    .session_service_protos
                    .get(&session_id)
                    .map(|protos| protos.contains(&proto_id))
                    .unwrap_or_else(|| false)
                {
                    if self.config.event.contains(&proto_id) {
                        if let Some(session_context) = self.sessions.get(&session_id) {
                            // event output
                            self.handle.handle_proto(
                                &mut self.service_context,
                                ProtocolEvent::ProtocolSessionNotify {
                                    proto_id,
                                    session_context,
                                    token,
                                },
                            )
                        }
                    } else if self
                        .session_proto_handles
                        .contains_key(&(session_id, proto_id))
                    {
                        // callback output
                        self.read_session_buf.push_back((
                            session_id,
                            proto_id,
                            SessionProtocolEvent::Notify { token },
                        ));
                        self.distribute_to_user_level();
                    }
                } else {
                    self.service_context
                        .remove_session_notify_senders(session_id, proto_id);
                }
            }
            ServiceTask::ProtocolOpen {
                session_id,
                proto_id,
            } => self.protocol_open(session_id, proto_id, String::default(), Source::External),
            ServiceTask::ProtocolClose {
                session_id,
                proto_id,
            } => self.protocol_close(session_id, proto_id, Source::External),
        }
    }

    /// Poll client requests
    #[inline]
    fn client_poll(&mut self) {
        for (address, mut dialer) in self.dial.split_off(0) {
            match dialer.poll() {
                Ok(Async::Ready(socket)) => {
                    self.handshake(socket, SessionType::Client, address);
                }
                Ok(Async::NotReady) => {
                    trace!("client not ready, {}", address);
                    self.dial.push((address, dialer));
                }
                Err(err) => {
                    self.task_count -= 1;
                    let error = if err.is_timer() {
                        // tokio timer error
                        io::Error::new(io::ErrorKind::Other, err.description())
                    } else if err.is_elapsed() {
                        // time out error
                        io::Error::new(io::ErrorKind::TimedOut, err.description())
                    } else {
                        // dialer error
                        err.into_inner().unwrap()
                    };
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::DialerError {
                            address,
                            error: error.into(),
                        },
                    );
                }
            }
        }
    }

    /// Poll listen connections
    #[inline]
    fn listen_poll(&mut self) {
        let mut update = false;
        for (address, mut listen) in self.listens.split_off(0) {
            match listen.poll() {
                Ok(Async::Ready(Some(socket))) => {
                    let remote_address: Multiaddr =
                        socket.peer_addr().unwrap().to_multiaddr().unwrap();
                    self.handshake(socket, SessionType::Server, remote_address);
                    self.listens.push((address, listen));
                }
                Ok(Async::Ready(None)) => (),
                Ok(Async::NotReady) => {
                    self.listens.push((address, listen));
                }
                Err(err) => {
                    update = true;
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::ListenError {
                            address,
                            error: err.into(),
                        },
                    );
                }
            }
        }

        if update || self.service_context.listens().is_empty() {
            self.update_listens()
        }
    }

    #[inline]
    fn notify(&mut self) {
        if let Some(task) = self.notify.take() {
            task.notify();
        }
    }
}

impl<T> Stream for Service<T>
where
    T: ServiceHandle,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if self.listens.is_empty()
            && self.task_count == 0
            && self.sessions.is_empty()
            && self.service_context.pending_tasks.is_empty()
        {
            return Ok(Async::Ready(None));
        }

        if !self.write_buf.is_empty()
            || !self.read_service_buf.is_empty()
            || !self.read_session_buf.is_empty()
        {
            self.distribute_to_session();
            self.distribute_to_user_level();
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

        // process any task buffer
        self.send_pending_task();

        // Double check service state
        if self.listens.is_empty()
            && self.task_count == 0
            && self.sessions.is_empty()
            && self.service_context.pending_tasks.is_empty()
        {
            return Ok(Async::Ready(None));
        }
        debug!(
            "listens count: {}, task_count: {}, sessions count: {}, pending task: {}",
            self.listens.len(),
            self.task_count,
            self.sessions.len(),
            self.service_context.pending_tasks.len(),
        );

        self.notify = Some(task::current());
        Ok(Async::NotReady)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Source {
    /// Event from user
    External,
    /// Event from session
    Internal,
}
