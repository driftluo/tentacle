use futures::{
    prelude::*,
    sync::{mpsc, oneshot},
};
use log::{debug, error, trace, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{error::Error as ErrorTrait, io};
use tokio::prelude::{AsyncRead, AsyncWrite, FutureExt};
use tokio::timer::{self, Delay, Interval};

use crate::{
    context::{ServiceContext, SessionContext, SessionControl},
    error::Error,
    multiaddr::{multihash::Multihash, Multiaddr, Protocol},
    protocol_handle_stream::{
        ServiceProtocolEvent, ServiceProtocolStream, SessionProtocolEvent, SessionProtocolStream,
    },
    protocol_select::ProtocolInfo,
    secio::{handshake::Config, PublicKey, SecioKeyPair},
    service::{
        config::{ServiceConfig, State},
        event::{Priority, ServiceTask},
        future_task::{BoxedFutureTask, FutureTaskManager},
    },
    session::{Session, SessionEvent, SessionMeta},
    traits::{ServiceHandle, ServiceProtocol, SessionProtocol},
    transports::{MultiIncoming, MultiTransport, Transport, TransportError},
    utils::extract_peer_id,
    yamux::{session::SessionType as YamuxType, Config as YamuxConfig},
    ProtocolId, SessionId,
};

pub(crate) mod config;
mod control;
pub(crate) mod event;
pub(crate) mod future_task;

pub use crate::service::{
    config::{DialProtocol, ProtocolHandle, ProtocolMeta, TargetSession},
    control::ServiceControl,
    event::{ProtocolEvent, ServiceError, ServiceEvent},
};
use bytes::Bytes;

/// If the buffer capacity is greater than u8 max, shrink it
pub(crate) const BUF_SHRINK_THRESHOLD: usize = u8::max_value() as usize;
/// Received from remote, aggregate mode, buffer size is 8 times that of any send
pub(crate) const RECEIVED_SIZE: usize = 256;
/// Send to remote, distribute mode, buffer size is less than 8 times the received
pub(crate) const SEND_SIZE: usize = 32;
pub(crate) const DELAY_TIME: Duration = Duration::from_millis(300);

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

    sessions: HashMap<SessionId, SessionControl>,

    multi_transport: MultiTransport,

    listens: Vec<(Multiaddr, MultiIncoming)>,

    dial_protocols: HashMap<Multiaddr, DialProtocol>,
    config: ServiceConfig,
    /// service state
    state: State,

    next_session: SessionId,

    /// Can be upgrade to list service level protocols
    handle: T,
    /// The buffer will be prioritized for distribution to session
    high_write_buf: VecDeque<(SessionId, SessionEvent)>,
    /// The buffer which will distribute to sessions
    write_buf: VecDeque<(SessionId, SessionEvent)>,
    /// The buffer which will distribute to service protocol handle
    read_service_buf: VecDeque<(ProtocolId, ServiceProtocolEvent)>,
    /// The buffer which will distribute to session protocol handle
    read_session_buf: VecDeque<(SessionId, ProtocolId, SessionProtocolEvent)>,

    // Future task manager
    future_task_manager: Option<FutureTaskManager>,
    // To add a future task
    // TODO: use this to spawn every task
    future_task_sender: mpsc::Sender<BoxedFutureTask>,

    service_notify_signals: HashMap<ProtocolId, HashMap<u64, oneshot::Sender<()>>>,

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
    service_task_receiver: mpsc::UnboundedReceiver<ServiceTask>,
    quick_task_receiver: mpsc::UnboundedReceiver<ServiceTask>,

    pending_tasks: VecDeque<ServiceTask>,
    /// When handle channel full, set a deadline(30 second) to notify user
    handles_error_count: HashMap<(ProtocolId, Option<SessionId>), Option<Delay>>,
    /// Delay notify with abnormally poor machines
    delay: Option<Delay>,
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
        let (session_event_sender, session_event_receiver) = mpsc::channel(RECEIVED_SIZE);
        let (service_task_sender, service_task_receiver) = mpsc::unbounded();
        let (quick_task_sender, quick_task_receiver) = mpsc::unbounded();
        let proto_infos = protocol_configs
            .values()
            .map(|meta| {
                let proto_info = ProtocolInfo::new(&meta.name(), meta.support_versions());
                (meta.id(), proto_info)
            })
            .collect();
        let (future_task_sender, future_task_receiver) = mpsc::channel(SEND_SIZE);

        Service {
            protocol_configs,
            handle,
            multi_transport: MultiTransport::new(config.timeout),
            future_task_sender,
            future_task_manager: Some(FutureTaskManager::new(future_task_receiver)),
            service_notify_signals: HashMap::default(),
            sessions: HashMap::default(),
            session_service_protos: HashMap::default(),
            service_proto_handles: HashMap::default(),
            session_proto_handles: HashMap::default(),
            listens: Vec::new(),
            dial_protocols: HashMap::default(),
            config,
            state: State::new(forever),
            next_session: SessionId::default(),
            high_write_buf: VecDeque::default(),
            write_buf: VecDeque::default(),
            read_service_buf: VecDeque::default(),
            read_session_buf: VecDeque::default(),
            session_event_sender,
            session_event_receiver,
            service_context: ServiceContext::new(
                service_task_sender,
                quick_task_sender,
                proto_infos,
                key_pair,
            ),
            service_task_receiver,
            quick_task_receiver,
            pending_tasks: VecDeque::default(),
            handles_error_count: HashMap::default(),
            delay: None,
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
        let (listen_future, listen_addr) = self
            .multi_transport
            .listen(address.clone())
            .map_err::<io::Error, _>(Into::into)?;
        let sender = self.session_event_sender.clone();
        let task = listen_future.then(move |result| match result {
            Ok(value) => tokio::spawn(
                sender
                    .send(SessionEvent::ListenStart {
                        listen_address: value.0,
                        incoming: value.1,
                    })
                    .map(|_| ())
                    .map_err(|err| {
                        error!("Listen address success send back error: {:?}", err);
                    }),
            ),
            Err(err) => {
                let event = if let TransportError::DNSResolverError((address, error)) = err {
                    SessionEvent::ListenError {
                        address,
                        error: Error::DNSResolverError(error),
                    }
                } else {
                    SessionEvent::ListenError {
                        address,
                        error: Error::DNSResolverError(io::ErrorKind::InvalidData.into()),
                    }
                };
                tokio::spawn(sender.send(event).map(|_| ()).map_err(|err| {
                    error!("Listen address fail send back error: {:?}", err);
                }))
            }
        });
        self.pending_tasks.push_back(ServiceTask::FutureTask {
            task: Box::new(task),
        });
        self.state.increase();
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
        self.dial_protocols.insert(address.clone(), target);
        let dial_future = self
            .multi_transport
            .dial(address.clone())
            .map_err::<io::Error, _>(Into::into)?;

        let sender = self.session_event_sender.clone();
        let task = dial_future.then(|result| match result {
            Ok(value) => tokio::spawn(
                sender
                    .send(SessionEvent::DialStart {
                        remote_address: value.0,
                        stream: value.1,
                    })
                    .map(|_| ())
                    .map_err(|err| {
                        error!("dial address success send back error: {:?}", err);
                    }),
            ),
            Err(err) => {
                let event = match err {
                    TransportError::DNSResolverError((address, error)) => SessionEvent::DialError {
                        address,
                        error: Error::DNSResolverError(error),
                    },
                    e => SessionEvent::DialError {
                        address,
                        error: Error::IoError(e.into()),
                    },
                };
                tokio::spawn(sender.send(event).map(|_| ()).map_err(|err| {
                    error!("dial address fail send back error: {:?}", err);
                }))
            }
        });

        self.pending_tasks.push_back(ServiceTask::FutureTask {
            task: Box::new(task),
        });
        self.state.increase();
        Ok(())
    }

    /// Get service current protocol configure
    pub fn protocol_configs(&self) -> &HashMap<String, ProtocolMeta> {
        &self.protocol_configs
    }

    /// Get service control, control can send tasks externally to the runtime inside
    pub fn control(&self) -> &ServiceControl {
        self.service_context.control()
    }

    fn push_back(&mut self, priority: Priority, id: SessionId, event: SessionEvent) {
        if priority.is_high() {
            self.high_write_buf.push_back((id, event));
        } else {
            self.write_buf.push_back((id, event));
        }
    }

    #[inline(always)]
    fn distribute_to_session_process<D: Iterator<Item = (SessionId, SessionEvent)>>(
        &mut self,
        data: D,
        priority: Priority,
        block_sessions: &mut HashSet<SessionId>,
    ) {
        for (id, event) in data {
            // Guarantee the order in which messages are sent
            if block_sessions.contains(&id) {
                self.push_back(priority, id, event);
                continue;
            }
            if let Some(session) = self.sessions.get_mut(&id) {
                if let Err(e) = session.event_sender.try_send(event) {
                    if e.is_full() {
                        block_sessions.insert(id);
                        debug!("session [{}] is full", id);
                        self.push_back(priority, id, e.into_inner());
                        self.set_delay();
                    } else {
                        error!("channel shutdown, message can't send")
                    }
                }
            } else {
                debug!("Can't find session {} to send data", id);
            }
        }
    }

    /// Distribute event to sessions
    #[inline]
    fn distribute_to_session(&mut self) {
        let mut block_sessions = HashSet::new();

        let high = self.high_write_buf.split_off(0).into_iter();
        self.distribute_to_session_process(high, Priority::High, &mut block_sessions);

        if self.sessions.len() > block_sessions.len() {
            let normal = self.write_buf.split_off(0).into_iter();
            self.distribute_to_session_process(normal, Priority::Normal, &mut block_sessions);
        }

        if self.write_buf.capacity() > BUF_SHRINK_THRESHOLD {
            self.write_buf.shrink_to_fit();
        }

        if self.high_write_buf.capacity() > BUF_SHRINK_THRESHOLD {
            self.high_write_buf.shrink_to_fit();
        }
    }

    /// Distribute event to user level
    #[inline(always)]
    fn distribute_to_user_level(&mut self) {
        let mut error = false;
        let mut block_handles = HashSet::new();

        for (proto_id, event) in self.read_service_buf.split_off(0) {
            // Guarantee the order in which messages are sent
            if block_handles.contains(&proto_id) {
                self.read_service_buf.push_back((proto_id, event));
                continue;
            }
            if let Some(sender) = self.service_proto_handles.get_mut(&proto_id) {
                if let Err(e) = sender.try_send(event) {
                    if e.is_full() {
                        debug!("service proto [{}] handle is full", proto_id);
                        self.read_service_buf.push_back((proto_id, e.into_inner()));
                        self.proto_handle_error(proto_id, None);
                        block_handles.insert(proto_id);
                    } else {
                        error!(
                            "channel shutdown, proto [{}] message can't send to user",
                            proto_id
                        );

                        error = true;
                        self.handle.handle_error(
                            &mut self.service_context,
                            ServiceError::ProtocolHandleError {
                                proto_id,
                                error: Error::ServiceProtoHandleAbnormallyClosed,
                            },
                        );
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
                        self.proto_handle_error(proto_id, Some(session_id));
                    } else {
                        error!(
                            "channel shutdown, proto [{}] session [{}] message can't send to user",
                            proto_id, session_id
                        );

                        error = true;
                        self.handle.handle_error(
                            &mut self.service_context,
                            ServiceError::ProtocolHandleError {
                                proto_id,
                                error: Error::SessionProtoHandleAbnormallyClosed(session_id),
                            },
                        )
                    }
                }
            }
        }

        if error {
            // if handle panic, close service
            self.handle_service_task(ServiceTask::Shutdown(false));
        }

        if self.read_service_buf.capacity() > BUF_SHRINK_THRESHOLD {
            self.read_service_buf.shrink_to_fit();
        }

        if self.read_session_buf.capacity() > BUF_SHRINK_THRESHOLD {
            self.read_session_buf.shrink_to_fit();
        }
    }

    /// When proto handle channel is full, call here
    #[inline]
    fn proto_handle_error(&mut self, proto_id: ProtocolId, session_id: Option<SessionId>) {
        let delay_time = Instant::now() + Duration::from_secs(30);

        let delay = self
            .handles_error_count
            .entry((proto_id, session_id))
            .or_insert_with(|| Some(Delay::new(delay_time)));

        match delay.take() {
            Some(mut inner) => match inner.poll() {
                Ok(Async::Ready(_)) => {
                    let error = session_id
                        .map(Error::SessionProtoHandleBlock)
                        .unwrap_or(Error::ServiceProtoHandleBlock);
                    self.set_delay();
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::ProtocolHandleError { proto_id, error },
                    );
                }
                Ok(Async::NotReady) => *delay = Some(inner),
                Err(_) => {
                    *delay = Some(Delay::new(delay_time));
                }
            },
            None => {
                *delay = Some(Delay::new(delay_time));
            }
        }
    }

    /// Spawn protocol handle
    #[inline]
    fn handle_open(
        &mut self,
        handle: InnerProtocolHandle,
        proto_id: ProtocolId,
        id: Option<SessionId>,
    ) {
        match handle {
            InnerProtocolHandle::Service(handle) => {
                debug!("init service level [{}] proto handle", proto_id);
                let (sender, receiver) = mpsc::channel(RECEIVED_SIZE);
                let mut stream = ServiceProtocolStream::new(
                    handle,
                    self.service_context.clone_self(),
                    receiver,
                    proto_id,
                );

                self.service_proto_handles
                    .entry(proto_id)
                    .and_modify(|old| *old = sender.clone())
                    .or_insert(sender);

                stream.handle_event(ServiceProtocolEvent::Init);

                tokio::spawn(stream.for_each(|_| Ok(())).map_err(|_| ()));
            }

            InnerProtocolHandle::Session(handle) => {
                let id = id.unwrap();
                if let Some(session_control) = self.sessions.get(&id) {
                    debug!("init session [{}] level proto [{}] handle", id, proto_id);
                    let (sender, receiver) = mpsc::channel(32);
                    let stream = SessionProtocolStream::new(
                        handle,
                        self.service_context.clone_self(),
                        Arc::clone(&session_control.inner),
                        receiver,
                        proto_id,
                    );

                    tokio::spawn(stream.for_each(|_| Ok(())).map_err(|_| ()));

                    self.session_proto_handles
                        .entry((id, proto_id))
                        .and_modify(|old| *old = sender.clone())
                        .or_insert(sender);
                }
            }
        }
    }

    /// Send data to the specified protocol for the specified session.
    #[inline]
    fn send_message_to(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        priority: Priority,
        data: Bytes,
    ) {
        let message_event = SessionEvent::ProtocolMessage {
            id: session_id,
            proto_id,
            priority,
            data,
        };
        self.push_back(priority, session_id, message_event);

        self.distribute_to_session();
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    fn filter_broadcast(
        &mut self,
        ids: Vec<SessionId>,
        proto_id: ProtocolId,
        priority: Priority,
        data: Bytes,
    ) {
        for id in self.sessions.keys().cloned().collect::<Vec<SessionId>>() {
            if ids.contains(&id) {
                debug!(
                    "send message to session [{}], proto [{}], data len: {}",
                    id,
                    proto_id,
                    data.len()
                );

                let message_event = SessionEvent::ProtocolMessage {
                    id,
                    proto_id,
                    priority,
                    data: data.clone(),
                };
                self.push_back(priority, id, message_event);
            }
        }
        self.distribute_to_session();
    }

    /// Broadcast data for a specified protocol.
    #[inline]
    fn broadcast(&mut self, proto_id: ProtocolId, priority: Priority, data: Bytes) {
        debug!(
            "broadcast message, peer count: {}, proto_id: {}, data len: {}",
            self.sessions.len(),
            proto_id,
            data.len()
        );
        for id in self.sessions.keys().cloned().collect::<Vec<SessionId>>() {
            let message_event = SessionEvent::ProtocolMessage {
                id,
                proto_id,
                priority,
                data: data.clone(),
            };
            self.push_back(priority, id, message_event);
        }
        self.distribute_to_session();
    }

    /// Get the callback handle of the specified protocol
    #[inline]
    fn proto_handle(&mut self, session: bool, proto_id: ProtocolId) -> Option<InnerProtocolHandle> {
        let handle = self.protocol_configs.values_mut().find_map(|proto| {
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
        if ty.is_outbound() {
            self.state.decrease();
        }
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
                .find(|&context| context.inner.remote_pubkey.as_ref() == Some(key))
            {
                Some(context) => {
                    trace!("Connected to the connected node");
                    let _ = handle.shutdown();
                    if ty.is_outbound() {
                        self.handle.handle_error(
                            &mut self.service_context,
                            ServiceError::DialerError {
                                error: Error::RepeatedConnection(context.inner.id),
                                address,
                            },
                        );
                    } else {
                        self.handle.handle_error(
                            &mut self.service_context,
                            ServiceError::ListenError {
                                error: Error::RepeatedConnection(context.inner.id),
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
                        address.push(Protocol::P2p(
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

        let (service_event_sender, service_event_receiver) = mpsc::channel(SEND_SIZE);
        let session_control = SessionControl {
            notify_signals: HashMap::default(),
            event_sender: service_event_sender,
            inner: Arc::new(SessionContext {
                id: self.next_session,
                address,
                ty,
                remote_pubkey,
            }),
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

        if ty.is_outbound() {
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
                session_context: Arc::clone(&session_control.inner),
            },
        );

        self.sessions
            .insert(session_control.inner.id, session_control);
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

        if let Some(session_control) = self.sessions.remove(&id) {
            // Service handle processing flow
            self.handle.handle_event(
                &mut self.service_context,
                ServiceEvent::SessionClose {
                    session_context: session_control.inner,
                },
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

        // Regardless of the existence of the session level handle,
        // you **must record** which protocols are opened for each session.
        self.session_service_protos
            .entry(id)
            .or_default()
            .insert(proto_id);

        if self.config.event.contains(&proto_id) {
            if let Some(session_control) = self.sessions.get(&id) {
                // event output
                self.handle.handle_proto(
                    &mut self.service_context,
                    ProtocolEvent::Connected {
                        session_context: Arc::clone(&session_control.inner),
                        proto_id,
                        version: version.clone(),
                    },
                );
            }
        }

        // callback output
        // Service proto handle processing flow
        if !self.service_proto_handles.contains_key(&proto_id) {
            if let Some(handle) = self.proto_handle(false, proto_id) {
                self.handle_open(handle, proto_id, None)
            }
        }

        if self.service_proto_handles.contains_key(&proto_id) {
            if let Some(session_control) = self.sessions.get(&id) {
                self.read_service_buf.push_back((
                    proto_id,
                    ServiceProtocolEvent::Connected {
                        session: Arc::clone(&session_control.inner),
                        version: version.clone(),
                    },
                ));
            }
        }

        // Session proto handle processing flow
        if let Some(handle) = self.proto_handle(true, proto_id) {
            self.handle_open(handle, proto_id, Some(id));

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
            if let Some(session_control) = self.sessions.get(&session_id) {
                // event output
                self.handle.handle_proto(
                    &mut self.service_context,
                    ProtocolEvent::Received {
                        session_context: Arc::clone(&session_control.inner),
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
            if let Some(session_control) = self.sessions.get(&session_id) {
                self.handle.handle_proto(
                    &mut self.service_context,
                    ProtocolEvent::Disconnected {
                        proto_id,
                        session_context: Arc::clone(&session_control.inner),
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

        // remove handle error count
        self.handles_error_count
            .remove(&(proto_id, Some(session_id)));
    }

    #[inline(always)]
    fn send_pending_task(&mut self) {
        while let Some(task) = self.pending_tasks.pop_front() {
            self.handle_service_task(task);
        }
    }

    #[inline]
    fn send_future_task(&mut self, task: BoxedFutureTask) {
        if let Err(err) = self.future_task_sender.try_send(task) {
            if err.is_full() {
                let task = ServiceTask::FutureTask {
                    task: err.into_inner(),
                };
                self.pending_tasks.push_back(task);
            }
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
            }
            SessionEvent::HandshakeFail { ty, error, address } => {
                if ty.is_outbound() {
                    self.state.decrease();
                    self.dial_protocols.remove(&address);
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::DialerError { address, error },
                    )
                }
            }
            SessionEvent::ProtocolMessage {
                id, proto_id, data, ..
            } => self.protocol_message(id, proto_id, data),
            SessionEvent::ProtocolOpen {
                id,
                proto_id,
                version,
            } => self.protocol_open(id, proto_id, version, Source::Internal),
            SessionEvent::ProtocolClose { id, proto_id } => {
                self.protocol_close(id, proto_id, Source::Internal)
            }
            SessionEvent::ProtocolSelectError { id, proto_name } => {
                if let Some(session_control) = self.sessions.get(&id) {
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::ProtocolSelectError {
                            proto_name,
                            session_context: Arc::clone(&session_control.inner),
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
            SessionEvent::DialError { address, error } => {
                self.state.decrease();
                self.dial_protocols.remove(&address);
                self.handle.handle_error(
                    &mut self.service_context,
                    ServiceError::DialerError { address, error },
                )
            }
            SessionEvent::ListenError { address, error } => {
                self.state.decrease();
                self.handle.handle_error(
                    &mut self.service_context,
                    ServiceError::ListenError { address, error },
                )
            }
            SessionEvent::SessionTimeout { id } => {
                if let Some(session_control) = self.sessions.get(&id) {
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::SessionTimeout {
                            session_context: Arc::clone(&session_control.inner),
                        },
                    )
                }
            }
            SessionEvent::MuxerError { id, error } => {
                if let Some(session_control) = self.sessions.get(&id) {
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::MuxerError {
                            session_context: Arc::clone(&session_control.inner),
                            error,
                        },
                    )
                }
            }
            SessionEvent::ListenStart {
                listen_address,
                incoming,
            } => {
                self.handle.handle_event(
                    &mut self.service_context,
                    ServiceEvent::ListenStarted {
                        address: listen_address.clone(),
                    },
                );
                self.listens.push((listen_address, incoming));
                self.state.decrease();
                self.update_listens();
                self.listen_poll();
            }
            SessionEvent::DialStart {
                remote_address,
                stream,
            } => self.handshake(stream, SessionType::Outbound, remote_address),
        }
    }

    /// Handling various tasks sent externally
    fn handle_service_task(&mut self, event: ServiceTask) {
        match event {
            ServiceTask::ProtocolMessage {
                target,
                proto_id,
                priority,
                data,
            } => match target {
                TargetSession::Single(id) => self.send_message_to(id, proto_id, priority, data),
                TargetSession::Multi(ids) => self.filter_broadcast(ids, proto_id, priority, data),
                TargetSession::All => self.broadcast(proto_id, priority, data),
            },
            ServiceTask::Dial { address, target } => {
                if !self.dial_protocols.contains_key(&address) {
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
                self.send_future_task(task);
            }
            ServiceTask::SetProtocolNotify {
                proto_id,
                interval,
                token,
            } => {
                // TODO: if not contains should call handle_error let user know
                if self.service_proto_handles.contains_key(&proto_id)
                    || self.config.event.contains(&proto_id)
                {
                    let (signal_sender, mut signal_receiver) = oneshot::channel::<()>();
                    let interval_sender =
                        self.service_context.control().service_task_sender.clone();
                    let fut = Interval::new(Instant::now(), interval)
                        .for_each(move |_| {
                            if signal_receiver.poll() == Ok(Async::NotReady) {
                                interval_sender
                                    .unbounded_send(ServiceTask::ProtocolNotify { proto_id, token })
                                    .map_err(|err| {
                                        debug!("interval error: {:?}", err);
                                        timer::Error::shutdown()
                                    })
                            } else {
                                Err(timer::Error::shutdown())
                            }
                        })
                        .map_err(|err| debug!("notify close by: {}", err));

                    // If set more than once, the older task will stop when sender dropped
                    self.service_notify_signals
                        .entry(proto_id)
                        .or_default()
                        .insert(token, signal_sender);
                    self.send_future_task(Box::new(fut));
                }
            }
            ServiceTask::RemoveProtocolNotify { proto_id, token } => {
                if let Some(signals) = self.service_notify_signals.get_mut(&proto_id) {
                    signals
                        .remove(&token)
                        .and_then(|signal| signal.send(()).ok());
                    if signals.is_empty() {
                        self.service_notify_signals.remove(&proto_id);
                    }
                }
            }
            ServiceTask::SetProtocolSessionNotify {
                session_id,
                proto_id,
                interval,
                token,
            } => {
                // TODO: if not contains should call handle_error let user know
                if self
                    .session_proto_handles
                    .contains_key(&(session_id, proto_id))
                    || self.config.event.contains(&proto_id)
                {
                    let (signal_sender, mut signal_receiver) = oneshot::channel::<()>();
                    let interval_sender =
                        self.service_context.control().service_task_sender.clone();
                    let fut = Interval::new(Instant::now(), interval)
                        .for_each(move |_| {
                            if signal_receiver.poll() == Ok(Async::NotReady) {
                                interval_sender
                                    .unbounded_send(ServiceTask::ProtocolSessionNotify {
                                        session_id,
                                        proto_id,
                                        token,
                                    })
                                    .map_err(|err| {
                                        debug!("interval error: {:?}", err);
                                        timer::Error::shutdown()
                                    })
                            } else {
                                Err(timer::Error::shutdown())
                            }
                        })
                        .map_err(|err| debug!("session notify close by: {}", err));

                    // If set more than once, the older task will stop when sender dropped
                    if let Some(session) = self.sessions.get_mut(&session_id) {
                        session
                            .notify_signals
                            .entry(proto_id)
                            .or_default()
                            .insert(token, signal_sender);
                    }
                    self.send_future_task(Box::new(fut));
                }
            }
            ServiceTask::RemoveProtocolSessionNotify {
                session_id,
                proto_id,
                token,
            } => {
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    if let Some(signals) = session.notify_signals.get_mut(&proto_id) {
                        signals
                            .remove(&token)
                            .and_then(|signal| signal.send(()).ok());
                        if signals.is_empty() {
                            session.notify_signals.remove(&proto_id);
                        }
                    }
                }
            }
            ServiceTask::ProtocolNotify { proto_id, token } => {
                if self.config.event.contains(&proto_id) {
                    // event output
                    self.handle.handle_proto(
                        &mut self.service_context,
                        ProtocolEvent::ProtocolNotify { proto_id, token },
                    )
                }
                if self.service_proto_handles.contains_key(&proto_id) {
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
                        if let Some(session_control) = self.sessions.get(&session_id) {
                            // event output
                            self.handle.handle_proto(
                                &mut self.service_context,
                                ProtocolEvent::ProtocolSessionNotify {
                                    proto_id,
                                    session_context: Arc::clone(&session_control.inner),
                                    token,
                                },
                            )
                        }
                    }

                    if self
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
            ServiceTask::Shutdown(quick) => {
                self.state.pre_shutdown();

                while let Some((address, incoming)) = self.listens.pop() {
                    drop(incoming);
                    self.handle.handle_event(
                        &mut self.service_context,
                        ServiceEvent::ListenClose { address },
                    )
                }
                self.pending_tasks.clear();

                let sessions = self.sessions.keys().cloned().collect::<Vec<SessionId>>();

                if quick {
                    // clean buffer
                    self.write_buf.clear();
                    self.read_session_buf.clear();
                    self.read_service_buf.clear();

                    // don't care about any session action
                    sessions
                        .into_iter()
                        .for_each(|i| self.session_close(i, Source::Internal));
                } else {
                    sessions
                        .into_iter()
                        .for_each(|i| self.session_close(i, Source::External));
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
                Ok(Async::Ready(Some((remote_address, socket)))) => {
                    self.handshake(socket, SessionType::Inbound, remote_address);
                    self.listens.push((address, listen));
                }
                Ok(Async::Ready(None)) => {
                    update = true;
                    self.handle.handle_event(
                        &mut self.service_context,
                        ServiceEvent::ListenClose { address },
                    );
                }
                Ok(Async::NotReady) => {
                    self.listens.push((address, listen));
                }
                Err(err) => {
                    update = true;
                    self.handle.handle_error(
                        &mut self.service_context,
                        ServiceError::ListenError {
                            address: address.clone(),
                            error: err.into(),
                        },
                    );
                    self.handle.handle_event(
                        &mut self.service_context,
                        ServiceEvent::ListenClose { address },
                    );
                }
            }
        }

        if update || self.service_context.listens().is_empty() {
            self.update_listens()
        }
    }

    #[inline]
    fn user_task_poll(&mut self) {
        for _ in 0..256 {
            let task = match self.quick_task_receiver.poll() {
                Ok(Async::Ready(Some(task))) => Some(task),
                Ok(Async::Ready(None)) => None,
                Ok(Async::NotReady) => None,
                Err(_) => None,
            }
            .or_else(|| match self.service_task_receiver.poll() {
                Ok(Async::Ready(Some(task))) => Some(task),
                Ok(Async::Ready(None)) => None,
                Ok(Async::NotReady) => None,
                Err(_) => None,
            });

            match task {
                Some(task) => self.handle_service_task(task),
                None => break,
            }
        }
    }

    #[inline]
    fn set_delay(&mut self) {
        // Why use `delay` instead of `notify`?
        //
        // In fact, on machines that can use multi-core normally, there is almost no problem with the `notify` behavior,
        // and even the efficiency will be higher.
        //
        // However, if you are on a single-core bully machine, `notify` may have a very amazing starvation behavior.
        //
        // Under a single-core machine, `notify` may fall into the loop of infinitely preemptive CPU, causing starvation.
        if self.delay.is_none() {
            self.delay = Some(Delay::new(Instant::now() + DELAY_TIME));
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
            && self.state.is_shutdown()
            && self.sessions.is_empty()
            && self.pending_tasks.is_empty()
        {
            return Ok(Async::Ready(None));
        }

        if let Some(stream) = self.future_task_manager.take() {
            tokio::spawn(stream.for_each(|_| Ok(())));
        }

        if !self.write_buf.is_empty()
            || !self.high_write_buf.is_empty()
            || !self.read_service_buf.is_empty()
            || !self.read_session_buf.is_empty()
        {
            self.distribute_to_session();
            self.distribute_to_user_level();
        }

        if let Some(mut inner) = self.delay.take() {
            match inner.poll() {
                Ok(Async::Ready(_)) => {}
                Ok(Async::NotReady) => self.delay = Some(inner),
                Err(_) => {
                    self.delay = Some(Delay::new(Instant::now() + DELAY_TIME));
                }
            }
        }

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

        // receive user task
        self.user_task_poll();

        // process any task buffer
        self.send_pending_task();

        // Double check service state
        if self.listens.is_empty()
            && self.state.is_shutdown()
            && self.sessions.is_empty()
            && self.pending_tasks.is_empty()
        {
            return Ok(Async::Ready(None));
        }
        debug!(
            "listens count: {}, state: {:?}, sessions count: {}, pending task: {}",
            self.listens.len(),
            self.state,
            self.sessions.len(),
            self.pending_tasks.len(),
        );

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

/// Indicates the session type
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SessionType {
    /// Representing yourself as the active party means that you are the client side
    Outbound,
    /// Representing yourself as a passive recipient means that you are the server side
    Inbound,
}

impl SessionType {
    /// is outbound
    #[inline]
    pub fn is_outbound(self) -> bool {
        match self {
            SessionType::Outbound => true,
            SessionType::Inbound => false,
        }
    }

    /// is inbound
    #[inline]
    pub fn is_inbound(self) -> bool {
        !self.is_outbound()
    }
}

impl From<YamuxType> for SessionType {
    #[inline]
    fn from(ty: YamuxType) -> Self {
        match ty {
            YamuxType::Client => SessionType::Outbound,
            YamuxType::Server => SessionType::Inbound,
        }
    }
}

impl Into<YamuxType> for SessionType {
    #[inline]
    fn into(self) -> YamuxType {
        match self {
            SessionType::Outbound => YamuxType::Client,
            SessionType::Inbound => YamuxType::Server,
        }
    }
}
