use futures::{channel::mpsc, future::poll_fn, prelude::*, stream::StreamExt, SinkExt};
use log::{debug, error, trace};
use nohash_hasher::IntMap;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[cfg(not(target_arch = "wasm32"))]
use crate::service::helper::Listener;
use crate::{
    buffer::Buffer,
    channel::{mpsc as priority_mpsc, mpsc::Priority},
    context::{ServiceContext, SessionContext, SessionController},
    error::{DialerErrorKind, ListenErrorKind, ProtocolHandleErrorKind, TransportErrorKind},
    multiaddr::{Multiaddr, Protocol},
    protocol_handle_stream::{
        ServiceProtocolEvent, ServiceProtocolStream, SessionProtocolEvent, SessionProtocolStream,
    },
    protocol_select::ProtocolInfo,
    secio::{PublicKey, SecioKeyPair},
    service::{
        config::{ServiceConfig, State},
        event::{ServiceEventAndError, ServiceTask},
        future_task::{BoxedFutureTask, FutureTaskManager},
        helper::{HandshakeContext, Source},
    },
    session::{Session, SessionEvent, SessionMeta},
    traits::ServiceHandle,
    transports::{MultiIncoming, MultiTransport, Transport},
    utils::extract_peer_id,
    yamux::Config as YamuxConfig,
    ProtocolId, SessionId,
};

pub(crate) mod config;
mod control;
pub(crate) mod event;
pub(crate) mod future_task;
mod helper;

pub use crate::service::{
    config::{ProtocolHandle, ProtocolMeta, TargetProtocol, TargetSession, TcpSocket},
    control::{ServiceAsyncControl, ServiceControl},
    event::{ServiceError, ServiceEvent},
    helper::SessionType,
};
use bytes::Bytes;

#[cfg(feature = "tls")]
pub use crate::service::config::TlsConfig;

type Result<T> = std::result::Result<T, TransportErrorKind>;

struct InnerService {
    protocol_configs: IntMap<ProtocolId, ProtocolMeta>,

    sessions: IntMap<SessionId, SessionController>,

    multi_transport: MultiTransport,

    listens: HashSet<Multiaddr>,

    #[cfg(all(not(target_arch = "wasm32"), feature = "upnp"))]
    igd_client: Option<crate::upnp::IgdClient>,

    dial_protocols: HashMap<Multiaddr, TargetProtocol>,
    config: ServiceConfig,
    /// service state
    state: State,

    next_session: SessionId,

    before_sends: IntMap<ProtocolId, Box<dyn Fn(bytes::Bytes) -> bytes::Bytes + Send + 'static>>,

    handle_sender: mpsc::Sender<ServiceEventAndError>,

    future_task_sender: mpsc::Sender<BoxedFutureTask>,

    service_proto_handles: IntMap<ProtocolId, mpsc::Sender<ServiceProtocolEvent>>,

    session_proto_handles: HashMap<(SessionId, ProtocolId), mpsc::Sender<SessionProtocolEvent>>,

    /// Send events to service, clone to session
    session_event_sender: mpsc::Sender<SessionEvent>,
    /// Receive event from service
    session_event_receiver: mpsc::Receiver<SessionEvent>,

    /// External event is passed in from this
    service_context: ServiceContext,
    /// External event receiver
    service_task_receiver: priority_mpsc::Receiver<ServiceTask>,

    shutdown: Arc<AtomicBool>,

    wait_handle: Vec<(
        Option<futures::channel::oneshot::Sender<()>>,
        crate::runtime::JoinHandle<()>,
    )>,
}

/// An abstraction of p2p service, currently only supports TCP/websocket protocol
pub struct Service<T> {
    /// Can be upgrade to list service level protocols
    handle: T,
    service_context: ServiceContext,
    recv: mpsc::Receiver<ServiceEventAndError>,

    // Future task manager
    future_task_manager: Option<FutureTaskManager>,

    inner_service: Option<InnerService>,
}

impl<T> Service<T>
where
    T: ServiceHandle + Unpin,
{
    /// New a Service
    pub(crate) fn new(
        protocol_configs: IntMap<ProtocolId, ProtocolMeta>,
        handle: T,
        key_pair: Option<SecioKeyPair>,
        forever: bool,
        config: ServiceConfig,
    ) -> Self {
        let (session_event_sender, session_event_receiver) =
            mpsc::channel(config.session_config.channel_size);
        let (task_sender, task_receiver) =
            priority_mpsc::channel(config.session_config.channel_size);
        let proto_infos = protocol_configs
            .values()
            .map(|meta| {
                let proto_info = ProtocolInfo::new(&meta.name(), meta.support_versions());
                (meta.id(), proto_info)
            })
            .collect();
        let (future_task_sender, future_task_receiver) =
            mpsc::channel(config.session_config.channel_size);
        let (user_handle_sender, user_handle_receiver) =
            mpsc::channel(config.session_config.channel_size);
        let shutdown = Arc::new(AtomicBool::new(false));
        #[cfg(all(not(target_arch = "wasm32"), feature = "upnp"))]
        let igd_client = if config.upnp {
            crate::upnp::IgdClient::new()
        } else {
            None
        };

        let service_context =
            ServiceContext::new(task_sender, proto_infos, key_pair, shutdown.clone());

        Service {
            handle,
            service_context: service_context.clone_self(),
            recv: user_handle_receiver,

            future_task_manager: Some(FutureTaskManager::new(
                future_task_receiver,
                shutdown.clone(),
            )),

            inner_service: Some(InnerService {
                protocol_configs,
                before_sends: HashMap::default(),
                handle_sender: user_handle_sender,
                future_task_sender,
                multi_transport: {
                    #[cfg(target_arch = "wasm32")]
                    let transport = MultiTransport::new(config.timeout);
                    #[allow(clippy::let_and_return)]
                    #[cfg(not(target_arch = "wasm32"))]
                    let transport = MultiTransport::new(config.timeout, config.tcp_config.clone());
                    #[cfg(feature = "tls")]
                    let transport = transport.tls_config(config.tls_config.clone());
                    transport
                },
                sessions: HashMap::default(),
                service_proto_handles: HashMap::default(),
                session_proto_handles: HashMap::default(),
                listens: HashSet::new(),
                #[cfg(all(not(target_arch = "wasm32"), feature = "upnp"))]
                igd_client,
                dial_protocols: HashMap::default(),
                state: State::new(forever),
                next_session: SessionId::default(),
                session_event_sender,
                session_event_receiver,
                service_context,
                config,
                service_task_receiver: task_receiver,
                shutdown,
                wait_handle: Vec::new(),
            }),
        }
    }

    /// Yamux config for service
    ///
    /// Panic when max_frame_length < yamux_max_window_size
    pub fn yamux_config(mut self, config: YamuxConfig) -> Self {
        assert!(
            self.inner_service.as_ref().unwrap().config.max_frame_length as u32
                >= config.max_stream_window_size
        );
        self.inner_service
            .as_mut()
            .unwrap()
            .config
            .session_config
            .yamux_config = config;
        self
    }

    /// Secio max frame length
    ///
    /// Panic when max_frame_length < yamux_max_window_size
    pub fn max_frame_length(mut self, size: usize) -> Self {
        assert!(
            size as u32
                >= self
                    .inner_service
                    .as_ref()
                    .unwrap()
                    .config
                    .session_config
                    .yamux_config
                    .max_stream_window_size
        );
        self.inner_service.as_mut().unwrap().config.max_frame_length = size;
        self
    }

    /// Listen on the given address.
    ///
    /// Return really listen multiaddr, but if use `/dns4/localhost/tcp/80`,
    /// it will return original value, and create a future task to DNS resolver later.
    pub async fn listen(&mut self, address: Multiaddr) -> Result<Multiaddr> {
        let inner = self.inner_service.as_mut().unwrap();
        let listen_future = inner.multi_transport.clone().listen(address.clone())?;

        #[cfg(target_arch = "wasm32")]
        unreachable!();

        #[cfg(not(target_arch = "wasm32"))]
        match listen_future.await {
            Ok((addr, incoming)) => {
                let listen_address = addr.clone();

                let _ignore = inner
                    .handle_sender
                    .send(ServiceEventAndError::Event(ServiceEvent::ListenStarted {
                        address: listen_address.clone(),
                    }))
                    .await;
                #[cfg(feature = "upnp")]
                if let Some(client) = inner.igd_client.as_mut() {
                    client.register(&listen_address)
                }
                inner.listens.insert(listen_address.clone());

                inner.spawn_listener(incoming, listen_address);

                Ok(addr)
            }
            Err(err) => Err(err),
        }
    }

    /// Dial the given address, doesn't actually make a request, just generate a future
    pub async fn dial(&mut self, address: Multiaddr, target: TargetProtocol) -> Result<&mut Self> {
        let inner = self.inner_service.as_mut().unwrap();
        let dial_future = inner.multi_transport.clone().dial(address.clone())?;

        match dial_future.await {
            Ok((addr, incoming)) => {
                inner.handshake(incoming, SessionType::Outbound, addr, None);
                inner.dial_protocols.insert(address, target);
                inner.state.increase();
                Ok(self)
            }
            Err(err) => Err(err),
        }
    }

    /// Get service control, control can send tasks externally to the runtime inside
    pub fn control(&self) -> &ServiceAsyncControl {
        self.service_context.control()
    }

    /// start service
    pub async fn run(&mut self) {
        let mut inner = self.inner_service.take().unwrap();
        if let Some(stream) = self.future_task_manager.take() {
            let (sender, receiver) = futures::channel::oneshot::channel();
            let handle = crate::runtime::spawn(async move {
                future::select(stream.for_each(|_| future::ready(())), receiver).await;
            });
            inner.wait_handle.push((Some(sender), handle));
            inner.init_proto_handles();
        }

        crate::runtime::spawn(async move { inner.run().await });

        while let Some(s) = self.recv.next().await {
            match s {
                ServiceEventAndError::Event(e) => {
                    self.handle.handle_event(&mut self.service_context, e).await
                }
                ServiceEventAndError::Error(e) => {
                    self.handle.handle_error(&mut self.service_context, e).await
                }
                ServiceEventAndError::Update { listen_addrs } => {
                    self.service_context.update_listens(listen_addrs)
                }
            }
        }
    }
}

impl InnerService {
    #[cfg(not(target_arch = "wasm32"))]
    fn spawn_listener(&mut self, incoming: MultiIncoming, listen_address: Multiaddr) {
        let listener = Listener {
            inner: incoming,
            key_pair: self.service_context.key_pair().cloned(),
            event_sender: self.session_event_sender.clone(),
            max_frame_length: self.config.max_frame_length,
            timeout: self.config.timeout,
            listen_addr: listen_address,
            future_task_sender: self.future_task_sender.clone(),
        };
        let mut sender = self.future_task_sender.clone();
        crate::runtime::spawn(async move {
            let res = sender
                .send(Box::pin(listener.for_each(|_| future::ready(()))))
                .await;
            if res.is_err() {
                trace!("spawn listener fail")
            }
        });
    }

    /// Use by inner
    fn listen_inner(&mut self, address: Multiaddr) -> Result<()> {
        let listen_future = self.multi_transport.clone().listen(address.clone())?;

        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut sender = self.session_event_sender.clone();
            let task = async move {
                let result = listen_future.await;
                let event = match result {
                    Ok((addr, incoming)) => SessionEvent::ListenStart {
                        listen_address: addr,
                        incoming,
                    },
                    Err(error) => SessionEvent::ListenError { address, error },
                };
                if let Err(err) = sender.send(event).await {
                    error!("Listen address result send back error: {:?}", err);
                }
            };
            let mut sender = self.future_task_sender.clone();
            crate::runtime::spawn(async move {
                let _ignore = sender.send(Box::pin(task)).await;
            });

            self.state.increase();
        }

        Ok(())
    }

    /// Use by inner
    #[inline(always)]
    fn dial_inner(&mut self, address: Multiaddr, target: TargetProtocol) -> Result<()> {
        self.dial_protocols.insert(address.clone(), target);
        let dial_future = self.multi_transport.clone().dial(address.clone())?;

        let key_pair = self.service_context.key_pair().cloned();
        let timeout = self.config.timeout;
        let max_frame_length = self.config.max_frame_length;

        let mut sender = self.session_event_sender.clone();
        let task = async move {
            let result = dial_future.await;

            match result {
                Ok((addr, incoming)) => {
                    HandshakeContext {
                        ty: SessionType::Outbound,
                        remote_address: addr,
                        listen_address: None,
                        key_pair,
                        event_sender: sender,
                        max_frame_length,
                        timeout,
                    }
                    .handshake(incoming)
                    .await;
                }
                Err(error) => {
                    if let Err(err) = sender
                        .send(SessionEvent::DialError { address, error })
                        .await
                    {
                        error!("dial address result send back error: {:?}", err);
                    }
                }
            };
        };

        let mut sender = self.future_task_sender.clone();
        crate::runtime::spawn(async move {
            let _ignore = sender.send(Box::pin(task)).await;
        });
        self.state.increase();
        Ok(())
    }

    /// Spawn protocol handle
    #[inline]
    fn session_handles_open(
        &mut self,
        id: SessionId,
    ) -> Vec<(
        Option<futures::channel::oneshot::Sender<()>>,
        crate::runtime::JoinHandle<()>,
    )> {
        let mut handles = Vec::new();
        for (proto_id, meta) in self.protocol_configs.iter_mut() {
            if let ProtocolHandle::Callback(handle) = meta.session_handle() {
                if let Some(session_control) = self.sessions.get(&id) {
                    debug!("init session [{}] level proto [{}] handle", id, proto_id);
                    let (sender, receiver) = mpsc::channel(self.config.session_config.channel_size);
                    self.session_proto_handles.insert((id, *proto_id), sender);

                    let mut stream = SessionProtocolStream::new(
                        handle,
                        self.service_context.clone_self(),
                        Arc::clone(&session_control.inner),
                        receiver,
                        *proto_id,
                        self.session_event_sender.clone(),
                        (self.shutdown.clone(), self.future_task_sender.clone()),
                    );
                    let (sender, receiver) = futures::channel::oneshot::channel();
                    let handle = crate::runtime::spawn(async move {
                        stream.run(receiver).await;
                    });
                    handles.push((Some(sender), handle));
                }
            } else {
                debug!("can't find proto [{}] session handle", proto_id);
            }
        }
        handles
    }

    async fn handle_message(
        &mut self,
        target: TargetSession,
        proto_id: ProtocolId,
        priority: Priority,
        data: Bytes,
    ) {
        let data = match self.before_sends.get(&proto_id) {
            Some(function) => function(data),
            None => data,
        };

        match target {
            // Send data to the specified protocol for the specified session.
            TargetSession::Single(id) => {
                if let Some(control) = self.sessions.get_mut(&id) {
                    control.inner.incr_pending_data_size(data.len());
                    let _ignore = control
                        .send(priority, SessionEvent::ProtocolMessage { proto_id, data })
                        .await;
                }
            }
            TargetSession::Multi(iter) => {
                for id in iter {
                    if let Some(control) = self.sessions.get_mut(&id) {
                        control.inner.incr_pending_data_size(data.len());
                        let _ignore = control
                            .send(
                                priority,
                                SessionEvent::ProtocolMessage {
                                    proto_id,
                                    data: data.clone(),
                                },
                            )
                            .await;
                    }
                }
            }
            // Send data to the specified protocol for the specified sessions.
            TargetSession::Filter(mut filter) => {
                for (id, control) in self.sessions.iter_mut().filter(|(id, _)| filter(id)) {
                    debug!(
                        "send message to session [{}], proto [{}], data len: {}",
                        id,
                        proto_id,
                        data.len()
                    );
                    control.inner.incr_pending_data_size(data.len());
                    let _ignore = control
                        .send(
                            priority,
                            SessionEvent::ProtocolMessage {
                                proto_id,
                                data: data.clone(),
                            },
                        )
                        .await;
                }
            }
            // Broadcast data for a specified protocol.
            TargetSession::All => {
                debug!(
                    "broadcast message, peer count: {}, proto_id: {}, data len: {}",
                    self.sessions.len(),
                    proto_id,
                    data.len()
                );
                for control in self.sessions.values_mut() {
                    control.inner.incr_pending_data_size(data.len());
                    let _ignore = control
                        .send(
                            priority,
                            SessionEvent::ProtocolMessage {
                                proto_id,
                                data: data.clone(),
                            },
                        )
                        .await;
                }
            }
        }
    }

    /// Handshake
    #[inline]
    fn handshake<H>(
        &mut self,
        socket: H,
        ty: SessionType,
        remote_address: Multiaddr,
        listen_address: Option<Multiaddr>,
    ) where
        H: AsyncRead + AsyncWrite + Send + 'static + Unpin,
    {
        let handshake_task = HandshakeContext {
            ty,
            remote_address,
            listen_address,
            key_pair: self.service_context.key_pair().cloned(),
            event_sender: self.session_event_sender.clone(),
            max_frame_length: self.config.max_frame_length,
            timeout: self.config.timeout,
        }
        .handshake(socket);

        let mut future_task_sender = self.future_task_sender.clone();

        crate::runtime::spawn(async move {
            if future_task_sender
                .send(Box::pin(handshake_task))
                .await
                .is_err()
            {
                trace!("handshake send err")
            }
        });
    }

    fn generate_next_session(&mut self) {
        loop {
            self.next_session = self.next_session.wrapping_add(1);
            if !self.sessions.contains_key(&self.next_session) {
                break;
            }
        }
    }

    fn reached_max_connection_limit(&self) -> bool {
        self.sessions
            .len()
            .checked_add(self.state.into_inner().unwrap_or_default())
            .map(|count| self.config.max_connection_number < count)
            .unwrap_or_default()
    }

    /// Session open
    #[inline]
    async fn session_open<H>(
        &mut self,
        mut handle: H,
        remote_pubkey: Option<PublicKey>,
        mut address: Multiaddr,
        ty: SessionType,
        listen_addr: Option<Multiaddr>,
    ) where
        H: AsyncRead + AsyncWrite + Send + 'static + Unpin,
    {
        let target = self
            .dial_protocols
            .remove(&address)
            .unwrap_or(TargetProtocol::All);
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
                    crate::runtime::spawn(async move {
                        let _ignore = handle.shutdown().await;
                    });
                    if ty.is_outbound() {
                        let _ignore = self
                            .handle_sender
                            .send(ServiceEventAndError::Error(ServiceError::DialerError {
                                error: DialerErrorKind::RepeatedConnection(context.inner.id),
                                address,
                            }))
                            .await;
                    } else {
                        let _ignore = self
                            .handle_sender
                            .send(ServiceEventAndError::Error(ServiceError::ListenError {
                                error: ListenErrorKind::RepeatedConnection(context.inner.id),
                                address: listen_addr.expect("listen address must exist"),
                            }))
                            .await;
                    }
                    return;
                }
                None => {
                    // if peer id doesn't match return an error
                    if let Some(peer_id) = extract_peer_id(&address) {
                        if key.peer_id() != peer_id {
                            trace!("Peer id not match");
                            let _ignore = self
                                .handle_sender
                                .send(ServiceEventAndError::Error(ServiceError::DialerError {
                                    error: DialerErrorKind::PeerIdNotMatch,
                                    address,
                                }))
                                .await;
                            return;
                        }
                    } else {
                        address.push(Protocol::P2P(Cow::Owned(key.peer_id().into_bytes())))
                    }
                }
            }
        }

        self.generate_next_session();

        let session_closed = Arc::new(AtomicBool::new(false));
        let pending_data_size = Arc::new(AtomicUsize::new(0));
        let (service_event_sender, service_event_receiver) =
            priority_mpsc::channel(self.config.session_config.channel_size);
        let session_control = SessionController::new(
            service_event_sender.clone(),
            Arc::new(SessionContext::new(
                self.next_session,
                address,
                ty,
                remote_pubkey,
                session_closed,
                pending_data_size,
            )),
        );

        let session_context = session_control.inner.clone();

        // must insert here, otherwise, the session protocol handle cannot be opened
        self.sessions
            .insert(session_control.inner.id, session_control);

        // Open all session protocol handles
        let handles = self.session_handles_open(self.next_session);

        let mut by_name = HashMap::with_capacity(self.protocol_configs.len());
        let mut by_id =
            HashMap::with_capacity_and_hasher(self.protocol_configs.len(), Default::default());
        self.protocol_configs.iter().for_each(|(key, value)| {
            by_name.insert(value.name(), value.inner.clone());
            by_id.insert(*key, value.inner.clone());
        });

        let meta = SessionMeta::new(
            self.config.timeout,
            session_context.clone(),
            service_event_sender,
            self.service_context.control().clone(),
        )
        .protocol_by_name(by_name)
        .protocol_by_id(by_id)
        .config(self.config.session_config)
        .keep_buffer(self.config.keep_buffer)
        .service_proto_senders(
            self.service_proto_handles
                .clone()
                .into_iter()
                .map(|(k, v)| (k, Buffer::new(v)))
                .collect(),
        )
        .session_senders(
            self.session_proto_handles
                .iter()
                .filter_map(|((session_id, key), value)| {
                    if *session_id == self.next_session {
                        Some((*key, Buffer::new(value.clone())))
                    } else {
                        None
                    }
                })
                .collect(),
        )
        .session_proto_handles(handles);

        let mut session = Session::new(
            handle,
            self.session_event_sender.clone(),
            service_event_receiver,
            meta,
            self.future_task_sender.clone(),
        );

        if ty.is_outbound() {
            match target {
                TargetProtocol::All => {
                    self.protocol_configs
                        .values()
                        .for_each(|meta| session.open_proto_stream(&meta.name()));
                }
                TargetProtocol::Single(proto_id) => {
                    if let Some(meta) = self.protocol_configs.get(&proto_id) {
                        session.open_proto_stream(&meta.name());
                    }
                }
                TargetProtocol::Filter(filter) => self
                    .protocol_configs
                    .iter()
                    .filter(|(id, _)| filter(id))
                    .for_each(|(_, meta)| session.open_proto_stream(&meta.name())),
            }
        }

        crate::runtime::spawn(session.for_each(|_| future::ready(())));

        let _ignore = self
            .handle_sender
            .send(ServiceEventAndError::Event(ServiceEvent::SessionOpen {
                session_context,
            }))
            .await;
    }

    /// Close the specified session, clean up the handle
    #[inline]
    async fn session_close(&mut self, id: SessionId, source: Source) {
        if source == Source::External {
            if let Some(control) = self.sessions.get_mut(&id) {
                debug!("try close service session [{}] ", id);
                let _ignore = control
                    .send(Priority::High, SessionEvent::SessionClose { id })
                    .await;
            }
            return;
        }

        debug!("close service session [{}]", id);

        // clean session proto handles sender
        self.session_proto_handles.retain(|key, _| id != key.0);

        if let Some(session_control) = self.sessions.remove(&id) {
            // Service handle processing flow
            let _ignore = self
                .handle_sender
                .send(ServiceEventAndError::Event(ServiceEvent::SessionClose {
                    session_context: session_control.inner,
                }))
                .await;
        }
    }

    /// Open the handle corresponding to the protocol
    #[inline]
    async fn protocol_open(&mut self, id: SessionId, proto_id: ProtocolId) {
        if let Some(control) = self.sessions.get_mut(&id) {
            debug!("try open session [{}] proto [{}]", id, proto_id);
            let _ignore = control
                .send(Priority::High, SessionEvent::ProtocolOpen { proto_id })
                .await;
        }
    }

    /// Protocol stream is closed, clean up data
    #[inline]
    async fn protocol_close(&mut self, session_id: SessionId, proto_id: ProtocolId) {
        if let Some(control) = self.sessions.get_mut(&session_id) {
            debug!("try close session [{}] proto [{}]", session_id, proto_id);
            let _ignore = control
                .send(Priority::High, SessionEvent::ProtocolClose { proto_id })
                .await;
        }
    }

    #[inline]
    fn send_future_task(&mut self, task: BoxedFutureTask) {
        let mut sender = self.future_task_sender.clone();
        crate::runtime::spawn(async move {
            let _ignore = sender.send(task).await;
        });
    }

    fn init_proto_handles(&mut self) {
        for (proto_id, meta) in self.protocol_configs.iter_mut() {
            if let ProtocolHandle::Callback(handle) = meta.service_handle() {
                debug!("init service level [{}] proto handle", proto_id);
                let (sender, receiver) = mpsc::channel(self.config.session_config.channel_size);
                self.service_proto_handles.insert(*proto_id, sender);

                let mut stream = ServiceProtocolStream::new(
                    handle,
                    self.service_context.clone_self(),
                    receiver,
                    *proto_id,
                    self.session_event_sender.clone(),
                    (self.shutdown.clone(), self.future_task_sender.clone()),
                );
                let (sender, receiver) = futures::channel::oneshot::channel();
                let handle = crate::runtime::spawn(async move {
                    stream.handle_event(ServiceProtocolEvent::Init).await;
                    stream.run(receiver).await;
                });
                self.wait_handle.push((Some(sender), handle));
            } else {
                debug!("can't find proto [{}] service handle", proto_id);
            }
            if let Some(function) = meta.before_send.take() {
                self.before_sends.insert(*proto_id, function);
            }
        }
    }

    /// When listen update, call here
    #[cfg(not(target_arch = "wasm32"))]
    #[inline]
    async fn try_update_listens(&mut self) {
        #[cfg(feature = "upnp")]
        if let Some(client) = self.igd_client.as_mut() {
            client.process_only_leases_support()
        }
        if self.listens.len() == self.service_context.listens().len() {
            return;
        }
        let new_listens = self.listens.iter().cloned().collect::<Vec<Multiaddr>>();
        self.service_context.update_listens(new_listens.clone());

        let mut error = false;

        let _ignore = self
            .handle_sender
            .send(ServiceEventAndError::Update {
                listen_addrs: new_listens.clone(),
            })
            .await;

        for (proto_id, sender) in self.service_proto_handles.iter_mut() {
            if sender
                .send(ServiceProtocolEvent::Update {
                    listen_addrs: new_listens.clone(),
                })
                .await
                .is_err()
            {
                let _ignore = self
                    .handle_sender
                    .send(ServiceEventAndError::Error(
                        ServiceError::ProtocolHandleError {
                            proto_id: *proto_id,
                            error: ProtocolHandleErrorKind::AbnormallyClosed(None),
                        },
                    ))
                    .await;
                error = true;
            }
        }

        for ((session_id, proto_id), sender) in self.session_proto_handles.iter_mut() {
            if sender
                .send(SessionProtocolEvent::Update {
                    listen_addrs: new_listens.clone(),
                })
                .await
                .is_err()
            {
                error = true;
                let _ignore = self
                    .handle_sender
                    .send(ServiceEventAndError::Error(
                        ServiceError::ProtocolHandleError {
                            proto_id: *proto_id,
                            error: ProtocolHandleErrorKind::AbnormallyClosed(Some(*session_id)),
                        },
                    ))
                    .await;
            }
        }

        if error {
            // if handle panic, close service
            self.handle_service_task(ServiceTask::Shutdown(false), Priority::High)
                .await;
        }
    }

    /// Handling various events uploaded by the session
    async fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::SessionClose { id } => self.session_close(id, Source::Internal).await,
            SessionEvent::HandshakeSuccess {
                handle,
                public_key,
                address,
                ty,
                listen_address,
            } => {
                if ty.is_outbound() {
                    self.state.decrease();
                }
                if !self.reached_max_connection_limit() {
                    self.session_open(handle, public_key, address, ty, listen_address)
                        .await;
                }
            }
            SessionEvent::HandshakeError { ty, error, address } => {
                if ty.is_outbound() {
                    self.state.decrease();
                    self.dial_protocols.remove(&address);
                    let _ignore = self
                        .handle_sender
                        .send(ServiceEventAndError::Error(ServiceError::DialerError {
                            address,
                            error: DialerErrorKind::HandshakeError(error),
                        }))
                        .await;
                }
            }
            SessionEvent::ProtocolMessage { .. }
            | SessionEvent::ProtocolOpen { .. }
            | SessionEvent::ProtocolClose { .. } => unreachable!(),
            SessionEvent::ProtocolSelectError { id, proto_name } => {
                if let Some(session_control) = self.sessions.get(&id) {
                    let _ignore = self
                        .handle_sender
                        .send(ServiceEventAndError::Error(
                            ServiceError::ProtocolSelectError {
                                proto_name,
                                session_context: Arc::clone(&session_control.inner),
                            },
                        ))
                        .await;
                }
            }
            SessionEvent::ProtocolError {
                id,
                proto_id,
                error,
            } => {
                let _ignore = self
                    .handle_sender
                    .send(ServiceEventAndError::Error(ServiceError::ProtocolError {
                        id,
                        proto_id,
                        error,
                    }))
                    .await;
            }
            SessionEvent::DialError { address, error } => {
                self.state.decrease();
                self.dial_protocols.remove(&address);
                let _ignore = self
                    .handle_sender
                    .send(ServiceEventAndError::Error(ServiceError::DialerError {
                        address,
                        error: DialerErrorKind::TransportError(error),
                    }))
                    .await;
            }
            #[cfg(not(target_arch = "wasm32"))]
            SessionEvent::ListenError { address, error } => {
                let _ignore = self
                    .handle_sender
                    .send(ServiceEventAndError::Error(ServiceError::ListenError {
                        address: address.clone(),
                        error: ListenErrorKind::TransportError(error),
                    }))
                    .await;
                if self.listens.remove(&address) {
                    #[cfg(feature = "upnp")]
                    if let Some(ref mut client) = self.igd_client {
                        client.remove(&address);
                    }

                    let _ignore = self
                        .handle_sender
                        .send(ServiceEventAndError::Event(ServiceEvent::ListenClose {
                            address,
                        }))
                        .await;
                } else {
                    // try start listen error
                    self.state.decrease();
                }
            }
            SessionEvent::SessionTimeout { id } => {
                if let Some(session_control) = self.sessions.get(&id) {
                    let _ignore = self
                        .handle_sender
                        .send(ServiceEventAndError::Error(ServiceError::SessionTimeout {
                            session_context: Arc::clone(&session_control.inner),
                        }))
                        .await;
                }
            }
            SessionEvent::MuxerError { id, error } => {
                if let Some(session_control) = self.sessions.get(&id) {
                    let _ignore = self
                        .handle_sender
                        .send(ServiceEventAndError::Error(ServiceError::MuxerError {
                            session_context: Arc::clone(&session_control.inner),
                            error,
                        }))
                        .await;
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            SessionEvent::ListenStart {
                listen_address,
                incoming,
            } => {
                let _ignore = self
                    .handle_sender
                    .send(ServiceEventAndError::Event(ServiceEvent::ListenStarted {
                        address: listen_address.clone(),
                    }))
                    .await;
                self.listens.insert(listen_address.clone());
                self.state.decrease();
                self.try_update_listens().await;
                #[cfg(feature = "upnp")]
                if let Some(client) = self.igd_client.as_mut() {
                    client.register(&listen_address)
                }
                self.spawn_listener(incoming, listen_address);
            }
            SessionEvent::ProtocolHandleError { error, proto_id } => {
                let _ignore = self
                    .handle_sender
                    .send(ServiceEventAndError::Error(
                        ServiceError::ProtocolHandleError { error, proto_id },
                    ))
                    .await;
                // if handle panic, close service
                self.handle_service_task(ServiceTask::Shutdown(false), Priority::High)
                    .await;
            }
            SessionEvent::ChangeState { id, .. } => {
                if let Some(session) = self.sessions.get(&id) {
                    let _ignore = self
                        .handle_sender
                        .send(ServiceEventAndError::Error(ServiceError::SessionBlocked {
                            session_context: session.inner.clone(),
                        }))
                        .await;
                }
            }
            _ => (),
        }
    }

    /// Handling various tasks sent externally
    #[allow(clippy::needless_collect)]
    async fn handle_service_task(&mut self, event: ServiceTask, priority: Priority) {
        match event {
            ServiceTask::ProtocolMessage {
                target,
                proto_id,
                data,
            } => {
                self.handle_message(target, proto_id, priority, data).await;
            }
            ServiceTask::Dial { address, target } => {
                if !self.dial_protocols.contains_key(&address) {
                    if let Err(e) = self.dial_inner(address.clone(), target) {
                        let _ignore = self
                            .handle_sender
                            .send(ServiceEventAndError::Error(ServiceError::DialerError {
                                address,
                                error: DialerErrorKind::TransportError(e),
                            }))
                            .await;
                    }
                }
            }
            ServiceTask::Listen { address } => {
                if !self.listens.contains(&address) {
                    if let Err(e) = self.listen_inner(address.clone()) {
                        let _ignore = self
                            .handle_sender
                            .send(ServiceEventAndError::Error(ServiceError::ListenError {
                                address,
                                error: ListenErrorKind::TransportError(e),
                            }))
                            .await;
                    }
                }
            }
            ServiceTask::Disconnect { session_id } => {
                self.session_close(session_id, Source::External).await
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
                if let Some(sender) = self.service_proto_handles.get_mut(&proto_id) {
                    let _ignore = sender
                        .send(ServiceProtocolEvent::SetNotify { interval, token })
                        .await;
                }
            }
            ServiceTask::RemoveProtocolNotify { proto_id, token } => {
                if let Some(sender) = self.service_proto_handles.get_mut(&proto_id) {
                    let _ignore = sender
                        .send(ServiceProtocolEvent::RemoveNotify { token })
                        .await;
                }
            }
            ServiceTask::SetProtocolSessionNotify {
                session_id,
                proto_id,
                interval,
                token,
            } => {
                // TODO: if not contains should call handle_error let user know
                if let Some(sender) = self.session_proto_handles.get_mut(&(session_id, proto_id)) {
                    let _ignore = sender
                        .send(SessionProtocolEvent::SetNotify { interval, token })
                        .await;
                }
            }
            ServiceTask::RemoveProtocolSessionNotify {
                session_id,
                proto_id,
                token,
            } => {
                if let Some(sender) = self.session_proto_handles.get_mut(&(session_id, proto_id)) {
                    let _ignore = sender
                        .send(SessionProtocolEvent::RemoveNotify { token })
                        .await;
                }
            }
            ServiceTask::ProtocolOpen { session_id, target } => match target {
                TargetProtocol::All => {
                    // Borrowed check attack
                    #[allow(clippy::needless_collect)]
                    {
                        let ids = self.protocol_configs.keys().copied().collect::<Vec<_>>();
                        for id in ids {
                            self.protocol_open(session_id, id).await
                        }
                    }
                }
                TargetProtocol::Single(id) => self.protocol_open(session_id, id).await,
                TargetProtocol::Filter(filter) => {
                    let ids = self.protocol_configs.keys().copied().collect::<Vec<_>>();
                    for id in ids.into_iter().filter(filter) {
                        self.protocol_open(session_id, id).await
                    }
                }
            },
            ServiceTask::ProtocolClose {
                session_id,
                proto_id,
            } => self.protocol_close(session_id, proto_id).await,
            ServiceTask::Shutdown(quick) => {
                self.state.pre_shutdown();

                let mut events = futures::stream::iter(
                    self.listens
                        .drain()
                        .map(|address| {
                            ServiceEventAndError::Event(ServiceEvent::ListenClose { address })
                        })
                        .collect::<Vec<_>>(),
                )
                .map(Ok);

                let _ignore = self.handle_sender.send_all(&mut events).await;

                // clear upnp register
                #[cfg(all(not(target_arch = "wasm32"), feature = "upnp"))]
                if let Some(client) = self.igd_client.as_mut() {
                    client.clear()
                };

                let sessions = self.sessions.keys().cloned().collect::<Vec<SessionId>>();

                if quick {
                    self.service_task_receiver.close();
                    self.session_event_receiver.close();
                    // clean buffer
                    self.service_proto_handles.clear();
                    self.session_proto_handles.clear();

                    // don't care about any session action
                    for i in sessions {
                        self.session_close(i, Source::Internal).await
                    }
                } else {
                    for i in sessions {
                        self.session_close(i, Source::External).await
                    }
                }
            }
        }
    }

    #[cold]
    async fn wait_handle_poll(&mut self) {
        // close user handle first
        self.handle_sender.close_channel();
        for (sender, handle) in self.wait_handle.split_off(0) {
            if let Some(sender) = sender {
                // don't care about it
                let _ignore = sender.send(());
            }
            let _ignore = handle.await;
        }
    }

    /// start service
    pub async fn run(&mut self) {
        loop {
            if self.listens.is_empty() && self.state.is_shutdown() && self.sessions.is_empty() {
                debug!("shutdown because all state is empty head");
                self.shutdown.store(true, Ordering::SeqCst);
                self.wait_handle_poll().await;
                break;
            }

            poll_fn(crate::runtime::poll_proceed).await;
            #[cfg(not(target_arch = "wasm32"))]
            self.try_update_listens().await;
            tokio::select! {
                Some(event) = self.session_event_receiver.next() => {
                    self.handle_session_event(event).await
                },
                Some((priority, task)) = self.service_task_receiver.next() => {
                    self.handle_service_task(task, priority).await
                }
            }
        }
    }
}
