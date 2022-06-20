use futures::{channel::mpsc, prelude::*, stream::iter, SinkExt};
use log::{debug, error, log_enabled, trace, warn};
use nohash_hasher::IntMap;
use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    pin::Pin,
    sync::{atomic::Ordering, Arc},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, FramedParts, FramedRead, FramedWrite, LengthDelimitedCodec};
use yamux::{Control, Session as YamuxSession, StreamHandle};

use crate::{
    buffer::{Buffer, PriorityBuffer, SendResult},
    channel::{mpsc as priority_mpsc, mpsc::Priority, QuickSinkExt},
    context::SessionContext,
    error::{HandshakeErrorKind, ProtocolHandleErrorKind, TransportErrorKind},
    multiaddr::Multiaddr,
    protocol_handle_stream::{ServiceProtocolEvent, SessionProtocolEvent},
    protocol_select::{client_select, server_select, ProtocolInfo},
    secio::PublicKey,
    service::{
        config::{Meta, SessionConfig},
        future_task::BoxedFutureTask,
        ServiceAsyncControl, SessionType,
    },
    substream::{ProtocolEvent, SubstreamBuilder, SubstreamWritePartBuilder},
    transports::MultiIncoming,
    ProtocolId, SessionId, StreamId, SubstreamReadPart,
};

pub trait AsyncRw: AsyncWrite + AsyncRead {}

impl<T: AsyncRead + AsyncWrite> AsyncRw for T {}

/// Event generated/received by the Session
pub(crate) enum SessionEvent {
    /// Session close event
    SessionClose {
        /// Session id
        id: SessionId,
    },
    ListenStart {
        listen_address: Multiaddr,
        incoming: MultiIncoming,
    },
    HandshakeSuccess {
        /// In order to be compatible with multiple underlying connection abstractions,
        /// the dyn trait needs to be used here
        handle: Box<dyn AsyncRw + Send + Unpin + 'static>,
        /// Remote Public key
        public_key: Option<PublicKey>,
        /// Remote address
        address: Multiaddr,
        /// Session type
        ty: SessionType,
        /// listen addr
        listen_address: Option<Multiaddr>,
    },
    HandshakeError {
        /// remote address
        address: Multiaddr,
        /// Session type
        ty: SessionType,
        /// error
        error: HandshakeErrorKind,
    },
    DialError {
        /// remote address
        address: Multiaddr,
        /// error
        error: TransportErrorKind,
    },
    ListenError {
        /// listen address
        address: Multiaddr,
        /// error
        error: TransportErrorKind,
    },
    /// Protocol data
    ProtocolMessage {
        /// Protocol id
        proto_id: ProtocolId,
        /// Data
        data: bytes::Bytes,
    },
    /// Protocol open event
    ProtocolOpen {
        /// Protocol id
        proto_id: ProtocolId,
    },
    /// Protocol close event
    ProtocolClose {
        /// Protocol id
        proto_id: ProtocolId,
    },
    StreamStart {
        stream: StreamHandle,
    },
    ChangeState {
        id: SessionId,
        state: SessionState,
        error: Option<io::Error>,
    },
    ProtocolSelectError {
        /// Session id
        id: SessionId,
        /// proto_name
        proto_name: Option<String>,
    },
    SessionTimeout {
        /// Session id
        id: SessionId,
    },
    /// Codec error
    ProtocolError {
        /// Session id
        id: SessionId,
        /// Protocol id
        proto_id: ProtocolId,
        /// Codec error
        error: std::io::Error,
    },
    MuxerError {
        id: SessionId,
        error: std::io::Error,
    },
    /// Protocol handle error, will cause memory leaks/abnormal CPU usage
    ProtocolHandleError {
        /// Error message
        error: ProtocolHandleErrorKind,
        /// Protocol id
        proto_id: ProtocolId,
    },
}

/// Wrapper for real data streams, such as TCP stream
pub(crate) struct Session {
    control: Control,

    protocol_configs_by_name: HashMap<String, Arc<Meta>>,
    protocol_configs_by_id: IntMap<ProtocolId, Arc<Meta>>,

    config: SessionConfig,

    timeout: Duration,

    keep_buffer: bool,

    state: SessionState,

    context: Arc<SessionContext>,
    service_control: ServiceAsyncControl,

    next_stream: StreamId,

    /// Sub streams maps a stream id to a sender of sub stream
    substreams: IntMap<StreamId, PriorityBuffer<ProtocolEvent>>,
    proto_streams: IntMap<ProtocolId, StreamId>,

    /// Clone to new sub stream
    proto_event_sender: mpsc::Sender<ProtocolEvent>,
    /// Receive events from sub streams
    proto_event_receiver: mpsc::Receiver<ProtocolEvent>,

    /// Send events to service
    service_sender: Buffer<SessionEvent>,
    /// Receive event from service
    service_receiver: priority_mpsc::Receiver<SessionEvent>,

    service_proto_senders: IntMap<ProtocolId, Buffer<ServiceProtocolEvent>>,
    session_proto_senders: IntMap<ProtocolId, Buffer<SessionProtocolEvent>>,

    future_task_sender: mpsc::Sender<BoxedFutureTask>,
    wait_handle: Vec<(
        Option<futures::channel::oneshot::Sender<()>>,
        crate::runtime::JoinHandle<()>,
    )>,
}

impl Session {
    /// New a session
    pub fn new<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        socket: T,
        service_sender: mpsc::Sender<SessionEvent>,
        service_receiver: priority_mpsc::Receiver<SessionEvent>,
        meta: SessionMeta,
        future_task_sender: mpsc::Sender<BoxedFutureTask>,
    ) -> Self {
        let socket = YamuxSession::new(socket, meta.config.yamux_config, meta.context.ty.into());
        let control = socket.control();
        let (proto_event_sender, proto_event_receiver) = mpsc::channel(meta.config.channel_size);
        let mut interval = proto_event_sender.clone();

        // NOTE: A Interval/Delay will block tokio runtime from gracefully shutdown.
        //       So we spawn it in FutureTaskManager
        let mut future_task_sender_ = future_task_sender.clone();
        let timeout = meta.timeout;
        crate::runtime::spawn(async move {
            crate::runtime::delay_for(timeout).await;
            let task = Box::pin(async move {
                if interval.send(ProtocolEvent::TimeoutCheck).await.is_err() {
                    trace!("timeout check send err")
                }
            });
            if future_task_sender_.send(task).await.is_err() {
                trace!("timeout check task send err")
            }
        });
        // background inner socket
        let sid = meta.context.id;
        crate::runtime::spawn(
            InnerSocket::new(socket, meta.event_sender, sid).for_each(|_| future::ready(())),
        );

        Session {
            control,
            protocol_configs_by_name: meta.protocol_configs_by_name,
            protocol_configs_by_id: meta.protocol_configs_by_id,
            config: meta.config,
            timeout: meta.timeout,
            context: meta.context,
            service_control: meta.service_control,
            keep_buffer: meta.keep_buffer,
            next_stream: 0,
            substreams: HashMap::default(),
            proto_streams: HashMap::default(),
            proto_event_sender,
            proto_event_receiver,
            service_sender: Buffer::new(service_sender),
            service_receiver,
            service_proto_senders: meta.service_proto_senders,
            session_proto_senders: meta.session_proto_senders,
            state: SessionState::Normal,
            future_task_sender,
            wait_handle: meta.session_proto_handles,
        }
    }

    /// select procedure
    #[inline(always)]
    fn select_procedure(
        &mut self,
        procedure: impl Future<
                Output = Result<
                    (
                        Framed<StreamHandle, LengthDelimitedCodec>,
                        String,
                        Option<String>,
                    ),
                    io::Error,
                >,
            > + Send
            + 'static,
    ) {
        let mut event_sender = self.proto_event_sender.clone();
        let timeout = self.timeout;

        // NOTE: A Interval/Delay will block tokio runtime from gracefully shutdown.
        //       So we spawn it in FutureTaskManager
        let task = Box::pin(async move {
            let event = match crate::runtime::timeout(timeout, procedure).await {
                Ok(res) => match res {
                    Ok((handle, name, version)) => match version {
                        Some(version) => ProtocolEvent::Open {
                            substream: Box::new(handle),
                            proto_name: name,
                            version,
                        },
                        None => {
                            debug!("Negotiation to open the protocol {} failed", name);
                            ProtocolEvent::SelectError {
                                proto_name: Some(name),
                            }
                        }
                    },
                    Err(err) => {
                        debug!("stream protocol select err: {:?}", err);
                        ProtocolEvent::SelectError { proto_name: None }
                    }
                },
                Err(err) => {
                    debug!("stream protocol select err: {:?}", err);
                    ProtocolEvent::SelectError { proto_name: None }
                }
            };
            if let Err(err) = event_sender.send(event).await {
                debug!("select result send back error: {:?}", err);
            }
        }) as BoxedFutureTask;

        let mut future_task_sender = self.future_task_sender.clone();
        crate::runtime::spawn(async move {
            if future_task_sender.send(task).await.is_err() {
                trace!("select procedure send err")
            }
        });
    }

    /// After the session is established, the client is requested to open some custom protocol sub stream.
    pub fn open_proto_stream(&mut self, proto_name: &str) {
        debug!("try open proto, {}", proto_name);
        let versions = self.protocol_configs_by_name[proto_name]
            .support_versions
            .clone();
        let proto_info = ProtocolInfo::new(proto_name, versions);
        let mut control = self.control.clone();
        let id = self.context.id;

        let task = async move {
            let handle = match control.open_stream().await {
                Ok(handle) => handle,
                Err(e) => {
                    debug!("session {} open stream error: {}", id, e);
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
            };
            client_select(handle, proto_info).await
        };
        self.select_procedure(task);
    }

    /// Push the generated event to the Service
    #[inline]
    fn event_output(&mut self, cx: &mut Context, event: SessionEvent) {
        self.service_sender.push(event);
        self.output(cx);
    }

    #[inline]
    fn output(&mut self, cx: &mut Context) {
        if let SendResult::Disconnect = self.service_sender.try_send(cx) {
            error!("session send to service error: Disconnect");
            self.service_sender.clear();
            self.state = SessionState::Abnormal;
        }
    }

    #[inline]
    fn distribute_to_substream(&mut self, cx: &mut Context) {
        for buffer in self
            .substreams
            .values_mut()
            .filter(|buffer| !buffer.is_empty())
        {
            if let SendResult::Pending = buffer.try_send(cx) {
                if self.context.pending_data_size() > self.config.send_buffer_size {
                    self.state = SessionState::Abnormal;
                    warn!(
                        "session {:?} unable to send message, \
                         user allow buffer size: {}, \
                         current buffer size: {}, so kill it",
                        self.context,
                        self.config.send_buffer_size,
                        self.context.pending_data_size()
                    );
                    buffer.clear();
                    self.event_output(
                        cx,
                        SessionEvent::ChangeState {
                            id: self.context.id,
                            state: SessionState::Abnormal,
                            error: None,
                        },
                    );
                }
                break;
            }
        }
    }

    /// Handling client-initiated open protocol sub stream requests
    fn handle_substream(&mut self, substream: StreamHandle) {
        let proto_metas = self
            .protocol_configs_by_name
            .values()
            .map(|proto_meta| {
                let name = (proto_meta.name)(proto_meta.id);
                let proto_info = ProtocolInfo::new(&name, proto_meta.support_versions.clone());
                let select_fn = (proto_meta.select_version)();
                (name, (proto_info, select_fn))
            })
            .collect();

        let task = server_select(substream, proto_metas);
        self.select_procedure(task);
    }

    fn open_protocol(
        &mut self,
        cx: &mut Context,
        name: String,
        version: String,
        substream: Box<Framed<StreamHandle, LengthDelimitedCodec>>,
    ) {
        let proto = match self.protocol_configs_by_name.get(&name) {
            Some(proto) => proto,
            None => {
                // if the server intentionally returns malicious protocol data with arbitrary
                // protocol names, close the connection and feedback error
                self.state = SessionState::Abnormal;
                self.event_output(
                    cx,
                    SessionEvent::ProtocolSelectError {
                        id: self.context.id,
                        proto_name: None,
                    },
                );
                return;
            }
        };

        let proto_id = proto.id;
        // open twice at the same protocol, ignore it
        if self.proto_streams.contains_key(&proto_id) {
            return;
        }

        let before_receive_fn = (proto.before_receive)();
        let (session_to_proto_sender, session_to_proto_receiver) =
            priority_mpsc::channel(self.config.channel_size);

        self.substreams.insert(
            self.next_stream,
            PriorityBuffer::new(session_to_proto_sender.clone()),
        );
        self.proto_streams.insert(proto_id, self.next_stream);
        let raw_part = substream.into_parts();

        match proto.spawn {
            Some(ref spawn) => {
                let (read, write) = crate::runtime::split(raw_part.io);
                let read_part = {
                    let mut frame = FramedRead::new(read, (proto.codec)());
                    *frame.read_buffer_mut() = raw_part.read_buf;

                    SubstreamReadPart {
                        substream: frame,
                        before_receive: before_receive_fn,
                        proto_id,
                        stream_id: self.next_stream,
                        version,
                        close_sender: session_to_proto_sender,
                    }
                };

                let write_part = SubstreamWritePartBuilder::new(
                    self.proto_event_sender.clone(),
                    session_to_proto_receiver,
                    self.context.clone(),
                )
                .proto_id(proto_id)
                .stream_id(self.next_stream)
                .config(self.config)
                .build(FramedWrite::new(write, (proto.codec)()));

                crate::runtime::spawn(write_part.for_each(|_| future::ready(())));
                spawn.spawn(self.context.clone(), &self.service_control, read_part);
            }
            None => {
                let mut part = FramedParts::new(raw_part.io, (proto.codec)());
                // Replace buffered data
                part.read_buf = raw_part.read_buf;
                part.write_buf = raw_part.write_buf;
                let frame = Framed::from_parts(part);

                let mut proto_stream = SubstreamBuilder::new(
                    self.proto_event_sender.clone(),
                    session_to_proto_receiver,
                    self.context.clone(),
                )
                .proto_id(proto_id)
                .stream_id(self.next_stream)
                .config(self.config)
                .service_proto_sender(self.service_proto_senders.get(&proto_id).cloned())
                .session_proto_sender(self.session_proto_senders.get(&proto_id).cloned())
                .keep_buffer(self.keep_buffer)
                .before_receive(before_receive_fn)
                .build(frame);

                proto_stream.proto_open(version);
                crate::runtime::spawn(proto_stream.for_each(|_| future::ready(())));
            }
        }

        self.next_stream += 1;

        debug!("session [{}] proto [{}] open", self.context.id, proto_id);
    }

    /// Handling events uploaded by the protocol stream
    fn handle_stream_event(&mut self, cx: &mut Context, event: ProtocolEvent) {
        match event {
            ProtocolEvent::Open {
                proto_name,
                substream,
                version,
            } => {
                self.open_protocol(cx, proto_name, version, substream);
            }
            ProtocolEvent::Close { id, proto_id } => {
                debug!("session [{}] proto [{}] closed", self.context.id, proto_id);
                if self.substreams.remove(&id).is_some() {
                    self.proto_streams.remove(&proto_id);
                }
            }
            ProtocolEvent::Message { .. } => unreachable!(),
            ProtocolEvent::SelectError { proto_name } => self.event_output(
                cx,
                SessionEvent::ProtocolSelectError {
                    id: self.context.id,
                    proto_name,
                },
            ),
            ProtocolEvent::Error {
                proto_id, error, ..
            } => {
                debug!("Codec error: {:?}", error);
                self.event_output(
                    cx,
                    SessionEvent::ProtocolError {
                        id: self.context.id,
                        proto_id,
                        error,
                    },
                )
            }
            ProtocolEvent::TimeoutCheck => {
                if self.substreams.is_empty() {
                    self.event_output(
                        cx,
                        SessionEvent::SessionTimeout {
                            id: self.context.id,
                        },
                    );
                    self.state = SessionState::LocalClose;
                }
            }
        }
    }

    /// Handling events send by the service
    fn handle_session_event(&mut self, cx: &mut Context, event: SessionEvent, priority: Priority) {
        match event {
            SessionEvent::ProtocolMessage { proto_id, data, .. } => {
                if let Some(stream_id) = self.proto_streams.get(&proto_id) {
                    if let Some(buffer) = self.substreams.get_mut(stream_id) {
                        let event = ProtocolEvent::Message { data };
                        if priority.is_high() {
                            buffer.push_high(event)
                        } else {
                            buffer.push_normal(event)
                        }
                        buffer.try_send(cx);
                    }
                } else {
                    trace!("protocol {} not ready", proto_id);
                }
            }
            SessionEvent::SessionClose { .. } => {
                if self.substreams.is_empty() {
                    // if no proto open, just close session
                    self.close_session();
                } else {
                    self.state = SessionState::LocalClose;
                    self.close_all_proto(cx);
                }
            }
            SessionEvent::ProtocolOpen { proto_id, .. } => {
                if self.proto_streams.contains_key(&proto_id) {
                    debug!("proto [{}] has been open", proto_id);
                } else if let Some(name) = self
                    .protocol_configs_by_id
                    .get(&proto_id)
                    .map(|meta| (meta.name)(meta.id))
                {
                    self.open_proto_stream(&name)
                } else {
                    debug!("This protocol [{}] is not supported", proto_id)
                }
            }
            SessionEvent::ProtocolClose { proto_id, .. } => {
                if let Some(stream_id) = self.proto_streams.get(&proto_id) {
                    if let Some(buffer) = self.substreams.get_mut(stream_id) {
                        buffer.push_high(ProtocolEvent::Close {
                            id: *stream_id,
                            proto_id,
                        });
                        buffer.try_send(cx);
                    }
                } else {
                    debug!("proto [{}] has been closed", proto_id);
                }
            }
            SessionEvent::StreamStart { stream } => self.handle_substream(stream),
            SessionEvent::ChangeState { state, error, id } => {
                if self.state == SessionState::Normal {
                    self.state = state;
                    if let Some(err) = error {
                        if !self.keep_buffer {
                            self.service_sender.clear()
                        }
                        self.event_output(cx, SessionEvent::MuxerError { id, error: err })
                    }
                }
            }
            _ => (),
        }
    }

    fn recv_substreams(&mut self, cx: &mut Context) -> Poll<Option<()>> {
        match Pin::new(&mut self.proto_event_receiver)
            .as_mut()
            .poll_next(cx)
        {
            Poll::Ready(Some(event)) => {
                // Local close means user doesn't want any message from this session
                // But when remote close, we should try my best to accept all data as much as possible
                if !self.state.is_local_close() {
                    self.handle_stream_event(cx, event);
                    Poll::Ready(Some(()))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Ready(None) => {
                // Drop by self
                self.state = SessionState::LocalClose;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn recv_service(&mut self, cx: &mut Context) -> Poll<Option<()>> {
        match Pin::new(&mut self.service_receiver).as_mut().poll_next(cx) {
            Poll::Ready(Some((priority, event))) => {
                if !self.state.is_normal() {
                    Poll::Ready(None)
                } else {
                    self.handle_session_event(cx, event, priority);
                    Poll::Ready(Some(()))
                }
            }
            Poll::Ready(None) => {
                // Must drop by service
                self.state = SessionState::LocalClose;
                self.clean();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Try close all protocol
    #[inline]
    fn close_all_proto(&mut self, cx: &mut Context) {
        if self.context.closed.load(Ordering::SeqCst) {
            self.close_session()
        } else {
            for (pid, buffer) in self.substreams.iter_mut() {
                buffer.push_high(ProtocolEvent::Close {
                    id: *pid,
                    proto_id: 0.into(),
                });
                buffer.try_send(cx);
            }
            self.context.closed.store(true, Ordering::SeqCst);
        }
    }

    /// Close session
    fn close_session(&mut self) {
        self.context.closed.store(true, Ordering::SeqCst);

        let (mut sender, mut events) = self.service_sender.take();
        events.push_back(SessionEvent::SessionClose {
            id: self.context.id,
        });

        crate::runtime::spawn(async move {
            let mut iter = iter(events).map(Ok);
            if let Err(e) = sender.send_all(&mut iter).await {
                debug!("session close event send to service error: {:?}", e)
            }
        });
        self.clean();
    }

    #[cold]
    fn wait_handle_poll(&mut self, cx: &mut Context) -> Poll<Option<()>> {
        for (sender, mut handle) in self.wait_handle.split_off(0) {
            if let Some(sender) = sender {
                // don't care about it
                let _ignore = sender.send(());
            }
            match handle.poll_unpin(cx) {
                Poll::Pending => {
                    self.wait_handle.push((None, handle));
                }
                Poll::Ready(_) => (),
            }
        }
        if self.wait_handle.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    /// Clean env
    fn clean(&mut self) {
        self.substreams.clear();
        self.service_receiver.close();
        self.proto_event_receiver.close();

        let mut control = self.control.clone();
        crate::runtime::spawn(async move {
            control.close().await;
        });
    }

    #[inline]
    fn flush(&mut self, cx: &mut Context) {
        self.distribute_to_substream(cx);
        if !self.service_sender.is_empty() {
            self.output(cx);
        }
    }
}

impl Stream for Session {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if log_enabled!(target: "tentacle", log::Level::Debug) {
            debug!(
                "session [{}], [{:?}], proto count [{}], state: {:?} ,\
             read buf: {}, write buf: {}",
                self.context.id,
                self.context.ty,
                self.substreams.len(),
                self.state,
                self.service_sender.len(),
                self.substreams
                    .values()
                    .map(PriorityBuffer::len)
                    .sum::<usize>(),
            );
        }

        // double check here
        if self.state.is_local_close() {
            debug!(
                "Session({:?}) finished, self.state.is_local_close()",
                self.context.id
            );
            return Poll::Ready(None);
        }

        self.flush(cx);

        futures::ready!(crate::runtime::poll_proceed(cx));

        let mut is_pending = self.recv_substreams(cx).is_pending();

        is_pending &= self.recv_service(cx).is_pending();

        match self.state {
            SessionState::LocalClose | SessionState::Abnormal => {
                debug!(
                    "Session({:?}) finished, LocalClose||Abnormal",
                    self.context.id
                );
                ::std::mem::take(&mut self.proto_streams);
                self.close_session();
                return self.wait_handle_poll(cx);
            }
            SessionState::RemoteClose => {
                // try close all protocol stream, and then close session
                if self.proto_streams.is_empty() {
                    debug!("Session({:?}) finished, RemoteClose", self.context.id);
                    self.close_session();
                    return self.wait_handle_poll(cx);
                } else {
                    self.close_all_proto(cx);
                }
            }
            SessionState::Normal => (),
        }

        if is_pending {
            Poll::Pending
        } else {
            Poll::Ready(Some(()))
        }
    }
}

pub(crate) struct SessionMeta {
    config: SessionConfig,
    protocol_configs_by_name: HashMap<String, Arc<Meta>>,
    protocol_configs_by_id: IntMap<ProtocolId, Arc<Meta>>,
    context: Arc<SessionContext>,
    timeout: Duration,
    keep_buffer: bool,
    service_proto_senders: IntMap<ProtocolId, Buffer<ServiceProtocolEvent>>,
    session_proto_senders: IntMap<ProtocolId, Buffer<SessionProtocolEvent>>,
    event_sender: priority_mpsc::Sender<SessionEvent>,
    service_control: ServiceAsyncControl,
    session_proto_handles: Vec<(
        Option<futures::channel::oneshot::Sender<()>>,
        crate::runtime::JoinHandle<()>,
    )>,
}

impl SessionMeta {
    pub fn new(
        timeout: Duration,
        context: Arc<SessionContext>,
        event_sender: priority_mpsc::Sender<SessionEvent>,
        control: ServiceAsyncControl,
    ) -> Self {
        SessionMeta {
            config: SessionConfig::default(),
            protocol_configs_by_name: HashMap::new(),
            protocol_configs_by_id: HashMap::default(),
            context,
            timeout,
            keep_buffer: false,
            service_proto_senders: HashMap::default(),
            session_proto_senders: HashMap::default(),
            session_proto_handles: Vec::new(),
            service_control: control,
            event_sender,
        }
    }

    pub fn protocol_by_name(mut self, config: HashMap<String, Arc<Meta>>) -> Self {
        self.protocol_configs_by_name = config;
        self
    }

    pub fn protocol_by_id(mut self, config: IntMap<ProtocolId, Arc<Meta>>) -> Self {
        self.protocol_configs_by_id = config;
        self
    }

    pub fn config(mut self, config: SessionConfig) -> Self {
        self.config = config;
        self
    }

    pub fn keep_buffer(mut self, keep: bool) -> Self {
        self.keep_buffer = keep;
        self
    }

    pub fn service_proto_senders(
        mut self,
        senders: IntMap<ProtocolId, Buffer<ServiceProtocolEvent>>,
    ) -> Self {
        self.service_proto_senders = senders;
        self
    }

    pub fn session_senders(
        mut self,
        senders: IntMap<ProtocolId, Buffer<SessionProtocolEvent>>,
    ) -> Self {
        self.session_proto_senders = senders;
        self
    }

    pub fn session_proto_handles(
        mut self,
        handles: Vec<(
            Option<futures::channel::oneshot::Sender<()>>,
            crate::runtime::JoinHandle<()>,
        )>,
    ) -> Self {
        self.session_proto_handles = handles;
        self
    }
}

/// Session state
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum SessionState {
    /// Close by remote, accept all data as much as possible
    RemoteClose,
    /// Close by self, don't receive any more
    LocalClose,
    /// Normal communication
    Normal,
    /// Abnormal state
    Abnormal,
}

impl SessionState {
    #[inline]
    fn is_local_close(self) -> bool {
        matches!(self, SessionState::LocalClose)
    }

    #[inline]
    fn is_normal(self) -> bool {
        matches!(self, SessionState::Normal)
    }
}

struct InnerSocket<T> {
    socket: YamuxSession<T>,
    sender: priority_mpsc::Sender<SessionEvent>,
    id: SessionId,
}

impl<T> InnerSocket<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn new(
        socket: YamuxSession<T>,
        sender: priority_mpsc::Sender<SessionEvent>,
        id: SessionId,
    ) -> Self {
        InnerSocket { socket, sender, id }
    }
}

impl<T> Stream for InnerSocket<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.socket).as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(stream))) => {
                let mut sender = self.sender.clone();

                crate::runtime::spawn(async move {
                    let _ignore = sender
                        .quick_send(SessionEvent::StreamStart { stream })
                        .await;
                });

                Poll::Ready(Some(()))
            }
            Poll::Ready(None) => {
                let mut sender = self.sender.clone();
                let id = self.id;

                crate::runtime::spawn(async move {
                    let _ignore = sender
                        .quick_send(SessionEvent::ChangeState {
                            state: SessionState::RemoteClose,
                            error: None,
                            id,
                        })
                        .await;
                });
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(err))) => {
                debug!("session poll error: {:?}", err);

                let event = match err.kind() {
                    ErrorKind::BrokenPipe
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionReset
                    | ErrorKind::NotConnected
                    | ErrorKind::UnexpectedEof => SessionEvent::ChangeState {
                        state: SessionState::RemoteClose,
                        error: None,
                        id: self.id,
                    },
                    _ => {
                        debug!("MuxerError: {:?}", err);

                        SessionEvent::ChangeState {
                            state: SessionState::Abnormal,
                            error: Some(err),
                            id: self.id,
                        }
                    }
                };
                let mut sender = self.sender.clone();

                crate::runtime::spawn(async move {
                    let _ignore = sender.quick_send(event).await;
                });

                Poll::Ready(None)
            }
        }
    }
}
