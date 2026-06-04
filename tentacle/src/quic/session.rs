//! QUIC session main loop.
//!
//! Mirrors the role of [`crate::session::Session`] for the yamux path:
//! drives one tentacle session on top of a single `quinn::Connection`,
//! routing protocol events between the substream layer and `InnerService`.
//!
//! Differences vs the yamux session:
//!
//! - There is no underlying byte stream and no `InnerSocket` driver task —
//!   `quinn::Connection` is self-driving (its `quinn::Endpoint` runs the
//!   UDP / packet driver in the background). Inbound substreams are
//!   discovered by polling `Connection::accept_bi()` directly inside
//!   `poll_next` instead of being injected via `SessionEvent::StreamStart`.
//! - Outgoing substreams use `Connection::open_bi()` rather than
//!   `yamux::Control::open_stream()`. Otherwise the protocol negotiation
//!   (`client_select` / `server_select`) and protocol-level state machinery
//!   (`Substream<U>`, `SubstreamReadPart`, `SubstreamWritePart`) are reused
//!   verbatim — they are abstracted over `SubstreamInner`.
//! - Connection-level errors are surfaced via `quinn::ConnectionError`
//!   variants and mapped onto `SessionState`.

use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
    time::Duration,
};

use futures::{SinkExt, channel::mpsc, future::BoxFuture, prelude::*, stream::iter};
use log::{debug, error, log_enabled, trace, warn};
use nohash_hasher::IntMap;
use quinn::{Connection, ConnectionError, RecvStream, SendStream};
use tokio_util::codec::{Framed, FramedParts, LengthDelimitedCodec};

use crate::{
    ProtocolId, StreamId, SubstreamReadPart,
    buffer::{Buffer, PriorityBuffer, SendResult},
    channel::mpsc::{self as priority_mpsc, Priority},
    context::SessionContext,
    protocol_handle_stream::{ServiceProtocolEvent, SessionProtocolEvent},
    protocol_select::{ProtocolInfo, client_select, server_select},
    quic::stream::QuicBiStream,
    secio::PublicKey,
    service::{
        ServiceAsyncControl,
        config::{Meta, SessionConfig},
        future_task::BoxedFutureTask,
    },
    session::{SessionEvent, SessionMeta, SessionState, split_spawn_framed},
    substream::{ProtocolEvent, SubstreamBuilder, SubstreamInner, SubstreamWritePartBuilder},
};

/// Successfully-handshaken QUIC connection paired with the remote secio
/// public key recovered from its tentacle identity extension.
///
/// This is what `QuicEndpoint::dial()` returns and what
/// `QuicListener::accept()` yields. Once the higher-level service has set
/// up a `SessionMeta` for it, the handshake is consumed by
/// [`QuicSession::new`] to build the full session loop.
#[derive(Debug)]
pub struct QuicHandshake {
    conn: Connection,
    remote_pubkey: PublicKey,
}

impl QuicHandshake {
    pub(crate) fn new(conn: Connection, remote_pubkey: PublicKey) -> Self {
        Self {
            conn,
            remote_pubkey,
        }
    }

    /// Remote peer's secio public key, recovered from the tentacle identity
    /// extension on the TLS leaf cert.
    pub fn remote_pubkey(&self) -> &PublicKey {
        &self.remote_pubkey
    }

    /// Borrow the underlying `quinn::Connection`. Useful for inspection in
    /// tests; the session main loop takes ownership via [`Self::into_inner`].
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Decompose the handshake into its `quinn::Connection` and remote
    /// `PublicKey`, ready to be threaded into [`QuicSession::new`].
    pub fn into_inner(self) -> (Connection, PublicKey) {
        (self.conn, self.remote_pubkey)
    }
}

/// QUIC-backed tentacle session.
///
/// Owns a `quinn::Connection` and a registry of per-protocol substreams,
/// driving the same protocol-level state machine as
/// [`crate::session::Session`] over a different multiplexer.
pub(crate) struct QuicSession {
    conn: Connection,

    protocol_configs_by_name: HashMap<String, Arc<Meta>>,
    protocol_configs_by_id: IntMap<ProtocolId, Arc<Meta>>,

    config: SessionConfig,
    timeout: Duration,
    keep_buffer: bool,
    state: SessionState,
    context: Arc<SessionContext>,
    service_control: ServiceAsyncControl,

    next_stream: StreamId,

    /// Per-substream per-protocol event buffer.
    substreams: IntMap<StreamId, PriorityBuffer<ProtocolEvent>>,
    proto_streams: IntMap<ProtocolId, StreamId>,

    /// Cloned into every spawned substream task; receives upcalls from them.
    proto_event_sender: mpsc::Sender<ProtocolEvent>,
    proto_event_receiver: mpsc::Receiver<ProtocolEvent>,

    /// session → InnerService.
    service_sender: Buffer<SessionEvent>,
    /// InnerService → session.
    service_receiver: priority_mpsc::Receiver<SessionEvent>,

    service_proto_senders: IntMap<ProtocolId, Buffer<ServiceProtocolEvent>>,
    session_proto_senders: IntMap<ProtocolId, Buffer<SessionProtocolEvent>>,

    future_task_sender: mpsc::Sender<BoxedFutureTask>,
    wait_handle: Vec<(
        Option<futures::channel::oneshot::Sender<()>>,
        crate::runtime::JoinHandle<()>,
    )>,

    /// Cached `accept_bi()` future. We re-create it after each successful
    /// pickup so the next inbound substream is awaited.
    accepting: Option<BoxFuture<'static, Result<(SendStream, RecvStream), ConnectionError>>>,
}

impl QuicSession {
    /// Build a new QUIC session.
    ///
    /// Mirrors [`crate::session::Session::new`] but takes an already-established
    /// `quinn::Connection` (whose TLS handshake and tentacle identity check
    /// have completed) instead of a byte stream.
    pub(crate) fn new(
        conn: Connection,
        _remote_pubkey: PublicKey,
        service_sender: mpsc::Sender<SessionEvent>,
        service_receiver: priority_mpsc::Receiver<SessionEvent>,
        meta: SessionMeta,
        future_task_sender: mpsc::Sender<BoxedFutureTask>,
    ) -> Self {
        // Channel between the session loop and the spawned substream tasks.
        let (proto_event_sender, proto_event_receiver) = mpsc::channel(meta.config.channel_size);

        // Schedule a one-shot timeout-check tick so dangling sessions with no
        // substream activity get garbage-collected. Mirrors the yamux session.
        let mut interval = proto_event_sender.clone();
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

        QuicSession {
            conn,
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
            accepting: None,
        }
    }

    /// Spawn a future that runs `client_select` or `server_select` against the
    /// given substream and reports the outcome back as a `ProtocolEvent`.
    /// Identical in shape to `Session::select_procedure`.
    #[inline(always)]
    fn select_procedure(
        &mut self,
        procedure: impl Future<
            Output = Result<
                (
                    Framed<SubstreamInner, LengthDelimitedCodec>,
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

    /// Open a new substream and run client-side protocol negotiation on it.
    pub fn open_proto_stream(&mut self, proto_name: &str) {
        debug!("try open proto, {}", proto_name);
        let versions = self.protocol_configs_by_name[proto_name]
            .support_versions
            .clone();
        let proto_info = ProtocolInfo::new(proto_name, versions);
        let conn = self.conn.clone();
        let id = self.context.id;

        let task = async move {
            let (send, recv) = match conn.open_bi().await {
                Ok(bi) => bi,
                Err(e) => {
                    debug!("session {} open_bi error: {}", id, e);
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
            };
            let handle = SubstreamInner::Quic(QuicBiStream::new(send, recv));
            client_select(handle, proto_info).await
        };
        self.select_procedure(task);
    }

    /// Push a session-level event up to `InnerService`.
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

    /// Run server-side protocol negotiation on a freshly accepted substream.
    fn handle_substream(&mut self, send: SendStream, recv: RecvStream) {
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

        let task = server_select(
            SubstreamInner::Quic(QuicBiStream::new(send, recv)),
            proto_metas,
        );
        self.select_procedure(task);
    }

    /// Wire a successfully-negotiated substream into the protocol layer.
    /// Logic mirrors `Session::open_protocol`.
    fn open_protocol(
        &mut self,
        cx: &mut Context,
        name: String,
        version: String,
        substream: Box<Framed<SubstreamInner, LengthDelimitedCodec>>,
    ) {
        let proto = match self.protocol_configs_by_name.get(&name) {
            Some(proto) => proto,
            None => {
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
                let mut part = FramedParts::new(raw_part.io, (proto.codec)());
                part.read_buf = raw_part.read_buf;
                part.write_buf = raw_part.write_buf;
                let (write, read) = split_spawn_framed(part);
                let read_part = SubstreamReadPart {
                    substream: read,
                    before_receive: before_receive_fn,
                    proto_id,
                    stream_id: self.next_stream,
                    version,
                    close_sender: session_to_proto_sender,
                };

                let write_part = SubstreamWritePartBuilder::new(
                    self.proto_event_sender.clone(),
                    session_to_proto_receiver,
                    self.context.clone(),
                )
                .proto_id(proto_id)
                .stream_id(self.next_stream)
                .config(self.config)
                .build(write);

                crate::runtime::spawn(write_part.for_each(|_| future::ready(())));
                spawn.spawn(self.context.clone(), &self.service_control, read_part);
            }
            None => {
                let mut part = FramedParts::new(raw_part.io, (proto.codec)());
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

    /// Handle an event reported by a spawned substream task.
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

    /// Handle an event injected by `InnerService`.
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
            // QUIC path discovers inbound substreams via `accept_bi()` in
            // `poll_inbound_streams`, not via this event.
            SessionEvent::StreamStart { .. } => {
                debug!("StreamStart should not be delivered to a quic session");
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
                if !self.state.is_local_close() {
                    self.handle_stream_event(cx, event);
                    Poll::Ready(Some(()))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Ready(None) => {
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
                self.state = SessionState::LocalClose;
                self.clean();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Drive `accept_bi()` and dispatch any newly-accepted substream to
    /// server-side protocol negotiation. Returns `Pending` while waiting for
    /// the next inbound stream and `Ready(None)` once the connection has
    /// closed (which folds into `state` and is handled by the outer loop).
    fn poll_inbound_streams(&mut self, cx: &mut Context) -> Poll<Option<()>> {
        if !self.state.is_normal() {
            return Poll::Pending;
        }
        loop {
            if self.accepting.is_none() {
                let conn = self.conn.clone();
                self.accepting = Some(Box::pin(async move { conn.accept_bi().await }));
            }
            let fut = self
                .accepting
                .as_mut()
                .expect("accepting future just initialised");
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok((send, recv))) => {
                    self.accepting = None;
                    self.handle_substream(send, recv);
                    // Loop to start the next accept_bi future immediately.
                }
                Poll::Ready(Err(err)) => {
                    self.accepting = None;
                    self.map_connection_error(cx, err);
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Translate `quinn::ConnectionError` into our `SessionState` machine.
    fn map_connection_error(&mut self, cx: &mut Context, err: ConnectionError) {
        let id = self.context.id;
        match err {
            ConnectionError::LocallyClosed => {
                debug!("quic session {}: locally closed", id);
                self.state = SessionState::LocalClose;
            }
            ConnectionError::ApplicationClosed(_) | ConnectionError::ConnectionClosed(_) => {
                debug!("quic session {}: closed by peer ({:?})", id, err);
                self.state = SessionState::RemoteClose;
            }
            ConnectionError::TimedOut => {
                debug!("quic session {}: idle timeout", id);
                self.state = SessionState::RemoteClose;
            }
            ConnectionError::Reset => {
                debug!("quic session {}: stateless reset", id);
                self.state = SessionState::RemoteClose;
            }
            ConnectionError::TransportError(e) => {
                self.state = SessionState::Abnormal;
                let io_err = io::Error::other(format!("quic transport error: {:?}", e));
                self.event_output(cx, SessionEvent::MuxerError { id, error: io_err });
            }
            other => {
                self.state = SessionState::Abnormal;
                let io_err = io::Error::other(format!("quic connection error: {:?}", other));
                self.event_output(cx, SessionEvent::MuxerError { id, error: io_err });
            }
        }
    }

    /// Try to close all open protocol substreams. Mirrors
    /// `Session::close_all_proto`.
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

    /// Send a final `SessionClose` event upstream and tear down local state.
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

    /// Drop all session-local state and ask quinn to close the underlying
    /// connection. The owning `quinn::Endpoint` is kept alive elsewhere
    /// until its connections drain.
    fn clean(&mut self) {
        self.substreams.clear();
        self.service_receiver.close();
        self.proto_event_receiver.close();
        self.accepting = None;
        self.conn.close(0u32.into(), b"closed");
    }

    #[inline]
    fn flush(&mut self, cx: &mut Context) {
        self.distribute_to_substream(cx);
        if !self.service_sender.is_empty() {
            self.output(cx);
        }
    }
}

impl Stream for QuicSession {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if log_enabled!(target: "tentacle", log::Level::Debug) {
            debug!(
                "quic session [{}], [{:?}], proto count [{}], state: {:?}, \
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

        // Same double-check as `Session::poll_next`: if we've already entered
        // local-close, terminate the stream immediately.
        if self.state.is_local_close() {
            debug!(
                "QuicSession({:?}) finished, self.state.is_local_close()",
                self.context.id
            );
            return Poll::Ready(None);
        }

        self.flush(cx);

        futures::ready!(crate::runtime::poll_proceed(cx));

        let mut is_pending = self.recv_substreams(cx).is_pending();
        is_pending &= self.recv_service(cx).is_pending();
        is_pending &= self.poll_inbound_streams(cx).is_pending();

        match self.state {
            SessionState::LocalClose | SessionState::Abnormal => {
                debug!(
                    "QuicSession({:?}) finished, LocalClose||Abnormal",
                    self.context.id
                );
                ::std::mem::take(&mut self.proto_streams);
                self.close_session();
                return self.wait_handle_poll(cx);
            }
            SessionState::RemoteClose => {
                if self.proto_streams.is_empty() {
                    debug!("QuicSession({:?}) finished, RemoteClose", self.context.id);
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

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::*;
    use std::{
        str::FromStr,
        sync::atomic::{AtomicBool, AtomicUsize},
    };

    use crate::{
        SessionId,
        context::SessionContext,
        multiaddr::Multiaddr,
        quic::{config::QuicConfig, endpoint::QuicEndpoint},
        secio::SecioKeyPair,
        service::{ServiceAsyncControl, ServiceControl, SessionType, config::SessionConfig},
        session::SessionMeta,
    };
    use futures::channel::mpsc as fmpsc;

    /// Build a minimal `SessionMeta` with no registered protocols. Enough to
    /// spin up the session loop and observe connection-level lifecycle
    /// without needing the full `InnerService` wiring.
    fn dummy_meta(ctx: Arc<SessionContext>) -> SessionMeta {
        let (event_sender, _event_receiver) = priority_mpsc::channel(8);
        let (task_sender, _task_receiver) = priority_mpsc::channel(8);
        let service_control: ServiceAsyncControl =
            ServiceControl::new(task_sender, Arc::new(AtomicBool::new(false))).into();
        SessionMeta::new(Duration::from_secs(60), ctx, event_sender, service_control)
            .config(SessionConfig::default())
    }

    fn make_context(
        id: SessionId,
        addr: Multiaddr,
        ty: SessionType,
        pk: PublicKey,
    ) -> Arc<SessionContext> {
        Arc::new(SessionContext::new(
            id,
            addr,
            ty,
            Some(pk),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicUsize::new(0)),
        ))
    }

    /// Stand up a server + client `QuicEndpoint`, dial through, build a
    /// `QuicSession` around the resulting connection on the client side,
    /// then have the server close the connection and confirm the session
    /// loop terminates cleanly.
    #[tokio::test]
    async fn quic_session_drives_to_completion_on_remote_close() {
        let server_key = SecioKeyPair::secp256k1_generated();
        let server_pid = server_key.peer_id();
        let server_endpoint = QuicEndpoint::new(server_key.clone(), QuicConfig::default()).unwrap();

        let listener = server_endpoint
            .listen(Multiaddr::from_str("/ip4/127.0.0.1/udp/0/quic-v1").unwrap())
            .expect("listen");
        let server_addr = listener.listen_addr().clone();

        let server_task = tokio::spawn(async move {
            let (_addr, hs) = listener
                .accept()
                .await
                .expect("accept ok")
                .expect("not closed");
            // Application-initiated close on the server side.
            hs.connection().close(0u32.into(), b"bye");
        });

        let client_key = SecioKeyPair::secp256k1_generated();
        let client_endpoint = QuicEndpoint::new(client_key, QuicConfig::default()).unwrap();
        let dial_addr: Multiaddr = format!("{}/p2p/{}", server_addr, server_pid.to_base58())
            .parse()
            .unwrap();
        let handshake = client_endpoint.dial(dial_addr.clone()).await.expect("dial");
        let (conn, remote_pubkey) = handshake.into_inner();

        let context = make_context(
            0.into(),
            dial_addr,
            SessionType::Outbound,
            remote_pubkey.clone(),
        );
        let meta = dummy_meta(context);
        let (svc_sender, _svc_receiver) = fmpsc::channel(8);
        let (_to_session_sender, to_session_receiver) = priority_mpsc::channel(8);
        let (future_task_sender, _future_task_receiver) = fmpsc::channel(8);

        let quic_session = QuicSession::new(
            conn,
            remote_pubkey,
            svc_sender,
            to_session_receiver,
            meta,
            future_task_sender,
        );

        // Drive the session loop. The remote application close maps to
        // `SessionState::RemoteClose`, so the loop should yield `None` after
        // a finite number of polls.
        tokio::time::timeout(Duration::from_secs(5), quic_session.for_each(|_| async {}))
            .await
            .expect("session must complete after remote close");

        server_task.await.expect("server task");
    }
}
