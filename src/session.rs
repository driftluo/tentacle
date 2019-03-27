use futures::{
    prelude::*,
    sync::mpsc,
    task::{self, Task},
};
use log::{debug, error, trace, warn};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::{
    io::{self, ErrorKind},
    time::{Duration, Instant},
};
use tokio::prelude::{AsyncRead, AsyncWrite, FutureExt};
use tokio::{
    codec::{Framed, FramedParts, LengthDelimitedCodec},
    timer::Delay,
};

use crate::{
    error::Error,
    multiaddr::Multiaddr,
    protocol_select::{client_select, server_select, ProtocolInfo},
    secio::{codec::stream_handle::StreamHandle as SecureHandle, PublicKey},
    service::{config::Meta, ServiceTask, SessionType},
    substream::{ProtocolEvent, SubStream},
    transports::{MultiIncoming, MultiStream},
    yamux::{Config, Session as YamuxSession, StreamHandle},
    ProtocolId, SessionId, StreamId,
};

/// Event generated/received by the Session
#[derive(Debug)]
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
    DialStart {
        remote_address: Multiaddr,
        stream: MultiStream,
    },
    HandshakeSuccess {
        /// Secure handle
        handle: SecureHandle,
        /// Remote Public key
        public_key: PublicKey,
        /// Remote address
        address: Multiaddr,
        /// Session type
        ty: SessionType,
    },
    HandshakeFail {
        /// remote address
        address: Multiaddr,
        /// Session type
        ty: SessionType,
        /// error
        error: Error<ServiceTask>,
    },
    DialError {
        /// remote address
        address: Multiaddr,
        /// error
        error: Error<ServiceTask>,
    },
    ListenError {
        /// listen address
        address: Multiaddr,
        /// error
        error: Error<ServiceTask>,
    },
    /// Protocol data
    ProtocolMessage {
        /// Session id
        id: SessionId,
        /// Protocol id
        proto_id: ProtocolId,
        /// Data
        data: bytes::Bytes,
    },
    /// Protocol open event
    ProtocolOpen {
        /// Session id
        id: SessionId,
        /// Protocol id
        proto_id: ProtocolId,
        /// Protocol version
        version: String,
    },
    /// Protocol close event
    ProtocolClose {
        /// Session id
        id: SessionId,
        /// Protocol id
        proto_id: ProtocolId,
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
        error: Error<ServiceTask>,
    },
    MuxerError {
        id: SessionId,
        error: Error<ServiceTask>,
    },
}

/// Wrapper for real data streams, such as TCP stream
pub(crate) struct Session<T> {
    socket: YamuxSession<T>,

    protocol_configs: HashMap<String, Arc<Meta>>,

    id: SessionId,
    timeout: Duration,
    timeout_check: Option<Delay>,

    dead: bool,

    // NOTE: Not used yet, may useful later
    // remote_address: ::std::net::SocketAddr,
    // remote_public_key: Option<PublicKey>,
    next_stream: StreamId,
    /// Indicates the identity of the current session
    ty: SessionType,

    /// Sub streams maps a stream id to a sender of sub stream
    sub_streams: HashMap<StreamId, mpsc::Sender<ProtocolEvent>>,
    proto_streams: HashMap<ProtocolId, StreamId>,
    /// The buffer which will distribute to sub streams
    write_buf: VecDeque<ProtocolEvent>,
    /// The buffer which will send to service
    read_buf: VecDeque<SessionEvent>,

    /// Clone to new sub stream
    proto_event_sender: mpsc::Sender<ProtocolEvent>,
    /// Receive events from sub streams
    proto_event_receiver: mpsc::Receiver<ProtocolEvent>,

    /// Send events to service
    service_sender: mpsc::Sender<SessionEvent>,
    /// Receive event from service
    service_receiver: mpsc::Receiver<SessionEvent>,

    notify: Option<Task>,
}

impl<T> Session<T>
where
    T: AsyncRead + AsyncWrite,
{
    /// New a session
    pub fn new(
        socket: T,
        service_sender: mpsc::Sender<SessionEvent>,
        service_receiver: mpsc::Receiver<SessionEvent>,
        meta: SessionMeta,
    ) -> Self {
        let socket = YamuxSession::new(socket, meta.config, meta.ty.into());
        let (proto_event_sender, proto_event_receiver) = mpsc::channel(256);
        Session {
            socket,
            protocol_configs: meta.protocol_configs,
            id: meta.id,
            timeout: meta.timeout,
            timeout_check: Some(Delay::new(Instant::now() + meta.timeout)),
            ty: meta.ty,
            next_stream: 0,
            sub_streams: HashMap::default(),
            proto_streams: HashMap::default(),
            write_buf: VecDeque::default(),
            read_buf: VecDeque::default(),
            proto_event_sender,
            proto_event_receiver,
            service_sender,
            service_receiver,
            notify: None,
            dead: false,
        }
    }

    /// select procedure
    #[inline(always)]
    fn select_procedure(
        &mut self,
        procedure: impl Future<
                Item = (
                    Framed<StreamHandle, LengthDelimitedCodec>,
                    String,
                    Option<String>,
                ),
                Error = io::Error,
            > + Send
            + 'static,
    ) {
        let event_sender = self.proto_event_sender.clone();
        let task = procedure.timeout(self.timeout).then(|result| {
            match result {
                Ok((handle, name, version)) => match version {
                    Some(version) => {
                        let send_task = event_sender.send(ProtocolEvent::Open {
                            sub_stream: Box::new(handle),
                            proto_name: name,
                            version,
                        });
                        tokio::spawn(send_task.map(|_| ()).map_err(|err| {
                            error!("stream send back error: {:?}", err);
                        }));
                    }
                    None => {
                        debug!("Negotiation to open the protocol {} failed", name);
                        let send_task = event_sender.send(ProtocolEvent::SelectError {
                            proto_name: Some(name),
                        });
                        tokio::spawn(send_task.map(|_| ()).map_err(|err| {
                            error!("select error send back error: {:?}", err);
                        }));
                    }
                },
                Err(err) => {
                    debug!("stream protocol select err: {:?}", err);
                    let send_task =
                        event_sender.send(ProtocolEvent::SelectError { proto_name: None });
                    tokio::spawn(send_task.map(|_| ()).map_err(|err| {
                        error!("select error send back error: {:?}", err);
                    }));
                }
            }

            Ok(())
        });

        tokio::spawn(task);
    }

    /// After the session is established, the client is requested to open some custom protocol sub stream.
    pub fn open_proto_stream(&mut self, proto_name: &str) {
        debug!("try open proto, {}", proto_name);
        let handle = self.socket.open_stream().unwrap();
        let versions = self.protocol_configs[proto_name].support_versions.clone();
        let proto_info = ProtocolInfo::new(&proto_name, versions);

        let task = client_select(handle, proto_info);
        self.select_procedure(task);
    }

    /// Push the generated event to the Service
    #[inline]
    fn event_output(&mut self, event: SessionEvent) {
        self.read_buf.push_back(event);
        self.output();
    }

    #[inline]
    fn output(&mut self) {
        while let Some(event) = self.read_buf.pop_front() {
            if let Err(e) = self.service_sender.try_send(event) {
                if e.is_full() {
                    self.read_buf.push_front(e.into_inner());
                    self.notify();
                    return;
                } else {
                    error!("session send to service error: {}", e);
                }
            }
        }
    }

    #[inline]
    fn distribute_to_substream(&mut self) {
        for event in self.write_buf.split_off(0) {
            match event {
                ProtocolEvent::Message { id, proto_id, data } => {
                    if let Some(sender) = self.sub_streams.get_mut(&id) {
                        if let Err(e) =
                            sender.try_send(ProtocolEvent::Message { id, proto_id, data })
                        {
                            if e.is_full() {
                                self.write_buf.push_back(e.into_inner());
                                self.notify();
                            } else {
                                error!("session send to sub stream error: {}", e);
                            }
                        }
                    };
                }
                ProtocolEvent::Close { id, proto_id } => {
                    if let Some(sender) = self.sub_streams.get_mut(&id) {
                        if let Err(e) = sender.try_send(ProtocolEvent::Close { id, proto_id }) {
                            if e.is_full() {
                                self.write_buf.push_back(e.into_inner());
                                self.notify();
                            } else {
                                error!("session send to sub stream error: {}", e);
                            }
                        }
                    };
                }
                _ => (),
            }
        }
    }

    /// Handling client-initiated open protocol sub stream requests
    fn handle_sub_stream(&mut self, sub_stream: StreamHandle) {
        let proto_metas = self
            .protocol_configs
            .values()
            .map(|proto_meta| {
                let name = (proto_meta.name)(proto_meta.id);
                let proto_info = ProtocolInfo::new(&name, proto_meta.support_versions.clone());
                (name, proto_info)
            })
            .collect();

        let task = server_select(sub_stream, proto_metas);
        self.select_procedure(task);
    }

    /// Handling events uploaded by the protocol stream
    fn handle_stream_event(&mut self, event: ProtocolEvent) {
        match event {
            ProtocolEvent::Open {
                proto_name,
                sub_stream,
                version,
            } => {
                let proto = match self.protocol_configs.get(&proto_name) {
                    Some(proto) => proto,
                    None => unreachable!(),
                };

                let proto_id = proto.id;
                let raw_part = sub_stream.into_parts();
                let mut part = FramedParts::new(raw_part.io, (proto.codec)());
                // Replace buffered data
                part.read_buf = raw_part.read_buf;
                part.write_buf = raw_part.write_buf;
                let frame = Framed::from_parts(part);
                let (session_to_proto_sender, session_to_proto_receiver) = mpsc::channel(32);
                let proto_stream = SubStream::new(
                    frame,
                    self.proto_event_sender.clone(),
                    session_to_proto_receiver,
                    self.next_stream,
                    proto_id,
                );
                self.sub_streams
                    .insert(self.next_stream, session_to_proto_sender);
                self.proto_streams.insert(proto_id, self.next_stream);

                self.event_output(SessionEvent::ProtocolOpen {
                    id: self.id,
                    proto_id,
                    version,
                });
                self.next_stream += 1;

                debug!("session [{}] proto [{}] open", self.id, proto_id);

                tokio::spawn(proto_stream.for_each(|_| Ok(())));
            }
            ProtocolEvent::Close { id, proto_id } => {
                debug!("session [{}] proto [{}] closed", self.id, proto_id);
                let _ = self.sub_streams.remove(&id);
                let _ = self.proto_streams.remove(&proto_id);
                self.event_output(SessionEvent::ProtocolClose {
                    id: self.id,
                    proto_id,
                });
            }
            ProtocolEvent::Message { data, proto_id, .. } => {
                debug!("get proto [{}] data len: {}", proto_id, data.len());
                self.event_output(SessionEvent::ProtocolMessage {
                    id: self.id,
                    proto_id,
                    data,
                })
            }
            ProtocolEvent::SelectError { proto_name } => {
                self.event_output(SessionEvent::ProtocolSelectError {
                    id: self.id,
                    proto_name,
                })
            }
            ProtocolEvent::Error {
                proto_id, error, ..
            } => {
                debug!("Codec error: {:?}", error);
                self.event_output(SessionEvent::ProtocolError {
                    id: self.id,
                    proto_id,
                    error,
                })
            }
        }
    }

    /// Handling events send by the service
    fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::ProtocolMessage { proto_id, data, .. } => {
                if let Some(stream_id) = self.proto_streams.get(&proto_id) {
                    self.write_buf.push_back(ProtocolEvent::Message {
                        id: *stream_id,
                        proto_id,
                        data,
                    });
                } else {
                    trace!("protocol {} not ready", proto_id);
                }
            }
            SessionEvent::SessionClose { .. } => {
                if self.sub_streams.is_empty() {
                    // if no proto open, just close session
                    self.close_session();
                } else {
                    for (proto_id, stream_id) in self.proto_streams.iter() {
                        self.write_buf.push_back(ProtocolEvent::Close {
                            id: *stream_id,
                            proto_id: *proto_id,
                        });
                    }
                }
            }
            SessionEvent::ProtocolOpen { proto_id, .. } => {
                if self.proto_streams.contains_key(&proto_id) {
                    debug!("proto [{}] has been open", proto_id);
                } else {
                    let name = self.protocol_configs.values().find_map(|meta| {
                        if meta.id == proto_id {
                            Some((meta.name)(meta.id))
                        } else {
                            None
                        }
                    });
                    match name {
                        Some(name) => self.open_proto_stream(&name),
                        None => debug!("This protocol [{}] is not supported", proto_id),
                    }
                }
            }
            SessionEvent::ProtocolClose { proto_id, .. } => {
                if !self.proto_streams.contains_key(&proto_id) {
                    debug!("proto [{}] has been closed", proto_id);
                } else {
                    self.write_buf.push_back(ProtocolEvent::Close {
                        id: self.proto_streams[&proto_id],
                        proto_id,
                    });
                }
            }
            _ => (),
        }
        self.distribute_to_substream();
    }

    /// Close session
    fn close_session(&mut self) {
        let _ = self
            .service_sender
            .try_send(SessionEvent::SessionClose { id: self.id });
        self.sub_streams.clear();
        self.service_receiver.close();
        self.proto_event_receiver.close();

        let _ = self.socket.shutdown();
    }

    #[inline]
    fn flush(&mut self) {
        self.distribute_to_substream();
        self.output();
    }

    #[inline]
    fn notify(&mut self) {
        if let Some(task) = self.notify.take() {
            task.notify();
        }
    }
}

impl<T> Stream for Session<T>
where
    T: AsyncRead + AsyncWrite,
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        debug!(
            "session [{}], [{:?}], proto count [{}] ",
            self.id,
            self.ty,
            self.sub_streams.len()
        );

        if !self.read_buf.is_empty() || !self.write_buf.is_empty() {
            self.flush();
        }

        if let Some(mut check) = self.timeout_check.take() {
            match check.poll() {
                Ok(Async::Ready(_)) => {
                    if self.sub_streams.is_empty() {
                        self.event_output(SessionEvent::SessionTimeout { id: self.id });
                        self.dead = true;
                    }
                }
                Ok(Async::NotReady) => self.timeout_check = Some(check),
                Err(e) => debug!("timeout check error: {}", e),
            }
        }

        loop {
            match self.socket.poll() {
                Ok(Async::Ready(Some(sub_stream))) => self.handle_sub_stream(sub_stream),
                Ok(Async::Ready(None)) => {
                    self.dead = true;
                    break;
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("session poll error: {:?}", err);
                    self.dead = true;

                    match err.kind() {
                        ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::NotConnected
                        | ErrorKind::UnexpectedEof => (),
                        _ => {
                            self.event_output(SessionEvent::MuxerError {
                                id: self.id,
                                error: err.into(),
                            });
                        }
                    }

                    break;
                }
            }
        }

        loop {
            match self.proto_event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_stream_event(event),
                Ok(Async::Ready(None)) => {
                    // Drop by self
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    debug!("receive proto event error: {:?}", err);
                    break;
                }
            }
        }

        loop {
            match self.service_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_session_event(event),
                Ok(Async::Ready(None)) => {
                    // Must drop by service
                    self.dead = true;
                    break;
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("receive service message error: {:?}", err);
                    break;
                }
            }
        }

        if self.dead {
            self.close_session();
            return Ok(Async::Ready(None));
        }

        self.notify = Some(task::current());
        Ok(Async::NotReady)
    }
}

pub(crate) struct SessionMeta {
    config: Config,
    id: SessionId,
    protocol_configs: HashMap<String, Arc<Meta>>,
    ty: SessionType,
    // remote_address: ::std::net::SocketAddr,
    // remote_public_key: Option<PublicKey>,
    timeout: Duration,
}

impl SessionMeta {
    pub fn new(id: SessionId, ty: SessionType, timeout: Duration) -> Self {
        SessionMeta {
            config: Config::default(),
            id,
            ty,
            protocol_configs: HashMap::new(),
            timeout,
        }
    }

    pub fn protocol(mut self, config: HashMap<String, Arc<Meta>>) -> Self {
        self.protocol_configs = config;
        self
    }

    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }
}
