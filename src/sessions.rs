use futures::{prelude::*, sync::mpsc};
use log::{debug, error, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::{error, io};
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::prelude::{AsyncRead, AsyncWrite};
use yamux::{session::SessionType, Config, Session as YamuxSession, StreamHandle};

use crate::service::ProtocolHandle;
use crate::substream::{ProtocolEvent, SubStream};

pub type StreamId = usize;
pub type ProtocolId = usize;
pub type SessionId = usize;

#[derive(Debug)]
pub enum SessionEvent {
    SessionClose {
        id: SessionId,
    },
    ProtocolMessage {
        id: SessionId,
        proto_id: ProtocolId,
        data: bytes::Bytes,
    },
    ProtocolOpen {
        id: SessionId,
        proto_id: ProtocolId,
        stream_id: StreamId,
    },
    ProtocolClose {
        id: SessionId,
        proto_id: ProtocolId,
        stream_id: StreamId,
    },
}

pub trait ProtocolMeta<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error,
    <U as Encoder>::Error: error::Error,
{
    fn name(&self) -> String {
        format!("/p2p/{}", self.id())
    }
    fn id(&self) -> ProtocolId;
    fn framed(&self, stream: StreamHandle) -> Framed<StreamHandle, U>;
    fn handle(&self) -> Box<dyn ProtocolHandle + Send + 'static>;
}

pub struct Session<T, U> {
    socket: YamuxSession<T>,

    protocol_configs: Arc<HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>>,

    id: SessionId,

    next_stream: StreamId,
    ty: SessionType,

    /// sub streams maps a stream id to a sender of sub stream
    sub_streams: HashMap<StreamId, mpsc::Sender<ProtocolEvent>>,
    proto_streams: HashMap<ProtocolId, StreamId>,

    /// clone to new sub stream
    proto_event_sender: mpsc::Sender<ProtocolEvent>,
    /// receive events from sub streams
    proto_event_receiver: mpsc::Receiver<ProtocolEvent>,

    /// send events to service
    service_sender: mpsc::Sender<SessionEvent>,
    /// receive event from service
    service_receiver: mpsc::Receiver<SessionEvent>,
}

impl<T, U> Session<T, U>
where
    T: AsyncRead + AsyncWrite,
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error,
    <U as Encoder>::Error: error::Error,
{
    pub fn new_client(
        socket: T,
        service_sender: mpsc::Sender<SessionEvent>,
        service_receiver: mpsc::Receiver<SessionEvent>,
        id: SessionId,
        protocol_configs: Arc<HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>>,
    ) -> Self {
        let config = Config::default();
        let socket = YamuxSession::new_client(socket, config);
        let (proto_event_sender, proto_event_receiver) = mpsc::channel(256);
        Session {
            socket,
            protocol_configs,
            id,
            ty: SessionType::Client,
            next_stream: 0,
            sub_streams: HashMap::default(),
            proto_streams: HashMap::default(),
            proto_event_sender,
            proto_event_receiver,
            service_sender,
            service_receiver,
        }
    }

    pub fn new_server(
        socket: T,
        service_sender: mpsc::Sender<SessionEvent>,
        service_receiver: mpsc::Receiver<SessionEvent>,
        id: SessionId,
        protocol_configs: Arc<HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>>,
    ) -> Self {
        let config = Config::default();
        let socket = YamuxSession::new_client(socket, config);
        let (proto_event_sender, proto_event_receiver) = mpsc::channel(32);
        Session {
            socket,
            protocol_configs,
            id,
            ty: SessionType::Server,
            next_stream: 0,
            sub_streams: HashMap::default(),
            proto_streams: HashMap::default(),
            proto_event_sender,
            proto_event_receiver,
            service_sender,
            service_receiver,
        }
    }

    pub fn open_proto_stream(&mut self, proto_name: String) {
        debug!("open proto, {}", proto_name);
        let event_sender = self.proto_event_sender.clone();
        let handle = self.socket.open_stream().unwrap();
        let task = tokio::io::write_all(handle, format!("{}\n", proto_name))
            .and_then(move |(sub_stream, _)| {
                let mut send_task = event_sender.send(ProtocolEvent::ProtocolOpen {
                    sub_stream,
                    proto_name: proto_name.into_bytes(),
                });
                loop {
                    match send_task.poll() {
                        Ok(Async::NotReady) => continue,
                        Ok(Async::Ready(_)) => break,
                        Err(err) => trace!("stream send back error: {:?}", err),
                    }
                }
                Ok(())
            })
            .map_err(|err| {
                trace!("stream protocol identify err: {:?}", err);
            });
        tokio::spawn(task);
    }

    fn event_output(&mut self, event: SessionEvent) {
        if let Err(e) = self.service_sender.try_send(event) {
            error!("session send to service error: {}", e);
        }
    }

    fn handle_sub_stream(&mut self, sub_stream: StreamHandle) {
        debug!("new handle start");
        let event_sender = self.proto_event_sender.clone();
        let task = tokio::io::read_until(io::BufReader::new(sub_stream), b'\n', Vec::new())
            .and_then(move |(sub_stream, proto_name)| {
                let mut send_task = event_sender.send(ProtocolEvent::ProtocolOpen {
                    sub_stream: sub_stream.into_inner(),
                    proto_name,
                });
                loop {
                    match send_task.poll() {
                        Ok(Async::NotReady) => continue,
                        Ok(Async::Ready(_)) => break,
                        Err(err) => trace!("stream send back error: {:?}", err),
                    }
                }
                Ok(())
            })
            .map_err(|err| {
                trace!("stream protocol identify err: {:?}", err);
            });
        tokio::spawn(task);
    }

    fn handle_stream_event(&mut self, event: ProtocolEvent) {
        debug!("start proto event");
        match event {
            ProtocolEvent::ProtocolOpen {
                proto_name,
                mut sub_stream,
            } => {
                let name = match String::from_utf8(proto_name) {
                    Ok(name) => name.trim().to_string(),
                    Err(err) => {
                        let _ = sub_stream.shutdown();
                        warn!("Can't read proto name: {}", err);
                        return;
                    }
                };
                let proto = match self.protocol_configs.get(&name) {
                    Some(proto) => proto,
                    None => {
                        let _ = sub_stream.shutdown();
                        return;
                    }
                };
                let frame = proto.framed(sub_stream);
                let (session_to_proto_sender, session_to_proto_receiver) = mpsc::channel(32);
                let proto_stream = SubStream::new(
                    frame,
                    self.proto_event_sender.clone(),
                    session_to_proto_receiver,
                    self.next_stream,
                    proto.id(),
                );
                self.sub_streams
                    .insert(self.next_stream, session_to_proto_sender);
                self.proto_streams.insert(proto.id(), self.next_stream);

                self.event_output(SessionEvent::ProtocolOpen {
                    id: self.id,
                    stream_id: self.next_stream,
                    proto_id: proto.id(),
                });
                self.next_stream += 1;

                tokio::spawn(proto_stream.for_each(|_| Ok(())));
            }
            ProtocolEvent::ProtocolClose { id, proto_id } => {
                debug!("session [{}] proto [{}] closed", self.id, proto_id);
                let _ = self.sub_streams.remove(&id);
                let _ = self.proto_streams.remove(&proto_id);
                self.event_output(SessionEvent::ProtocolClose {
                    id: self.id,
                    proto_id,
                    stream_id: id,
                })
            }
            ProtocolEvent::ProtocolMessage { data, proto_id, .. } => {
                debug!("get proto [{}] data: {:?}", proto_id, data);
                self.event_output(SessionEvent::ProtocolMessage {
                    id: self.id,
                    proto_id,
                    data,
                })
            }
        }
    }

    fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::ProtocolMessage { proto_id, data, .. } => {
                if let Some(stream_id) = self.proto_streams.get(&proto_id) {
                    if let Some(sender) = self.sub_streams.get_mut(stream_id) {
                        let _ = sender.try_send(ProtocolEvent::ProtocolMessage {
                            id: *stream_id,
                            proto_id,
                            data,
                        });
                    };
                } else {
                    debug!("protocol {} not ready", proto_id);
                }
            }
            SessionEvent::SessionClose { .. } => {
                let _ = self.socket.shutdown();
                self.sub_streams.clear();
            }
            _ => (),
        }
    }
}

impl<T, U> Stream for Session<T, U>
where
    T: AsyncRead + AsyncWrite,
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error,
    <U as Encoder>::Error: error::Error,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        trace!("[{:?}] do something", self.ty);
        match self.socket.poll() {
            Ok(Async::Ready(Some(sub_stream))) => self.handle_sub_stream(sub_stream),
            Ok(Async::Ready(None)) => {
                let _ = self
                    .service_sender
                    .try_send(SessionEvent::SessionClose { id: self.id });
                self.sub_streams.clear();
                return Ok(Async::Ready(None));
            }
            Ok(Async::NotReady) => (),
            Err(err) => {
                warn!("{:?}", err);
            }
        }

        loop {
            match self.proto_event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_stream_event(event),
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("{:?}", err);
                    break;
                }
            }
        }

        loop {
            match self.service_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_session_event(event),
                Ok(Async::Ready(None)) => {
                    // Must stop by service
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("{:?}", err);
                    break;
                }
            }
        }

        Ok(Async::NotReady)
    }
}
