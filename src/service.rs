use futures::{prelude::*, sync::mpsc};
use log::{debug, error, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{error, io};
use tokio::codec::{Decoder, Encoder};
use tokio::net::{
    tcp::{ConnectFuture, Incoming},
    TcpListener, TcpStream,
};
use yamux::session::SessionType;

use crate::sessions::{ProtocolId, ProtocolMeta, Session, SessionEvent, SessionId, StreamId};

/// All functions on this trait will block the entire server running, do not insert long-time tasks,
/// you can use the futures task instead.
pub trait ServiceHandle {
    fn error_handle(&mut self, _control: &mut ServiceContext, _error: ServiceEvent) {}

    fn session_handle(&mut self, _control: &mut ServiceContext, _event: ServiceEvent) {}
}

/// All functions on this trait will block the entire server running, do not insert long-time tasks,
/// you can use the futures task instead.
pub trait ProtocolHandle {
    fn received(&mut self, _control: &mut ServiceContext, _data: Message) {}

    fn opened(
        &mut self,
        _control: &mut ServiceContext,
        _session_id: SessionId,
        _stream_id: StreamId,
    ) {
    }

    fn closed(
        &mut self,
        _control: &mut ServiceContext,
        _session_id: SessionId,
        _stream_id: StreamId,
    ) {
    }
}

#[derive(Debug)]
pub struct Message {
    pub id: SessionId,
    pub proto_id: ProtocolId,
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

// TODO: Need to maintain the network topology map here?
#[derive(Clone)]
pub struct ServiceContext {
    service_event_sender: mpsc::Sender<ServiceTask>,
}

impl ServiceContext {
    fn new(service_event_sender: mpsc::Sender<ServiceTask>) -> Self {
        ServiceContext {
            service_event_sender,
        }
    }

    pub fn dial(&mut self, address: SocketAddr) {
        self.send(ServiceTask::Dial { address })
    }

    pub fn disconnect(&mut self, id: SessionId) {
        self.send(ServiceTask::Disconnect { id })
    }

    pub fn send_message(&mut self, ids: Option<Vec<SessionId>>, message: Message) {
        self.send(ServiceTask::ProtocolMessage { ids, message })
    }

    pub fn future_task(&mut self, task: Box<dyn Future<Item = (), Error = ()> + 'static + Send>) {
        self.send(ServiceTask::FutureTask { task })
    }

    pub fn sender(&mut self) -> &mut mpsc::Sender<ServiceTask> {
        &mut self.service_event_sender
    }

    fn send(&mut self, event: ServiceTask) {
        let _ = self.service_event_sender.try_send(event);
    }
}

#[derive(Debug)]
pub enum ServiceEvent {
    DialerError {
        address: SocketAddr,
        error: io::Error,
    },
    ListenError {
        address: SocketAddr,
        error: io::Error,
    },
    SessionClose {
        id: SessionId,
    },
    SessionOpen {
        id: SessionId,
        address: SocketAddr,
        ty: SessionType,
    },
}

pub enum ServiceTask {
    ProtocolMessage {
        ids: Option<Vec<SessionId>>,
        message: Message,
    },
    FutureTask {
        task: Box<dyn Future<Item = (), Error = ()> + 'static + Send>,
    },
    StreamTask {
        task: Box<dyn Stream<Item = (), Error = ()> + 'static + Send>,
    },
    Disconnect {
        id: SessionId,
    },
    Dial {
        address: SocketAddr,
    },
}

pub struct Service<T, U> {
    protocol_configs: Arc<HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>>,

    sessions: HashMap<SessionId, mpsc::Sender<SessionEvent>>,

    listens: Vec<(SocketAddr, Incoming)>,

    dial: Vec<(SocketAddr, ConnectFuture)>,

    next_session: SessionId,

    handle: T,

    proto_handles: HashMap<(SessionId, ProtocolId), Box<dyn ProtocolHandle + Send + 'static>>,

    /// send events to service, clone to session
    session_event_sender: mpsc::Sender<SessionEvent>,
    /// receive event from service
    session_event_receiver: mpsc::Receiver<SessionEvent>,

    /// external event is passed in from this
    service_context: ServiceContext,
    /// external event receiver
    service_event_receiver: mpsc::Receiver<ServiceTask>,
}

impl<T, U> Service<T, U>
where
    T: ServiceHandle,
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error,
    <U as Encoder>::Error: error::Error,
{
    pub fn new(
        protocol_configs: Arc<HashMap<String, Box<dyn ProtocolMeta<U> + Send + Sync>>>,
        handle: T,
    ) -> Self {
        let (session_event_sender, session_event_receiver) = mpsc::channel(256);
        let (service_event_sender, service_event_receiver) = mpsc::channel(256);
        Service {
            protocol_configs,
            handle,
            sessions: HashMap::default(),
            proto_handles: HashMap::default(),
            listens: Vec::new(),
            dial: Vec::new(),
            next_session: 0,
            session_event_sender,
            session_event_receiver,
            service_context: ServiceContext::new(service_event_sender),
            service_event_receiver,
        }
    }

    pub fn listen(&mut self, address: SocketAddr) -> Result<(), io::Error> {
        let tcp = TcpListener::bind(&address)?;
        self.listens.push((address, tcp.incoming()));
        Ok(())
    }

    pub fn dial(mut self, address: SocketAddr) -> Self {
        let dial = TcpStream::connect(&address);
        self.dial.push((address, dial));
        self
    }

    pub fn send_message(&mut self, message: Message) {
        if let Some(sender) = self.sessions.get_mut(&message.id) {
            let _ = sender.try_send(SessionEvent::ProtocolMessage {
                id: message.id,
                proto_id: message.proto_id,
                data: message.data.into(),
            });
        }
    }

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

    fn broadcast(&mut self, message: Message) {
        debug!(
            "broadcast message, peer number: {}, proto_id: {}",
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

    fn get_proto_handle(
        &self,
        proto_id: ProtocolId,
    ) -> Option<Box<dyn ProtocolHandle + Send + 'static>> {
        let handle = self
            .protocol_configs
            .values()
            .map(|proto| {
                if proto.id() == proto_id {
                    Some(proto.handle())
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
            error!("can't find proto [{}] handle", proto_id);
            None
        }
    }

    fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::SessionClose { id } => {
                let _ = self.sessions.remove(&id);
                self.handle
                    .session_handle(&mut self.service_context, ServiceEvent::SessionClose { id });
            }
            SessionEvent::ProtocolMessage { id, proto_id, data } => {
                debug!(
                    "service receive session [{}] proto [{}] data: {:?}",
                    id, proto_id, data
                );
                if let Some(handle) = self.proto_handles.get_mut(&(id, proto_id)) {
                    handle.received(
                        &mut self.service_context,
                        Message {
                            id,
                            proto_id,
                            data: data.to_vec(),
                        },
                    );
                } else {
                    error!("can't find proto [{}] on protocol message event", proto_id);
                }
            }
            SessionEvent::ProtocolOpen {
                id,
                proto_id,
                stream_id,
            } => {
                if let Some(mut handle) = self.get_proto_handle(proto_id) {
                    handle.opened(&mut self.service_context, id, stream_id);
                    self.proto_handles.insert((id, proto_id), handle);
                } else {
                    error!("can't create proto [{}] handle on protocol open", proto_id);
                }
            }
            SessionEvent::ProtocolClose {
                id,
                proto_id,
                stream_id,
            } => {
                if let Some(mut handle) = self.proto_handles.remove(&(id, proto_id)) {
                    handle.closed(&mut self.service_context, id, stream_id);
                } else {
                    error!("can't find proto [{}] on protocol close event", proto_id);
                }
            }
        }
    }

    fn handle_service_event(&mut self, event: ServiceTask) {
        match event {
            ServiceTask::ProtocolMessage { ids, message } => self.filter_broadcast(ids, message),
            ServiceTask::Dial { address } => {
                let dial = TcpStream::connect(&address);
                self.dial.push((address, dial));
            }
            ServiceTask::Disconnect { id } => {
                if let Some(mut session_sender) = self.sessions.remove(&id) {
                    let _ = session_sender.try_send(SessionEvent::SessionClose { id });
                }
                self.handle
                    .session_handle(&mut self.service_context, ServiceEvent::SessionClose { id });
            }
            ServiceTask::FutureTask { task } => {
                tokio::spawn(task);
            }
            ServiceTask::StreamTask { task } => {
                tokio::spawn(task.for_each(|_| Ok(())));
            }
        }
    }

    fn client_poll(&mut self) -> Option<()> {
        let mut no_ready_client = Vec::new();
        while let Some((address, mut dialer)) = self.dial.pop() {
            match dialer.poll() {
                Ok(Async::Ready(socket)) => {
                    self.next_session += 1;
                    let address = socket.peer_addr().unwrap();
                    let (service_event_sender, service_event_receiver) = mpsc::channel(256);
                    let mut session = Session::new_client(
                        socket,
                        self.session_event_sender.clone(),
                        service_event_receiver,
                        self.next_session,
                        self.protocol_configs.clone(),
                    );
                    self.protocol_configs
                        .keys()
                        .for_each(|name| session.open_proto_stream(name.to_owned()));
                    self.sessions
                        .insert(self.next_session, service_event_sender);

                    tokio::spawn(session.for_each(|_| Ok(())));

                    self.handle.session_handle(
                        &mut self.service_context,
                        ServiceEvent::SessionOpen {
                            id: self.next_session,
                            address,
                            ty: SessionType::Client,
                        },
                    );
                    return Some(());
                }
                Ok(Async::NotReady) => {
                    debug!("client not ready");
                    no_ready_client.push((address, dialer));
                }
                Err(err) => {
                    self.handle.error_handle(
                        &mut self.service_context,
                        ServiceEvent::DialerError {
                            address,
                            error: err,
                        },
                    );
                    return Some(());
                }
            }
        }
        self.dial = no_ready_client;
        None
    }

    fn listen_poll(&mut self) -> Option<bool> {
        for (address, listen) in self.listens.iter_mut() {
            match listen.poll() {
                Ok(Async::Ready(Some(socket))) => {
                    self.next_session += 1;
                    let address = socket.peer_addr().unwrap();
                    let (service_event_sender, service_event_receiver) = mpsc::channel(256);
                    let session = Session::new_server(
                        socket,
                        self.session_event_sender.clone(),
                        service_event_receiver,
                        self.next_session,
                        self.protocol_configs.clone(),
                    );

                    self.sessions
                        .insert(self.next_session, service_event_sender);

                    tokio::spawn(session.for_each(|_| Ok(())));

                    self.handle.session_handle(
                        &mut self.service_context,
                        ServiceEvent::SessionOpen {
                            id: self.next_session,
                            address,
                            ty: SessionType::Server,
                        },
                    );
                    return Some(false);
                }
                Ok(Async::Ready(None)) => {
                    if self.sessions.is_empty() {
                        return Some(true);
                    }
                }
                Ok(Async::NotReady) => (),
                Err(err) => {
                    self.handle.error_handle(
                        &mut self.service_context,
                        ServiceEvent::ListenError {
                            address: *address,
                            error: err,
                        },
                    );
                    return Some(false);
                }
            }
        }
        None
    }
}

impl<T, U> Stream for Service<T, U>
where
    T: ServiceHandle,
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error,
    <U as Encoder>::Error: error::Error,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if let Some(result) = self.listen_poll() {
            if result {
                return Ok(Async::Ready(None));
            } else {
                return Ok(Async::Ready(Some(())));
            }
        }

        if self.client_poll().is_some() {
            return Ok(Async::Ready(Some(())));
        }

        loop {
            match self.session_event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_session_event(event),
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("{:?}", err);
                    break;
                }
            }
        }

        loop {
            match self.service_event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_service_event(event),
                Ok(Async::Ready(None)) => unreachable!(),
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
