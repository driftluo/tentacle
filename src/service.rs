use futures::{prelude::*, sync::mpsc};
use log::{warn, debug};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{error, io};
use tokio::codec::{Decoder, Encoder};
use tokio::net::{
    tcp::{ConnectFuture, Incoming},
    TcpListener, TcpStream,
};
use yamux::{session::SessionType, StreamHandle};

use crate::sessions::{ProtocolId, ProtocolUpgrade, SessionEvent, SessionId, SessionManager};

#[derive(Debug)]
pub enum ServiceEvent {
    SessionClose {
        id: SessionId,
    },
    SessionOpen {
        id: SessionId,
        address: SocketAddr,
        ty: SessionType,
    },
    ProtocolMessage {
        id: SessionId,
        proto_id: ProtocolId,
        data: bytes::Bytes,
    },
    ProtocolOpen {
        id: SessionId,
        proto_id: ProtocolId,
    },
    DialerError {
        address: SocketAddr,
        error: io::Error
    },
    ListenError {
        error: io::Error,
    }
}

pub struct Service<U> {
    protocol_configs: Arc<HashMap<String, Box<dyn ProtocolUpgrade<StreamHandle, U> + Send + Sync>>>,

    sessions: HashMap<SessionId, mpsc::Sender<SessionEvent>>,

    listens: Vec<Incoming>,

    dialer: Vec<(SocketAddr, ConnectFuture)>,

    next_session: SessionId,

    /// send events to service
    service_sender: mpsc::Sender<SessionEvent>,
    /// receive event from service
    service_receiver: mpsc::Receiver<SessionEvent>,
}

impl<U> Service<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error,
    <U as Encoder>::Error: error::Error,
{
    pub fn new(
        protocol_configs: Arc<
            HashMap<String, Box<dyn ProtocolUpgrade<StreamHandle, U> + Send + Sync>>,
        >,
    ) -> Self {
        let (service_sender, service_receiver) = mpsc::channel(256);
        Service {
            protocol_configs,
            sessions: HashMap::default(),
            listens: Vec::new(),
            dialer: Vec::new(),
            next_session: 0,
            service_sender,
            service_receiver,
        }
    }

    pub fn listen(&mut self, address: SocketAddr) -> Result<(), io::Error> {
        let tcp = TcpListener::bind(&address)?;
        self.listens.push(tcp.incoming());
        Ok(())
    }

    pub fn dialer(mut self, address: SocketAddr) -> Self {
        let dialer = TcpStream::connect(&address);
        self.dialer.push((address, dialer));
        self
    }

    pub fn send_message(&mut self, session_id: SessionId, proto_id: ProtocolId, data: Vec<u8>) {
        if let Some(send) = self.sessions.get_mut(&session_id) {
            let _ = send.try_send(SessionEvent::ProtocolMessage {
                id: session_id,
                proto_id,
                data: data.into(),
            });
        }
    }

    pub fn broadcast(&mut self, proto_id: ProtocolId, data: Vec<u8>) {
        let data: bytes::Bytes = data.into();
        self.sessions.iter_mut().for_each(|(id, send)| {
            let _ = send.try_send(SessionEvent::ProtocolMessage {
                id: *id,
                proto_id,
                data: data.clone(),
            });
        });
    }

    fn handle_session_event(&mut self, event: SessionEvent) -> Option<ServiceEvent> {
        match event {
            SessionEvent::SessionClose { id } => {
                let _ = self.sessions.remove(&id);
                Some(ServiceEvent::SessionClose { id })
            }
            SessionEvent::ProtocolMessage { id, proto_id, data } => {
                Some(ServiceEvent::ProtocolMessage { id, proto_id, data })
            }
            SessionEvent::ProtocolOpen { id, proto_id } => {
                Some(ServiceEvent::ProtocolOpen { id, proto_id })
            }
        }
    }
}

impl<U> Stream for Service<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error,
    <U as Encoder>::Error: error::Error,
{
    type Item = ServiceEvent;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        for listen in self.listens.iter_mut() {
            match listen.poll()? {
                Async::Ready(Some(socket)) => {
                    self.next_session += 1;
                    let address = socket.peer_addr().unwrap();
                    let (service_sender, service_receiver) = mpsc::channel(256);
                    let session = SessionManager::new_server(
                        socket,
                        self.service_sender.clone(),
                        service_receiver,
                        self.next_session,
                        self.protocol_configs.clone(),
                    );

                    self.sessions.insert(self.next_session, service_sender);

                    tokio::spawn(session.for_each(|_| Ok(())));

                    return Ok(Async::Ready(Some(ServiceEvent::SessionOpen {
                        id: self.next_session,
                        address,
                        ty: SessionType::Server,
                    })));
                }
                Async::Ready(None) => (),
                Async::NotReady => (),
            }
        }

        let mut no_ready_client = Vec::new();
        while let Some((address, mut dialer)) = self.dialer.pop() {
            match dialer.poll() {
                Ok(Async::Ready(socket)) => {
                    self.next_session += 1;
                    let address = socket.peer_addr().unwrap();
                    let (service_sender, service_receiver) = mpsc::channel(256);
                    let mut session = SessionManager::new_client(
                        socket,
                        self.service_sender.clone(),
                        service_receiver,
                        self.next_session,
                        self.protocol_configs.clone(),
                    );
                    self.protocol_configs.keys().for_each(|name| {
                        session.open_proto_stream(name.to_owned())
                    });
                    self.sessions.insert(self.next_session, service_sender);

                    tokio::spawn(session.for_each(|_| Ok(())));
                    return Ok(Async::Ready(Some(ServiceEvent::SessionOpen {
                        id: self.next_session,
                        address,
                        ty: SessionType::Client,
                    })));
                }
                Ok(Async::NotReady) => {
                    debug!("client not ready");
                    no_ready_client.push((address, dialer));
                },
                Err(err) => {
                    return Ok(Async::Ready(Some(ServiceEvent::DialerError {address, error: err})))
                }
            }
        }
        self.dialer = no_ready_client;

        loop {
            match self.service_receiver.poll() {
                Ok(Async::Ready(Some(event))) => match self.handle_session_event(event) {
                    Some(event) => return Ok(Async::Ready(Some(event))),
                    None => (),
                },
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
