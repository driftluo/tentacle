use env_logger;
use futures::{oneshot, prelude::*, sync::oneshot::Sender};
use log::info;
use p2p::{
    builder::ServiceBuilder,
    service::{
        Message, ProtocolHandle, Service, ServiceContext, ServiceEvent, ServiceHandle, ServiceTask,
    },
    session::{ProtocolId, ProtocolMeta, SessionId},
    SessionType,
};
use std::collections::HashMap;
use std::{
    net::SocketAddr,
    str,
    time::{Duration, Instant},
};
use tokio::codec::length_delimited::LengthDelimitedCodec;
use tokio::timer::{Delay, Error, Interval};

pub struct Protocol {
    id: ProtocolId,
}

impl Protocol {
    fn new(id: ProtocolId) -> Self {
        Protocol { id }
    }
}

impl ProtocolMeta<LengthDelimitedCodec> for Protocol {
    fn id(&self) -> ProtocolId {
        self.id
    }
    fn codec(&self) -> LengthDelimitedCodec {
        LengthDelimitedCodec::new()
    }
    fn handle(&self) -> Option<Box<dyn ProtocolHandle + Send + 'static>> {
        // All protocol use the same handle.
        // This is just an example. In the actual environment, this should be a different handle.
        Some(Box::new(PHandle {
            proto_id: self.id,
            count: 0,
            connected_session_ids: Vec::new(),
            clear_handle: HashMap::new(),
        }))
    }
}

#[derive(Default)]
struct PHandle {
    proto_id: ProtocolId,
    count: usize,
    connected_session_ids: Vec<SessionId>,
    clear_handle: HashMap<SessionId, Sender<()>>,
}

impl ProtocolHandle for PHandle {
    fn init(&mut self, control: &mut ServiceContext) {
        if self.proto_id == 0 {
            let mut interval_sender = control.sender().clone();
            let proto_id = self.proto_id;
            let interval_task = Interval::new(Instant::now(), Duration::from_secs(5))
                .for_each(move |_| {
                    match interval_sender
                        .try_send(ServiceTask::ProtocolNotify { proto_id, token: 3 })
                    {
                        Ok(_) => Ok(()),
                        Err(_) => Err(Error::shutdown()),
                    }
                })
                .map_err(|err| info!("{}", err));
            control.future_task(interval_task);
        }
    }

    fn connected(
        &mut self,
        control: &mut ServiceContext,
        session_id: SessionId,
        address: SocketAddr,
        ty: SessionType,
    ) {
        self.connected_session_ids.push(session_id);
        info!(
            "proto id [{}] open on session [{}], address: [{}], type: [{:?}]",
            self.proto_id, session_id, address, ty
        );
        info!("connected sessions are: {:?}", self.connected_session_ids);

        if self.proto_id != 1 {
            return;
        }

        // Register a scheduled task to send data to the remote peer.
        // Clear the task via channel when disconnected
        let (sender, mut receiver) = oneshot();
        self.clear_handle.insert(session_id, sender);
        let mut interval_sender = control.sender().clone();
        let interval_task = Interval::new(Instant::now(), Duration::from_secs(5))
            .for_each(move |_| {
                let _ = interval_sender.try_send(ServiceTask::ProtocolMessage {
                    ids: Some(vec![session_id]),
                    message: Message {
                        id: 0,
                        proto_id: 1,
                        data: b"I am a interval message".to_vec(),
                    },
                });
                if let Ok(Async::Ready(_)) = receiver.poll() {
                    Err(Error::shutdown())
                } else {
                    Ok(())
                }
            })
            .map_err(|err| info!("{}", err));
        control.future_task(interval_task);
    }

    fn disconnected(&mut self, _control: &mut ServiceContext, session_id: SessionId) {
        let new_list = self
            .connected_session_ids
            .iter()
            .filter(|&id| id != &session_id)
            .cloned()
            .collect();
        self.connected_session_ids = new_list;

        if let Some(handle) = self.clear_handle.remove(&session_id) {
            let _ = handle.send(());
        }

        info!(
            "proto id [{}] close on session [{}]",
            self.proto_id, session_id
        );
    }

    fn received(&mut self, _env: &mut ServiceContext, data: Message) {
        self.count += 1;
        info!(
            "received from [{}]: proto [{}] data {:?}, message count: {}",
            data.id,
            data.proto_id,
            str::from_utf8(&data.data).unwrap(),
            self.count
        );
    }

    fn notify(&mut self, _control: &mut ServiceContext, token: u64) {
        info!("proto [{}] received notify token: {}", self.proto_id, token);
    }
}

struct SHandle;

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceEvent) {
        info!("service error: {:?}", error);
    }
    fn handle_event(&mut self, env: &mut ServiceContext, event: ServiceEvent) {
        info!("service event: {:?}", event);
        if let ServiceEvent::SessionOpen { id, .. } = event {
            let mut delay_sender = env.sender().clone();

            let delay_task = Delay::new(Instant::now() + Duration::from_secs(3))
                .and_then(move |_| {
                    let _ = delay_sender.try_send(ServiceTask::ProtocolMessage {
                        ids: None,
                        message: Message {
                            id,
                            proto_id: 0,
                            data: b"I am a delayed message".to_vec(),
                        },
                    });
                    Ok(())
                })
                .map_err(|err| info!("{}", err));

            env.future_task(Box::new(delay_task));
        }
    }
}

fn main() {
    env_logger::init();

    if std::env::args().nth(1) == Some("server".to_string()) {
        info!("Starting server ......");
        server();
    } else {
        info!("Starting client ......");
        client();
    }
}

fn create_server() -> Service<SHandle, LengthDelimitedCodec> {
    ServiceBuilder::default()
        .insert_protocol(Protocol::new(0))
        .insert_protocol(Protocol::new(1))
        .build(SHandle)
}

/// Proto 0 open success
/// Proto 1 open success
/// Proto 2 open failure
///
/// Because server only supports 0,1
fn create_client() -> Service<SHandle, LengthDelimitedCodec> {
    ServiceBuilder::default()
        .insert_protocol(Protocol::new(0))
        .insert_protocol(Protocol::new(1))
        .insert_protocol(Protocol::new(2))
        .build(SHandle)
}

fn server() {
    let mut service = create_server();
    let _ = service.listen("127.0.0.1:1337".parse().unwrap());

    tokio::run(service.for_each(|_| Ok(())))
}

fn client() {
    let mut service = create_client().dial("127.0.0.1:1337".parse().unwrap());
    let _ = service.listen("127.0.0.1:1337".parse().unwrap());

    tokio::run(service.for_each(|_| Ok(())))
}
