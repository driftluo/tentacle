use env_logger;
use futures::{oneshot, prelude::*, sync::oneshot::Sender};
use log::info;
use p2p::{
    builder::ServiceBuilder,
    context::{ServiceContext, SessionContext},
    service::{Service, ServiceError, ServiceEvent},
    traits::{ProtocolMeta, ServiceHandle, ServiceProtocol},
    ProtocolId, SecioKeyPair, SessionId,
};
use std::collections::HashMap;
use std::{
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

    fn service_handle(&self) -> Option<Box<dyn ServiceProtocol + Send + 'static>> {
        // All protocol use the same handle.
        // This is just an example. In the actual environment, this should be a different handle.
        let handle = Box::new(PHandle {
            proto_id: self.id,
            count: 0,
            connected_session_ids: Vec::new(),
            clear_handle: HashMap::new(),
        });
        Some(handle)
    }
}

#[derive(Default)]
struct PHandle {
    proto_id: ProtocolId,
    count: usize,
    connected_session_ids: Vec<SessionId>,
    clear_handle: HashMap<SessionId, Sender<()>>,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, control: &mut ServiceContext) {
        if self.proto_id == 0 {
            control.set_service_notify(0, Duration::from_secs(5), 3);
        }
    }

    fn connected(&mut self, control: &mut ServiceContext, session: &SessionContext, version: &str) {
        self.connected_session_ids.push(session.id);
        info!(
            "proto id [{}] open on session [{}], address: [{}], type: [{:?}], version: {}",
            self.proto_id, session.id, session.address, session.ty, version
        );
        info!("connected sessions are: {:?}", self.connected_session_ids);

        if self.proto_id != 1 {
            return;
        }

        // Register a scheduled task to send data to the remote peer.
        // Clear the task via channel when disconnected
        let (sender, mut receiver) = oneshot();
        self.clear_handle.insert(session.id, sender);
        let session_id = session.id;
        let mut interval_sender = control.control().clone();
        let interval_task = Interval::new(Instant::now(), Duration::from_secs(5))
            .for_each(move |_| {
                let _ = interval_sender.send_message(
                    Some(vec![session_id]),
                    1,
                    b"I am a interval message".to_vec(),
                );
                if let Ok(Async::Ready(_)) = receiver.poll() {
                    Err(Error::shutdown())
                } else {
                    Ok(())
                }
            })
            .map_err(|err| info!("{}", err));
        let _ = control.future_task(interval_task);
    }

    fn disconnected(&mut self, _control: &mut ServiceContext, session: &SessionContext) {
        let new_list = self
            .connected_session_ids
            .iter()
            .filter(|&id| id != &session.id)
            .cloned()
            .collect();
        self.connected_session_ids = new_list;

        if let Some(handle) = self.clear_handle.remove(&session.id) {
            let _ = handle.send(());
        }

        info!(
            "proto id [{}] close on session [{}]",
            self.proto_id, session.id
        );
    }

    fn received(&mut self, _env: &mut ServiceContext, session: &SessionContext, data: Vec<u8>) {
        self.count += 1;
        info!(
            "received from [{}]: proto [{}] data {:?}, message count: {}",
            session.id,
            self.proto_id,
            str::from_utf8(&data).unwrap(),
            self.count
        );
    }

    fn notify(&mut self, _control: &mut ServiceContext, token: u64) {
        info!("proto [{}] received notify token: {}", self.proto_id, token);
    }
}

struct SHandle;

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        info!("service error: {:?}", error);
    }
    fn handle_event(&mut self, env: &mut ServiceContext, event: ServiceEvent) {
        info!("service event: {:?}", event);
        if let ServiceEvent::SessionOpen { .. } = event {
            let mut delay_sender = env.control().clone();

            let delay_task = Delay::new(Instant::now() + Duration::from_secs(3))
                .and_then(move |_| {
                    let _ = delay_sender.send_message(None, 0, b"I am a delayed message".to_vec());
                    Ok(())
                })
                .map_err(|err| info!("{}", err));

            let _ = env.future_task(Box::new(delay_task));
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
        .key_pair(SecioKeyPair::secp256k1_generated())
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
        .key_pair(SecioKeyPair::secp256k1_generated())
        .build(SHandle)
}

fn server() {
    let mut service = create_server();
    let _ = service.listen(&"/ip4/127.0.0.1/tcp/1337".parse().unwrap());

    tokio::run(service.for_each(|_| Ok(())))
}

fn client() {
    let mut service = create_client();
    let _ = service.dial("/ip4/127.0.0.1/tcp/1337".parse().unwrap());
    let _ = service.listen(&"/ip4/127.0.0.1/tcp/1337".parse().unwrap());

    tokio::run(service.for_each(|_| Ok(())))
}
