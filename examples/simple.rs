use bytes::Bytes;
use env_logger;
use futures::{
    channel::oneshot::{channel, Sender},
    future::select,
    prelude::*,
};
use log::info;
use std::collections::HashMap;
use std::{
    str,
    time::{Duration, Instant},
};
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    secio::SecioKeyPair,
    service::{
        DialProtocol, ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent,
        TargetSession,
    },
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId, SessionId,
};
use tokio::timer::{self, Interval};

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            // All protocol use the same handle.
            // This is just an example. In the actual environment, this should be a different handle.
            let handle = Box::new(PHandle {
                count: 0,
                connected_session_ids: Vec::new(),
                clear_handle: HashMap::new(),
            });
            ProtocolHandle::Callback(handle)
        })
        .build()
}

#[derive(Default)]
struct PHandle {
    count: usize,
    connected_session_ids: Vec<SessionId>,
    clear_handle: HashMap<SessionId, Sender<()>>,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, context: &mut ProtocolContext) {
        if context.proto_id == 0.into() {
            let _ = context.set_service_notify(0.into(), Duration::from_secs(5), 3);
        }
    }

    fn connected(&mut self, context: ProtocolContextMutRef, version: &str) {
        let session = context.session;
        self.connected_session_ids.push(session.id);
        info!(
            "proto id [{}] open on session [{}], address: [{}], type: [{:?}], version: {}",
            context.proto_id, session.id, session.address, session.ty, version
        );
        info!("connected sessions are: {:?}", self.connected_session_ids);

        if context.proto_id != 1.into() {
            return;
        }

        // Register a scheduled task to send data to the remote peer.
        // Clear the task via channel when disconnected
        let (sender, receiver) = channel();
        self.clear_handle.insert(session.id, sender);
        let session_id = session.id;
        let interval_sender = context.control().clone();

        let interval_send_task = async move {
            let mut interval = Interval::new(Instant::now(), Duration::from_secs(5));
            loop {
                match interval.next().await {
                    Some(_) => {
                        let _ = interval_sender.send_message_to(
                            session_id,
                            1.into(),
                            Bytes::from("I am a interval message"),
                        );
                    }
                    None => break,
                }
            }
        };

        let task = select(receiver, interval_send_task.boxed());

        let _ = context.future_task(async move {
            task.await;
        });
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        let new_list = self
            .connected_session_ids
            .iter()
            .filter(|&id| id != &context.session.id)
            .cloned()
            .collect();
        self.connected_session_ids = new_list;

        if let Some(handle) = self.clear_handle.remove(&context.session.id) {
            let _ = handle.send(());
        }

        info!(
            "proto id [{}] close on session [{}]",
            context.proto_id, context.session.id
        );
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        self.count += 1;
        info!(
            "received from [{}]: proto [{}] data {:?}, message count: {}",
            context.session.id,
            context.proto_id,
            str::from_utf8(data.as_ref()).unwrap(),
            self.count
        );
    }

    fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        info!(
            "proto [{}] received notify token: {}",
            context.proto_id, token
        );
    }
}

struct SHandle;

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _context: &mut ServiceContext, error: ServiceError) {
        info!("service error: {:?}", error);
    }
    fn handle_event(&mut self, context: &mut ServiceContext, event: ServiceEvent) {
        info!("service event: {:?}", event);
        if let ServiceEvent::SessionOpen { .. } = event {
            let delay_sender = context.control().clone();

            let _ = context.future_task(async move {
                timer::delay(Instant::now() + Duration::from_secs(3)).await;
                let _ = delay_sender.filter_broadcast(
                    TargetSession::All,
                    0.into(),
                    Bytes::from("I am a delayed message"),
                );
            });
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

fn create_server() -> Service<SHandle> {
    ServiceBuilder::default()
        .insert_protocol(create_meta(0.into()))
        .insert_protocol(create_meta(1.into()))
        .key_pair(SecioKeyPair::secp256k1_generated())
        .build(SHandle)
}

/// Proto 0 open success
/// Proto 1 open success
/// Proto 2 open failure
///
/// Because server only supports 0,1
fn create_client() -> Service<SHandle> {
    ServiceBuilder::default()
        .insert_protocol(create_meta(0.into()))
        .insert_protocol(create_meta(1.into()))
        .insert_protocol(create_meta(2.into()))
        .key_pair(SecioKeyPair::secp256k1_generated())
        .build(SHandle)
}

fn server() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.spawn(async {
        let mut service = create_server();
        service
            .listen("/ip4/127.0.0.1/tcp/1337".parse().unwrap())
            .await
            .unwrap();
        loop {
            if service.next().await.is_none() {
                break;
            }
        }
    });

    rt.shutdown_on_idle();
}

fn client() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.spawn(async {
        let mut service = create_client();
        service
            .dial(
                "/dns4/localhost/tcp/1337".parse().unwrap(),
                DialProtocol::All,
            )
            .await
            .unwrap();
        loop {
            if service.next().await.is_none() {
                break;
            }
        }
    });

    rt.shutdown_on_idle();
}
