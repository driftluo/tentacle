use bytes::Bytes;
use futures::prelude::Stream;
use log::info;
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    secio::SecioKeyPair,
    service::{DialProtocol, ProtocolHandle, ProtocolMeta, Service, SessionType},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId, SessionId,
};

struct PHandle {
    sessions: HashMap<SessionId, SessionType>,
    count: usize,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, context: &mut ProtocolContext) {
        let proto_id = context.proto_id;
        let _ = context.set_service_notify(proto_id, Duration::from_millis(10), 0);
        let _ = context.set_service_notify(proto_id, Duration::from_millis(40), 1);
    }

    fn connected(&mut self, context: ProtocolContextMutRef, _version: &str) {
        info!(
            "Session open: {:?} {}",
            context.session.id, context.session.address
        );
        self.sessions.insert(context.session.id, context.session.ty);
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        log::warn!(
            "Session close: {:?} {}",
            context.session.id,
            context.session.address
        );
        self.sessions.remove(&context.session.id);
    }

    fn received(&mut self, context: ProtocolContextMutRef, _data: Bytes) {
        let session_type = context.session.ty;
        let session_id = context.session.id;
        if session_type.is_outbound() {
            thread::sleep(Duration::from_millis(30));
            info!("> [Client] received {}", self.count);
            self.count += 1;
            if self.count + 1 == 512 {
                let _ = context.shutdown();
            }
        } else {
            // thread::sleep(Duration::from_millis(20));
            info!("> [Server] received from {:?}", session_id);
        }
    }

    fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        let proto_id = context.proto_id;
        match token {
            0 => {
                for session_id in self
                    .sessions
                    .iter()
                    .filter(|(_, session_type)| session_type.is_inbound())
                    .map(|(session_id, _)| session_id)
                {
                    info!("> [Server] send to {:?}", session_id);
                    let prefix = "abcde".repeat(80000);
                    let now = Instant::now();
                    let data = Bytes::from(format!("{:?} - {}", now, prefix));
                    let _ = context.send_message_to(*session_id, proto_id, data);
                }
            }
            1 => {
                for session_id in self
                    .sessions
                    .iter()
                    .filter(|(_, session_type)| session_type.is_outbound())
                    .map(|(session_id, _)| session_id)
                {
                    info!("> [Client] send to {:?}", session_id);
                    let prefix = "xxxx".repeat(20000);
                    let now = Instant::now();
                    let data = Bytes::from(format!("{:?} - {}", now, prefix));
                    let _ = context.send_message_to(*session_id, proto_id, data);
                }
            }
            _ => {}
        }
    }
}

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle,
{
    let builder = ServiceBuilder::default().insert_protocol(meta);

    if secio {
        builder
            .key_pair(SecioKeyPair::secp256k1_generated())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::Neither
            } else {
                let handle = Box::new(PHandle {
                    sessions: HashMap::default(),
                    count: 0,
                });
                ProtocolHandle::Callback(handle)
            }
        })
        .build()
}

fn main() {
    env_logger::init();

    if std::env::args().nth(1) == Some("server".to_string()) {
        let meta = create_meta(1.into());
        let mut service = create(true, meta, ());
        let listen_addr = service
            .listen("/ip4/127.0.0.1/tcp/8900".parse().unwrap())
            .unwrap();
        info!("listen_addr: {}", listen_addr);
        tokio::run(service.for_each(|_| Ok(())));
    } else {
        let listen_addr = std::env::args().nth(1).unwrap().parse().unwrap();
        let meta = create_meta(1.into());
        let mut service = create(true, meta, ());
        service.dial(listen_addr, DialProtocol::All).unwrap();
        tokio::run(service.for_each(|_| Ok(())));
    }
}
