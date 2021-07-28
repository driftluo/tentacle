use bytes::Bytes;
use log::info;
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, SessionType,
        TargetProtocol,
    },
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId, SessionId,
};

struct PHandle {
    sessions: HashMap<SessionId, SessionType>,
    count: usize,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, context: &mut ProtocolContext) {
        let proto_id = context.proto_id;
        let _ = context
            .set_service_notify(proto_id, Duration::from_millis(10), 0)
            .await;
        let _ = context
            .set_service_notify(proto_id, Duration::from_millis(40), 1)
            .await;
    }

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        info!(
            "Session open: {:?} {}",
            context.session.id, context.session.address
        );
        self.sessions.insert(context.session.id, context.session.ty);
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        log::warn!(
            "Session close: {:?} {}",
            context.session.id,
            context.session.address
        );
        self.sessions.remove(&context.session.id);
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, _data: Bytes) {
        let session_type = context.session.ty;
        let session_id = context.session.id;
        if session_type.is_outbound() {
            thread::sleep(Duration::from_millis(30));
            info!("> [Client] received {}", self.count);
            self.count += 1;
            if self.count + 1 == 512 {
                let _ = context.shutdown().await;
            }
        } else {
            // thread::sleep(Duration::from_millis(20));
            info!("> [Server] received from {:?}", session_id);
        }
    }

    async fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
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
                    let _ = context.send_message_to(*session_id, proto_id, data).await;
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
                    let _ = context.send_message_to(*session_id, proto_id, data).await;
                }
            }
            _ => {}
        }
    }
}

struct SHandle;

#[async_trait]
impl ServiceHandle for SHandle {
    async fn handle_error(&mut self, _context: &mut ServiceContext, error: ServiceError) {
        info!("service error: {:?}", error);
    }
    async fn handle_event(&mut self, _context: &mut ServiceContext, event: ServiceEvent) {
        info!("service event: {:?}", event);
    }
}

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
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
                ProtocolHandle::None
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
    let rt = tokio::runtime::Runtime::new().unwrap();

    if std::env::args().nth(1) == Some("server".to_string()) {
        rt.block_on(async move {
            let meta = create_meta(1.into());
            let mut service = create(true, meta, SHandle);
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/8900".parse().unwrap())
                .await
                .unwrap();
            info!("listen_addr: {}", listen_addr);
            service.run().await
        });
    } else {
        rt.block_on(async move {
            let listen_addr = std::env::args().nth(1).unwrap().parse().unwrap();
            let meta = create_meta(1.into());
            let mut service = create(true, meta, SHandle);
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();
            service.run().await
        });
    }
}
