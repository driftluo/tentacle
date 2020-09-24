use env_logger;
use log::{debug, info};

use std::time::Duration;

use futures::StreamExt;
use p2p::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, ServiceError, ServiceEvent, TargetProtocol},
    traits::ServiceHandle,
    ProtocolId, SessionId,
};
use tentacle_ping::{Callback, PingHandler};

fn main() {
    env_logger::init();
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    if std::env::args().nth(1) == Some("server".to_string()) {
        debug!("Starting server ......");
        let protocol = create_meta(1.into(), Duration::from_secs(5), Duration::from_secs(15));
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .key_pair(SecioKeyPair::secp256k1_generated())
            .forever(true)
            .build(SimpleHandler {});
        rt.block_on(async move {
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
    } else {
        debug!("Starting client ......");
        let protocol = create_meta(1.into(), Duration::from_secs(5), Duration::from_secs(15));
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .key_pair(SecioKeyPair::secp256k1_generated())
            .forever(true)
            .build(SimpleHandler {});
        rt.block_on(async move {
            service
                .dial(
                    "/ip4/127.0.0.1/tcp/1337".parse().unwrap(),
                    TargetProtocol::All,
                )
                .await
                .unwrap();
            service
                .listen("/ip4/127.0.0.1/tcp/1338".parse().unwrap())
                .await
                .unwrap();
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
    }
}

pub fn create_meta(id: ProtocolId, interval: Duration, timeout: Duration) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            let handle = Box::new(PingHandler::new(interval, timeout, PingCallback {}));
            ProtocolHandle::Callback(handle)
        })
        .build()
}

struct SimpleHandler {}

impl ServiceHandle for SimpleHandler {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        debug!("service error: {:?}", error);
    }

    fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        debug!("service event: {:?}", event);
    }
}

struct PingCallback {}

impl Callback for PingCallback {
    fn received_ping(&mut self, context: ProtocolContextMutRef) {
        info!("received session {:?} ping", context.session.id)
    }
    fn received_pong(&mut self, context: ProtocolContextMutRef, time: Duration) {
        info!(
            "received session {:?} pong on {:?}",
            context.session.id, time
        )
    }
    fn timeout(&mut self, context: &mut ProtocolContext, id: SessionId) {
        context.disconnect(id).unwrap();
    }
    fn unexpected_error(&mut self, context: ProtocolContextMutRef) {
        let id = context.session.id;
        context.disconnect(id).unwrap();
    }
}
