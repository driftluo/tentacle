use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ServiceContext},
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

use futures::{
    channel::mpsc::{channel, Receiver},
    prelude::*,
    StreamExt,
};
use log::info;
use std::time::Duration;

/// This example is used to illustrate how to implement the poll interface
/// and use it for inner loop notification
fn main() {
    env_logger::init();
    run()
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

struct PHandle {
    poll_recv: Receiver<()>,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn poll(&mut self, _context: &mut ProtocolContext) -> Option<()> {
        match self.poll_recv.next().await {
            Some(_) => {
                info!("get a trick");
                Some(())
            }
            None => None,
        }
    }
}

fn create_meta(id: ProtocolId, recv: Receiver<()>) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            // All protocol use the same handle.
            // This is just an example. In the actual environment, this should be a different handle.
            let handle = Box::new(PHandle { poll_recv: recv });
            ProtocolHandle::Callback(handle)
        })
        .build()
}

fn create_server(recv: Receiver<()>) -> Service<SHandle> {
    ServiceBuilder::default()
        .insert_protocol(create_meta(0.into(), recv))
        .key_pair(SecioKeyPair::secp256k1_generated())
        .build(SHandle)
}

fn run() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let (mut tx, rx) = channel(2);
        let mut service = create_server(rx);
        service
            .listen("/dns4/localhost/tcp/1337".parse().unwrap())
            .await
            .unwrap();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                tx.send(()).await.unwrap();
            }
        });
        service.run().await
    });
}
