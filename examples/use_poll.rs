use tentacle::{
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
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// This example is used to illustrate how to implement the poll interface
/// and use it for inner loop notification
fn main() {
    env_logger::init();
    run()
}

struct SHandle;

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _context: &mut ServiceContext, error: ServiceError) {
        info!("service error: {:?}", error);
    }
    fn handle_event(&mut self, _context: &mut ServiceContext, event: ServiceEvent) {
        info!("service event: {:?}", event);
    }
}

struct PHandle {
    poll_recv: Receiver<()>,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, _context: &mut ProtocolContext) {}

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        _context: &mut ProtocolContext,
    ) -> Poll<Option<()>> {
        match self.poll_recv.poll_next_unpin(cx) {
            Poll::Ready(Some(_)) => {
                info!("get a trick");
                Poll::Ready(Some(()))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
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
    let mut rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let (mut tx, rx) = channel(2);
        let mut service = create_server(rx);
        service
            .listen("/dns4/localhost/tcp/1337".parse().unwrap())
            .await
            .unwrap();
        tokio::spawn(async move {
            loop {
                tokio::time::delay_for(Duration::from_secs(1)).await;
                tx.send(()).await.unwrap();
            }
        });
        loop {
            if service.next().await.is_none() {
                break;
            }
        }
    });
}
