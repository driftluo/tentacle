use bytes::Bytes;
use futures::channel;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
{
    let builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true);

    if secio {
        builder
            .key_pair(SecioKeyPair::secp256k1_generated())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

struct PHandle {
    count: usize,
    test_result: Arc<AtomicBool>,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        if context.session.ty.is_inbound() {
            for i in 0..1024 {
                if i == 254 {
                    let _res = context.quick_send_message(Bytes::from("high")).await;
                }
                let _res = context.send_message(Bytes::from("normal")).await;
            }
        }
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        self.count += 1;
        if data == *"high" {
            // We are not sure that the message was sent in the first few,
            // but it will definitely be far ahead of the sending order.
            if self.count <= 255 {
                self.test_result.store(true, Ordering::SeqCst);
            }
            let _res = context.close().await;
        }
    }
}

fn create_meta(id: ProtocolId) -> (ProtocolMeta, Arc<AtomicBool>) {
    let test_result = Arc::new(AtomicBool::new(false));
    let clone_result = test_result.clone();
    (
        MetaBuilder::new()
            .id(id)
            .service_handle(move || {
                if id == 0.into() {
                    ProtocolHandle::None
                } else {
                    let handle = Box::new(PHandle {
                        count: 0,
                        test_result: clone_result,
                    });
                    ProtocolHandle::Callback(handle)
                }
            })
            .build(),
        test_result,
    )
}

fn test_priority(secio: bool, addr: &'static str) {
    let (meta, _) = create_meta(1.into());
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta, ());
        rt.block_on(async move {
            let listen_addr = service.listen(addr.parse().unwrap()).await.unwrap();
            let _res = addr_sender.send(listen_addr);
            service.run().await
        });
    });

    let (meta, result) = create_meta(1.into());

    let handle_1 = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta, ());
        rt.block_on(async move {
            let listen_addr = addr_receiver.await.unwrap();
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();
            service.run().await
        });
    });
    handle_1.join().unwrap();

    assert!(result.load(Ordering::SeqCst));
}

#[test]
fn test_priority_with_secio_tcp() {
    test_priority(true, "/ip4/127.0.0.1/tcp/0")
}

#[test]
fn test_priority_with_no_secio_tcp() {
    test_priority(false, "/ip4/127.0.0.1/tcp/0")
}

#[test]
#[cfg(feature = "ws")]
fn test_priority_with_secio_ws() {
    test_priority(true, "/ip4/127.0.0.1/tcp/0/ws")
}

#[test]
#[cfg(feature = "ws")]
fn test_priority_with_no_secio_ws() {
    test_priority(false, "/ip4/127.0.0.1/tcp/0/ws")
}

#[test]
fn test_priority_with_secio_mem() {
    test_priority(true, "/memory/0")
}

#[test]
fn test_priority_with_no_secio_mem() {
    test_priority(false, "/memory/0")
}
