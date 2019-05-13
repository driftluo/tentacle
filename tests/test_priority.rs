use bytes::Bytes;
use futures::prelude::Stream;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    secio::SecioKeyPair,
    service::{DialProtocol, ProtocolHandle, ProtocolMeta, Service},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle,
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

impl ServiceProtocol for PHandle {
    fn init(&mut self, _context: &mut ProtocolContext) {}

    fn connected(&mut self, context: ProtocolContextMutRef, _version: &str) {
        if context.session.ty.is_inbound() {
            for i in 0..1024 {
                if i == 254 {
                    let _ = context.quick_send_message(Bytes::from("high"));
                }
                let _ = context.send_message(Bytes::from("normal"));
            }
        }
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        self.count += 1;
        if data == Bytes::from("high") {
            // We are not sure that the message was sent in the first few,
            // but it will definitely be far ahead of the sending order.
            if self.count <= 200 {
                self.test_result.store(true, Ordering::SeqCst);
            }
            let _ = context.close();
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
                    ProtocolHandle::Neither
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

fn test_priority(secio: bool) {
    let (meta, _) = create_meta(1.into());
    let mut service = create(secio, meta, ());
    let listen_addr = service
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));
    thread::sleep(Duration::from_millis(100));

    let (meta, result) = create_meta(1.into());
    let mut service = create(secio, meta, ());
    service.dial(listen_addr, DialProtocol::All).unwrap();
    let handle_1 = thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));
    handle_1.join().unwrap();

    assert!(result.load(Ordering::SeqCst));
}

#[test]
fn test_priority_with_secio() {
    test_priority(true)
}

#[test]
fn test_priority_with_no_secio() {
    test_priority(false)
}
