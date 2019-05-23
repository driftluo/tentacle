use bytes::Bytes;
use futures::prelude::Stream;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
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
    let builder = ServiceBuilder::default().insert_protocol(meta);

    if secio {
        builder
            .key_pair(SecioKeyPair::secp256k1_generated())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

struct PHandle;

impl ServiceProtocol for PHandle {
    fn init(&mut self, _context: &mut ProtocolContext) {}

    fn connected(&mut self, context: ProtocolContextMutRef, _version: &str) {
        if context.session.ty.is_inbound() {
            let prefix = "x".repeat(10);
            let _ = context.send_message(Bytes::from(prefix));
        }
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        let _ = context.shutdown();
    }

    fn received(&mut self, context: ProtocolContextMutRef, _data: Bytes) {
        if context.session.ty.is_outbound() {
            let _ = context.shutdown();
        }
    }
}

fn create_meta(id: ProtocolId) -> (ProtocolMeta, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();
    let count_clone_1 = count.clone();
    let meta = MetaBuilder::new()
        .id(id)
        .before_send(move |data| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            data
        })
        .before_receive(move || {
            let count = count_clone_1.clone();
            Some(Box::new(move |data: bytes::BytesMut| {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(data.freeze())
            }))
        });

    (
        meta.service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::Neither
            } else {
                let handle = Box::new(PHandle);
                ProtocolHandle::Callback(handle)
            }
        })
        .build(),
        count,
    )
}

fn test_before_handle(secio: bool) {
    let (meta, result_1) = create_meta(1.into());
    let mut service = create(secio, meta, ());
    let listen_addr = service
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));
    thread::sleep(Duration::from_millis(100));

    let (meta, result_2) = create_meta(1.into());
    let mut service = create(secio, meta, ());
    service.dial(listen_addr, DialProtocol::All).unwrap();
    let handle_2 = thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));
    handle_2.join().unwrap();

    assert_eq!(result_1.load(Ordering::SeqCst), 1);
    assert_eq!(result_2.load(Ordering::SeqCst), 1);
}

#[test]
fn test_before_with_secio() {
    test_before_handle(true)
}

#[test]
fn test_before_with_no_secio() {
    test_before_handle(false)
}
