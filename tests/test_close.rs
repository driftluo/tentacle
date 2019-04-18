use futures::prelude::Stream;
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    secio::SecioKeyPair,
    service::{DialProtocol, ProtocolHandle, ProtocolMeta, Service},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

use std::{thread, time::Duration};

pub fn create<F>(secio: bool, metas: impl Iterator<Item = ProtocolMeta>, shandle: F) -> Service<F>
where
    F: ServiceHandle,
{
    let mut builder = ServiceBuilder::default().forever(true);

    for meta in metas {
        builder = builder.insert_protocol(meta);
    }

    if secio {
        builder
            .key_pair(SecioKeyPair::secp256k1_generated())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

struct PHandle {
    count: u8,
    shutdown: bool,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, _context: &mut ProtocolContext) {}

    fn connected(&mut self, context: ProtocolContextMutRef, _version: &str) {
        if context.session.ty.is_inbound() && context.proto_id == 1.into() {
            context.send_message(b"hello".to_vec());
            self.count += 1;
            if self.count >= 4 {
                let proto_id = context.proto_id;
                context.set_service_notify(proto_id, Duration::from_secs(2), 0);
            }
        }
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        context.send_message(data.to_vec());
    }

    fn notify(&mut self, context: &mut ProtocolContext, _token: u64) {
        self.count += 1;
        if self.count > 6 {
            if self.shutdown {
                context.shutdown();
            } else {
                context.close();
            }
        }
    }
}

fn create_meta(id: ProtocolId, shutdown: bool) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            let handle = Box::new(PHandle { count: 0, shutdown });
            ProtocolHandle::Callback(handle)
        })
        .build()
}

fn test(secio: bool, shutdown: bool) {
    let mut service_1 = create(
        secio,
        vec![
            create_meta(0.into(), shutdown),
            create_meta(1.into(), shutdown),
            create_meta(2.into(), shutdown),
        ]
        .into_iter(),
        (),
    );
    let mut service_2 = create(
        secio,
        vec![
            create_meta(0.into(), shutdown),
            create_meta(1.into(), shutdown),
            create_meta(2.into(), shutdown),
        ]
        .into_iter(),
        (),
    );
    let mut service_3 = create(
        secio,
        vec![
            create_meta(0.into(), shutdown),
            create_meta(1.into(), shutdown),
            create_meta(2.into(), shutdown),
        ]
        .into_iter(),
        (),
    );
    let mut service_4 = create(
        secio,
        vec![
            create_meta(0.into(), shutdown),
            create_meta(1.into(), shutdown),
            create_meta(2.into(), shutdown),
        ]
        .into_iter(),
        (),
    );
    let mut service_5 = create(
        secio,
        vec![
            create_meta(0.into(), shutdown),
            create_meta(1.into(), shutdown),
            create_meta(2.into(), shutdown),
        ]
        .into_iter(),
        (),
    );

    let listen_addr = service_1
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    let handle = thread::spawn(|| tokio::run(service_1.for_each(|_| Ok(()))));

    service_2
        .dial(listen_addr.clone(), DialProtocol::All)
        .unwrap();
    service_3
        .dial(listen_addr.clone(), DialProtocol::All)
        .unwrap();
    service_4
        .dial(listen_addr.clone(), DialProtocol::All)
        .unwrap();
    service_5.dial(listen_addr, DialProtocol::All).unwrap();

    thread::spawn(|| tokio::run(service_2.for_each(|_| Ok(()))));
    thread::spawn(|| tokio::run(service_3.for_each(|_| Ok(()))));
    thread::spawn(|| tokio::run(service_4.for_each(|_| Ok(()))));
    thread::spawn(|| tokio::run(service_5.for_each(|_| Ok(()))));

    handle.join().expect("test fail");
}

#[test]
fn test_close_with_secio() {
    test(true, false)
}

#[test]
fn test_close_with_no_secio() {
    test(false, false)
}

#[test]
fn test_shutdown_with_secio() {
    test(true, true)
}

#[test]
fn test_shutdown_with_no_secio() {
    test(false, true)
}
