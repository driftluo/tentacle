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
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, _context: &mut ProtocolContext) {}

    fn connected(&mut self, mut context: ProtocolContextMutRef, _version: &str) {
        if context.session.ty.is_inbound() && context.proto_id == 1.into() {
            self.count += 1;
            if self.count >= 4 {
                let proto_id = context.proto_id;
                context.set_service_notify(proto_id, Duration::from_secs(2), 0);
            }
        }
    }

    fn notify(&mut self, context: &mut ProtocolContext, _token: u64) {
        self.count += 1;
        if self.count > 6 {
            context.shutdown();
        }
    }
}

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            let handle = Box::new(PHandle { count: 0 });
            ProtocolHandle::Callback(handle)
        })
        .build()
}

fn test_close(secio: bool) {
    let mut service_1 = create(
        secio,
        vec![
            create_meta(0.into()),
            create_meta(1.into()),
            create_meta(2.into()),
        ]
        .into_iter(),
        (),
    );
    let mut service_2 = create(
        secio,
        vec![
            create_meta(0.into()),
            create_meta(1.into()),
            create_meta(2.into()),
        ]
        .into_iter(),
        (),
    );
    let mut service_3 = create(
        secio,
        vec![
            create_meta(0.into()),
            create_meta(1.into()),
            create_meta(2.into()),
        ]
        .into_iter(),
        (),
    );
    let mut service_4 = create(
        secio,
        vec![
            create_meta(0.into()),
            create_meta(1.into()),
            create_meta(2.into()),
        ]
        .into_iter(),
        (),
    );
    let mut service_5 = create(
        secio,
        vec![
            create_meta(0.into()),
            create_meta(1.into()),
            create_meta(2.into()),
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
    test_close(true)
}

#[test]
fn test_close_with_no_secio() {
    test_close(false)
}
