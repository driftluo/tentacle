use futures::StreamExt;
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

use std::{sync::mpsc::channel, thread, time::Duration};

pub fn create<F>(secio: bool, metas: impl Iterator<Item = ProtocolMeta>, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
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
        let _ = context.send_message(bytes::Bytes::from("hello"));
        if context.session.ty.is_inbound() && context.proto_id == 1.into() {
            self.count += 1;
            if self.count >= 4 {
                let proto_id = context.proto_id;
                let _ = context.set_service_notify(proto_id, Duration::from_secs(2), 0);
            }
        }
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        let _ = context.send_message(data);
    }

    fn notify(&mut self, context: &mut ProtocolContext, _token: u64) {
        self.count += 1;
        if self.count > 6 {
            if self.shutdown {
                let _ = context.shutdown();
            } else {
                let _ = context.close();
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
    let service_2 = create(
        secio,
        vec![
            create_meta(0.into(), shutdown),
            create_meta(1.into(), shutdown),
            create_meta(2.into(), shutdown),
        ]
        .into_iter(),
        (),
    );
    let service_3 = create(
        secio,
        vec![
            create_meta(0.into(), shutdown),
            create_meta(1.into(), shutdown),
            create_meta(2.into(), shutdown),
        ]
        .into_iter(),
        (),
    );
    let service_4 = create(
        secio,
        vec![
            create_meta(0.into(), shutdown),
            create_meta(1.into(), shutdown),
            create_meta(2.into(), shutdown),
        ]
        .into_iter(),
        (),
    );
    let service_5 = create(
        secio,
        vec![
            create_meta(0.into(), shutdown),
            create_meta(1.into(), shutdown),
            create_meta(2.into(), shutdown),
        ]
        .into_iter(),
        (),
    );

    let (addr_sender, addr_receiver) = channel::<Multiaddr>();

    let handle = thread::spawn(|| {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listen_addr = service_1
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();

            addr_sender.send(listen_addr).unwrap();

            loop {
                if service_1.next().await.is_none() {
                    break;
                }
            }
        });
    });

    let listen_addr = addr_receiver.recv().unwrap();

    let listen_addr_2 = listen_addr.clone();
    let listen_addr_3 = listen_addr.clone();
    let listen_addr_4 = listen_addr.clone();

    start_service(service_2, listen_addr_2);
    start_service(service_3, listen_addr_3);
    start_service(service_4, listen_addr_4);
    start_service(service_5, listen_addr);

    handle.join().expect("test fail");
}

fn start_service<F>(
    mut service: Service<F>,
    listen_addr: Multiaddr,
) -> ::std::thread::JoinHandle<()>
where
    F: ServiceHandle + Unpin + Send + 'static,
{
    thread::spawn(move || {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();

            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
    })
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
