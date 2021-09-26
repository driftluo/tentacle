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

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        let _res = context.send_message(bytes::Bytes::from("hello")).await;
        if context.session.ty.is_inbound() && context.proto_id == 1.into() {
            self.count += 1;
            if self.count >= 4 {
                let _res = context
                    .set_service_notify(context.proto_id, Duration::from_millis(200), 0)
                    .await;
            }
        }
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        let _res = context.send_message(data).await;
    }

    async fn notify(&mut self, context: &mut ProtocolContext, _token: u64) {
        self.count += 1;
        if self.count > 6 {
            if self.shutdown {
                let _res = context.shutdown().await;
            } else {
                let _res = context.close().await;
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

    let rt = tokio::runtime::Runtime::new().unwrap();
    let async_handle = rt.handle().clone();

    let handle = thread::spawn(move || {
        async_handle.block_on(async move {
            let listen_addr = service_1
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();

            addr_sender.send(listen_addr).unwrap();

            service_1.run().await
        });
    });

    let listen_addr = addr_receiver.recv().unwrap();

    let listen_addr_2 = listen_addr.clone();
    let listen_addr_3 = listen_addr.clone();
    let listen_addr_4 = listen_addr.clone();

    let async_handle = rt.handle();
    start_service(service_2, listen_addr_2, async_handle);
    start_service(service_3, listen_addr_3, async_handle);
    start_service(service_4, listen_addr_4, async_handle);
    start_service(service_5, listen_addr, async_handle);

    handle.join().expect("test fail");
}

fn start_service<F>(
    mut service: Service<F>,
    listen_addr: Multiaddr,
    handle: &tokio::runtime::Handle,
) where
    F: ServiceHandle + Unpin + Send + 'static,
{
    handle.spawn(async move {
        service
            .dial(listen_addr, TargetProtocol::All)
            .await
            .unwrap();

        service.run().await;
    });
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
