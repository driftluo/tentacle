use bytes::Bytes;
use futures::channel;
use std::thread;
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceError, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
{
    let builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .set_send_buffer_size(1)
        .set_recv_buffer_size(1);

    if secio {
        builder
            .key_pair(SecioKeyPair::secp256k1_generated())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

struct PHandle;

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        if context.session.ty.is_inbound() {
            let data = Bytes::from(vec![0; 1024 * 1024 * 8]);
            loop {
                let _res = context.send_message(data.clone()).await;
            }
        }
    }

    async fn received(&mut self, _context: ProtocolContextMutRef<'_>, _data: bytes::Bytes) {
        thread::sleep(::std::time::Duration::from_secs(10));
    }
}

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle);
                ProtocolHandle::Callback(handle)
            }
        })
        .build()
}

#[derive(Clone)]
pub struct SHandle;

#[async_trait]
impl ServiceHandle for SHandle {
    async fn handle_error(&mut self, _control: &mut ServiceContext, error: ServiceError) {
        match error {
            ServiceError::SessionBlocked { .. } => (),
            e => panic!("Unexpected error: {:?}", e),
        }
    }
}

fn test_large_message(secio: bool) {
    let meta_1 = create_meta(1.into());
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta_1, SHandle);
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            let _res = addr_sender.send(listen_addr);
            service.run().await
        });
    });

    let meta = create_meta(1.into());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut service = create(secio, meta, SHandle);
    rt.block_on(async move {
        let listen_addr = addr_receiver.await.unwrap();
        service
            .dial(listen_addr, TargetProtocol::All)
            .await
            .unwrap();
        service.run().await
    });
}

#[test]
fn test_large_message_with_secio() {
    test_large_message(true)
}

#[test]
fn test_large_message_with_no_secio() {
    test_large_message(false)
}
