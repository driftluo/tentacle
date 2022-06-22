use futures::channel;
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    bytes::Bytes,
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

struct PHandle;

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        if context.session.ty.is_inbound() {
            let prefix = "x".repeat(10);
            let _res = context.send_message(Bytes::from(prefix)).await;
        }
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        let _res = context.shutdown().await;
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, _data: Bytes) {
        if context.session.ty.is_outbound() {
            let _res = context.shutdown().await;
        }
    }
    async fn poll(&mut self, _context: &mut ProtocolContext) -> Option<()> {
        Some(())
    }
}

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            let handle = Box::new(PHandle);
            ProtocolHandle::Callback(handle)
        })
        .build()
}

pub fn create<F>(meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
{
    ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true)
        .build(shandle)
}

#[test]
fn test_uninterrupter_poll() {
    let mut service_0 = create(create_meta(1.into()), ());
    let mut service_1 = create(create_meta(1.into()), ());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();
    rt.spawn(async move {
        let listen_addr = service_0
            .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .await
            .unwrap();
        let _res = addr_sender.send(listen_addr);
        service_0.run().await
    });

    rt.block_on(async move {
        let listen_addr = addr_receiver.await.unwrap();
        service_1
            .dial(listen_addr, TargetProtocol::All)
            .await
            .unwrap();
        service_1.run().await
    });
}
