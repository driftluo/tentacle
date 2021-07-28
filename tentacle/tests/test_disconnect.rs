use futures::channel;
use std::{thread, time::Duration};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceControl, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
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

struct PHandle {
    connected_count: usize,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, _context: ProtocolContextMutRef<'_>, _version: &str) {
        self.connected_count += 1;
    }

    async fn disconnected(&mut self, _context: ProtocolContextMutRef<'_>) {
        self.connected_count -= 1;
    }
}

fn create_meta(id: impl Into<ProtocolId> + Copy + Send + 'static) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id.into())
        .service_handle(move || {
            if id.into() == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle { connected_count: 0 });
                ProtocolHandle::Callback(handle)
            }
        })
        .build()
}

fn test_disconnect(secio: bool) {
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, create_meta(1), ());
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            let _res = addr_sender.send(listen_addr);
            service.run().await
        });
    });

    let mut service = create(secio, create_meta(1), ());
    let control: ServiceControl = service.control().clone().into();
    let handle = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listen_addr = addr_receiver.await.unwrap();
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();
            service.run().await
        });
    });
    thread::sleep(Duration::from_secs(5));

    control.disconnect(1.into()).unwrap();
    handle.join().expect("test fail");
}

#[test]
fn test_disconnect_with_secio() {
    test_disconnect(true);
}

#[test]
fn test_disconnect_with_no_secio() {
    test_disconnect(false);
}
