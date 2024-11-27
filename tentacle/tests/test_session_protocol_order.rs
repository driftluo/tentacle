use futures::channel;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceEvent, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F, SecioKeyPair>
where
    F: ServiceHandle + Unpin + 'static,
{
    let builder = ServiceBuilder::default().insert_protocol(meta);

    if secio {
        builder
            .handshake_type(SecioKeyPair::secp256k1_generated().into())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

struct PHandle {
    count: Arc<AtomicUsize>,
    result: Arc<AtomicBool>,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}
    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        // it must be 1, because SessionOpen mut be notified first
        assert_eq!(self.count.load(Ordering::SeqCst), 1);
        self.result.store(true, Ordering::SeqCst);
        if context.session.ty.is_outbound() {
            context.shutdown().await.unwrap();
        }
    }
}

struct SHandle {
    count: Arc<AtomicUsize>,
}

#[async_trait]
impl ServiceHandle for SHandle {
    async fn handle_event(&mut self, _control: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { .. } = event {
            thread::sleep(Duration::from_secs(2));
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn create_meta(id: ProtocolId) -> (ProtocolMeta, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();
    let res = Arc::new(AtomicBool::new(false));
    let res_clone = res.clone();
    let meta = MetaBuilder::new().id(id);

    (
        meta.service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle {
                    count: count_clone,
                    result: res_clone,
                });
                ProtocolHandle::Callback(handle)
            }
        })
        .build(),
        count,
        res,
    )
}

fn test_session_protocol_order(secio: bool) {
    let (meta, count, res_1) = create_meta(1.into());
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta, SHandle { count });
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            let _res = addr_sender.send(listen_addr);
            service.run().await
        });
    });

    let (meta, count, res_2) = create_meta(1.into());

    let handle_2 = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta, SHandle { count });
        rt.block_on(async move {
            let listen_addr = addr_receiver.await.unwrap();
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();
            service.run().await
        });
    });
    handle_2.join().unwrap();

    assert!(res_1.load(Ordering::SeqCst));
    assert!(res_2.load(Ordering::SeqCst));
}

#[test]
fn test_session_protocol_order_with_secio() {
    test_session_protocol_order(true)
}

#[test]
fn test_session_protocol_order_with_no_secio() {
    test_session_protocol_order(false)
}
