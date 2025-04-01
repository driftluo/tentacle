use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
        mpsc::{self, Sender},
    },
    thread,
    time::Duration,
};

use futures::channel;
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ServiceContext},
    multiaddr::{Multiaddr, Protocol},
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceError, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
};

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F, SecioKeyPair>
where
    F: ServiceHandle + Unpin + 'static,
{
    let builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true);

    if secio {
        builder
            .handshake_type(SecioKeyPair::secp256k1_generated().into())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

fn create_meta(id: impl Into<ProtocolId> + Copy + Send + 'static) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id.into())
        .service_handle(move || {
            if id.into() == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle);
                ProtocolHandle::Callback(handle)
            }
        })
        .build()
}

struct PHandle;

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}
}

struct SHandle {
    count: Arc<AtomicU8>,
    sender: Sender<()>,
}

#[async_trait]
impl ServiceHandle for SHandle {
    async fn handle_error(&mut self, _control: &mut ServiceContext, event: ServiceError) {
        if let ServiceError::DialerError { .. } = event {
            let prv = self
                .count
                .fetch_add(1, std::sync::atomic::Ordering::Acquire);
            if prv == 1 {
                self.sender.send(()).unwrap();
            }
        }
    }
}

fn test_dial_unsupport_protocol_order(secio: bool) {
    let meta = create_meta(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();
    let count = Arc::new(AtomicU8::new(0));
    let count_clone = count.clone();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta, ());
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            let _res = addr_sender.send(listen_addr);
            service.run().await
        });
    });

    let meta = create_meta(1);

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(
            secio,
            meta,
            SHandle {
                count: count_clone,
                sender: tx,
            },
        );
        let control = service.control().clone();
        rt.block_on(async move {
            let mut listen_addr = addr_receiver.await.unwrap();
            listen_addr.push(Protocol::Wss);
            control
                .dial(listen_addr.clone(), TargetProtocol::All)
                .await
                .unwrap();
            control
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();
            service.run().await
        });
    });

    rx.recv_timeout(Duration::from_secs(10)).unwrap();

    assert_eq!(count.load(Ordering::Acquire), 2);
}

#[test]
fn test_dial_unsupport_protocol_order_with_secio() {
    test_dial_unsupport_protocol_order(true)
}

#[test]
fn test_dial_unsupport_protocol_order_with_no_secio() {
    test_dial_unsupport_protocol_order(false)
}
