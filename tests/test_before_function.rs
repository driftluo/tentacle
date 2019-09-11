use bytes::Bytes;
use futures::{channel, StreamExt};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
};
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol},
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
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta, ());
        rt.spawn(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            let _ = addr_sender.send(listen_addr);
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
        rt.shutdown_on_idle();
    });

    let (meta, result_2) = create_meta(1.into());

    let handle_2 = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta, ());
        rt.spawn(async move {
            let listen_addr = addr_receiver.await.unwrap();
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
        rt.shutdown_on_idle();
    });
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
