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
    traits::{ServiceHandle, ServiceProtocol, SessionProtocol},
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
    count: Arc<AtomicUsize>,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, _context: &mut ProtocolContext) {}

    fn connected(&mut self, context: ProtocolContextMutRef, _version: &str) {
        if context.session.ty.is_inbound() {
            let prefix = "x".repeat(10);
            // NOTE: 256 is the send channel buffer size
            let length = 1024;
            for i in 0..length {
                let _ = context.send_message(Bytes::from(format!("{}-{}", prefix, i)));
            }
        }
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        let _ = context.shutdown();
    }

    fn received(&mut self, context: ProtocolContextMutRef, _data: Bytes) {
        if context.session.ty.is_outbound() && self.count.load(Ordering::SeqCst) < 512 {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
        let count_now = self.count.load(Ordering::SeqCst);
        //        println!("> receive {}", count_now);
        if count_now == 512 {
            let _ = context.shutdown();
        }
    }
}

impl SessionProtocol for PHandle {
    fn connected(&mut self, context: ProtocolContextMutRef, _version: &str) {
        if context.session.ty.is_inbound() {
            let prefix = "x".repeat(10);
            // NOTE: 256 is the send channel buffer size
            let length = 1024;
            for i in 0..length {
                let _ = context.send_message(Bytes::from(format!("{}-{}", prefix, i)));
            }
        }
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        let _ = context.shutdown();
    }

    fn received(&mut self, context: ProtocolContextMutRef, _data: bytes::Bytes) {
        if context.session.ty.is_outbound() && self.count.load(Ordering::SeqCst) < 512 {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
        let count_now = self.count.load(Ordering::SeqCst);
        //        println!("> receive {}", count_now);
        log::warn!("count_now: {}", count_now);
        if count_now == 512 {
            let _ = context.shutdown();
        }
    }
}

fn create_meta(id: ProtocolId, session_protocol: bool) -> (ProtocolMeta, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();
    let meta = MetaBuilder::new().id(id);
    if session_protocol {
        (
            meta.session_handle(move || {
                if id == 0.into() {
                    ProtocolHandle::Neither
                } else {
                    let handle = Box::new(PHandle {
                        count: count_clone.clone(),
                    });
                    ProtocolHandle::Callback(handle)
                }
            })
            .build(),
            count,
        )
    } else {
        (
            meta.service_handle(move || {
                if id == 0.into() {
                    ProtocolHandle::Neither
                } else {
                    let handle = Box::new(PHandle { count: count_clone });
                    ProtocolHandle::Callback(handle)
                }
            })
            .build(),
            count,
        )
    }
}

fn test_block_send(secio: bool, session_protocol: bool) {
    let (meta, _) = create_meta(1.into(), session_protocol);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    thread::spawn(move || {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta, ());
        rt.block_on(async move {
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
    });

    let (meta, result) = create_meta(1.into(), session_protocol);

    let handle_2 = thread::spawn(move || {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta, ());
        rt.block_on(async move {
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
    });
    handle_2.join().unwrap();

    assert_eq!(result.load(Ordering::SeqCst), 512);
}

#[test]
fn test_block_send_with_secio_session() {
    test_block_send(true, true)
}

#[test]
fn test_block_send_with_no_secio_session() {
    test_block_send(false, true)
}
