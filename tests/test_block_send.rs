use bytes::Bytes;
use futures::prelude::Stream;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    secio::SecioKeyPair,
    service::{DialProtocol, ProtocolHandle, ProtocolMeta, Service},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle,
{
    let builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true);

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

    fn connected(&mut self, mut context: ProtocolContextMutRef, _version: &str) {
        if context.session.ty.is_inbound() {
            let prefix = "x".repeat(1000);
            // NOTE: 256 is the send channel buffer size
            let length = 1024;
            let mut first_256 = Duration::default();
            let mut last_256 = Duration::default();
            for i in 0..length {
                let now = Instant::now();
                // println!("> send {}", i);
                context.send_message(Bytes::from(format!("{}-{}", prefix, i)));
                if i >= 0 && i < 256 {
                    first_256 += now.elapsed();
                } else if i >= length - 256 && i < length {
                    last_256 += now.elapsed();
                }
            }
            let first_256_micros = first_256.as_micros();
            let last_256_micros = last_256.as_micros();

            assert!(last_256_micros > first_256_micros * 2);
        }
    }

    fn received(&mut self, mut context: ProtocolContextMutRef, _data: Bytes) {
        if context.session.ty.is_outbound() {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
        let count_now = self.count.load(Ordering::SeqCst);
        // println!("> receive {}", count_now);
        if count_now == 1024 {
            context.close();
        }
    }
}

fn create_meta(id: ProtocolId) -> (ProtocolMeta, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();
    (
        MetaBuilder::new()
            .id(id)
            .service_handle(move || {
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

fn test_block_send(secio: bool) {
    let (meta, _) = create_meta(1.into());
    let mut service = create(secio, meta, ());
    let listen_addr = service
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let _handle_1 = thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));
    thread::sleep(Duration::from_millis(100));

    let (meta, result) = create_meta(1.into());
    let mut service = create(secio, meta, ());
    service.dial(listen_addr, DialProtocol::All).unwrap();
    let handle_2 = thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));
    // handle_1.join().unwrap();
    handle_2.join().unwrap();

    assert_eq!(result.load(Ordering::SeqCst), 1024);
}

#[test]
fn test_block_send_with_secio() {
    test_block_send(true)
}

// #[test]
// fn test_block_send_with_no_secio() {
//     test_block_send(false)
// }
