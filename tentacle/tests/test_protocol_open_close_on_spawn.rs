#![cfg(feature = "unstable")]
use futures::StreamExt;
use std::{
    sync::mpsc::channel,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::SessionContext,
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolMeta, Service, ServiceAsyncControl, ServiceControl, TargetProtocol},
    traits::{ProtocolSpawn, ServiceHandle},
    SubstreamReadPart,
};

/// test case:
/// 1. open with dummy session protocol
/// 2. dummy protocol open test protocol
/// 3. test protocol open/close self 10 times, each closed count + 1
/// 4. when count >= 10, test done

#[derive(Clone)]
struct Dummy;

impl ProtocolSpawn for Dummy {
    fn spawn(
        &self,
        context: Arc<SessionContext>,
        control: &ServiceAsyncControl,
        _read_part: SubstreamReadPart,
    ) {
        // dummy open the test protocol
        let c: ServiceControl = control.clone().into();
        c.open_protocol(context.id, 1.into()).unwrap()
        // protocol close here
    }
}

struct PHandle {
    count: Arc<AtomicUsize>,
    once: AtomicBool,
}

impl ProtocolSpawn for PHandle {
    fn spawn(
        &self,
        context: Arc<SessionContext>,
        control: &ServiceAsyncControl,
        mut read_part: SubstreamReadPart,
    ) {
        let id = context.id;
        let pid = read_part.protocol_id();
        let is_outbound = context.ty.is_outbound();

        if is_outbound && self.once.load(Ordering::Relaxed) {
            self.once.store(false, Ordering::Relaxed);
            let control = control.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval_at(
                    tokio::time::Instant::now(),
                    Duration::from_millis(100),
                );
                loop {
                    interval.tick().await;
                    let _ignore = control.open_protocol(id, pid).await;
                }
            });
        }

        if is_outbound {
            let control = control.clone();

            tokio::spawn(async move {
                control.close_protocol(id, pid).await.unwrap();
            });
        }

        let count = self.count.clone();
        let control = control.clone();
        tokio::spawn(async move {
            while let Some(Ok(_)) = read_part.next().await {}
            if is_outbound {
                count.fetch_add(1, Ordering::SeqCst);
                if count.load(Ordering::SeqCst) >= 10 {
                    let _ignore = control.shutdown().await;
                }
            }
        });
    }
}

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

fn test_session_proto_open_close(secio: bool) {
    let p_handle_1 = PHandle {
        count: Arc::new(AtomicUsize::new(0)),
        once: AtomicBool::new(true),
    };
    let p_handle_2 = PHandle {
        count: Arc::new(AtomicUsize::new(0)),
        once: AtomicBool::new(true),
    };

    let meta_dummy_1 = MetaBuilder::new()
        .id(0.into())
        .protocol_spawn(Dummy)
        .build();

    let meta_dummy_2 = MetaBuilder::new()
        .id(0.into())
        .protocol_spawn(Dummy)
        .build();

    let meta_1 = MetaBuilder::new()
        .id(1.into())
        .protocol_spawn(p_handle_1)
        .build();

    let meta_2 = MetaBuilder::new()
        .id(1.into())
        .protocol_spawn(p_handle_2)
        .build();

    let mut service_1 = create(secio, vec![meta_dummy_1, meta_1].into_iter(), ());
    let mut service_2 = create(secio, vec![meta_dummy_2, meta_2].into_iter(), ());

    let (addr_sender, addr_receiver) = channel::<Multiaddr>();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listen_addr = service_2
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();

            addr_sender.send(listen_addr).unwrap();

            service_2.run().await
        });
    });

    let listen_addr = addr_receiver.recv().unwrap();

    let handle = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            service_1
                .dial(listen_addr, TargetProtocol::Single(0.into()))
                .await
                .unwrap();

            service_1.run().await
        });
    });

    handle.join().unwrap();
}

#[test]
fn test_spawn_proto_open_close_with_secio() {
    test_session_proto_open_close(true)
}

#[test]
fn test_spawn_proto_open_close_with_no_secio() {
    test_session_proto_open_close(false)
}
