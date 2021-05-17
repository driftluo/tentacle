use futures::channel;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::ProtocolContextMutRef,
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol},
    traits::{ServiceHandle, SessionProtocol},
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
    count_close: usize,
    count: Arc<AtomicUsize>,
}

#[async_trait]
impl SessionProtocol for PHandle {
    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        let _res = context
            .set_session_notify(
                context.session.id,
                context.proto_id,
                Duration::from_millis(300),
                1,
            )
            .await;
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        let _res = context.shutdown().await;
    }

    async fn notify(&mut self, context: ProtocolContextMutRef<'_>, token: u64) {
        match token {
            1 => {
                self.count_close += 1;
                if self.count_close > 10 {
                    let _res = context.shutdown().await;
                } else if self.count_close > 3 {
                    // 1. open protocol
                    // 2. set another notify
                    // 3. must notify same session protocol handle
                    let _res = context
                        .open_protocol(context.session.id, context.proto_id)
                        .await;
                    let _res = context
                        .set_session_notify(
                            context.session.id,
                            context.proto_id,
                            Duration::from_millis(300),
                            2,
                        )
                        .await;
                }
            }
            2 => {
                // if protocol handle is same, `count close` must be greater than zero
                // Otherwise it is a bug
                if self.count_close > 0 {
                    self.count.fetch_add(1, Ordering::SeqCst);
                }
            }
            _ => (),
        }
    }
}

fn create_meta(id: ProtocolId) -> (ProtocolMeta, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();
    let meta = MetaBuilder::new().id(id);

    (
        meta.session_handle(move || {
            if id == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle {
                    count_close: 0,
                    count: count_clone.clone(),
                });
                ProtocolHandle::Callback(handle)
            }
        })
        .build(),
        count,
    )
}

fn test_protocol_open(secio: bool) {
    let (meta, _) = create_meta(1.into());
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

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

    let (meta, result) = create_meta(1.into());

    let handle_2 = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta, ());
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

    assert!(result.load(Ordering::SeqCst) > 0);
}

#[test]
fn test_protocol_open_with_secio_session() {
    test_protocol_open(true)
}

#[test]
fn test_protocol_open_with_no_secio_session() {
    test_protocol_open(false)
}
