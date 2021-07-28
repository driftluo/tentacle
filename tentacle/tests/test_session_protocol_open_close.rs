use std::{sync::mpsc::channel, thread, time::Duration};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::ProtocolContextMutRef,
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol},
    traits::{ServiceHandle, SessionProtocol},
};

/// test case:
/// 1. open with dummy session protocol
/// 2. dummy protocol open test protocol
/// 3. test protocol open/close self 10 times, each closed count + 1
/// 4. when count >= 10, test done

#[derive(Clone)]
struct Dummy;

#[async_trait]
impl SessionProtocol for Dummy {
    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        // dummy open the test protocol
        context
            .open_protocol(context.session.id, 1.into())
            .await
            .unwrap();
    }
}

#[derive(Clone)]
struct PHandle {
    count: usize,
}

#[async_trait]
impl SessionProtocol for PHandle {
    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        if context.session.ty.is_outbound() {
            // close self protocol
            context
                .close_protocol(context.session.id, context.proto_id)
                .await
                .unwrap();
            // set a timer to open self protocol
            // because service state may not clean
            context
                .set_session_notify(
                    context.session.id,
                    context.proto_id,
                    Duration::from_millis(100),
                    1,
                )
                .await
                .unwrap();
        }
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        if context.session.ty.is_outbound() {
            // each close add one
            self.count += 1;
            if self.count >= 10 {
                let _ignore = context.shutdown().await;
            }
        }
    }

    async fn notify(&mut self, context: ProtocolContextMutRef<'_>, _token: u64) {
        // try open self with remote
        context
            .open_protocol(context.session.id, context.proto_id)
            .await
            .unwrap();
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
    let p_handle_1 = PHandle { count: 0 };
    let p_handle_2 = PHandle { count: 0 };

    let meta_dummy_1 = MetaBuilder::new()
        .id(0.into())
        .session_handle(move || {
            let handle = Box::new(Dummy);
            ProtocolHandle::Callback(handle)
        })
        .build();

    let meta_dummy_2 = MetaBuilder::new()
        .id(0.into())
        .session_handle(move || {
            let handle = Box::new(Dummy);
            ProtocolHandle::Callback(handle)
        })
        .build();

    let meta_1 = MetaBuilder::new()
        .id(1.into())
        .session_handle(move || {
            let handle = Box::new(p_handle_1.clone());
            ProtocolHandle::Callback(handle)
        })
        .build();

    let meta_2 = MetaBuilder::new()
        .id(1.into())
        .session_handle(move || {
            let handle = Box::new(p_handle_2.clone());
            ProtocolHandle::Callback(handle)
        })
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
fn test_session_proto_open_close_with_secio() {
    test_session_proto_open_close(true)
}

#[test]
fn test_session_proto_open_close_with_no_secio() {
    test_session_proto_open_close(false)
}
