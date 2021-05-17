use std::{sync::mpsc::channel, thread};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceEvent, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol, SessionProtocol},
};

/// test case:
/// 1. open with dummy protocol
/// 2. open test session protocol
/// 3. test protocol disconnect current session
/// 4. service handle dial with dummy protocol,
///   4.1. goto 1
///   4.2. count >= 10, test done

#[derive(Clone)]
struct PHandle;

#[async_trait]
impl SessionProtocol for PHandle {
    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        if context.session.ty.is_inbound() {
            // Close the session after opening the protocol correctly
            let _res = context.disconnect(context.session.id).await;
        }
    }
}

struct Dummy;

#[async_trait]
impl ServiceProtocol for Dummy {
    async fn init(&mut self, _context: &mut ProtocolContext) {}
}

struct SHandle {
    count: usize,
    addr: Option<Multiaddr>,
}

#[async_trait]
impl ServiceHandle for SHandle {
    async fn handle_event(&mut self, control: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { session_context } = event {
            self.addr = Some(session_context.address.clone());
            if session_context.ty.is_outbound() {
                control
                    .open_protocol(session_context.id, 1.into())
                    .await
                    .unwrap();
            }
        } else if let ServiceEvent::SessionClose { session_context } = event {
            // Test ends after 10 connections and opening session protocol
            if session_context.ty.is_outbound() {
                self.count += 1;
                if self.count >= 10 {
                    control.shutdown().await.unwrap();
                } else {
                    let _res = control
                        .dial(self.addr.clone().unwrap(), TargetProtocol::Single(0.into()))
                        .await;
                }
            }
        }
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

fn test_session_handle_open(secio: bool) {
    let p_handle_1 = PHandle;
    let s_handle_1 = SHandle {
        count: 0,
        addr: None,
    };

    let p_handle_2 = PHandle;
    let s_handle_2 = SHandle {
        count: 0,
        addr: None,
    };

    let meta_dummy_1 = MetaBuilder::new()
        .id(0.into())
        .service_handle(move || {
            let handle = Box::new(Dummy);
            ProtocolHandle::Callback(handle)
        })
        .build();

    let meta_dummy_2 = MetaBuilder::new()
        .id(0.into())
        .service_handle(move || {
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

    let mut service_1 = create(secio, vec![meta_dummy_1, meta_1].into_iter(), s_handle_1);
    let mut service_2 = create(secio, vec![meta_dummy_2, meta_2].into_iter(), s_handle_2);

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
fn test_session_handle_with_secio() {
    test_session_handle_open(true)
}

#[test]
fn test_session_handle_with_no_secio() {
    test_session_handle_open(false)
}
