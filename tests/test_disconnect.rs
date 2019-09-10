use futures::{channel, StreamExt};
use std::{thread, time::Duration};
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{DialProtocol, ProtocolHandle, ProtocolMeta, Service},
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

impl ServiceProtocol for PHandle {
    fn init(&mut self, _context: &mut ProtocolContext) {}

    fn connected(&mut self, _context: ProtocolContextMutRef, _version: &str) {
        self.connected_count += 1;
    }

    fn disconnected(&mut self, _context: ProtocolContextMutRef) {
        self.connected_count -= 1;
    }
}

fn create_meta(id: impl Into<ProtocolId> + Copy + Send + 'static) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id.into())
        .service_handle(move || {
            if id.into() == 0.into() {
                ProtocolHandle::Neither
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

    let mut service = create(secio, create_meta(1), ());
    let control = service.control().clone();
    let handle = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.spawn(async move {
            let listen_addr = addr_receiver.await.unwrap();
            service.dial(listen_addr, DialProtocol::All).await.unwrap();
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
        rt.shutdown_on_idle();
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
