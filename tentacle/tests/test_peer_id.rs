use std::{borrow::Cow, sync::mpsc::channel, thread};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ServiceContext},
    error::DialerErrorKind,
    multiaddr::Multiaddr,
    multiaddr::Protocol as MultiProtocol,
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceControl, ServiceError, ServiceEvent,
        TargetProtocol,
    },
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

pub fn create<F>(key_pair: SecioKeyPair, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
{
    ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true)
        .key_pair(key_pair)
        .build(shandle)
}

struct PHandle;

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _control: &mut ProtocolContext) {}
}

#[derive(Clone)]
struct EmptySHandle {
    sender: crossbeam_channel::Sender<usize>,
    error_count: usize,
}

#[async_trait]
impl ServiceHandle for EmptySHandle {
    async fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        self.error_count += 1;

        if let ServiceError::DialerError { error, .. } = error {
            match error {
                DialerErrorKind::PeerIdNotMatch => {}
                err => panic!(
                    "test fail, expected DialerErrorKind::PeerIdNotMatch, got {:?}",
                    err
                ),
            }
        } else {
            panic!("test fail {:?}", error);
        }

        if self.error_count > 8 {
            let _res = self.sender.try_send(self.error_count);
        }
    }

    async fn handle_event(&mut self, _control: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { .. } = event {
            let _res = self.sender.try_send(self.error_count);
        }
    }
}

fn create_shandle() -> (EmptySHandle, crossbeam_channel::Receiver<usize>) {
    let (sender, receiver) = crossbeam_channel::bounded(2);
    (
        EmptySHandle {
            sender,
            error_count: 0,
        },
        receiver,
    )
}

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle);
                ProtocolHandle::Callback(handle)
            }
        })
        .build()
}

fn test_peer_id(fail: bool) {
    let meta = create_meta(1.into());
    let key = SecioKeyPair::secp256k1_generated();
    let (addr_sender, addr_receiver) = channel::<Multiaddr>();
    let mut service = create(key.clone(), meta, ());

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();

            addr_sender.send(listen_addr).unwrap();

            service.run().await
        });
    });

    let mut listen_addr = addr_receiver.recv().unwrap();

    let (shandle, error_receiver) = create_shandle();
    let meta = create_meta(1.into());
    let mut service = create(SecioKeyPair::secp256k1_generated(), meta, shandle);
    let control: ServiceControl = service.control().clone().into();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move { service.run().await });
    });

    if fail {
        (1..11).for_each(|_| {
            let mut addr = listen_addr.clone();
            addr.push(MultiProtocol::P2P(Cow::Owned(
                SecioKeyPair::secp256k1_generated().peer_id().into_bytes(),
            )));
            control.dial(addr, TargetProtocol::All).unwrap();
        });
        assert_eq!(error_receiver.recv(), Ok(9));
    } else {
        listen_addr.push(MultiProtocol::P2P(Cow::Owned(key.peer_id().into_bytes())));
        control.dial(listen_addr, TargetProtocol::All).unwrap();
        assert_eq!(error_receiver.recv(), Ok(0));
    }
}

#[test]
fn test_fail() {
    test_peer_id(true)
}

#[test]
fn test_succeed() {
    test_peer_id(false)
}
