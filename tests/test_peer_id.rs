use futures::prelude::Stream;
use std::thread;
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ServiceContext},
    error::Error,
    multiaddr::{multihash::Multihash, Protocol as MultiProtocol},
    secio::SecioKeyPair,
    service::{DialProtocol, ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

pub fn create<F>(key_pair: SecioKeyPair, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle,
{
    ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true)
        .key_pair(key_pair)
        .build(shandle)
}

struct PHandle;

impl ServiceProtocol for PHandle {
    fn init(&mut self, _control: &mut ProtocolContext) {}
}

#[derive(Clone)]
struct EmptySHandle {
    sender: crossbeam_channel::Sender<usize>,
    error_count: usize,
}

impl ServiceHandle for EmptySHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        self.error_count += 1;

        if let ServiceError::DialerError { error, .. } = error {
            assert_eq!(error, Error::PeerIdNotMatch);
        } else {
            panic!("test fail {:?}", error);
        }

        if self.error_count > 8 {
            let _ = self.sender.try_send(self.error_count);
        }
    }

    fn handle_event(&mut self, _control: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { .. } = event {
            let _ = self.sender.try_send(self.error_count);
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
                ProtocolHandle::Neither
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
    let mut service = create(key.clone(), meta, ());

    let mut listen_addr = service
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

    let (shandle, error_receiver) = create_shandle();
    let meta = create_meta(1.into());
    let service = create(SecioKeyPair::secp256k1_generated(), meta, shandle);
    let control = service.control().clone();
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

    if fail {
        (1..11).for_each(|_| {
            let mut addr = listen_addr.clone();
            addr.push(MultiProtocol::P2p(
                Multihash::from_bytes(
                    SecioKeyPair::secp256k1_generated()
                        .peer_id()
                        .as_bytes()
                        .to_vec(),
                )
                .expect("Invalid peer id"),
            ));
            control.dial(addr, DialProtocol::All).unwrap();
        });
        assert_eq!(error_receiver.recv(), Ok(9));
    } else {
        listen_addr.push(MultiProtocol::P2p(
            Multihash::from_bytes(key.peer_id().into_bytes()).expect("Invalid peer id"),
        ));
        control.dial(listen_addr, DialProtocol::All).unwrap();
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
