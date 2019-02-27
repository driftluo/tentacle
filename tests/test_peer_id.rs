use futures::prelude::Stream;
use std::thread;
use tentacle::{
    builder::ServiceBuilder,
    context::ServiceContext,
    error::Error,
    multiaddr::{multihash::Multihash, Protocol as MultiProtocol},
    secio::SecioKeyPair,
    service::{Service, ServiceError, ServiceEvent},
    traits::{ProtocolMeta, ServiceHandle, ServiceProtocol},
    ProtocolId,
};
use tokio::codec::LengthDelimitedCodec;

pub fn create<T, F>(key_pair: SecioKeyPair, meta: T, shandle: F) -> Service<F, LengthDelimitedCodec>
where
    T: ProtocolMeta<LengthDelimitedCodec> + Send + Sync + 'static,
    F: ServiceHandle,
{
    ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true)
        .key_pair(key_pair)
        .build(shandle)
}

#[derive(Clone)]
pub struct Protocol {
    id: ProtocolId,
}

impl Protocol {
    fn new(id: ProtocolId) -> Self {
        Protocol { id }
    }
}

impl ProtocolMeta<LengthDelimitedCodec> for Protocol {
    fn id(&self) -> ProtocolId {
        self.id
    }
    fn codec(&self) -> LengthDelimitedCodec {
        LengthDelimitedCodec::new()
    }

    fn service_handle(&self) -> Option<Box<dyn ServiceProtocol + Send + 'static>> {
        if self.id == 0 {
            None
        } else {
            let handle = Box::new(PHandle);
            Some(handle)
        }
    }
}

struct PHandle;

impl ServiceProtocol for PHandle {
    fn init(&mut self, _control: &mut ServiceContext) {}
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

fn test_peer_id(fail: bool) {
    let meta = Protocol::new(1);
    let key = SecioKeyPair::secp256k1_generated();
    let mut service = create(key.clone(), meta.clone(), ());

    let mut listen_addr = service
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

    let (shandle, error_receiver) = create_shandle();
    let mut service = create(SecioKeyPair::secp256k1_generated(), meta, shandle);
    let mut control = service.control().clone();
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

    if fail {
        (1..11).for_each(|_| {
            let mut addr = listen_addr.clone();
            addr.append(MultiProtocol::P2p(
                Multihash::from_bytes(
                    SecioKeyPair::secp256k1_generated()
                        .to_peer_id()
                        .as_bytes()
                        .to_vec(),
                )
                .expect("Invalid peer id"),
            ));
            control.dial(addr).unwrap();
        });
        assert_eq!(error_receiver.recv(), Ok(9));
    } else {
        listen_addr.append(MultiProtocol::P2p(
            Multihash::from_bytes(key.to_peer_id().into_bytes()).expect("Invalid peer id"),
        ));
        control.dial(listen_addr).unwrap();
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
