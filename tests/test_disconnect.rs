use futures::prelude::Stream;
use p2p::{
    builder::ServiceBuilder,
    context::{ServiceContext, SessionContext},
    service::Service,
    traits::{ProtocolMeta, ServiceHandle, ServiceProtocol},
    ProtocolId, SecioKeyPair,
};
use std::{thread, time::Duration};
use tokio::codec::LengthDelimitedCodec;

pub fn create<T, F>(secio: bool, meta: T, shandle: F) -> Service<F, LengthDelimitedCodec>
where
    T: ProtocolMeta<LengthDelimitedCodec> + Send + Sync + 'static,
    F: ServiceHandle,
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
            let handle = Box::new(PHandle {
                proto_id: self.id,
                connected_count: 0,
            });
            Some(handle)
        }
    }
}

struct PHandle {
    proto_id: ProtocolId,
    connected_count: usize,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, _control: &mut ServiceContext) {}

    fn connected(
        &mut self,
        _control: &mut ServiceContext,
        session: &SessionContext,
        _version: &str,
    ) {
        self.connected_count += 1;
        assert_eq!(self.proto_id, session.id);
    }

    fn disconnected(&mut self, _control: &mut ServiceContext, _session: &SessionContext) {
        self.connected_count -= 1;
    }
}

fn test_disconnect(secio: bool) {
    let mut service = create(secio, Protocol::new(1), ());
    let listen_addr = service
        .listen(&"/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

    let mut service = create(secio, Protocol::new(1), ()).dial(listen_addr);
    let mut control = service.control().clone();
    let handle = thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));
    thread::sleep(Duration::from_secs(5));

    control.disconnect(1).unwrap();
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
