use futures::prelude::Stream;
use p2p::{
    builder::ServiceBuilder,
    multiaddr::Multiaddr,
    service::{ProtocolMeta, ServiceContext, ServiceProtocol, SessionContext},
    service::{Service, ServiceEvent, ServiceHandle},
    session::ProtocolId,
    SecioKeyPair, SessionType,
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
pub struct SHandle {
    sender: crossbeam_channel::Sender<usize>,
    secio: bool,
    error_count: usize,
}

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceEvent) {
        use std::io;
        self.error_count += 1;

        if let ServiceEvent::DialerError { error, .. } = error {
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe)
        } else {
            panic!("test fail {:?}", error);
        }
        if self.error_count > 8 {
            let _ = self.sender.try_send(self.error_count);
        }
    }
}

#[derive(Clone)]
pub struct Protocol {
    id: ProtocolId,
    sender: crossbeam_channel::Sender<usize>,
}

impl Protocol {
    fn new(id: ProtocolId, sender: crossbeam_channel::Sender<usize>) -> Self {
        Protocol { id, sender }
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
        let handle = Box::new(PHandle {
            proto_id: self.id,
            connected_count: 0,
            sender: self.sender.clone(),
            dial_count: 0,
            dial_addr: None,
        });
        Some(handle)
    }
}

struct PHandle {
    proto_id: ProtocolId,
    connected_count: usize,
    sender: crossbeam_channel::Sender<usize>,
    dial_count: usize,
    dial_addr: Option<Multiaddr>,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, control: &mut ServiceContext) {
        control.set_service_notify(self.proto_id, Duration::from_secs(1), 3);
    }

    fn connected(
        &mut self,
        control: &mut ServiceContext,
        session: &SessionContext,
        _version: &str,
    ) {
        if session.ty == SessionType::Server {
            // if server, dial itself
            self.dial_addr = Some(control.listens()[0].clone());
        } else {
            // if client, dial server
            self.dial_addr = Some(session.address.clone());
        }
        self.connected_count += 1;
    }

    fn disconnected(&mut self, _control: &mut ServiceContext, _session: &SessionContext) {
        self.connected_count -= 1;
    }

    fn notify(&mut self, control: &mut ServiceContext, _token: u64) {
        control.dial(self.dial_addr.as_ref().unwrap().clone());
        self.dial_count += 1;
        if self.dial_count == 10 {
            self.sender.try_send(self.connected_count).unwrap();
        }
    }
}

fn create_meta(id: ProtocolId) -> (Protocol, crossbeam_channel::Receiver<usize>) {
    let (sender, receiver) = crossbeam_channel::bounded(2);

    (Protocol::new(id, sender), receiver)
}

fn create_shandle(secio: bool) -> (SHandle, crossbeam_channel::Receiver<usize>) {
    let (sender, receiver) = crossbeam_channel::bounded(2);

    (
        SHandle {
            sender,
            secio,
            error_count: 0,
        },
        receiver,
    )
}

fn test_repeated_dial(secio: bool) {
    let (meta, receiver) = create_meta(0);
    let (shandle, error_receiver) = create_shandle(secio);

    let mut service = create(secio, meta.clone(), shandle.clone());

    let listen_addr = service
        .listen(&"/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

    let service = create(secio, meta, shandle).dial(listen_addr);
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

    if secio {
        assert_eq!(receiver.recv(), Ok(1));
        assert_eq!(receiver.recv(), Ok(1));
        assert!(error_receiver.recv().unwrap() > 0);
        assert!(error_receiver.recv().unwrap() > 0);
    } else {
        assert_ne!(receiver.recv(), Ok(1));
        assert_ne!(receiver.recv(), Ok(1));
        assert!(error_receiver.is_empty());
    }
}

#[test]
fn test_repeated_dial_with_secio() {
    test_repeated_dial(true)
}

#[test]
fn test_repeated_dial_with_no_secio() {
    test_repeated_dial(false)
}
