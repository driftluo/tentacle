use futures::prelude::Stream;
use p2p::{
    builder::ServiceBuilder,
    context::{ServiceContext, SessionContext},
    error::Error,
    multiaddr::Multiaddr,
    service::{Service, ServiceError, ServiceEvent},
    traits::{ProtocolMeta, ServiceHandle, ServiceProtocol},
    ProtocolId, SecioKeyPair, SessionId, SessionType,
};
use std::{thread, time::Duration};
use tokio::codec::LengthDelimitedCodec;

pub fn create<T, F>(secio: bool, meta: T, shandle: F) -> Service<F, LengthDelimitedCodec>
where
    T: ProtocolMeta<LengthDelimitedCodec> + Send + Sync + 'static,
    F: ServiceHandle,
{
    let builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true);

    if secio {
        builder
            .key_pair(SecioKeyPair::secp256k1_generated())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

#[derive(Clone)]
struct EmptySHandle {
    sender: crossbeam_channel::Sender<usize>,
    secio: bool,
    error_count: usize,
}

impl ServiceHandle for EmptySHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        use std::io;
        self.error_count += 1;

        if let ServiceError::DialerError { error, .. } = error {
            match error {
                Error::IoError(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused),
                e => panic!("test fail {}", e),
            }
        } else {
            panic!("test fail {:?}", error);
        }
        if self.error_count > 8 {
            let _ = self.sender.try_send(self.error_count);
        }
    }
}

#[derive(Clone)]
pub struct SHandle {
    sender: crossbeam_channel::Sender<usize>,
    secio: bool,
    error_count: usize,
    session_id: SessionId,
    kind: SessionType,
}

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        self.error_count += 1;

        match error {
            ServiceError::DialerError { error, .. } => {
                if self.kind == SessionType::Server {
                    match error {
                        Error::ConnectSelf => (),
                        _ => panic!("server test fail"),
                    }
                } else {
                    match error {
                        Error::RepeatedConnection(id) => assert_eq!(id, self.session_id),
                        _ => panic!("client test fail"),
                    }
                }
            }
            ServiceError::ListenError { error, .. } => {
                assert_eq!(error, Error::RepeatedConnection(self.session_id))
            }
            _ => panic!("test fail"),
        }

        if self.error_count > 8 {
            let _ = self.sender.try_send(self.error_count);
        }
    }

    fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { id, ty, .. } = event {
            self.session_id = id;
            self.kind = ty;
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
        if self.id == 0 {
            None
        } else {
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
        if let Err(e) = control.dial(self.dial_addr.as_ref().unwrap().clone()) {
            panic!("dial err: {}", e)
        }
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

fn create_shandle(
    secio: bool,
    empty: bool,
) -> (
    Box<dyn ServiceHandle + Send>,
    crossbeam_channel::Receiver<usize>,
) {
    let (sender, receiver) = crossbeam_channel::bounded(2);

    if empty {
        (
            Box::new(EmptySHandle {
                sender,
                secio,
                error_count: 0,
            }),
            receiver,
        )
    } else {
        (
            Box::new(SHandle {
                sender,
                secio,
                error_count: 0,
                session_id: 0,
                kind: SessionType::Server,
            }),
            receiver,
        )
    }
}

fn test_repeated_dial(secio: bool) {
    let (meta, receiver) = create_meta(1);
    let (shandle, error_receiver_1) = create_shandle(secio, false);

    let mut service = create(secio, meta.clone(), shandle);

    let listen_addr = service
        .listen(&"/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

    let (shandle, error_receiver_2) = create_shandle(secio, false);

    let service = create(secio, meta, shandle).dial(listen_addr);
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

    if secio {
        assert_eq!(receiver.recv(), Ok(1));
        assert_eq!(receiver.recv(), Ok(1));
        assert!(error_receiver_1.recv().unwrap() > 8);
        assert!(error_receiver_2.recv().unwrap() > 8);
    } else {
        assert_ne!(receiver.recv(), Ok(1));
        assert_ne!(receiver.recv(), Ok(1));
        assert!(error_receiver_1.is_empty());
        assert!(error_receiver_2.is_empty());
    }
}

fn test_dial_with_no_notify(secio: bool) {
    let (meta, _receiver) = create_meta(0);
    let (shandle, error_receiver) = create_shandle(secio, true);
    let mut service = create(secio, meta, shandle);
    let mut control = service.control().clone();
    thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));
    // macOs can't dial 0 port
    (1..11).for_each(|i| {
        let addr = format!("/ip4/127.0.0.1/tcp/{}", i).parse().unwrap();
        control.dial(addr).unwrap();
    });
    assert_eq!(error_receiver.recv(), Ok(9));
}

#[test]
fn test_repeated_dial_with_secio() {
    test_repeated_dial(true)
}

#[test]
fn test_repeated_dial_with_no_secio() {
    test_repeated_dial(false)
}

#[test]
fn test_dial_no_notify_with_secio() {
    test_dial_with_no_notify(true)
}

#[test]
fn test_dial_no_notify_with_no_secio() {
    test_dial_with_no_notify(false)
}
