use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use futures::prelude::Stream;
use p2p::{
    builder::ServiceBuilder,
    context::{ServiceContext, ServiceControl, SessionContext},
    service::{Message, Service},
    traits::{ProtocolMeta, ServiceHandle, ServiceProtocol},
    ProtocolId, SecioKeyPair,
};
use std::{sync::Once, thread};
use tokio::codec::LengthDelimitedCodec;

static START_SECIO: Once = Once::new();
static START_NO_SECIO: Once = Once::new();

static mut SECIO_CONTROL: Option<ServiceControl> = None;
static mut NO_SECIO_CONTROL: Option<ServiceControl> = None;

static mut SECIO_RECV: Option<crossbeam_channel::Receiver<Notify>> = None;
static mut NO_SECIO_RECV: Option<crossbeam_channel::Receiver<Notify>> = None;

#[derive(Debug, PartialEq)]
enum Notify {
    Connected,
    Message(Vec<u8>),
}

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
pub struct Protocol {
    id: ProtocolId,
    sender: crossbeam_channel::Sender<Notify>,
}

impl Protocol {
    fn new(id: ProtocolId, sender: crossbeam_channel::Sender<Notify>) -> Self {
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
            });
            Some(handle)
        }
    }
}

struct PHandle {
    proto_id: ProtocolId,
    connected_count: usize,
    sender: crossbeam_channel::Sender<Notify>,
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
        let _ = self.sender.send(Notify::Connected);
    }

    fn disconnected(&mut self, _control: &mut ServiceContext, _session: &SessionContext) {
        self.connected_count -= 1;
    }

    fn received(&mut self, _env: &mut ServiceContext, _session: &SessionContext, data: Vec<u8>) {
        let _ = self.sender.send(Notify::Message(data));
    }
}

fn create_meta(id: ProtocolId) -> (Protocol, crossbeam_channel::Receiver<Notify>) {
    let (sender, receiver) = crossbeam_channel::bounded(1);

    (Protocol::new(id, sender), receiver)
}

fn init() {
    // init secio two peers
    START_SECIO.call_once(|| {
        let (meta, _receiver) = create_meta(1);
        let mut service = create(true, meta, ());
        let listen_addr = service
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let control = service.control().clone();
        thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

        let (meta, client_receiver) = create_meta(1);
        let service = create(true, meta, ()).dial(listen_addr);
        thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

        assert_eq!(client_receiver.recv(), Ok(Notify::Connected));
        unsafe {
            SECIO_CONTROL = Some(control);
            SECIO_RECV = Some(client_receiver);
        }
    });

    // init no secio two peers
    START_NO_SECIO.call_once(|| {
        let (meta, _receiver) = create_meta(1);
        let mut service = create(true, meta, ());
        let listen_addr = service
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let control = service.control().clone();
        thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

        let (meta, client_receiver) = create_meta(1);
        let service = create(true, meta, ()).dial(listen_addr);
        thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

        assert_eq!(client_receiver.recv(), Ok(Notify::Connected));
        unsafe {
            NO_SECIO_CONTROL = Some(control);
            NO_SECIO_RECV = Some(client_receiver);
        }
    });
}

fn secio_and_send_data(bench: &mut Bencher, data: &[u8]) {
    bench.iter(move || unsafe {
        SECIO_CONTROL.as_mut().map(|control| {
            control.send_message(
                None,
                Message {
                    session_id: 1,
                    proto_id: 1,
                    data: data.to_vec(),
                },
            )
        });
        if let Some(rev) = SECIO_RECV.as_ref() {
            assert_eq!(rev.recv(), Ok(Notify::Message(data.to_vec())))
        }
    })
}

fn no_secio_and_send_data(bench: &mut Bencher, data: &[u8]) {
    bench.iter(move || unsafe {
        NO_SECIO_CONTROL.as_mut().map(|control| {
            control.send_message(
                None,
                Message {
                    session_id: 1,
                    proto_id: 1,
                    data: data.to_vec(),
                },
            )
        });

        if let Some(rev) = NO_SECIO_RECV.as_ref() {
            assert_eq!(rev.recv(), Ok(Notify::Message(data.to_vec())))
        }
    })
}

fn hello_criterion_benchmark(bench: &mut Criterion) {
    init();

    bench.bench_function("secio_and_send_hello", move |b| {
        secio_and_send_data(b, b"hello world")
    });
    bench.bench_function("no_secio_and_send_hello", move |b| {
        no_secio_and_send_data(b, b"hello world")
    });
}

fn kb_criterion_benchmark(bench: &mut Criterion) {
    let data = (0..1024).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
    bench.bench_function("secio_and_send_1kb", {
        let data = data.clone();
        move |b| secio_and_send_data(b, &data)
    });
    bench.bench_function("no_secio_and_send_1kb", move |b| {
        no_secio_and_send_data(b, &data)
    });
}

criterion_group!(benches, hello_criterion_benchmark, kb_criterion_benchmark);
criterion_main!(benches);
