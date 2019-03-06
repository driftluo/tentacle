use bench::Bench;
use futures::prelude::Stream;
use p2p::{
    builder::ServiceBuilder,
    context::{ServiceContext, SessionContext},
    secio::SecioKeyPair,
    service::{Service, ServiceControl},
    traits::{ProtocolHandle, ProtocolMeta, ServiceHandle, ServiceProtocol},
    ProtocolId,
};
use std::{sync::Once, thread};
use tokio::codec::{length_delimited::Builder, LengthDelimitedCodec};

static START_SECIO: Once = Once::new();
static START_NO_SECIO: Once = Once::new();

static mut SECIO_CONTROL: Option<ServiceControl> = None;
static mut NO_SECIO_CONTROL: Option<ServiceControl> = None;

static mut SECIO_RECV: Option<crossbeam_channel::Receiver<Notify>> = None;
static mut NO_SECIO_RECV: Option<crossbeam_channel::Receiver<Notify>> = None;

#[derive(Debug, PartialEq)]
enum Notify {
    Connected,
    Message(bytes::Bytes),
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
        Builder::new()
            .max_frame_length(1024 * 1024 * 20)
            .new_codec()
    }

    fn service_handle(&self) -> ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static>> {
        if self.id == 0 {
            ProtocolHandle::Neither
        } else {
            let handle = Box::new(PHandle {
                proto_id: self.id,
                connected_count: 0,
                sender: self.sender.clone(),
            });
            ProtocolHandle::Callback(handle)
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

    fn received(
        &mut self,
        _env: &mut ServiceContext,
        _session: &SessionContext,
        data: bytes::Bytes,
    ) {
        let _ = self.sender.send(Notify::Message(data));
    }
}

fn create_meta(id: ProtocolId) -> (Protocol, crossbeam_channel::Receiver<Notify>) {
    let (sender, receiver) = crossbeam_channel::bounded(1);

    (Protocol::new(id, sender), receiver)
}

pub fn init() {
    // init secio two peers
    START_SECIO.call_once(|| {
        let (meta, _receiver) = create_meta(1);
        let mut service = create(true, meta, ());
        let listen_addr = service
            .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let control = service.control().clone();
        thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

        let (meta, client_receiver) = create_meta(1);
        let mut service = create(true, meta, ());
        service.dial(listen_addr).unwrap();
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
        let mut service = create(false, meta, ());
        let listen_addr = service
            .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let control = service.control().clone();
        thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

        let (meta, client_receiver) = create_meta(1);
        let mut service = create(false, meta, ());
        service.dial(listen_addr).unwrap();
        thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));

        assert_eq!(client_receiver.recv(), Ok(Notify::Connected));
        unsafe {
            NO_SECIO_CONTROL = Some(control);
            NO_SECIO_RECV = Some(client_receiver);
        }
    });
}

fn secio_and_send_data(data: &[u8]) {
    unsafe {
        SECIO_CONTROL
            .as_mut()
            .map(|control| control.filter_broadcast(None, 1, data.to_vec()));
        if let Some(rev) = SECIO_RECV.as_ref() {
            assert_eq!(rev.recv(), Ok(Notify::Message(bytes::Bytes::from(data))))
        }
    }
}

fn no_secio_and_send_data(data: &[u8]) {
    unsafe {
        NO_SECIO_CONTROL
            .as_mut()
            .map(|control| control.filter_broadcast(None, 1, data.to_vec()));

        if let Some(rev) = NO_SECIO_RECV.as_ref() {
            assert_eq!(rev.recv(), Ok(Notify::Message(bytes::Bytes::from(data))))
        }
    }
}

fn main() {
    init();

    let cycles = std::env::args()
        .nth(1)
        .and_then(|number| number.parse().ok())
        .unwrap_or(100);

    let check_point = std::env::args()
        .nth(2)
        .and_then(|number| number.parse().ok())
        .unwrap_or(10);

    let mut bench = Bench::default().cycles(cycles).estimated_point(check_point);

    let mb = (0..1024 * 1024 * 10)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();
    let kb = (0..1024 * 10)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();

    bench.bench_function_with_init("10kb_benchmark_with_secio", &kb, move |data| {
        secio_and_send_data(&data)
    });
    bench.bench_function_with_init("10kb_benchmark_with_no_secio", &kb, move |data| {
        no_secio_and_send_data(&data)
    });
    bench.bench_function_with_init("10mb_benchmark_with_secio", &mb, move |data| {
        secio_and_send_data(&data)
    });
    bench.bench_function_with_init("10mb_benchmark_with_no_secio", &mb, move |data| {
        no_secio_and_send_data(&data)
    });
}
