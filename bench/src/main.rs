use bench::Bench;
use bytes::Bytes;
use futures::channel;
use p2p::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceControl, TargetProtocol, TargetSession,
    },
    traits::{ServiceHandle, ServiceProtocol},
};
use std::{
    sync::{Once, OnceLock},
    thread,
};
use tokio_util::codec::length_delimited::Builder;

static START_SECIO: Once = Once::new();
static START_NO_SECIO: Once = Once::new();

static SECIO_CONTROL: OnceLock<ServiceControl> = OnceLock::new();
static NO_SECIO_CONTROL: OnceLock<ServiceControl> = OnceLock::new();

static SECIO_RECV: OnceLock<crossbeam_channel::Receiver<Notify>> = OnceLock::new();
static NO_SECIO_RECV: OnceLock<crossbeam_channel::Receiver<Notify>> = OnceLock::new();

#[derive(Debug, PartialEq)]
enum Notify {
    Connected,
    Message(bytes::Bytes),
}

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F, SecioKeyPair>
where
    F: ServiceHandle + Unpin + 'static,
{
    let builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true);

    if secio {
        builder
            .handshake_type(SecioKeyPair::secp256k1_generated().into())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

struct PHandle {
    connected_count: usize,
    sender: crossbeam_channel::Sender<Notify>,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _control: &mut ProtocolContext) {}

    async fn connected(&mut self, _control: ProtocolContextMutRef<'_>, _version: &str) {
        self.connected_count += 1;
        let _res = self.sender.send(Notify::Connected);
    }

    async fn disconnected(&mut self, _control: ProtocolContextMutRef<'_>) {
        self.connected_count -= 1;
    }

    async fn received(&mut self, _env: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        let _res = self.sender.send(Notify::Message(data));
    }
}

fn create_meta(id: ProtocolId) -> (ProtocolMeta, crossbeam_channel::Receiver<Notify>) {
    let (sender, receiver) = crossbeam_channel::bounded(1);

    let meta = MetaBuilder::new()
        .id(id)
        .codec(|| {
            Box::new(
                Builder::new()
                    .max_frame_length(1024 * 1024 * 20)
                    .new_codec(),
            )
        })
        .service_handle(move || {
            if id == ProtocolId::default() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle {
                    connected_count: 0,
                    sender,
                });
                ProtocolHandle::Callback(handle)
            }
        })
        .build();

    (meta, receiver)
}

pub fn init() {
    // init secio two peers
    START_SECIO.call_once(|| {
        let (meta, _receiver) = create_meta(ProtocolId::new(1));
        let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();
        let mut service = create(true, meta, ());
        let control = service.control().clone();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listen_addr = service
                    .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                    .await
                    .unwrap();
                let _res = addr_sender.send(listen_addr);
                service.run().await
            });
        });

        let (meta, client_receiver) = create_meta(1.into());

        thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut service = create(true, meta, ());
            rt.block_on(async move {
                let listen_addr = addr_receiver.await.unwrap();
                service
                    .dial(listen_addr, TargetProtocol::All)
                    .await
                    .unwrap();
                service.run().await
            });
        });

        assert_eq!(client_receiver.recv(), Ok(Notify::Connected));
        assert!(SECIO_CONTROL.set(control.into()).is_ok());
        assert!(SECIO_RECV.set(client_receiver).is_ok());
    });

    // init no secio two peers
    START_NO_SECIO.call_once(|| {
        let (meta, _receiver) = create_meta(ProtocolId::new(1));
        let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();
        let mut service = create(false, meta, ());
        let control = service.control().clone();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listen_addr = service
                    .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                    .await
                    .unwrap();
                let _res = addr_sender.send(listen_addr);
                service.run().await
            });
        });

        let (meta, client_receiver) = create_meta(ProtocolId::new(1));

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut service = create(false, meta, ());
            rt.block_on(async move {
                let listen_addr = addr_receiver.await.unwrap();
                service
                    .dial(listen_addr, TargetProtocol::All)
                    .await
                    .unwrap();
                service.run().await
            });
        });

        assert_eq!(client_receiver.recv(), Ok(Notify::Connected));
        assert!(NO_SECIO_CONTROL.set(control.into()).is_ok());
        assert!(NO_SECIO_RECV.set(client_receiver).is_ok());
    });
}

fn secio_and_send_data(data: &[u8]) {
    SECIO_CONTROL.get().map(|control| {
        control.filter_broadcast(
            TargetSession::All,
            ProtocolId::new(1),
            Bytes::from(data.to_owned()),
        )
    });
    if let Some(rev) = SECIO_RECV.get() {
        assert_eq!(
            rev.recv(),
            Ok(Notify::Message(bytes::Bytes::from(data.to_owned())))
        )
    }
}

fn no_secio_and_send_data(data: &[u8]) {
    NO_SECIO_CONTROL.get().map(|control| {
        control.filter_broadcast(TargetSession::All, 1.into(), Bytes::from(data.to_owned()))
    });

    if let Some(rev) = NO_SECIO_RECV.get() {
        assert_eq!(
            rev.recv(),
            Ok(Notify::Message(bytes::Bytes::from(data.to_owned())))
        )
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
        secio_and_send_data(data)
    });
    bench.bench_function_with_init("10kb_benchmark_with_no_secio", &kb, move |data| {
        no_secio_and_send_data(data)
    });
    bench.bench_function_with_init("10mb_benchmark_with_secio", &mb, move |data| {
        secio_and_send_data(data)
    });
    bench.bench_function_with_init("10mb_benchmark_with_no_secio", &mb, move |data| {
        no_secio_and_send_data(data)
    });
}
