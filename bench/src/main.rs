use bench::Bench;
use bytes::Bytes;
use futures::channel;
use p2p::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceControl, TargetProtocol, TargetSession,
    },
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};
use std::{sync::Once, thread};
use tokio_util::codec::length_delimited::Builder;

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

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
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
        unsafe {
            SECIO_CONTROL = Some(control.into());
            SECIO_RECV = Some(client_receiver);
        }
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
        unsafe {
            NO_SECIO_CONTROL = Some(control.into());
            NO_SECIO_RECV = Some(client_receiver);
        }
    });
}

fn secio_and_send_data(data: &[u8]) {
    unsafe {
        SECIO_CONTROL.as_mut().map(|control| {
            control.filter_broadcast(
                TargetSession::All,
                ProtocolId::new(1),
                Bytes::from(data.to_owned()),
            )
        });
        if let Some(rev) = SECIO_RECV.as_ref() {
            assert_eq!(
                rev.recv(),
                Ok(Notify::Message(bytes::Bytes::from(data.to_owned())))
            )
        }
    }
}

fn no_secio_and_send_data(data: &[u8]) {
    unsafe {
        NO_SECIO_CONTROL.as_mut().map(|control| {
            control.filter_broadcast(TargetSession::All, 1.into(), Bytes::from(data.to_owned()))
        });

        if let Some(rev) = NO_SECIO_RECV.as_ref() {
            assert_eq!(
                rev.recv(),
                Ok(Notify::Message(bytes::Bytes::from(data.to_owned())))
            )
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
