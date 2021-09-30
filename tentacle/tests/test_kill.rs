#![cfg(target_os = "linux")]
use bytes::Bytes;
use futures::channel;
use nix::{
    sys::signal::{kill, Signal},
    unistd::{fork, ForkResult},
};
use std::{thread, time::Duration};
use systemstat::{Platform, System};
use tentacle::{
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

/// Get current used memory(bytes)
fn current_used_memory() -> Option<f64> {
    let sys = System::new();
    match sys.memory() {
        Ok(mem) => Some((mem.total.as_u64() - mem.free.as_u64()) as f64),
        Err(_) => None,
    }
}

/// Get current used cpu(all cores) average usage ratio
fn current_used_cpu() -> Option<f32> {
    let sys = System::new();
    match sys.cpu_load_aggregate() {
        Ok(cpu) => {
            thread::sleep(Duration::from_secs(1));
            cpu.done().ok().map(|cpu| cpu.user)
        }
        Err(_) => None,
    }
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
    sender: crossbeam_channel::Sender<()>,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, _context: ProtocolContextMutRef<'_>, _version: &str) {
        self.connected_count += 1;
        assert_eq!(self.sender.send(()), Ok(()));
    }

    async fn disconnected(&mut self, _context: ProtocolContextMutRef<'_>) {
        self.connected_count -= 1;
        assert_eq!(self.sender.send(()), Ok(()));
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        let _res = context
            .filter_broadcast(TargetSession::All, context.proto_id, data)
            .await;
    }
}

fn create_meta(id: ProtocolId) -> (ProtocolMeta, crossbeam_channel::Receiver<()>) {
    let (sender, receiver) = crossbeam_channel::bounded(1);

    let meta = MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            if id == 0.into() {
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

/// Test just like https://github.com/libp2p/rust-libp2p/issues/648 this issue, kill some peer
/// and observe if there has a memory leak, cpu takes up too much problem
fn test_kill(secio: bool) {
    let (meta, receiver) = create_meta(1.into());
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();
    let mut service = create(secio, meta, ());
    let control: ServiceControl = service.control().clone().into();
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
    thread::sleep(Duration::from_millis(100));

    match unsafe { fork() } {
        Err(e) => panic!("Fork failed, {}", e),
        Ok(ForkResult::Parent { child }) => {
            // wait connected
            assert_eq!(receiver.recv(), Ok(()));

            let _res =
                control.filter_broadcast(TargetSession::All, 1.into(), Bytes::from("hello world"));
            let mem_start = current_used_memory().unwrap();
            let cpu_start = current_used_cpu().unwrap();

            thread::sleep(Duration::from_secs(10));
            assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
            assert_eq!(receiver.recv(), Ok(()));

            let mem_stop = current_used_memory().unwrap();
            let cpu_stop = current_used_cpu().unwrap();
            assert!((mem_stop - mem_start) / mem_start < 0.1);
            assert!((cpu_stop - cpu_start) / cpu_start < 0.1);
        }
        Ok(ForkResult::Child) => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let (meta, _receiver) = create_meta(1.into());
            let mut service = create(secio, meta, ());
            rt.block_on(async move {
                let listen_addr = addr_receiver.await.unwrap();
                service
                    .dial(listen_addr, TargetProtocol::All)
                    .await
                    .unwrap();
                service.run().await
            });
        }
    }
}

#[test]
fn test_kill_with_secio() {
    test_kill(true)
}

#[test]
fn test_kill_with_no_secio() {
    test_kill(false)
}
