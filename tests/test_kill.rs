use futures::prelude::Stream;
use nix::{
    sys::signal::{kill, Signal},
    unistd::{fork, ForkResult},
};
use p2p::{
    builder::ServiceBuilder,
    context::{ServiceContext, SessionContext},
    service::{Message, Service},
    traits::{ProtocolMeta, ServiceHandle, ServiceProtocol},
    ProtocolId, SecioKeyPair,
};
use std::{thread, time::Duration};
use systemstat::{Platform, System};
use tokio::codec::LengthDelimitedCodec;

/// Get current used memory(bytes)
fn current_used_memory() -> Option<f32> {
    let sys = System::new();
    match sys.memory() {
        Ok(mem) => Some((mem.total.as_usize() - mem.free.as_usize()) as f32),
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

    fn received(&mut self, env: &mut ServiceContext, session: &SessionContext, data: Vec<u8>) {
        let _ = env.send_message(
            None,
            Message {
                proto_id: self.proto_id,
                data,
                session_id: session.id,
            },
        );
    }
}

/// Test just like https://github.com/libp2p/rust-libp2p/issues/648 this issue, kill some peer
/// and observe if there has a memory leak, cpu takes up too much problem
fn test_kill(secio: bool) {
    let mut service = create(secio, Protocol::new(1), ());
    let listen_addr = service
        .listen(&"/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let mut control = service.control().clone();

    match fork() {
        Err(e) => panic!("Fork failed, {}", e),
        Ok(ForkResult::Parent { child }) => {
            thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));
            thread::sleep(Duration::from_secs(1));

            let _ = control.send_message(
                None,
                Message {
                    session_id: 1,
                    proto_id: 1,
                    data: b"hello world".to_vec(),
                },
            );
            let mem_start = current_used_memory().unwrap();
            let cpu_start = current_used_cpu().unwrap();

            thread::sleep(Duration::from_secs(10));
            assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
            thread::sleep(Duration::from_secs(3));

            let mem_stop = current_used_memory().unwrap();
            let cpu_stop = current_used_cpu().unwrap();
            assert!((mem_stop - mem_start) / mem_start < 0.1);
            assert!((cpu_stop - cpu_start) / cpu_start < 0.1);
        }
        Ok(ForkResult::Child) => {
            let service = create(secio, Protocol::new(1), ()).dial(listen_addr);
            let handle = thread::spawn(|| tokio::run(service.for_each(|_| Ok(()))));
            handle.join().expect("child process done")
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
