

use env_logger;
use log::{info, warn};

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str,
    time::{Duration, Instant},
    collections::{HashMap},
};
use fnv::{FnvHashMap, FnvHashSet};

use futures::{oneshot, prelude::*, sync::oneshot::Sender};
use tokio::codec::length_delimited::LengthDelimitedCodec;
use tokio::timer::{Delay, Error, Interval};

use p2p::{
    builder::ServiceBuilder,
    service::{
        Message, ProtocolHandle, Service, ServiceContext, ServiceEvent, ServiceHandle, ServiceTask,
    },
    session::{ProtocolId, ProtocolMeta, SessionId},
    SessionType,
};

use discovery::{
    RawAddr,
    Discovery,
    DiscoveryHandle,
    DemoAddressManager,
};

fn main() {
    env_logger::init();
    if std::env::args().nth(1) == Some("server".to_string()) {
        info!("Starting server ......");
        let (discovery, handle) = create_discovery();
        let protocol = DiscoveryProtocol::new(0, "server", discovery);
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .build(SHandle {});
        let _ = service.listen("127.0.0.1:1337".parse().unwrap());
        tokio::run(service.for_each(|_| Ok(())))
    } else {
        info!("Starting client ......");
        let (discovery, handle) = create_discovery();
        let protocol = DiscoveryProtocol::new(0, "client", discovery);
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .build(SHandle {})
            .dial("127.0.0.1:1337".parse().unwrap());
        let _ = service.listen("127.0.0.1:1337".parse().unwrap());
        tokio::run(service.for_each(|_| Ok(())))
    }
}

fn create_discovery() -> (Discovery<DemoAddressManager>, DiscoveryHandle) {
    let addrs: FnvHashMap<RawAddr, i32>  = (1..3333)
        .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))
        .map(|addr| (RawAddr::from(addr), 100))
        .collect();
    let addr_mgr = DemoAddressManager { addrs };
    let discovery = Discovery::new(addr_mgr);
    let handle = discovery.handle();
    (discovery, handle)
}

struct DiscoveryProtocol{
    id: usize,
    ty: &'static str,
    notify_counter: u32,
    discovery: Discovery<DemoAddressManager>,
    sessions: HashMap<SessionId, SessionData>,
}

impl DiscoveryProtocol {
    fn new(id: usize, ty: &'static str, discovery: Discovery<DemoAddressManager>) -> DiscoveryProtocol {
        DiscoveryProtocol {
            id,
            ty,
            notify_counter: 0,
            discovery,
            sessions: HashMap::default(),
        }
    }
}

impl ProtocolMeta<LengthDelimitedCodec> for DiscoveryProtocol {
    fn id(&self) -> ProtocolId { self.id }
    fn codec(&self) -> LengthDelimitedCodec { LengthDelimitedCodec::new() }
    fn handle(&self) -> Option<Box<dyn ProtocolHandle + Send + 'static>> {
        Some(Box::new(DiscoveryProtocol {
            id: self.id,
            ty: self.ty,
            notify_counter: self.notify_counter,
            discovery: Discovery::new(self.discovery.addr_mgr().clone()),
            sessions: self.sessions.clone(),
        }))
    }
}

impl ProtocolHandle for DiscoveryProtocol {
    fn init(&mut self, control: &mut ServiceContext) {
        info!("protocol [discovery({})]: init", self.id);

        let mut interval_sender = control.sender().clone();
        let proto_id = self.id();
        let interval_task = Interval::new(Instant::now(), Duration::from_secs(5))
            .for_each(move |_| {
                interval_sender
                    .try_send(ServiceTask::ProtocolNotify { proto_id, token: 3 })
                    .map(|_| ())
                    .map_err(|err| {
                        warn!("interval error: {:?}", err);
                        Error::shutdown()
                    })
            })
            .map_err(|err| warn!("{}", err));
        control.future_task(interval_task);
    }

    fn connected(
        &mut self,
        _control: &mut ServiceContext,
        session_id: SessionId,
        address: SocketAddr,
        ty: SessionType,
    ) {
        self.sessions.entry(session_id).or_insert(SessionData::new(address, ty));
        info!(
            "protocol [discovery] open on session [{}], address: [{}], type: [{:?}]",
            session_id, address, ty
        );
    }

    fn disconnected(&mut self, _control: &mut ServiceContext, session_id: SessionId) {
        self.sessions.remove(&session_id);
        info!("protocol [discovery] close on session [{}]", session_id);
    }

    fn received(&mut self, _env: &mut ServiceContext, data: Message) {
        info!("[received message]: {}", String::from_utf8(data.data.clone()).unwrap());
        self.sessions.get_mut(&data.id).unwrap().push_data(data.data);
    }

    fn notify(&mut self, control: &mut ServiceContext, token: u64) {
        info!("protocol [discovery] received notify token: {}", token);
        self.notify_counter += 1;
        let message = Message {
            id: 0,
            proto_id: self.id,
            data: format!("notify counter from {}: {}", self.ty, self.notify_counter).into_bytes(),
        };
        control.send_message(None, message);
    }
}

struct SHandle {}

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceEvent) {
        info!("service error: {:?}", error);
    }

    fn handle_event(&mut self, env: &mut ServiceContext, event: ServiceEvent) {
        info!("service event: {:?}", event);
    }
}

#[derive(Clone)]
struct SessionData {
    ty: SessionType,
    address: SocketAddr,
    data: Vec<Vec<u8>>,
}

impl SessionData {
    fn new(address: SocketAddr, ty: SessionType) -> Self {
        SessionData { address, ty, data: Vec::new() }
    }

    fn push_data(&mut self, data: Vec<u8>) {
        self.data.push(data);
    }
}
