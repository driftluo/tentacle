use env_logger;
use log::{debug, warn};

use fnv::FnvHashMap;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str,
    time::{Duration, Instant},
};

use futures::{
    prelude::*,
    sync::mpsc::{channel, Sender},
};
use tokio::codec::length_delimited::LengthDelimitedCodec;
use tokio::timer::{Error, Interval};

use p2p::{
    builder::ServiceBuilder,
    service::{Message, ProtocolHandle, ServiceContext, ServiceEvent, ServiceHandle, ServiceTask},
    session::{ProtocolId, ProtocolMeta, SessionId},
    SessionType,
};
use secio::PublicKey;

use discovery::{AddressManager, Direction, Discovery, DiscoveryHandle, RawAddr, Substream};

fn main() {
    env_logger::init();
    if std::env::args().nth(1) == Some("server".to_string()) {
        debug!("Starting server ......");
        let (discovery, _) = create_discovery(1);
        let protocol = DiscoveryProtocol::new(0, "server", discovery);
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .forever(true)
            .build(SHandle {});
        let _ = service.listen("127.0.0.1:1337".parse().unwrap());
        tokio::run(service.for_each(|_| Ok(())))
    } else {
        debug!("Starting client ......");
        let (discovery, _) = create_discovery(5000);
        let protocol = DiscoveryProtocol::new(0, "client", discovery);
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .forever(true)
            .build(SHandle {})
            .dial("127.0.0.1:1337".parse().unwrap());
        let _ = service.listen("127.0.0.1:1338".parse().unwrap());
        tokio::run(service.for_each(|_| Ok(())))
    }
}

fn create_discovery(start: u16) -> (Discovery<SimpleAddressManager>, DiscoveryHandle) {
    let addrs: FnvHashMap<RawAddr, i32> = (start..start + 3333)
        .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))
        .map(|addr| (RawAddr::from(addr), 100))
        .collect();
    let addr_mgr = SimpleAddressManager { addrs };
    let discovery = Discovery::new(addr_mgr);
    let handle = discovery.handle();
    (discovery, handle)
}

struct DiscoveryProtocol {
    id: usize,
    ty: &'static str,
    notify_counter: u32,
    discovery: Option<Discovery<SimpleAddressManager>>,
    discovery_handle: DiscoveryHandle,
    discovery_senders: FnvHashMap<SessionId, Sender<Vec<u8>>>,
    sessions: HashMap<SessionId, SessionData>,
}

impl DiscoveryProtocol {
    fn new(
        id: usize,
        ty: &'static str,
        discovery: Discovery<SimpleAddressManager>,
    ) -> DiscoveryProtocol {
        let discovery_handle = discovery.handle();
        DiscoveryProtocol {
            id,
            ty,
            notify_counter: 0,
            discovery: Some(discovery),
            discovery_handle,
            discovery_senders: FnvHashMap::default(),
            sessions: HashMap::default(),
        }
    }
}

impl ProtocolMeta<LengthDelimitedCodec> for DiscoveryProtocol {
    fn id(&self) -> ProtocolId {
        self.id
    }
    fn codec(&self) -> LengthDelimitedCodec {
        LengthDelimitedCodec::new()
    }
    fn handle(&self) -> Option<Box<dyn ProtocolHandle + Send + 'static>> {
        let discovery = self
            .discovery
            .as_ref()
            .map(|discovery| Discovery::new(discovery.addr_mgr().clone()));
        let discovery_handle = discovery
            .as_ref()
            .map(|discovery| discovery.handle())
            .unwrap();

        Some(Box::new(DiscoveryProtocol {
            id: self.id,
            ty: self.ty,
            notify_counter: 0,
            discovery,
            discovery_handle,
            discovery_senders: FnvHashMap::default(),
            sessions: HashMap::default(),
        }))
    }
}

impl ProtocolHandle for DiscoveryProtocol {
    fn init(&mut self, control: &mut ServiceContext) {
        debug!("protocol [discovery({})]: init", self.id);

        let mut interval_sender = control.sender().clone();
        let proto_id = self.id();
        let interval_seconds = 5;
        debug!("Setup interval {} seconds", interval_seconds);
        let interval_task = Interval::new(Instant::now(), Duration::from_secs(interval_seconds))
            .for_each(move |_| {
                interval_sender
                    .try_send(ServiceTask::ProtocolNotify { proto_id, token: 3 })
                    .map_err(|err| {
                        warn!("interval error: {:?}", err);
                        Error::shutdown()
                    })
            })
            .map_err(|err| warn!("{}", err));
        let discovery_task = self
            .discovery
            .take()
            .map(|discovery| {
                debug!("Start discovery future_task");
                discovery
                    .for_each(|()| {
                        debug!("discovery.for_each()");
                        Ok(())
                    })
                    .map_err(|err| {
                        warn!("discovery stream error: {:?}", err);
                        ()
                    })
                    .then(|_| {
                        warn!("End of discovery");
                        Ok(())
                    })
            })
            .unwrap();
        control.future_task(interval_task);
        control.future_task(discovery_task);
    }

    fn connected(
        &mut self,
        control: &mut ServiceContext,
        session_id: SessionId,
        address: SocketAddr,
        ty: SessionType,
        _: &Option<PublicKey>,
        _: &str,
    ) {
        self.sessions
            .entry(session_id)
            .or_insert(SessionData::new(address, ty));
        debug!(
            "protocol [discovery] open on session [{}], address: [{}], type: [{:?}]",
            session_id, address, ty
        );

        let direction = if ty == SessionType::Server {
            Direction::Inbound
        } else {
            Direction::Outbound
        };
        let (sender, receiver) = channel(8);
        self.discovery_senders.insert(session_id, sender);
        let substream = Substream::new(
            address,
            direction,
            self.id,
            session_id,
            receiver,
            control.sender().clone(),
            control.listens(),
        );
        match self.discovery_handle.substream_sender.try_send(substream) {
            Ok(_) => {
                debug!("Send substream success");
            }
            Err(err) => {
                warn!("Send substream failed : {:?}", err);
            }
        }
    }

    fn disconnected(&mut self, _control: &mut ServiceContext, session_id: SessionId) {
        self.sessions.remove(&session_id);
        self.discovery_senders.remove(&session_id);
        debug!("protocol [discovery] close on session [{}]", session_id);
    }

    fn received(&mut self, _env: &mut ServiceContext, data: Message) {
        debug!("[received message]: length={}", data.data.len());
        self.sessions
            .get_mut(&data.id)
            .unwrap()
            .push_data(data.data.clone());
        if let Some(ref mut sender) = self.discovery_senders.get_mut(&data.id) {
            if let Err(err) = sender.try_send(data.data) {
                if err.is_full() {
                    warn!("channel is full");
                } else if err.is_disconnected() {
                    warn!("channel is disconnected");
                } else {
                    warn!("other channel error: {:?}", err);
                }
            }
        }
    }

    fn notify(&mut self, _control: &mut ServiceContext, token: u64) {
        debug!("protocol [discovery] received notify token: {}", token);
        self.notify_counter += 1;
    }
}

struct SHandle {}

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceEvent) {
        debug!("service error: {:?}", error);
    }

    fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        debug!("service event: {:?}", event);
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
        SessionData {
            address,
            ty,
            data: Vec::new(),
        }
    }

    fn push_data(&mut self, data: Vec<u8>) {
        self.data.push(data);
    }
}

#[derive(Default, Clone, Debug)]
pub struct SimpleAddressManager {
    pub addrs: FnvHashMap<RawAddr, i32>,
}

impl AddressManager for SimpleAddressManager {
    fn add_new(&mut self, addr: SocketAddr) {
        self.addrs.entry(RawAddr::from(addr)).or_insert(100);
    }

    fn misbehave(&mut self, addr: SocketAddr, _ty: u64) -> i32 {
        let value = self.addrs.entry(RawAddr::from(addr)).or_insert(100);
        *value -= 20;
        *value
    }

    fn get_random(&mut self, n: usize) -> Vec<SocketAddr> {
        self.addrs
            .keys()
            .take(n)
            .map(|addr| addr.socket_addr())
            .collect()
    }
}
