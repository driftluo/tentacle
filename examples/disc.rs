use env_logger;
use log::{debug, warn};

use fnv::FnvHashMap;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use futures::{
    prelude::*,
    sync::mpsc::{channel, Sender},
};
use tokio::codec::length_delimited::LengthDelimitedCodec;

use p2p::{
    builder::ServiceBuilder,
    service::{ServiceContext, ServiceEvent, ServiceHandle, ServiceProtocol, SessionContext},
    session::{ProtocolHandle, ProtocolId, ProtocolMeta, SessionId},
    SessionType,
};

use discovery::{AddressManager, Direction, Discovery, DiscoveryHandle, RawAddr, Substream};

fn main() {
    env_logger::init();
    if std::env::args().nth(1) == Some("server".to_string()) {
        debug!("Starting server ......");
        let meta = create_meta(1, 0);
        let mut service = ServiceBuilder::default()
            .insert_protocol(meta)
            .forever(true)
            .build(SHandle {});
        let _ = service.listen("127.0.0.1:1337".parse().unwrap());
        tokio::run(service.for_each(|_| Ok(())))
    } else {
        debug!("Starting client ......");
        let meta = create_meta(5000, 0);
        let mut service = ServiceBuilder::default()
            .insert_protocol(meta)
            .forever(true)
            .build(SHandle {})
            .dial("127.0.0.1:1337".parse().unwrap());
        let _ = service.listen("127.0.0.1:1338".parse().unwrap());
        tokio::run(service.for_each(|_| Ok(())))
    }
}

fn create_meta(start: u16, id: usize) -> DiscoveryProtocolMeta {
    let addrs: FnvHashMap<RawAddr, i32> = (start..start + 3333)
        .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))
        .map(|addr| (RawAddr::from(addr), 100))
        .collect();
    let addr_mgr = SimpleAddressManager { addrs };
    DiscoveryProtocolMeta { id, addr_mgr }
}

struct DiscoveryProtocolMeta {
    id: ProtocolId,
    addr_mgr: SimpleAddressManager,
}

struct DiscoveryProtocol {
    id: usize,
    notify_counter: u32,
    discovery: Option<Discovery<SimpleAddressManager>>,
    discovery_handle: DiscoveryHandle,
    discovery_senders: FnvHashMap<SessionId, Sender<Vec<u8>>>,
    sessions: HashMap<SessionId, SessionData>,
}

impl ProtocolMeta<LengthDelimitedCodec> for DiscoveryProtocolMeta {
    fn id(&self) -> ProtocolId {
        self.id
    }

    fn codec(&self) -> LengthDelimitedCodec {
        LengthDelimitedCodec::new()
    }

    fn handle(&self) -> ProtocolHandle {
        let discovery = Discovery::new(self.addr_mgr.clone());
        let discovery_handle = discovery.handle();
        let handle = Box::new(DiscoveryProtocol {
            id: self.id,
            notify_counter: 0,
            discovery: Some(discovery),
            discovery_handle,
            discovery_senders: FnvHashMap::default(),
            sessions: HashMap::default(),
        });

        ProtocolHandle::Service(handle)
    }
}

impl ServiceProtocol for DiscoveryProtocol {
    fn init(&mut self, control: &mut ServiceContext) {
        debug!("protocol [discovery({})]: init", self.id);

        let interval = Duration::from_secs(5);
        debug!("Setup interval {:?}", interval);
        control.set_notify(self.id, interval, 3);
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
        control.future_task(discovery_task);
    }

    fn connected(&mut self, control: &mut ServiceContext, session: &SessionContext) {
        self.sessions
            .entry(session.id)
            .or_insert(SessionData::new(session.address, session.ty));
        debug!(
            "protocol [discovery] open on session [{}], address: [{}], type: [{:?}]",
            session.id, session.address, session.ty
        );

        let direction = if session.ty == SessionType::Server {
            Direction::Inbound
        } else {
            Direction::Outbound
        };
        let (sender, receiver) = channel(8);
        self.discovery_senders.insert(session.id, sender);
        let substream = Substream::new(
            session.address,
            direction,
            self.id,
            session.id,
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

    fn disconnected(&mut self, _control: &mut ServiceContext, session: &SessionContext) {
        self.sessions.remove(&session.id);
        self.discovery_senders.remove(&session.id);
        debug!("protocol [discovery] close on session [{}]", session.id);
    }

    fn received(&mut self, _control: &mut ServiceContext, session: &SessionContext, data: Vec<u8>) {
        debug!("[received message]: length={}", data.len());
        self.sessions
            .get_mut(&session.id)
            .unwrap()
            .push_data(data.clone());
        if let Some(ref mut sender) = self.discovery_senders.get_mut(&session.id) {
            if let Err(err) = sender.try_send(data) {
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
