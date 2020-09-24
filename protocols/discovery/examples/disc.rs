use env_logger;
use log::debug;

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use futures::StreamExt;

use p2p::{
    builder::{MetaBuilder, ServiceBuilder},
    context::ServiceContext,
    multiaddr::Multiaddr,
    service::{ProtocolHandle, ProtocolMeta, ServiceError, ServiceEvent, TargetProtocol},
    traits::ServiceHandle,
    ProtocolId, SessionId,
};

use tentacle_discovery::{AddressManager, DiscoveryProtocol, MisbehaveResult, Misbehavior};

fn main() {
    env_logger::init();
    let meta = create_meta(1.into(), 1400);
    let mut service = ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true)
        .build(SHandle {});

    let mut rt = tokio::runtime::Runtime::new().unwrap();
    let first_arg = std::env::args().nth(1).unwrap();
    if first_arg == "server" {
        debug!("Starting server ......");
        rt.block_on(async move {
            service
                .listen("/ip4/127.0.0.1/tcp/1337".parse().unwrap())
                .await
                .unwrap();
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
    } else {
        debug!("Starting client ......");
        rt.block_on(async move {
            service
                .dial(
                    "/ip4/127.0.0.1/tcp/1337".parse().unwrap(),
                    TargetProtocol::All,
                )
                .await
                .unwrap();
            service
                .listen(format!("/ip4/127.0.0.1/tcp/{}", first_arg).parse().unwrap())
                .await
                .unwrap();
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
    }
}

fn create_meta(id: ProtocolId, start: u16) -> ProtocolMeta {
    let addrs: HashSet<Multiaddr> = (start..start + 3333)
        .map(|port| format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap())
        .collect();
    let mut peers = HashMap::default();
    peers.insert(0.into(), (100, addrs));
    let addr_mgr = SimpleAddressManager { peers };
    MetaBuilder::default()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(DiscoveryProtocol::new(
                addr_mgr,
                Some(Duration::from_secs(7)),
                None,
            )))
        })
        .build()
}

struct SHandle {}

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        debug!("service error: {:?}", error);
    }

    fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        debug!("service event: {:?}", event);
    }
}

#[derive(Default, Clone, Debug)]
pub struct SimpleAddressManager {
    pub peers: HashMap<SessionId, (i32, HashSet<Multiaddr>)>,
}

impl AddressManager for SimpleAddressManager {
    fn is_valid_addr(&self, _addr: &Multiaddr) -> bool {
        true
    }
    fn add_new_addr(&mut self, session_id: SessionId, addr: Multiaddr) {
        log::info!("{:?}", addr);
        let (_, addrs) = self
            .peers
            .entry(session_id)
            .or_insert_with(|| (100, HashSet::default()));
        addrs.insert(addr);
    }

    fn add_new_addrs(&mut self, session_id: SessionId, addrs: Vec<Multiaddr>) {
        for addr in addrs.into_iter() {
            self.add_new_addr(session_id, addr)
        }
    }

    fn misbehave(&mut self, session_id: SessionId, _ty: Misbehavior) -> MisbehaveResult {
        let (score, _) = self
            .peers
            .entry(session_id)
            .or_insert((100, HashSet::default()));
        *score -= 20;
        if *score < 0 {
            MisbehaveResult::Disconnect
        } else {
            MisbehaveResult::Continue
        }
    }

    fn get_random(&mut self, n: usize) -> Vec<Multiaddr> {
        self.peers
            .values()
            .flat_map(|(_, addrs)| addrs)
            .take(n)
            .cloned()
            .collect()
    }
}
