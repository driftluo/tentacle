use env_logger;
use log::debug;

use fnv::FnvHashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures::prelude::*;

use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::ServiceContext,
    multiaddr::{Multiaddr, ToMultiaddr},
    service::{DialProtocol, ProtocolHandle, ProtocolMeta, ServiceError, ServiceEvent},
    traits::ServiceHandle,
    utils::multiaddr_to_socketaddr,
    ProtocolId,
};

use discovery::{AddressManager, Discovery, DiscoveryProtocol, Misbehavior, RawAddr};

fn main() {
    env_logger::init();
    if std::env::args().nth(1) == Some("server".to_string()) {
        debug!("Starting server ......");
        let meta = create_meta(1, 0);
        let mut service = ServiceBuilder::default()
            .insert_protocol(meta)
            .forever(true)
            .build(SHandle {});
        let _ = service.listen("/ip4/127.0.0.1/tcp/1337".parse().unwrap());
        tokio::run(service.for_each(|_| Ok(())))
    } else {
        debug!("Starting client ......");
        let meta = create_meta(1, 0);
        let mut service = ServiceBuilder::default()
            .insert_protocol(meta)
            .forever(true)
            .build(SHandle {});

        let _ = service.dial(
            "/ip4/127.0.0.1/tcp/1337".parse().unwrap(),
            DialProtocol::All,
        );
        let _ = service.listen("/ip4/127.0.0.1/tcp/1338".parse().unwrap());
        tokio::run(service.for_each(|_| Ok(())))
    }
}

fn create_meta(id: ProtocolId, start: u16) -> ProtocolMeta {
    let addrs: FnvHashMap<RawAddr, i32> = (start..start + 3333)
        .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))
        .map(|addr| (RawAddr::from(addr), 100))
        .collect();
    let addr_mgr = SimpleAddressManager { addrs };
    MetaBuilder::default()
        .id(id)
        .service_handle(move |meta| {
            let discovery = Discovery::new(addr_mgr.clone());
            ProtocolHandle::Callback(Box::new(DiscoveryProtocol::new(meta.id(), discovery)))
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
    pub addrs: FnvHashMap<RawAddr, i32>,
}

impl AddressManager for SimpleAddressManager {
    fn add_new(&mut self, addr: Multiaddr) {
        self.addrs
            .entry(RawAddr::from(multiaddr_to_socketaddr(&addr).unwrap()))
            .or_insert(100);
    }

    fn misbehave(&mut self, addr: Multiaddr, _ty: Misbehavior) -> i32 {
        let value = self
            .addrs
            .entry(RawAddr::from(multiaddr_to_socketaddr(&addr).unwrap()))
            .or_insert(100);
        *value -= 20;
        *value
    }

    fn get_random(&mut self, n: usize) -> Vec<Multiaddr> {
        self.addrs
            .keys()
            .take(n)
            .map(|addr| addr.socket_addr().to_multiaddr().unwrap())
            .collect()
    }
}
