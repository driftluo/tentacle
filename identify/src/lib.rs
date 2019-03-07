#[rustfmt::skip]
#[allow(clippy::all)]
mod protocol_generated;

mod protocol;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use log::{debug, trace};
use p2p::{
    context::{ServiceContext, SessionContext},
    secio::PeerId,
    traits::{ProtocolHandle, ProtocolMeta, ServiceProtocol},
    utils::multiaddr_to_socketaddr,
    ProtocolId, SessionId,
};
use tokio::codec::length_delimited::LengthDelimitedCodec;

use protocol::IdentifyMessage;

const CHECK_TIMEOUT_TOKEN: u64 = 100;

pub trait AddrManager {}

pub struct IdentifyProtocol {
    id: ProtocolId,
    listen_addrs: Vec<SocketAddr>,
    observed_addrs: HashMap<PeerId, SocketAddr>,
    remote_infos: HashMap<SessionId, RemoteInfo>,
}

impl IdentifyProtocol {
    pub fn new(id: ProtocolId) -> IdentifyProtocol {
        IdentifyProtocol {
            id,
            listen_addrs: Vec::new(),
            observed_addrs: HashMap::default(),
            remote_infos: HashMap::default(),
        }
    }
}

pub(crate) struct RemoteInfo {
    peer_id: PeerId,

    #[allow(dead_code)]
    session: SessionContext,
    #[allow(dead_code)]
    version: String,

    connected_at: Instant,
    timeout: Duration,
    listen_addrs: Option<Vec<SocketAddr>>,
    observed_addr: Option<SocketAddr>,
}

impl RemoteInfo {
    fn new(session: SessionContext, version: &str, timeout: Duration) -> RemoteInfo {
        let peer_id = session
            .remote_pubkey
            .as_ref()
            .map(|key| PeerId::from_public_key(&key))
            .expect("secio must enabled!");
        RemoteInfo {
            peer_id,
            session,
            version: version.to_string(),
            connected_at: Instant::now(),
            timeout,
            listen_addrs: None,
            observed_addr: None,
        }
    }
}

impl ProtocolMeta<LengthDelimitedCodec> for IdentifyProtocol {
    fn id(&self) -> ProtocolId {
        self.id
    }

    fn codec(&self) -> LengthDelimitedCodec {
        LengthDelimitedCodec::new()
    }

    fn service_handle(&self) -> ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static>> {
        ProtocolHandle::Callback(Box::new(IdentifyProtocol::new(self.id)))
    }
}

impl ServiceProtocol for IdentifyProtocol {
    fn init(&mut self, service: &mut ServiceContext) {
        self.listen_addrs = service
            .listens()
            .iter()
            .map(|addr| multiaddr_to_socketaddr(addr).unwrap())
            .collect();

        // TODO: magic number
        service.set_service_notify(self.id, Duration::from_secs(1), CHECK_TIMEOUT_TOKEN);
    }

    fn connected(&mut self, service: &mut ServiceContext, session: &SessionContext, version: &str) {
        if session.remote_pubkey.is_none() {
            panic!("IdentifyProtocol require secio enabled!");
        }
        // TODO: magic number
        let remote_info = RemoteInfo::new(session.clone(), version, Duration::from_secs(8));
        trace!("IdentifyProtocol sconnected from {:?}", remote_info.peer_id);
        self.remote_infos.insert(session.id, remote_info);

        let listen_addrs: HashSet<SocketAddr> = self
            .observed_addrs
            .values()
            .chain(self.listen_addrs.iter())
            .map(Clone::clone)
            .collect();
        let data = IdentifyMessage::ListenAddrs(listen_addrs.into_iter().collect()).encode();
        service.send_message(session.id, self.id, data);
        let remote_addr =
            multiaddr_to_socketaddr(&session.address).expect("Can not get remote address");
        let data = IdentifyMessage::ObservedAddr(remote_addr).encode();
        service.send_message(session.id, self.id, data);
    }

    fn disconnected(&mut self, _service: &mut ServiceContext, session: &SessionContext) {
        let info = self
            .remote_infos
            .remove(&session.id)
            .expect("RemoteInfo must exists");
        trace!("IdentifyProtocol disconnected from {:?}", info.peer_id);
    }

    fn received(
        &mut self,
        service: &mut ServiceContext,
        session: &SessionContext,
        data: bytes::Bytes,
    ) {
        let info = self
            .remote_infos
            .get_mut(&session.id)
            .expect("RemoteInfo must exists");
        match IdentifyMessage::decode(&data) {
            Some(IdentifyMessage::ListenAddrs(addrs)) => {
                if info.listen_addrs.is_some() {
                    // TODO report misbehavior: repeat send listen_addrs
                    debug!("remote({:?}) repeat send observed address", info.peer_id);
                } else {
                    trace!("received listen addresses: {:?}", addrs);
                    info.listen_addrs = Some(addrs);
                }
            }
            Some(IdentifyMessage::ObservedAddr(addr)) => {
                if info.observed_addr.is_some() {
                    // TODO report misbehavior: repeat send listen_addrs
                    debug!("remote({:?}) repeat send listen addresses", info.peer_id);
                } else {
                    trace!("received observed address: {}", addr);
                    info.observed_addr = Some(addr);
                    // TODO how can we trust this address?
                    self.observed_addrs.insert(info.peer_id.clone(), addr);
                }
            }
            None => {
                debug!(
                    "IdentifyProtocol received invalid data from {:?}",
                    info.peer_id
                );
                // TODO: report misbehavior: invalid data
            }
        }
    }

    fn notify(&mut self, service: &mut ServiceContext, _token: u64) {
        for (session_id, info) in self.remote_infos.iter() {
            if (info.listen_addrs.is_none() || info.observed_addr.is_none())
                && (info.connected_at + info.timeout) <= Instant::now()
            {
                // TODO: report timeout
                debug!("{:?} receive identify message timeout", info.peer_id);
            }
        }
    }
}
