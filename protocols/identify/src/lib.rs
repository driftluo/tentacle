#[rustfmt::skip]
#[allow(clippy::all)]
mod protocol_generated;
#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod protocol_generated_verifier;

mod protocol;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use log::{debug, error, trace};
use p2p::{
    context::{ProtocolContext, ProtocolContextMutRef, SessionContext},
    multiaddr::{Multiaddr, Protocol},
    secio::PeerId,
    traits::ServiceProtocol,
    utils::multiaddr_to_socketaddr,
    ProtocolId, SessionId,
};

use protocol::IdentifyMessage;

const CHECK_TIMEOUT_TOKEN: u64 = 100;
// Check timeout interval (seconds)
const CHECK_TIMEOUT_INTERVAL: u64 = 1;
const DEFAULT_TIMEOUT: u64 = 8;
const MAX_ADDRS: usize = 10;

/// The misbehavior to report to underlying peer storage
pub enum Misbehavior {
    /// Repeat send listen addresses
    DuplicateListenAddrs,
    /// Repeat send observed address
    DuplicateObservedAddr,
    /// Timeout reached
    Timeout,
    /// Remote peer send invalid data
    InvalidData,
    /// Send too many addresses in listen addresses
    TooManyAddresses(usize),
}

/// Misbehavior report result
pub enum MisbehaveResult {
    /// Continue to run
    Continue,
    /// Disconnect this peer
    Disconnect,
}

impl MisbehaveResult {
    pub fn is_continue(&self) -> bool {
        match self {
            MisbehaveResult::Continue => true,
            _ => false,
        }
    }
    pub fn is_disconnect(&self) -> bool {
        match self {
            MisbehaveResult::Disconnect => true,
            _ => false,
        }
    }
}

/// The trait to communicate with underlying peer storage
pub trait AddrManager: Clone + Send {
    /// Add init listen address
    fn init_listen_addrs(&mut self, addrs: Vec<Multiaddr>);
    /// Add remote peer's listen addresses
    fn add_listen_addrs(&mut self, peer: &PeerId, addrs: Vec<Multiaddr>);
    /// Add our address observed by remote peer
    fn add_observed_addr(&mut self, peer: &PeerId, addr: Multiaddr) -> MisbehaveResult;
    /// Report misbehavior
    fn misbehave(&mut self, peer: &PeerId, kind: Misbehavior) -> MisbehaveResult;
}

/// Identify protocol
pub struct IdentifyProtocol<T> {
    id: ProtocolId,
    addr_mgr: T,
    listen_addrs: Vec<Multiaddr>,
    observed_addrs: HashMap<PeerId, Multiaddr>,
    remote_infos: HashMap<SessionId, RemoteInfo>,
    secio_enabled: bool,
}

impl<T: AddrManager> IdentifyProtocol<T> {
    pub fn new(id: ProtocolId, addr_mgr: T) -> IdentifyProtocol<T> {
        IdentifyProtocol {
            id,
            addr_mgr,
            listen_addrs: Vec::new(),
            observed_addrs: HashMap::default(),
            remote_infos: HashMap::default(),
            secio_enabled: true,
        }
    }
}

pub(crate) struct RemoteInfo {
    peer_id: PeerId,

    session: SessionContext,

    connected_at: Instant,
    timeout: Duration,
    listen_addrs: Option<Vec<Multiaddr>>,
    observed_addr: Option<Multiaddr>,
}

impl RemoteInfo {
    fn new(session: SessionContext, timeout: Duration) -> RemoteInfo {
        let peer_id = session
            .remote_pubkey
            .as_ref()
            .map(|key| PeerId::from_public_key(&key))
            .expect("secio must enabled!");
        RemoteInfo {
            peer_id,
            session,
            connected_at: Instant::now(),
            timeout,
            listen_addrs: None,
            observed_addr: None,
        }
    }
}

impl<T: AddrManager> ServiceProtocol for IdentifyProtocol<T> {
    fn init(&mut self, service: &mut ProtocolContext) {
        self.listen_addrs = service.listens().iter().cloned().collect();
        self.addr_mgr.init_listen_addrs(self.listen_addrs.clone());

        service.set_service_notify(
            self.id,
            Duration::from_secs(CHECK_TIMEOUT_INTERVAL),
            CHECK_TIMEOUT_TOKEN,
        );
    }

    fn connected(&mut self, mut service: ProtocolContextMutRef, _version: &str) {
        let session = service.session;
        if session.remote_pubkey.is_none() {
            error!("IdentifyProtocol require secio enabled!");
            service.disconnect(session.id);
            self.secio_enabled = false;
            return;
        }

        let remote_info = RemoteInfo::new(session.clone(), Duration::from_secs(DEFAULT_TIMEOUT));
        trace!("IdentifyProtocol sconnected from {:?}", remote_info.peer_id);
        self.remote_infos.insert(session.id, remote_info);

        let listen_addrs: HashSet<Multiaddr> = self
            .observed_addrs
            .values()
            .take(MAX_ADDRS)
            .cloned()
            .collect();
        let data = IdentifyMessage::ListenAddrs(listen_addrs.into_iter().collect()).encode();
        service.send_message(data);

        let observed_addr = session
            .address
            .iter()
            .filter(|proto| match proto {
                Protocol::P2p(_) => false,
                _ => true,
            })
            .collect::<Multiaddr>();
        let data = IdentifyMessage::ObservedAddr(observed_addr).encode();
        service.send_message(data);
    }

    fn disconnected(&mut self, service: ProtocolContextMutRef) {
        if self.secio_enabled {
            let info = self
                .remote_infos
                .remove(&service.session.id)
                .expect("RemoteInfo must exists");
            trace!("IdentifyProtocol disconnected from {:?}", info.peer_id);
        }
    }

    fn received(&mut self, mut service: ProtocolContextMutRef, data: bytes::Bytes) {
        if !self.secio_enabled {
            return;
        }

        let session = service.session;

        let info = self
            .remote_infos
            .get_mut(&session.id)
            .expect("RemoteInfo must exists");
        match IdentifyMessage::decode(&data) {
            Some(IdentifyMessage::ListenAddrs(addrs)) => {
                if info.listen_addrs.is_some() {
                    debug!("remote({:?}) repeat send observed address", info.peer_id);
                    if self
                        .addr_mgr
                        .misbehave(&info.peer_id, Misbehavior::DuplicateListenAddrs)
                        .is_disconnect()
                    {
                        service.disconnect(session.id);
                    }
                } else if addrs.len() > MAX_ADDRS {
                    if self
                        .addr_mgr
                        .misbehave(&info.peer_id, Misbehavior::TooManyAddresses(addrs.len()))
                        .is_disconnect()
                    {
                        service.disconnect(session.id);
                    }
                } else {
                    trace!("received listen addresses: {:?}", addrs);
                    self.addr_mgr.add_listen_addrs(&info.peer_id, addrs.clone());
                    info.listen_addrs = Some(addrs);
                }
            }
            Some(IdentifyMessage::ObservedAddr(addr)) => {
                if info.observed_addr.is_some() {
                    debug!("remote({:?}) repeat send listen addresses", info.peer_id);
                    if self
                        .addr_mgr
                        .misbehave(&info.peer_id, Misbehavior::DuplicateObservedAddr)
                        .is_disconnect()
                    {
                        service.disconnect(session.id);
                    }
                } else {
                    trace!("received observed address: {}", addr);

                    // TODO: this address shoulde be reachable
                    // Add transform observed address to local listen address list
                    if let Some(socket_addr) = multiaddr_to_socketaddr(&addr) {
                        let observed_ip = socket_addr.ip();

                        // replace observed address's port part
                        if self
                            .listen_addrs
                            .iter()
                            .filter_map(|listen_addr| multiaddr_to_socketaddr(listen_addr))
                            .map(|socket_addr| socket_addr.ip())
                            .all(|listen_ip| listen_ip != observed_ip)
                        {
                            // TODO: Choose a random port from current local listen addresses
                            if let Some(new_listen_addr) = self
                                .listen_addrs
                                .iter()
                                .next()
                                .and_then(|listen_addr| multiaddr_to_socketaddr(listen_addr))
                                .map(|socket_addr| socket_addr.port())
                                .map(|listen_port| {
                                    addr.iter()
                                        .map(|proto| match proto {
                                            Protocol::Tcp(_) if info.session.ty.is_outbound() => {
                                                // Replace only it's an outbound connnection
                                                Protocol::Tcp(listen_port)
                                            }
                                            value => value,
                                        })
                                        .collect()
                                })
                            {
                                // TODO how can we trust this address?
                                self.listen_addrs.push(new_listen_addr);
                                if self
                                    .addr_mgr
                                    .add_observed_addr(&info.peer_id, addr.clone())
                                    .is_disconnect()
                                {
                                    service.disconnect(session.id);
                                }
                            }
                        }
                    }
                    info.observed_addr = Some(addr.clone());
                    self.observed_addrs.insert(info.peer_id.clone(), addr);
                }
            }
            None => {
                debug!(
                    "IdentifyProtocol received invalid data from {:?}",
                    info.peer_id
                );
                if self
                    .addr_mgr
                    .misbehave(&info.peer_id, Misbehavior::InvalidData)
                    .is_disconnect()
                {
                    service.disconnect(session.id);
                }
            }
        }
    }

    fn notify(&mut self, service: &mut ProtocolContext, _token: u64) {
        if !self.secio_enabled {
            return;
        }

        let now = Instant::now();
        for (session_id, info) in &self.remote_infos {
            if (info.listen_addrs.is_none() || info.observed_addr.is_none())
                && (info.connected_at + info.timeout) <= now
            {
                debug!("{:?} receive identify message timeout", info.peer_id);
                if self
                    .addr_mgr
                    .misbehave(&info.peer_id, Misbehavior::Timeout)
                    .is_disconnect()
                {
                    service.disconnect(*session_id);
                }
            }
        }
    }
}
