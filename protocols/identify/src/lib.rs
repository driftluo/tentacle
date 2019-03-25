#[rustfmt::skip]
#[allow(clippy::all)]
mod protocol_generated;
#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod protocol_generated_verifier;

mod protocol;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use log::{debug, error, trace};
use p2p::{
    context::{ProtocolContext, ProtocolContextMutRef, SessionContext},
    multiaddr::{Multiaddr, Protocol},
    secio::PeerId,
    traits::ServiceProtocol,
    utils::{is_reachable, multiaddr_to_socketaddr},
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
pub trait Callback: Clone + Send {
    /// Add local init listen address
    fn init_local_listen_addrs(&mut self, addrs: Vec<Multiaddr>);
    /// Add local listen address
    fn add_local_listen_addr(&mut self, addr: Multiaddr);
    /// Get local listen addresses
    fn local_listen_addrs(&mut self) -> Vec<Multiaddr>;
    /// Add remote peer's listen addresses
    fn add_remote_listen_addrs(&mut self, peer: &PeerId, addrs: Vec<Multiaddr>);
    /// Add our address observed by remote peer
    fn add_observed_addr(&mut self, peer: &PeerId, addr: Multiaddr) -> MisbehaveResult;
    /// Report misbehavior
    fn misbehave(&mut self, peer: &PeerId, kind: Misbehavior) -> MisbehaveResult;
}

/// Identify protocol
pub struct IdentifyProtocol<T> {
    id: ProtocolId,
    callback: T,
    // Store last ServiceContext.listens().len() value
    listens_length: usize,
    remote_infos: HashMap<SessionId, RemoteInfo>,
    secio_enabled: bool,
}

impl<T: Callback> IdentifyProtocol<T> {
    pub fn new(id: ProtocolId, callback: T) -> IdentifyProtocol<T> {
        IdentifyProtocol {
            id,
            callback,
            listens_length: 0,
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

impl<T: Callback> ServiceProtocol for IdentifyProtocol<T> {
    fn init(&mut self, service: &mut ProtocolContext) {
        let local_listen_addrs = service.listens().to_vec();
        self.listens_length = local_listen_addrs.len();
        self.callback.init_local_listen_addrs(local_listen_addrs);

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

        // Update listen address added after current protocol init.
        let listens = service.listens();
        if listens.len() > self.listens_length {
            for addr in listens.iter().skip(self.listens_length) {
                self.callback.add_local_listen_addr(addr.clone());
            }
            self.listens_length = listens.len();
        }

        let remote_info = RemoteInfo::new(session.clone(), Duration::from_secs(DEFAULT_TIMEOUT));
        trace!("IdentifyProtocol sconnected from {:?}", remote_info.peer_id);
        self.remote_infos.insert(session.id, remote_info);

        let listen_addrs: Vec<Multiaddr> = self
            .callback
            .local_listen_addrs()
            .iter()
            .filter(|addr| {
                multiaddr_to_socketaddr(addr)
                    .map(|socket_addr| !is_reachable(socket_addr.ip()))
                    .unwrap_or(true)
            })
            .take(MAX_ADDRS)
            .cloned()
            .collect();
        let data = IdentifyMessage::ListenAddrs(listen_addrs).encode();
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
                        .callback
                        .misbehave(&info.peer_id, Misbehavior::DuplicateListenAddrs)
                        .is_disconnect()
                    {
                        service.disconnect(session.id);
                    }
                } else if addrs.len() > MAX_ADDRS {
                    if self
                        .callback
                        .misbehave(&info.peer_id, Misbehavior::TooManyAddresses(addrs.len()))
                        .is_disconnect()
                    {
                        service.disconnect(session.id);
                    }
                } else {
                    trace!("received listen addresses: {:?}", addrs);
                    let reachable_addrs = addrs
                        .into_iter()
                        .filter(|addr| {
                            multiaddr_to_socketaddr(addr)
                                .map(|socket_addr| is_reachable(socket_addr.ip()))
                                .unwrap_or(false)
                        })
                        .collect::<Vec<_>>();
                    self.callback
                        .add_remote_listen_addrs(&info.peer_id, reachable_addrs.clone());
                    info.listen_addrs = Some(reachable_addrs);
                }
            }
            Some(IdentifyMessage::ObservedAddr(addr)) => {
                if info.observed_addr.is_some() {
                    debug!("remote({:?}) repeat send listen addresses", info.peer_id);
                    if self
                        .callback
                        .misbehave(&info.peer_id, Misbehavior::DuplicateObservedAddr)
                        .is_disconnect()
                    {
                        service.disconnect(session.id);
                    }
                } else {
                    trace!("received observed address: {}", addr);

                    // Add transform observed address to local listen address list
                    if let Some(observed_ip) = multiaddr_to_socketaddr(&addr)
                        .map(|socket_addr| socket_addr.ip())
                        .filter(|ip_addr| is_reachable(*ip_addr))
                    {
                        let local_listen_addrs = self.callback.local_listen_addrs();
                        // replace observed address's port part
                        if local_listen_addrs
                            .iter()
                            .filter_map(|listen_addr| multiaddr_to_socketaddr(listen_addr))
                            .map(|socket_addr| socket_addr.ip())
                            .all(|listen_ip| listen_ip != observed_ip)
                        {
                            // NOTE: may transform too many addresses.
                            for new_listen_addr in local_listen_addrs
                                .into_iter()
                                .filter_map(|listen_addr| multiaddr_to_socketaddr(&listen_addr))
                                .filter(|socket_addr| is_reachable(socket_addr.ip()))
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
                                // TODO: how can we trust this address?
                                self.callback.add_local_listen_addr(new_listen_addr);
                                if self
                                    .callback
                                    .add_observed_addr(&info.peer_id, addr.clone())
                                    .is_disconnect()
                                {
                                    service.disconnect(session.id);
                                }
                            }
                        }
                    }
                    info.observed_addr = Some(addr.clone());
                }
            }
            None => {
                debug!(
                    "IdentifyProtocol received invalid data from {:?}",
                    info.peer_id
                );
                if self
                    .callback
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
                    .callback
                    .misbehave(&info.peer_id, Misbehavior::Timeout)
                    .is_disconnect()
                {
                    service.disconnect(*session_id);
                }
            }
        }
    }
}
