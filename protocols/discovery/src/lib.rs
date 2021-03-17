use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use log::{debug, trace, warn};
use p2p::{
    bytes::BytesMut,
    context::{ProtocolContext, ProtocolContextMutRef},
    traits::ServiceProtocol,
    SessionId,
};
use rand::seq::SliceRandom;

pub use addr::{AddressManager, MisbehaveResult, Misbehavior};
use protocol::{decode, encode, DiscoveryMessage, Node, Nodes};
use state::{RemoteAddress, SessionState};

mod addr;
mod protocol;
mod state;

#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod protocol_mol;

const CHECK_INTERVAL: Duration = Duration::from_secs(3);
const ANNOUNCE_THRESHOLD: usize = 10;
// The maximum number of new addresses to accumulate before announcing.
const MAX_ADDR_TO_SEND: usize = 1000;
// The maximum number addresses in one Nodes item
const MAX_ADDRS: usize = 3;
// Every 24 hours send announce nodes message
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3600 * 24);

pub struct DiscoveryProtocol<M> {
    sessions: HashMap<SessionId, SessionState>,
    dynamic_query_cycle: Option<Duration>,
    addr_mgr: M,

    check_interval: Option<Duration>,
}

impl<M: AddressManager> DiscoveryProtocol<M> {
    // query_cycle: Information broadcast interval per connection, default 24 hours
    // check_interval: Global timing check status interval, default 3s
    pub fn new(
        addr_mgr: M,
        query_cycle: Option<Duration>,
        check_interval: Option<Duration>,
    ) -> DiscoveryProtocol<M> {
        DiscoveryProtocol {
            sessions: HashMap::default(),
            dynamic_query_cycle: query_cycle,
            check_interval,
            addr_mgr,
        }
    }
}

impl<M: AddressManager> ServiceProtocol for DiscoveryProtocol<M> {
    fn init(&mut self, context: &mut ProtocolContext) {
        debug!("protocol [discovery({})]: init", context.proto_id);
        context
            .set_service_notify(
                context.proto_id,
                self.check_interval.unwrap_or(CHECK_INTERVAL),
                0,
            )
            .expect("set discovery notify fail")
    }

    fn connected(&mut self, context: ProtocolContextMutRef, _version: &str) {
        let session = context.session;
        debug!(
            "protocol [discovery] open on session [{}], address: [{}], type: [{:?}]",
            session.id, session.address, session.ty
        );

        self.sessions.insert(session.id, SessionState::new(context));
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        let session = context.session;
        self.sessions.remove(&session.id);
        debug!("protocol [discovery] close on session [{}]", session.id);
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        let session = context.session;
        trace!("[received message]: length={}", data.len());

        let mgr = &mut self.addr_mgr;
        let mut check = |behavior| -> bool {
            if mgr.misbehave(session.id, behavior).is_disconnect() {
                if context.disconnect(session.id).is_err() {
                    debug!("disconnect {:?} send fail", session.id)
                }
                true
            } else {
                false
            }
        };

        match decode(&mut BytesMut::from(data.as_ref())) {
            Some(item) => {
                match item {
                    DiscoveryMessage::GetNodes {
                        listen_port, count, ..
                    } => {
                        if let Some(state) = self.sessions.get_mut(&session.id) {
                            if state.received_get_nodes && check(Misbehavior::DuplicateGetNodes) {
                                return;
                            }

                            state.received_get_nodes = true;
                            // must get the item first, otherwise it is possible to load
                            // the address of peer listen.
                            let mut items = self.addr_mgr.get_random(2500);

                            // change client random outbound port to client listen port
                            debug!("listen port: {:?}", listen_port);
                            if let Some(port) = listen_port {
                                state.remote_addr.update_port(port);
                                state.addr_known.insert(state.remote_addr.to_inner());
                                // add client listen address to manager
                                if let RemoteAddress::Listen(ref addr) = state.remote_addr {
                                    self.addr_mgr.add_new_addr(session.id, addr.clone());
                                }
                            }

                            let max = ::std::cmp::max(MAX_ADDR_TO_SEND, count as usize);
                            if items.len() > max {
                                items = items
                                    .choose_multiple(&mut rand::thread_rng(), max)
                                    .cloned()
                                    .collect();
                            }

                            state.addr_known.extend(items.iter());

                            let items = items
                                .into_iter()
                                .map(|addr| Node {
                                    addresses: vec![addr],
                                })
                                .collect::<Vec<_>>();

                            let nodes = Nodes {
                                announce: false,
                                items,
                            };

                            let msg = encode(DiscoveryMessage::Nodes(nodes));
                            if context.send_message(msg).is_err() {
                                debug!("{:?} send discovery msg Nodes fail", session.id)
                            }
                        }
                    }
                    DiscoveryMessage::Nodes(nodes) => {
                        if let Some(misbehavior) = verify_nodes_message(&nodes) {
                            if check(misbehavior) {
                                return;
                            }
                        }

                        if let Some(state) = self.sessions.get_mut(&session.id) {
                            if !nodes.announce && state.received_nodes {
                                warn!("Nodes items more than {}", ANNOUNCE_THRESHOLD);
                                if check(Misbehavior::DuplicateFirstNodes) {
                                    return;
                                }
                            } else {
                                let addrs = nodes
                                    .items
                                    .into_iter()
                                    .flat_map(|node| node.addresses.into_iter())
                                    .collect::<Vec<_>>();

                                state.addr_known.extend(addrs.iter());
                                // Non-announce nodes can only receive once
                                // Due to the uncertainty of the other party’s state,
                                // the announce node may be sent out first, and it must be
                                // determined to be Non-announce before the state can be changed
                                if !nodes.announce {
                                    state.received_nodes = true;
                                }
                                self.addr_mgr.add_new_addrs(session.id, addrs);
                            }
                        }
                    }
                }
            }
            None => {
                if self
                    .addr_mgr
                    .misbehave(session.id, Misbehavior::InvalidData)
                    .is_disconnect()
                    && context.disconnect(session.id).is_err()
                {
                    debug!("disconnect {:?} send fail", session.id)
                }
            }
        }
    }

    fn notify(&mut self, context: &mut ProtocolContext, _token: u64) {
        let now = Instant::now();

        let dynamic_query_cycle = self.dynamic_query_cycle.unwrap_or(ANNOUNCE_INTERVAL);
        let addr_mgr = &self.addr_mgr;

        // get announce list
        let announce_list: Vec<_> = self
            .sessions
            .iter_mut()
            .filter_map(|(id, state)| {
                // send all announce addr to remote
                state.send_messages(context, *id);
                // check timer
                state
                    .check_timer(now, dynamic_query_cycle)
                    .filter(|addr| addr_mgr.is_valid_addr(addr))
                    .cloned()
            })
            .collect();

        if !announce_list.is_empty() {
            let mut rng = rand::thread_rng();
            let mut keys = self.sessions.keys().cloned().collect::<Vec<_>>();
            for announce_multiaddr in announce_list {
                keys.shuffle(&mut rng);
                for key in keys.iter().take(3) {
                    if let Some(value) = self.sessions.get_mut(key) {
                        trace!(
                            ">> send {} to: {:?}, contains: {}",
                            announce_multiaddr,
                            value.remote_addr,
                            value.addr_known.contains(&announce_multiaddr)
                        );
                        if value.announce_multiaddrs.len() < 10
                            && !value.addr_known.contains(&announce_multiaddr)
                        {
                            value.announce_multiaddrs.push(announce_multiaddr.clone());
                            value.addr_known.insert(&announce_multiaddr);
                        }
                    }
                }
            }
        }
    }
}

fn verify_nodes_message(nodes: &Nodes) -> Option<Misbehavior> {
    let mut misbehavior = None;
    if nodes.announce {
        if nodes.items.len() > ANNOUNCE_THRESHOLD {
            warn!("Nodes items more than {}", ANNOUNCE_THRESHOLD);
            misbehavior = Some(Misbehavior::TooManyItems {
                announce: nodes.announce,
                length: nodes.items.len(),
            });
        }
    } else if nodes.items.len() > MAX_ADDR_TO_SEND {
        warn!(
            "Too many items (announce=false) length={}",
            nodes.items.len()
        );
        misbehavior = Some(Misbehavior::TooManyItems {
            announce: nodes.announce,
            length: nodes.items.len(),
        });
    }

    if misbehavior.is_none() {
        for item in &nodes.items {
            if item.addresses.len() > MAX_ADDRS {
                misbehavior = Some(Misbehavior::TooManyAddresses(item.addresses.len()));
                break;
            }
        }
    }

    misbehavior
}
