use std::collections::VecDeque;
use std::io;

use fnv::{FnvHashMap, FnvHashSet};
use futures::{
    prelude::*,
    sync::mpsc::{channel, Receiver, Sender},
    Async, Poll, Stream,
};
use log::{debug, warn};
use p2p::{
    context::{HandleContext, HandleContextMutRef},
    traits::ServiceProtocol,
    yamux::session::SessionType,
    ProtocolId, SessionId,
};
use rand::seq::SliceRandom;

mod addr;
mod protocol;
mod substream;

#[rustfmt::skip]
#[allow(clippy::all)]
mod protocol_generated;

pub use crate::{
    addr::{AddrKnown, AddressManager, MisbehaveResult, Misbehavior, RawAddr},
    protocol::{DiscoveryMessage, Node, Nodes},
    substream::{Direction, Substream, SubstreamKey, SubstreamValue},
};

use crate::{addr::DEFAULT_MAX_KNOWN, substream::RemoteAddress};

pub struct DiscoveryProtocol<M> {
    id: ProtocolId,
    discovery: Option<Discovery<M>>,
    discovery_handle: DiscoveryHandle,
    discovery_senders: FnvHashMap<SessionId, Sender<Vec<u8>>>,
}

impl<M: AddressManager> DiscoveryProtocol<M> {
    pub fn new(id: ProtocolId, discovery: Discovery<M>) -> DiscoveryProtocol<M> {
        let discovery_handle = discovery.handle();
        DiscoveryProtocol {
            id,
            discovery: Some(discovery),
            discovery_handle,
            discovery_senders: FnvHashMap::default(),
        }
    }
}

impl<M: AddressManager + Send + 'static> ServiceProtocol for DiscoveryProtocol<M> {
    fn init(&mut self, control: &mut HandleContext) {
        debug!("protocol [discovery({})]: init", self.id);

        let discovery_task = self
            .discovery
            .take()
            .map(|discovery| {
                debug!("Start discovery future_task");
                discovery
                    .for_each(|()| Ok(()))
                    .map_err(|err| {
                        warn!("discovery stream error: {:?}", err);
                    })
                    .then(|_| {
                        debug!("End of discovery");
                        Ok(())
                    })
            })
            .unwrap();
        control.future_task(discovery_task);
    }

    fn connected(&mut self, mut control: HandleContextMutRef, _: &str) {
        let session = control.session_context;
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
            session.address.clone(),
            direction,
            self.id,
            session.id,
            receiver,
            control.control().clone(),
            control.listens(),
        );
        match self.discovery_handle.substream_sender.try_send(substream) {
            Ok(_) => {
                debug!("Send substream success");
            }
            Err(err) => {
                // TODO: handle channel is full (wait for poll API?)
                warn!("Send substream failed : {:?}", err);
            }
        }
    }

    fn disconnected(&mut self, control: HandleContextMutRef) {
        self.discovery_senders.remove(&control.session_context.id);
        debug!(
            "protocol [discovery] close on session [{}]",
            control.session_context.id
        );
    }

    fn received(&mut self, control: HandleContextMutRef, data: bytes::Bytes) {
        debug!("[received message]: length={}", data.len());

        if let Some(ref mut sender) = self.discovery_senders.get_mut(&control.session_context.id) {
            // TODO: handle channel is full (wait for poll API?)
            if let Err(err) = sender.try_send(data.to_vec()) {
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
}

pub struct Discovery<M> {
    // Default: 5000
    max_known: usize,

    // Address Manager
    addr_mgr: M,

    // The Nodes not yet been yield
    pending_nodes: VecDeque<(SubstreamKey, SessionId, Nodes)>,

    // For manage those substreams
    substreams: FnvHashMap<SubstreamKey, SubstreamValue>,

    // For add new substream to Discovery
    substream_sender: Sender<Substream>,
    // For add new substream to Discovery
    substream_receiver: Receiver<Substream>,

    err_keys: FnvHashSet<SubstreamKey>,
}

#[derive(Clone)]
pub struct DiscoveryHandle {
    pub substream_sender: Sender<Substream>,
}

impl<M: AddressManager> Discovery<M> {
    pub fn new(addr_mgr: M) -> Discovery<M> {
        let (substream_sender, substream_receiver) = channel(8);
        Discovery {
            max_known: DEFAULT_MAX_KNOWN,
            addr_mgr,
            pending_nodes: VecDeque::default(),
            substreams: FnvHashMap::default(),
            substream_sender,
            substream_receiver,
            err_keys: FnvHashSet::default(),
        }
    }

    pub fn addr_mgr(&self) -> &M {
        &self.addr_mgr
    }

    pub fn handle(&self) -> DiscoveryHandle {
        DiscoveryHandle {
            substream_sender: self.substream_sender.clone(),
        }
    }

    fn recv_substreams(&mut self) -> Result<(), io::Error> {
        loop {
            match self.substream_receiver.poll() {
                Ok(Async::Ready(Some(substream))) => {
                    let key = substream.key();
                    debug!("Received a substream: key={:?}", key);
                    let value = SubstreamValue::new(
                        key.direction,
                        substream.stream,
                        self.max_known,
                        substream.remote_addr,
                        substream.listen_port,
                    );
                    self.substreams.insert(key, value);
                }
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => {
                    debug!("Discovery.substream_receiver Async::NotReady");
                    break;
                }
                Err(err) => {
                    debug!("receive substream error: {:?}", err);
                    return Err(io::ErrorKind::Other.into());
                }
            }
        }
        Ok(())
    }
}

impl<M: AddressManager> Stream for Discovery<M> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        debug!("Discovery.poll()");
        self.recv_substreams()?;

        let mut announce_multiaddrs = Vec::new();
        for (key, value) in self.substreams.iter_mut() {
            if let Err(err) = value.check_timer() {
                debug!("substream {:?} poll timer_future error: {:?}", key, err);
                self.err_keys.insert(key.clone());
            }

            match value.receive_messages(&mut self.addr_mgr) {
                Ok(Some((session_id, nodes_list))) => {
                    for nodes in nodes_list {
                        self.pending_nodes
                            .push_back((key.clone(), session_id, nodes));
                    }
                }
                Ok(None) => {
                    // TODO: EOF => remote closed the connection
                }
                Err(err) => {
                    debug!("substream {:?} receive messages error: {:?}", key, err);
                    // remove the substream
                    self.err_keys.insert(key.clone());
                }
            }

            match value.send_messages() {
                Ok(_) => {}
                Err(err) => {
                    debug!("substream {:?} send messages error: {:?}", key, err);
                    // remove the substream
                    self.err_keys.insert(key.clone());
                }
            }

            if value.announce {
                if let RemoteAddress::Listen(ref addr) = value.remote_addr {
                    announce_multiaddrs.push(addr.clone());
                }
                value.announce = false;
            }
        }

        for key in self.err_keys.drain() {
            self.substreams.remove(&key);
        }

        let mut rng = rand::thread_rng();
        let mut remain_keys = self.substreams.keys().cloned().collect::<Vec<_>>();
        for announce_multiaddr in announce_multiaddrs.into_iter() {
            let announce_addr = RawAddr::from(announce_multiaddr.clone());
            remain_keys.shuffle(&mut rng);
            for i in 0..2 {
                if let Some(key) = remain_keys.get(i) {
                    if let Some(value) = self.substreams.get_mut(key) {
                        if value.announce_multiaddrs.len() < 10
                            && !value.addr_known.contains(&announce_addr)
                        {
                            value.announce_multiaddrs.push(announce_multiaddr.clone());
                            value.addr_known.insert(announce_addr);
                        }
                    }
                }
            }
        }

        for (key, value) in self.substreams.iter_mut() {
            let announce_multiaddrs = value.announce_multiaddrs.split_off(0);
            if !announce_multiaddrs.is_empty() {
                let items = announce_multiaddrs
                    .into_iter()
                    .map(|addr| Node {
                        addresses: vec![addr],
                    })
                    .collect::<Vec<_>>();
                let nodes = Nodes {
                    announce: true,
                    items,
                };
                value
                    .pending_messages
                    .push_back(DiscoveryMessage::Nodes(nodes));
            }

            match value.send_messages() {
                Ok(_) => {}
                Err(err) => {
                    debug!("substream {:?} send messages error: {:?}", key, err);
                    // remove the substream
                    self.err_keys.insert(key.clone());
                }
            }
        }

        match self.pending_nodes.pop_front() {
            Some((_key, session_id, nodes)) => {
                let addrs = nodes
                    .items
                    .into_iter()
                    .flat_map(|node| node.addresses.into_iter())
                    .collect::<Vec<_>>();
                self.addr_mgr.add_new_addrs(session_id, addrs);
                Ok(Async::Ready(Some(())))
            }
            None => Ok(Async::NotReady),
        }
    }
}
