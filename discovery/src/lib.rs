use std::collections::{VecDeque};
use std::io;

use fnv::{FnvHashMap, FnvHashSet};
use futures::{
    sync::mpsc::{channel, Receiver, Sender},
    try_ready, Async, AsyncSink, Poll, Sink, Stream,
};
use log::{debug, trace};
use rand::seq::SliceRandom;

mod addr;
mod message;
mod substream;

pub use crate::{
    addr::{AddrKnown, RawAddr, AddressManager},
    message::{DiscoveryMessage, Nodes, Node},
    substream::{Direction, SubstreamKey, SubstreamValue, Substream},
};

use crate::addr::{DEFAULT_MAX_KNOWN};

pub struct Discovery<M> {
    // Default: 5000
    max_known: usize,

    // Address Manager
    addr_mgr: M,

    // The Nodes not yet been yield
    pending_nodes: VecDeque<(SubstreamKey, Nodes)>,

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

    // fn bootstrap() {}
    // fn query_dns() {}
    // fn get_builtin_addresses() {}

    fn get_nodes(&mut self) {}
    fn handle_nodes(&mut self) {}
}

impl<M: AddressManager> Stream for Discovery<M> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        debug!("Discovery.poll()");
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

        let mut announce_addrs = Vec::new();
        for (key, value) in self.substreams.iter_mut() {
            if let Err(err) = value.check_timer() {
                debug!("substream {:?} poll timer_future error: {:?}", key, err);
                self.err_keys.insert(key.clone());
            }

            match value.receive_messages(&mut self.addr_mgr) {
                Ok(Some(nodes_list)) => {
                    for nodes in nodes_list {
                        self.pending_nodes.push_back((key.clone(), nodes));
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
                announce_addrs.push(RawAddr::from(value.remote_addr));
                value.announce = false;
            }
        }

        for key in self.err_keys.drain() {
            self.substreams.remove(&key);
        }

        let mut rng = rand::thread_rng();
        let mut remain_keys = self.substreams.keys().cloned().collect::<Vec<_>>();
        for announce_addr in announce_addrs.into_iter() {
            remain_keys.shuffle(&mut rng);
            for i in 0..2 {
                if let Some(key) = remain_keys.get(i) {
                    if let Some(value) = self.substreams.get_mut(key) {
                        if value.announce_addrs.len() < 10 && !value.addr_known.contains(&announce_addr) {
                            value.announce_addrs.push(announce_addr);
                            value.addr_known.insert(announce_addr);
                        }
                    }
                }
            }
        }

        for (key, value) in self.substreams.iter_mut() {
            let announce_addrs = value.announce_addrs.split_off(0);
            if !announce_addrs.is_empty() {
                let items = announce_addrs
                    .into_iter()
                    .map(|addr| Node { addresses: vec![addr] })
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
            Some((_key, nodes)) => {
                for node in nodes.items.into_iter() {
                    for addr in node.addresses.into_iter() {
                        self.addr_mgr.add_new(addr.socket_addr());
                    }
                }
                Ok(Async::Ready(Some(())))
            },
            None => Ok(Async::NotReady),
        }
    }
}

