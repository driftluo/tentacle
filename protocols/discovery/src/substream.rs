use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use futures::{sync::mpsc::Receiver, Async, AsyncSink, Poll, Sink, Stream};
use log::{debug, trace, warn};
use p2p::multiaddr::{Multiaddr, Protocol};
use p2p::{
    service::{ServiceControl, SessionType},
    utils::multiaddr_to_socketaddr,
    ProtocolId, SessionId,
};
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Interval;

use crate::addr::{AddrKnown, AddressManager, Misbehavior, RawAddr};
use crate::protocol::{DiscoveryCodec, DiscoveryMessage, Node, Nodes};

// FIXME: should be a more high level version number
const VERSION: u32 = 0;
// The maximum number of new addresses to accumulate before announcing.
const MAX_ADDR_TO_SEND: usize = 1000;
// Every 24 hours send announce nodes message
// const ANNOUNCE_INTERVAL: u64 = 3600 * 24;
const ANNOUNCE_THRESHOLD: usize = 10;

// The maximum number addresses in on Nodes item
const MAX_ADDRS: usize = 3;

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct SubstreamKey {
    pub(crate) direction: SessionType,
    pub(crate) session_id: SessionId,
    pub(crate) proto_id: ProtocolId,
}

pub struct StreamHandle {
    data_buf: BytesMut,
    proto_id: ProtocolId,
    session_id: SessionId,
    pub(crate) receiver: Receiver<Vec<u8>>,
    pub(crate) sender: ServiceControl,
}

impl io::Read for StreamHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        for _ in 0..10 {
            match self.receiver.poll() {
                Ok(Async::Ready(Some(data))) => {
                    self.data_buf.reserve(data.len());
                    self.data_buf.put(&data);
                }
                Ok(Async::Ready(None)) => {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                Ok(Async::NotReady) => {
                    break;
                }
                Err(_err) => {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
            }
        }
        let n = std::cmp::min(buf.len(), self.data_buf.len());
        if n == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let b = self.data_buf.split_to(n);
        buf[..n].copy_from_slice(&b);
        Ok(n)
    }
}

impl AsyncRead for StreamHandle {}

impl io::Write for StreamHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sender
            .send_message(self.session_id, self.proto_id, buf.to_vec())
            .map(|()| buf.len())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for StreamHandle {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        Ok(Async::Ready(()))
    }
}

pub struct SubstreamValue {
    framed_stream: Framed<StreamHandle, DiscoveryCodec>,
    // received pending messages
    pub(crate) pending_messages: VecDeque<DiscoveryMessage>,
    pub(crate) addr_known: AddrKnown,
    // FIXME: Remote listen address, resolved by id protocol
    pub(crate) remote_addr: RemoteAddress,
    pub(crate) announce: bool,
    pub(crate) announce_multiaddrs: Vec<Multiaddr>,
    session_id: SessionId,
    timer_future: Interval,
    received_get_nodes: bool,
    received_nodes: bool,
    remote_closed: bool,
}

impl SubstreamValue {
    pub(crate) fn new(
        direction: SessionType,
        stream: StreamHandle,
        max_known: usize,
        remote_addr: Multiaddr,
        listen_port: Option<u16>,
    ) -> SubstreamValue {
        let session_id = stream.session_id;
        let mut pending_messages = VecDeque::default();
        debug!("direction: {:?}", direction);
        let mut addr_known = AddrKnown::new(max_known);
        let remote_addr = if direction.is_outbound() {
            pending_messages.push_back(DiscoveryMessage::GetNodes {
                version: VERSION,
                count: MAX_ADDR_TO_SEND as u32,
                listen_port,
            });
            addr_known.insert(RawAddr::from(
                multiaddr_to_socketaddr(&remote_addr).unwrap(),
            ));

            RemoteAddress::Listen(remote_addr)
        } else {
            RemoteAddress::Init(remote_addr)
        };

        SubstreamValue {
            framed_stream: Framed::new(stream, DiscoveryCodec::default()),
            // timer_future: Interval::new_interval(Duration::from_secs(ANNOUNCE_INTERVAL)),
            timer_future: Interval::new_interval(Duration::from_secs(7)),
            pending_messages,
            addr_known,
            remote_addr,
            session_id,
            announce: false,
            announce_multiaddrs: Vec::new(),
            received_get_nodes: false,
            received_nodes: false,
            remote_closed: false,
        }
    }

    fn remote_raw_addr(&self) -> Option<RawAddr> {
        multiaddr_to_socketaddr(self.remote_addr.to_inner()).map(RawAddr::from)
    }

    pub(crate) fn check_timer(&mut self) -> Result<(), tokio::timer::Error> {
        loop {
            match self.timer_future.poll()? {
                Async::Ready(Some(_announce_at)) => {
                    self.announce = true;
                }
                Async::Ready(None) => unreachable!(),
                Async::NotReady => {
                    break;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn send_messages(&mut self) -> Result<(), io::Error> {
        while let Some(message) = self.pending_messages.pop_front() {
            debug!("Discovery sending message: {}", message);
            match self.framed_stream.start_send(message)? {
                AsyncSink::NotReady(message) => {
                    self.pending_messages.push_front(message);
                    return Ok(());
                }
                AsyncSink::Ready => {}
            }
        }
        self.framed_stream.poll_complete()?;
        Ok(())
    }

    pub(crate) fn handle_message<M: AddressManager>(
        &mut self,
        message: DiscoveryMessage,
        addr_mgr: &mut M,
    ) -> Result<Option<Nodes>, io::Error> {
        match message {
            DiscoveryMessage::GetNodes { listen_port, .. } => {
                if self.received_get_nodes {
                    // TODO: misbehavior
                    if addr_mgr
                        .misbehave(self.session_id, Misbehavior::DuplicateGetNodes)
                        .is_disconnect()
                    {
                        // TODO: more clear error type
                        warn!("Already received get nodes");
                        return Err(io::ErrorKind::Other.into());
                    }
                } else {
                    // change client random outbound port to client listen port
                    debug!("listen port: {:?}", listen_port);
                    if let Some(port) = listen_port {
                        self.remote_addr.update_port(port);
                        if let Some(raw_addr) = self.remote_raw_addr() {
                            self.addr_known.insert(raw_addr);
                        }
                        // add client listen address to manager
                        addr_mgr
                            .add_new_addr(self.session_id, self.remote_addr.clone().into_inner());
                    }

                    // TODO: magic number
                    let mut items = addr_mgr.get_random(2500);
                    while items.len() > 1000 {
                        if let Some(last_item) = items.pop() {
                            let idx = rand::random::<usize>() % 1000;
                            items[idx] = last_item;
                        }
                    }
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
                    self.pending_messages
                        .push_back(DiscoveryMessage::Nodes(nodes));
                    self.received_get_nodes = true;
                }
            }
            DiscoveryMessage::Nodes(nodes) => {
                for item in &nodes.items {
                    if item.addresses.len() > MAX_ADDRS {
                        let misbehavior = Misbehavior::TooManyAddresses(item.addresses.len());
                        if addr_mgr
                            .misbehave(self.session_id, misbehavior)
                            .is_disconnect()
                        {
                            // TODO: more clear error type
                            return Err(io::ErrorKind::Other.into());
                        }
                    }
                }

                if nodes.announce {
                    if nodes.items.len() > ANNOUNCE_THRESHOLD {
                        warn!("Nodes items more than {}", ANNOUNCE_THRESHOLD);
                        // TODO: misbehavior
                        let misbehavior = Misbehavior::TooManyItems {
                            announce: nodes.announce,
                            length: nodes.items.len(),
                        };
                        if addr_mgr
                            .misbehave(self.session_id, misbehavior)
                            .is_disconnect()
                        {
                            // TODO: more clear error type
                            return Err(io::ErrorKind::Other.into());
                        }
                    } else {
                        return Ok(Some(nodes));
                    }
                } else if self.received_nodes {
                    warn!("already received Nodes(announce=false) message");
                    // TODO: misbehavior
                    if addr_mgr
                        .misbehave(self.session_id, Misbehavior::DuplicateFirstNodes)
                        .is_disconnect()
                    {
                        // TODO: more clear error type
                        return Err(io::ErrorKind::Other.into());
                    }
                } else if nodes.items.len() > MAX_ADDR_TO_SEND {
                    warn!(
                        "Too many items (announce=false) length={}",
                        nodes.items.len()
                    );
                    // TODO: misbehavior
                    let misbehavior = Misbehavior::TooManyItems {
                        announce: nodes.announce,
                        length: nodes.items.len(),
                    };

                    if addr_mgr
                        .misbehave(self.session_id, misbehavior)
                        .is_disconnect()
                    {
                        // TODO: more clear error type
                        return Err(io::ErrorKind::Other.into());
                    }
                } else {
                    self.received_nodes = true;
                    return Ok(Some(nodes));
                }
            }
        }
        Ok(None)
    }

    pub(crate) fn receive_messages<M: AddressManager>(
        &mut self,
        addr_mgr: &mut M,
    ) -> Result<Option<(SessionId, Vec<Nodes>)>, io::Error> {
        if self.remote_closed {
            return Ok(None);
        }

        let mut nodes_list = Vec::new();
        loop {
            match self.framed_stream.poll()? {
                Async::Ready(Some(message)) => {
                    trace!("received message {}", message);
                    if let Some(nodes) = self.handle_message(message, addr_mgr)? {
                        // Add to known address list
                        for node in &nodes.items {
                            for addr in &node.addresses {
                                trace!("received address: {}", addr);
                                self.addr_known.insert(RawAddr::from(addr.clone()));
                            }
                        }
                        nodes_list.push(nodes);
                    }
                }
                Async::Ready(None) => {
                    debug!("remote closed");
                    self.remote_closed = true;
                    break;
                }
                Async::NotReady => {
                    break;
                }
            }
        }
        Ok(Some((self.session_id, nodes_list)))
    }
}

pub struct Substream {
    pub remote_addr: Multiaddr,
    pub direction: SessionType,
    pub stream: StreamHandle,
    pub listen_port: Option<u16>,
}

impl Substream {
    pub fn new(
        remote_addr: Multiaddr,
        direction: SessionType,
        proto_id: ProtocolId,
        session_id: SessionId,
        receiver: Receiver<Vec<u8>>,
        sender: ServiceControl,
        listens: &[Multiaddr],
    ) -> Substream {
        let stream = StreamHandle {
            data_buf: BytesMut::default(),
            proto_id,
            session_id,
            receiver,
            sender,
        };
        let listen_port = if direction.is_outbound() {
            let local = multiaddr_to_socketaddr(&remote_addr)
                .unwrap()
                .ip()
                .is_loopback();

            listens
                .iter()
                .map(|address| multiaddr_to_socketaddr(address).unwrap())
                .filter_map(|address| {
                    if local || RawAddr::from(address).is_reachable() {
                        Some(address.port())
                    } else {
                        None
                    }
                })
                .nth(0)
        } else {
            None
        };
        Substream {
            remote_addr,
            direction,
            stream,
            listen_port,
        }
    }
}

impl Substream {
    pub fn key(&self) -> SubstreamKey {
        SubstreamKey {
            direction: self.direction,
            session_id: self.stream.session_id,
            proto_id: self.stream.proto_id,
        }
    }
}

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub(crate) enum RemoteAddress {
    /// Inbound init remote address
    Init(Multiaddr),
    /// Outbound init remote address or Inbound listen address
    Listen(Multiaddr),
}

impl RemoteAddress {
    fn to_inner(&self) -> &Multiaddr {
        match self {
            RemoteAddress::Init(ref addr) | RemoteAddress::Listen(ref addr) => addr,
        }
    }

    fn into_inner(self) -> Multiaddr {
        match self {
            RemoteAddress::Init(addr) | RemoteAddress::Listen(addr) => addr,
        }
    }

    fn update_port(&mut self, port: u16) {
        if let RemoteAddress::Init(ref addr) = self {
            let addr = addr
                .into_iter()
                .map(|proto| {
                    match proto {
                        // TODO: ohter transport, UDP for example
                        Protocol::Tcp(_) => Protocol::Tcp(port),
                        value => value,
                    }
                })
                .collect();
            *self = RemoteAddress::Listen(addr);
        }
    }
}