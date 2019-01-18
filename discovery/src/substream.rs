use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use futures::{sync::mpsc::Receiver, Async, AsyncSink, Poll, Sink, Stream};
use log::{debug, trace, warn};
use p2p::multiaddr::{Multiaddr, ToMultiaddr};
use p2p::service::Message;
use p2p::{
    context::ServiceControl, error::Error, utils::multiaddr_to_socketaddr, ProtocolId, SessionId,
};
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Interval;

use crate::addr::{AddrKnown, AddressManager, RawAddr};
use crate::message::{DiscoveryCodec, DiscoveryMessage, Node, Nodes};

// FIXME: should be a more high level version number
const VERSION: u32 = 0;
// The maximum number of new addresses to accumulate before announcing.
const MAX_ADDR_TO_SEND: usize = 1000;
// Every 24 hours send announce nodes message
// const ANNOUNCE_INTERVAL: u64 = 3600 * 24;
const ANNOUNCE_THRESHOLD: usize = 10;

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct SubstreamKey {
    pub(crate) direction: Direction,
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
            .send_message(
                Some(vec![self.session_id]),
                Message {
                    session_id: self.session_id,
                    proto_id: self.proto_id,
                    data: buf.to_vec(),
                },
            )
            .map(|()| buf.len())
            .map_err(|err| {
                if let Error::TaskFull(_) = err {
                    io::ErrorKind::WouldBlock.into()
                } else {
                    io::ErrorKind::BrokenPipe.into()
                }
            })
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
    pub(crate) announce_addrs: Vec<RawAddr>,
    timer_future: Interval,
    received_get_nodes: bool,
    received_nodes: bool,
    remote_closed: bool,
}

impl SubstreamValue {
    pub(crate) fn new(
        direction: Direction,
        stream: StreamHandle,
        max_known: usize,
        remote_addr: SocketAddr,
        listen_port: Option<u16>,
    ) -> SubstreamValue {
        let mut pending_messages = VecDeque::default();
        debug!("direction: {:?}", direction);
        let mut addr_known = AddrKnown::new(max_known);
        let remote_addr = if direction == Direction::Outbound {
            pending_messages.push_back(DiscoveryMessage::GetNodes {
                version: VERSION,
                count: MAX_ADDR_TO_SEND as u32,
                listen_port,
            });
            addr_known.insert(RawAddr::from(remote_addr));

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
            announce: false,
            announce_addrs: Vec::new(),
            received_get_nodes: false,
            received_nodes: false,
            remote_closed: false,
        }
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
                    if addr_mgr.misbehave(self.remote_addr.into_multiaddr(), 111) < 0 {
                        // TODO: more clear error type
                        warn!("Already received get nodes");
                        return Err(io::ErrorKind::Other.into());
                    }
                } else {
                    // change client random outbound port to client listen port
                    debug!("listen port: {:?}", listen_port);
                    if let Some(port) = listen_port {
                        self.remote_addr = self.remote_addr.into_listen(port);
                        self.addr_known.insert(self.remote_addr.into_inner().into());
                        // add client listen address to manager
                        addr_mgr.add_new(self.remote_addr.into_multiaddr());
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
                            addresses: vec![RawAddr::from(multiaddr_to_socketaddr(&addr).unwrap())],
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
                if nodes.announce {
                    if nodes.items.len() > ANNOUNCE_THRESHOLD {
                        warn!("Nodes number more than {}", ANNOUNCE_THRESHOLD);
                        // TODO: misbehavior
                        if addr_mgr.misbehave(self.remote_addr.into_multiaddr(), 222) < 0 {
                            // TODO: more clear error type
                            return Err(io::ErrorKind::Other.into());
                        }
                    } else {
                        return Ok(Some(nodes));
                    }
                } else if self.received_nodes {
                    warn!("already received Nodes(announce=false) message");
                    // TODO: misbehavior
                    if addr_mgr.misbehave(self.remote_addr.into_multiaddr(), 333) < 0 {
                        // TODO: more clear error type
                        return Err(io::ErrorKind::Other.into());
                    }
                } else if nodes.items.len() > MAX_ADDR_TO_SEND {
                    warn!(
                        "Too many addresses(announce=false): the length={}",
                        nodes.items.len()
                    );
                    // TODO: misbehavior
                    if addr_mgr.misbehave(self.remote_addr.into_multiaddr(), 444) < 0 {
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
    ) -> Result<Option<Vec<Nodes>>, io::Error> {
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
                                trace!("received address: {}", addr.socket_addr());
                                self.addr_known.insert(*addr);
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
        Ok(Some(nodes_list))
    }
}

pub struct Substream {
    pub remote_addr: SocketAddr,
    pub direction: Direction,
    pub stream: StreamHandle,
    pub listen_port: Option<u16>,
}

impl Substream {
    pub fn new(
        remote_addr: &Multiaddr,
        direction: Direction,
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
        let remote_addr = multiaddr_to_socketaddr(remote_addr).unwrap();
        let listen_port = if direction == Direction::Outbound {
            let local = remote_addr.ip().is_loopback();

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

#[derive(Eq, PartialEq, Hash, Debug, Clone, Copy)]
pub enum Direction {
    // The connection(session) is open by other peer
    Inbound,
    // The connection(session) is open by current peer
    Outbound,
}

#[derive(Eq, PartialEq, Hash, Debug, Clone, Copy)]
pub(crate) enum RemoteAddress {
    /// Inbound init remote address
    Init(SocketAddr),
    /// Outbound init remote address or Inbound listen address
    Listen(SocketAddr),
}

impl RemoteAddress {
    pub(crate) fn into_multiaddr(self) -> Multiaddr {
        match self {
            RemoteAddress::Init(addr) | RemoteAddress::Listen(addr) => addr.to_multiaddr().unwrap(),
        }
    }

    fn into_inner(self) -> SocketAddr {
        match self {
            RemoteAddress::Init(addr) | RemoteAddress::Listen(addr) => addr,
        }
    }

    fn into_listen(self, port: u16) -> Self {
        if let RemoteAddress::Init(mut addr) = self {
            addr.set_port(port);
            RemoteAddress::Listen(addr)
        } else {
            self
        }
    }
}
