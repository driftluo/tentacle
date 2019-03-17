use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use fnv::{FnvHashMap, FnvHashSet};
use p2p::{multiaddr::Multiaddr, secio::PeerId, utils::multiaddr_to_socketaddr};
use serde_derive::{Deserialize, Serialize};

// See: bitcoin/netaddress.cpp pchIPv4[12]
pub(crate) const PCH_IPV4: [u8; 18] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, // ipv4 part
    0, 0, 0, 0, // port part
    0, 0,
];
pub(crate) const DEFAULT_MAX_KNOWN: usize = 5000;

pub enum Misbehavior {
    // Already received GetNodes message
    DuplicateGetNodes,
    // Already received Nodes(announce=false) message
    DuplicateFirstNodes,
    // Nodes message include too many items
    TooManyItems { announce: bool, length: usize },
    // Too many address in one item
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

// FIXME: Should be peer store?
pub trait AddressManager {
    fn add_new_addr(&mut self, peer: &PeerId, addr: Multiaddr);
    fn add_new_addrs(&mut self, peer: &PeerId, addrs: Vec<Multiaddr>);
    fn misbehave(&mut self, peer: &PeerId, kind: Misbehavior) -> MisbehaveResult;
    fn get_random(&mut self, n: usize) -> Vec<Multiaddr>;
}

// bitcoin: bloom.h, bloom.cpp => CRollingBloomFilter
pub struct AddrKnown {
    max_known: usize,
    addrs: FnvHashSet<RawAddr>,
    addr_times: FnvHashMap<RawAddr, Instant>,
    time_addrs: BTreeMap<Instant, RawAddr>,
}

impl AddrKnown {
    pub(crate) fn new(max_known: usize) -> AddrKnown {
        AddrKnown {
            max_known,
            addrs: FnvHashSet::default(),
            addr_times: FnvHashMap::default(),
            time_addrs: BTreeMap::default(),
        }
    }

    pub(crate) fn insert(&mut self, key: RawAddr) {
        let now = Instant::now();
        self.addrs.insert(key);
        self.time_addrs.insert(now, key);
        self.addr_times.insert(key, now);

        if self.addrs.len() > self.max_known {
            let first_time = {
                let (first_time, first_key) = self.time_addrs.iter().next().unwrap();
                self.addrs.remove(&first_key);
                self.addr_times.remove(&first_key);
                *first_time
            };
            self.time_addrs.remove(&first_time);
        }
    }

    pub(crate) fn contains(&self, addr: &RawAddr) -> bool {
        self.addrs.contains(addr)
    }
}

impl Default for AddrKnown {
    fn default() -> AddrKnown {
        AddrKnown::new(DEFAULT_MAX_KNOWN)
    }
}

#[derive(Copy, Clone, Debug, PartialOrd, Ord, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct RawAddr(pub(crate) [u8; 18]);

impl From<&[u8]> for RawAddr {
    fn from(source: &[u8]) -> RawAddr {
        let n = std::cmp::min(source.len(), 18);
        let mut data = PCH_IPV4;
        data.copy_from_slice(&source[0..n]);
        RawAddr(data)
    }
}

impl From<Multiaddr> for RawAddr {
    fn from(addr: Multiaddr) -> RawAddr {
        // FIXME: maybe not socket addr
        RawAddr::from(multiaddr_to_socketaddr(&addr).unwrap())
    }
}

impl From<SocketAddr> for RawAddr {
    // CService::GetKey()
    fn from(addr: SocketAddr) -> RawAddr {
        let mut data = PCH_IPV4;
        match addr.ip() {
            IpAddr::V4(ipv4) => {
                data[12..16].copy_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                data[0..16].copy_from_slice(&ipv6.octets());
            }
        }
        let port = addr.port();
        data[16] = (port / 0x100) as u8;
        data[17] = (port & 0x0FF) as u8;
        RawAddr(data)
    }
}

impl RawAddr {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip(), self.port())
    }

    pub fn ip(&self) -> IpAddr {
        let mut is_ipv4 = true;
        for (i, value) in PCH_IPV4.iter().enumerate().take(12) {
            if self.0[i] != *value {
                is_ipv4 = false;
                break;
            }
        }
        if is_ipv4 {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&self.0[12..16]);
            From::from(buf)
        } else {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&self.0[0..16]);
            From::from(buf)
        }
    }

    pub fn port(&self) -> u16 {
        0x100 * u16::from(self.0[16]) + u16::from(self.0[17])
    }

    // Copy from std::net::IpAddr::is_global
    pub fn is_reachable(&self) -> bool {
        match self.socket_addr().ip() {
            IpAddr::V4(ipv4) => {
                !ipv4.is_private()
                    && !ipv4.is_loopback()
                    && !ipv4.is_link_local()
                    && !ipv4.is_broadcast()
                    && !ipv4.is_documentation()
                    && !ipv4.is_unspecified()
            }
            IpAddr::V6(ipv6) => {
                let scope = if ipv6.is_multicast() {
                    match ipv6.segments()[0] & 0x000f {
                        1 => Some(false),
                        2 => Some(false),
                        3 => Some(false),
                        4 => Some(false),
                        5 => Some(false),
                        8 => Some(false),
                        14 => Some(true),
                        _ => None,
                    }
                } else {
                    None
                };
                match scope {
                    Some(true) => true,
                    None => {
                        !(ipv6.is_multicast()
                          || ipv6.is_loopback()
                          // && !ipv6.is_unicast_link_local()
                          || ((ipv6.segments()[0] & 0xffc0) == 0xfe80)
                          // && !ipv6.is_unicast_site_local()
                          || ((ipv6.segments()[0] & 0xffc0) == 0xfec0)
                          // && !ipv6.is_unique_local()
                          || ((ipv6.segments()[0] & 0xfe00) == 0xfc00)
                          || ipv6.is_unspecified()
                          // && !ipv6.is_documentation()
                          || ((ipv6.segments()[0] == 0x2001) && (ipv6.segments()[1] == 0xdb8)))
                    }
                    _ => false,
                }
            }
        }
    }
}
