use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use bincode::{deserialize, serialize};
use bytes::{BufMut, Bytes, BytesMut};
use fnv::{FnvHashMap, FnvHashSet};
use log::debug;
use rand::seq::SliceRandom;
use serde_derive::{Deserialize, Serialize};


// See: bitcoin/netaddress.cpp pchIPv4[12]
pub(crate) const PCH_IPV4: [u8; 18] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, // ipv4 part
    0, 0, 0, 0, // port part
    0, 0,
];
pub(crate) const DEFAULT_MAX_KNOWN: usize = 5000;

// FIXME: Should be peer store?
pub trait AddressManager {
    fn add_new(&mut self, addr: SocketAddr);
    fn misbehave(&mut self, addr: SocketAddr, ty: u64) -> i32;
    fn get_random(&mut self, n: usize) -> Vec<SocketAddr>;
}

#[derive(Default, Clone)]
pub struct DemoAddressManager {
    pub addrs: FnvHashMap<RawAddr, i32>,
}

impl DemoAddressManager {
}

impl AddressManager for DemoAddressManager {
    fn add_new(&mut self, addr: SocketAddr) {
        self.addrs.entry(RawAddr::from(addr)).or_insert(100);
    }

    fn misbehave(&mut self, addr: SocketAddr, ty: u64) -> i32 {
        let value = self.addrs
            .entry(RawAddr::from(addr))
            .or_insert(100);
        *value -= 20;
        *value
    }

    fn get_random(&mut self, n: usize) -> Vec<SocketAddr> {
        self.addrs
            .keys()
            .take(n)
            .map(|addr| addr.socket_addr())
            .collect()
    }
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
        self.addrs.insert(key.clone());
        self.time_addrs.insert(now.clone(), key.clone());
        self.addr_times.insert(key, now);

        if self.addrs.len() > self.max_known {
            let first_time = {
                let (first_time, first_key) = self.time_addrs.iter().next().unwrap();
                self.addrs.remove(&first_key);
                self.addr_times.remove(&first_key);
                first_time.clone()
            };
            self.time_addrs.remove(&first_time);
        }
    }

    pub(crate) fn contains(&self, addr: &RawAddr) -> bool {
        self.addrs.contains(addr)
    }

    pub(crate) fn reset(&mut self) {
        self.addrs.clear();
        self.time_addrs.clear();
        self.addr_times.clear();
    }
}

impl Default for AddrKnown {
    fn default() -> AddrKnown {
        AddrKnown::new(DEFAULT_MAX_KNOWN)
    }
}

#[derive(Clone, Debug, PartialOrd, Ord, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct RawAddr([u8; 18]);

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
        let mut is_ipv4 = true;
        for i in 0..12 {
            if self.0[i] != PCH_IPV4[i] {
                is_ipv4 = false;
                break;
            }
        }
        let ip: IpAddr = if is_ipv4 {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&self.0[12..16]);
            From::from(buf)
        } else {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&self.0[0..16]);
            From::from(buf)
        };
        let port = 0x100 * self.0[16] as u16 + self.0[17] as u16;
        SocketAddr::new(ip, port)
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
                        !ipv6.is_multicast()
                            && !ipv6.is_loopback()
                        // && !ipv6.is_unicast_link_local()
                            && !((ipv6.segments()[0] & 0xffc0) == 0xfe80)
                        // && !ipv6.is_unicast_site_local()
                            && !((ipv6.segments()[0] & 0xffc0) == 0xfec0)
                        // && !ipv6.is_unique_local()
                            && !((ipv6.segments()[0] & 0xfe00) == 0xfc00)
                            && !ipv6.is_unspecified()
                        // && !ipv6.is_documentation()
                            && !((ipv6.segments()[0] == 0x2001) && (ipv6.segments()[1] == 0xdb8))
                    }
                    _ => false,
                }
            }
        }
    }
}
