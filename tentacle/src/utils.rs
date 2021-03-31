use crate::{
    multiaddr::{Multiaddr, Protocol},
    secio::PeerId,
};
use std::{
    iter::{self},
    net::{IpAddr, SocketAddr},
};

/// This module create a `DnsResolver` future task to DNS resolver
#[cfg(not(target_arch = "wasm32"))]
pub mod dns;

/// Check if the ip address is reachable.
/// Copy from std::net::IpAddr::is_global
pub fn is_reachable(ip: IpAddr) -> bool {
    match ip {
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

/// Change multiaddr to socketaddr
pub fn multiaddr_to_socketaddr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut iter = addr.iter().peekable();

    while iter.peek().is_some() {
        match iter.peek() {
            Some(Protocol::Ip4(_)) | Some(Protocol::Ip6(_)) => (),
            _ => {
                // ignore is true
                let _ignore = iter.next();
                continue;
            }
        }

        let proto1 = iter.next()?;
        let proto2 = iter.next()?;

        match (proto1, proto2) {
            (Protocol::Ip4(ip), Protocol::Tcp(port)) => {
                return Some(SocketAddr::new(ip.into(), port));
            }
            (Protocol::Ip6(ip), Protocol::Tcp(port)) => {
                return Some(SocketAddr::new(ip.into(), port));
            }
            _ => (),
        }
    }

    None
}

/// convert socket address to multiaddr
pub fn socketaddr_to_multiaddr(address: SocketAddr) -> Multiaddr {
    let proto = match address.ip() {
        IpAddr::V4(ip) => Protocol::Ip4(ip),
        IpAddr::V6(ip) => Protocol::Ip6(ip),
    };
    iter::once(proto)
        .chain(iter::once(Protocol::Tcp(address.port())))
        .collect()
}

/// Get peer id from multiaddr
pub fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    let mut iter = addr.iter();

    iter.find_map(|proto| {
        if let Protocol::P2P(raw_bytes) = proto {
            PeerId::from_bytes(raw_bytes.to_vec()).ok()
        } else {
            None
        }
    })
}

#[cfg(test)]
mod test {
    use crate::{
        multiaddr::Multiaddr,
        secio::SecioKeyPair,
        utils::{extract_peer_id, multiaddr_to_socketaddr},
    };

    #[test]
    fn parser_peer_id_from_multiaddr() {
        let peer_id = SecioKeyPair::secp256k1_generated().peer_id();
        let addr_1: Multiaddr = format!("/ip4/127.0.0.1/tcp/1337/p2p/{}", peer_id.to_base58())
            .parse()
            .unwrap();
        let addr_2: Multiaddr = format!("/p2p/{}", peer_id.to_base58()).parse().unwrap();

        let second = extract_peer_id(&addr_1).unwrap();
        let third = extract_peer_id(&addr_2).unwrap();
        assert_eq!(peer_id, second);
        assert_eq!(peer_id, third);
    }

    #[test]
    fn parser_socket_addr_from_multiaddr() {
        let peer_id = SecioKeyPair::secp256k1_generated().peer_id();
        let addr_1: Multiaddr = format!("/ip4/127.0.0.1/tcp/1337/p2p/{}", peer_id.to_base58())
            .parse()
            .unwrap();
        let addr_2: Multiaddr = format!("/p2p/{}/ip4/127.0.0.1/tcp/1337", peer_id.to_base58())
            .parse()
            .unwrap();
        let addr_3: Multiaddr = "/ip4/127.0.0.1/tcp/1337".parse().unwrap();

        let second = multiaddr_to_socketaddr(&addr_1).unwrap();
        let third = multiaddr_to_socketaddr(&addr_2).unwrap();
        let fourth = multiaddr_to_socketaddr(&addr_3).unwrap();
        assert_eq!(second, "127.0.0.1:1337".parse().unwrap());
        assert_eq!(third, "127.0.0.1:1337".parse().unwrap());
        assert_eq!(fourth, "127.0.0.1:1337".parse().unwrap());
    }

    #[test]
    #[should_panic]
    fn parser_socket_addr_fail() {
        let peer_id = SecioKeyPair::secp256k1_generated().peer_id();
        let addr: Multiaddr = format!("/ip4/127.0.0.1/p2p/{}/tcp/1337", peer_id.to_base58())
            .parse()
            .unwrap();
        multiaddr_to_socketaddr(&addr).unwrap();
    }
}
