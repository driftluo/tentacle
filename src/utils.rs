use crate::{
    multiaddr::{Multiaddr, Protocol},
    secio::PeerId,
};
use std::net::SocketAddr;

/// This module create a `DNSResolver` future task to DNS resolver
pub mod dns;

/// Change multiaddr to socketaddr
pub fn multiaddr_to_socketaddr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut iter = addr.iter().peekable();

    while iter.peek().is_some() {
        match iter.peek() {
            Some(Protocol::Ip4(_)) | Some(Protocol::Ip6(_)) => (),
            _ => {
                let _ = iter.next();
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

/// Get peer id from multiaddr
pub fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    let mut iter = addr.iter();

    iter.find_map(|proto| {
        if let Protocol::P2p(raw_bytes) = proto {
            PeerId::from_bytes(raw_bytes.into_bytes()).ok()
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
        let peer_id = SecioKeyPair::secp256k1_generated().to_peer_id();
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
        let peer_id = SecioKeyPair::secp256k1_generated().to_peer_id();
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
        let peer_id = SecioKeyPair::secp256k1_generated().to_peer_id();
        let addr: Multiaddr = format!("/ip4/127.0.0.1/p2p/{}/tcp/1337", peer_id.to_base58())
            .parse()
            .unwrap();
        multiaddr_to_socketaddr(&addr).unwrap();
    }
}
