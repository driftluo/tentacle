use futures::{Async, Future, Poll};
use std::{io, net::ToSocketAddrs};

use crate::{
    multiaddr::{multihash::Multihash, Multiaddr, Protocol, ToMultiaddr},
    secio::PeerId,
    utils::extract_peer_id,
};

/// DNS resolver, use on multi-thread tokio runtime
pub struct DNSResolver {
    source_address: Multiaddr,
    peer_id: Option<PeerId>,
    port: u16,
    domain: String,
}

impl DNSResolver {
    /// If address like `/dns4/localhost/tcp/80` or `"/dns6/localhost/tcp/80"`,
    /// it will be return Some, else None
    pub fn new(source_address: Multiaddr) -> Option<Self> {
        let mut iter = source_address.iter().peekable();

        let (domain, port) = loop {
            if iter.peek().is_none() {
                break (None, None);
            }
            match iter.peek() {
                Some(Protocol::Dns4(_)) | Some(Protocol::Dns6(_)) => (),
                _ => {
                    let _ = iter.next();
                    continue;
                }
            }

            let proto1 = iter.next()?;
            let proto2 = iter.next()?;

            match (proto1, proto2) {
                (Protocol::Dns4(domain), Protocol::Tcp(port)) => break (Some(domain), Some(port)),
                (Protocol::Dns6(domain), Protocol::Tcp(port)) => break (Some(domain), Some(port)),
                _ => (),
            }
        };

        match (domain, port) {
            (Some(domain), Some(port)) => Some(DNSResolver {
                peer_id: extract_peer_id(&source_address),
                domain: domain.to_string(),
                source_address,
                port,
            }),
            _ => None,
        }
    }
}

impl Future for DNSResolver {
    type Item = Multiaddr;
    type Error = (Multiaddr, io::Error);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match tokio_threadpool::blocking(|| (self.domain.as_str(), self.port).to_socket_addrs()) {
            Ok(Async::Ready(Ok(mut iter))) => match iter.next() {
                Some(address) => {
                    let mut address = address.to_multiaddr().unwrap();
                    if let Some(peer_id) = self.peer_id.take() {
                        address.append(Protocol::P2p(
                            Multihash::from_bytes(peer_id.into_bytes()).expect("Invalid peer id"),
                        ))
                    }
                    Ok(Async::Ready(address))
                }
                None => Err((
                    self.source_address.clone(),
                    io::ErrorKind::InvalidData.into(),
                )),
            },
            Ok(Async::Ready(Err(e))) => Err((self.source_address.clone(), e)),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err((
                self.source_address.clone(),
                io::Error::new(io::ErrorKind::Other, e),
            )),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        multiaddr::{Multiaddr, Protocol},
        utils::dns::DNSResolver,
    };

    #[test]
    fn dns_parser() {
        let future: DNSResolver =
            DNSResolver::new("/dns4/localhost/tcp/80".parse().unwrap()).unwrap();
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let addr = rt.block_on(future).unwrap();
        match addr.iter().next().unwrap() {
            Protocol::Ip4(_) => {
                assert_eq!("/ip4/127.0.0.1/tcp/80".parse::<Multiaddr>().unwrap(), addr)
            }
            Protocol::Ip6(_) => assert_eq!("/ip6/::1/tcp/80".parse::<Multiaddr>().unwrap(), addr),
            _ => panic!("Dns resolver fail"),
        }
    }
}
