use futures::{Async, Future, Poll};
use std::{borrow::Cow, io, net::SocketAddr, net::ToSocketAddrs, vec::IntoIter};

use crate::{
    multiaddr::{Multiaddr, Protocol},
    secio::PeerId,
    utils::{extract_peer_id, socketaddr_to_multiaddr},
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
                Some(Protocol::DNS4(_)) | Some(Protocol::DNS6(_)) => (),
                _ => {
                    let _ = iter.next();
                    continue;
                }
            }

            let proto1 = iter.next()?;
            let proto2 = iter.next()?;

            match (proto1, proto2) {
                (Protocol::DNS4(domain), Protocol::TCP(port)) => break (Some(domain), Some(port)),
                (Protocol::DNS6(domain), Protocol::TCP(port)) => break (Some(domain), Some(port)),
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

    fn new_addr(
        &mut self,
        mut iter: IntoIter<SocketAddr>,
    ) -> Poll<Multiaddr, (Multiaddr, io::Error)> {
        match iter.next() {
            Some(address) => {
                let mut address = socketaddr_to_multiaddr(address);

                if let Some(peer_id) = self.peer_id.take() {
                    address.push(Protocol::P2P(Cow::Owned(peer_id.into_bytes())))
                }
                Ok(Async::Ready(address))
            }
            None => Err((
                self.source_address.clone(),
                io::ErrorKind::InvalidData.into(),
            )),
        }
    }
}

impl Future for DNSResolver {
    type Item = Multiaddr;
    type Error = (Multiaddr, io::Error);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match tokio_threadpool::blocking(|| (self.domain.as_str(), self.port).to_socket_addrs()) {
            Ok(Async::Ready(Ok(iter))) => self.new_addr(iter),
            Ok(Async::Ready(Err(e))) => Err((self.source_address.clone(), e)),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            // https://docs.rs/tokio-threadpool/0.1.14/tokio_threadpool/fn.blocking.html#return
            // In this case, the big probability is that the tokio runtime is current thread runtime,
            // so just use block search here
            Err(_) => match (self.domain.as_str(), self.port).to_socket_addrs() {
                Ok(iter) => self.new_addr(iter),
                Err(e) => Err((self.source_address.clone(), e)),
            },
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
            Protocol::IP4(_) => {
                assert_eq!("/ip4/127.0.0.1/tcp/80".parse::<Multiaddr>().unwrap(), addr)
            }
            Protocol::IP6(_) => assert_eq!("/ip6/::1/tcp/80".parse::<Multiaddr>().unwrap(), addr),
            _ => panic!("Dns resolver fail"),
        }
    }

    #[test]
    fn dns_parser_current_thread_runtime() {
        let future: DNSResolver =
            DNSResolver::new("/dns4/localhost/tcp/80".parse().unwrap()).unwrap();
        let mut rt = tokio::runtime::current_thread::Runtime::new().unwrap();
        let addr = rt.block_on(future).unwrap();
        match addr.iter().next().unwrap() {
            Protocol::IP4(_) => {
                assert_eq!("/ip4/127.0.0.1/tcp/80".parse::<Multiaddr>().unwrap(), addr)
            }
            Protocol::IP6(_) => assert_eq!("/ip6/::1/tcp/80".parse::<Multiaddr>().unwrap(), addr),
            _ => panic!("Dns resolver fail"),
        }
    }
}
