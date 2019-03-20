use futures::prelude::{Async, Future, Poll};
use futures::{future::err, task};
use std::{error::Error as _, io, time::Duration};
use tokio::{
    net::{
        tcp::{ConnectFuture, Incoming},
        TcpListener, TcpStream,
    },
    prelude::FutureExt,
    timer::Timeout,
};

use crate::{
    multiaddr::{Multiaddr, ToMultiaddr},
    transports::{Transport, TransportError},
    utils::{dns::DNSResolver, multiaddr_to_socketaddr},
};

/// Tcp listen bind
fn bind(address: Multiaddr) -> Result<(Multiaddr, Incoming), TransportError> {
    match multiaddr_to_socketaddr(&address) {
        Some(socket_address) => {
            let tcp = TcpListener::bind(&socket_address).map_err(TransportError::Io)?;
            let listen_addr = tcp
                .local_addr()
                .map_err(TransportError::Io)?
                .to_multiaddr()
                .unwrap();

            Ok((listen_addr, tcp.incoming()))
        }
        None => Err(TransportError::NotSupport(address)),
    }
}

/// Tcp connect
fn connect(
    address: Multiaddr,
    timeout: Duration,
) -> Result<(Multiaddr, Timeout<ConnectFuture>), TransportError> {
    match multiaddr_to_socketaddr(&address) {
        Some(socket_address) => {
            let connect = TcpStream::connect(&socket_address).timeout(timeout);
            Ok((address, connect))
        }
        None => Err(TransportError::NotSupport(address)),
    }
}

/// Tcp transport
#[derive(Default)]
pub struct TcpTransport {
    timeout: Duration,
}

impl TcpTransport {
    pub fn new(timeout: Duration) -> Self {
        TcpTransport { timeout }
    }
}

impl Transport for TcpTransport {
    type ListenFuture = TcpListenFuture;
    type DialFuture = TcpDialFuture;

    fn listen(self, address: Multiaddr) -> Result<(Self::ListenFuture, Multiaddr), TransportError> {
        match DNSResolver::new(address.clone()) {
            Some(dns) => {
                let task = dns.then(|result| match result {
                    Ok(address) => bind(address),
                    Err(e) => Err(TransportError::DNSResolverError(e)),
                });
                Ok((TcpListenFuture::new(None, task), address))
            }
            None => {
                let listen = bind(address)?;
                let listen_addr = listen.0.clone();
                Ok((
                    TcpListenFuture::new(
                        Some(listen),
                        err::<_, TransportError>(TransportError::Empty),
                    ),
                    listen_addr,
                ))
            }
        }
    }

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture, TransportError> {
        match DNSResolver::new(address.clone()) {
            Some(dns) => {
                let task =
                    dns.map_err(TransportError::DNSResolverError)
                        .and_then(move |new_address| {
                            let rs = connect(new_address, self.timeout)?;
                            // Why do this?
                            // Because here need to save the original address as an index to open the specified protocol.
                            Ok((address, rs.1))
                        });
                Ok(TcpDialFuture::new(None, task))
            }
            None => {
                let dial = connect(address, self.timeout)?;
                Ok(TcpDialFuture::new(
                    Some(dial),
                    err::<_, TransportError>(TransportError::Empty),
                ))
            }
        }
    }
}

/// Tcp listen future
pub struct TcpListenFuture {
    finished: Option<(Multiaddr, Incoming)>,
    executed: Box<dyn Future<Item = (Multiaddr, Incoming), Error = TransportError> + Send>,
}

impl TcpListenFuture {
    fn new<T>(finished: Option<(Multiaddr, Incoming)>, executed: T) -> Self
    where
        T: Future<Item = (Multiaddr, Incoming), Error = TransportError> + 'static + Send,
    {
        TcpListenFuture {
            finished,
            executed: Box::new(executed),
        }
    }
}

impl Future for TcpListenFuture {
    type Item = (Multiaddr, Incoming);
    type Error = TransportError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(r) = self.finished.take() {
            return Ok(Async::Ready(r));
        }

        self.executed.poll()
    }
}

/// Tcp dial future
pub struct TcpDialFuture {
    finished: Option<(Multiaddr, Timeout<ConnectFuture>)>,
    executed:
        Box<dyn Future<Item = (Multiaddr, Timeout<ConnectFuture>), Error = TransportError> + Send>,
}

impl TcpDialFuture {
    fn new<T>(finished: Option<(Multiaddr, Timeout<ConnectFuture>)>, executed: T) -> Self
    where
        T: Future<Item = (Multiaddr, Timeout<ConnectFuture>), Error = TransportError>
            + 'static
            + Send,
    {
        TcpDialFuture {
            finished,
            executed: Box::new(executed),
        }
    }
}

impl Future for TcpDialFuture {
    type Item = (Multiaddr, TcpStream);
    type Error = TransportError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some((address, mut task)) = self.finished.take() {
            match task.poll() {
                Ok(Async::Ready(tcp)) => return Ok(Async::Ready((address, tcp))),
                Ok(Async::NotReady) => {
                    self.finished = Some((address, task));
                    return Ok(Async::NotReady);
                }
                Err(err) => {
                    let error = if err.is_timer() {
                        // tokio timer error
                        io::Error::new(io::ErrorKind::Other, err.description())
                    } else if err.is_elapsed() {
                        // time out error
                        io::Error::new(io::ErrorKind::TimedOut, err.description())
                    } else {
                        // dialer error
                        err.into_inner().unwrap()
                    };
                    return Err(TransportError::Io(error));
                }
            }
        }

        match self.executed.poll()? {
            Async::Ready(r) => {
                if self.finished.is_none() {
                    self.finished = Some(r);
                    task::current().notify();
                }
            }
            Async::NotReady => return Ok(Async::NotReady),
        }

        Ok(Async::NotReady)
    }
}
