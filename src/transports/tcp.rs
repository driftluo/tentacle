use futures::future::ok;
use futures::prelude::{Future, Poll};
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
    multiaddr::Multiaddr,
    transports::{Transport, TransportError},
    utils::{dns::DNSResolver, multiaddr_to_socketaddr, socketaddr_to_multiaddr},
};

/// Tcp listen bind
fn bind(address: Multiaddr) -> Result<(Multiaddr, Incoming), TransportError> {
    match multiaddr_to_socketaddr(&address) {
        Some(socket_address) => {
            let tcp = TcpListener::bind(&socket_address).map_err(TransportError::Io)?;
            let listen_addr =
                socketaddr_to_multiaddr(tcp.local_addr().map_err(TransportError::Io)?);

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
                Ok((TcpListenFuture::new(task), address))
            }
            None => {
                let listen = bind(address)?;
                let listen_addr = listen.0.clone();
                Ok((TcpListenFuture::new(ok(listen)), listen_addr))
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
                Ok(TcpDialFuture::new(task))
            }
            None => {
                let dial = connect(address, self.timeout)?;
                Ok(TcpDialFuture::new(ok(dial)))
            }
        }
    }
}

/// Tcp listen future
pub struct TcpListenFuture {
    executed: Box<dyn Future<Item = (Multiaddr, Incoming), Error = TransportError> + Send>,
}

impl TcpListenFuture {
    fn new<T>(executed: T) -> Self
    where
        T: Future<Item = (Multiaddr, Incoming), Error = TransportError> + 'static + Send,
    {
        TcpListenFuture {
            executed: Box::new(executed),
        }
    }
}

impl Future for TcpListenFuture {
    type Item = (Multiaddr, Incoming);
    type Error = TransportError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.executed.poll()
    }
}

/// Tcp dial future
pub struct TcpDialFuture {
    executed: Box<dyn Future<Item = (Multiaddr, TcpStream), Error = TransportError> + Send>,
}

impl TcpDialFuture {
    fn new<T>(executed: T) -> Self
    where
        T: Future<Item = (Multiaddr, Timeout<ConnectFuture>), Error = TransportError>
            + 'static
            + Send,
    {
        let task = executed.and_then(|(address, connect_future)| {
            connect_future
                .map(move |tcp| (address, tcp))
                .map_err(|err| {
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
                    TransportError::Io(error)
                })
        });

        TcpDialFuture {
            executed: Box::new(task),
        }
    }
}

impl Future for TcpDialFuture {
    type Item = (Multiaddr, TcpStream);
    type Error = TransportError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.executed.poll()
    }
}
