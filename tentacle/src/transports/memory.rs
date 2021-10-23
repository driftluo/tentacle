use crate::{
    error::TransportErrorKind,
    lock::Mutex,
    multiaddr::{Multiaddr, Protocol},
    transports::{Result, Transport, TransportFuture},
};

use bytes::Bytes;
use futures::{
    channel::mpsc::{channel, Receiver, Sender},
    stream::{FusedStream, Stream, StreamExt},
    SinkExt,
};
use once_cell::sync::Lazy;
use std::{
    collections::{hash_map::Entry, HashMap},
    future::Future,
    io,
    num::NonZeroU64,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

static MEMORY_HUB: Lazy<Mutex<HashMap<NonZeroU64, Sender<MemorySocket>>>> =
    Lazy::new(|| Mutex::new(HashMap::default()));

async fn bind(address: Multiaddr) -> Result<(Multiaddr, MemoryListener)> {
    match parse_memory_port(&address) {
        Some(port) => {
            let insert_hub = |port: NonZeroU64, tx: Sender<MemorySocket>| -> Result<()> {
                let hub = &mut *MEMORY_HUB.lock();
                match hub.entry(port) {
                    Entry::Occupied(_) => Err(TransportErrorKind::Io(
                        io::ErrorKind::AddrNotAvailable.into(),
                    )),
                    Entry::Vacant(inner) => {
                        inner.insert(tx);
                        Ok(())
                    }
                }
            };

            let (tx, rx) = channel(8);

            let port = match NonZeroU64::new(port) {
                Some(a) => {
                    insert_hub(a, tx)?;
                    a
                }
                None => loop {
                    let port = match NonZeroU64::new(rand::random()) {
                        Some(p) => p,
                        None => continue,
                    };
                    insert_hub(port, tx)?;
                    break port;
                },
            };

            Ok((
                Protocol::Memory(port.get()).into(),
                MemoryListener { port, recv: rx },
            ))
        }
        None => Err(TransportErrorKind::NotSupported(address)),
    }
}

async fn connect(address: Multiaddr) -> Result<(Multiaddr, MemorySocket)> {
    match parse_memory_port(&address) {
        Some(port) => {
            let port = match NonZeroU64::new(port) {
                Some(port) => port,
                None => {
                    return Err(TransportErrorKind::Io(
                        io::ErrorKind::AddrNotAvailable.into(),
                    ))
                }
            };

            // don't lock too long
            let mut sender = {
                if let Some(sender) = MEMORY_HUB.lock().get(&port) {
                    sender.clone()
                } else {
                    return Err(TransportErrorKind::Io(
                        io::ErrorKind::AddrNotAvailable.into(),
                    ));
                }
            };

            let (local, remote) = MemorySocket::new();

            sender
                .send(remote)
                .await
                .map_err(|_| TransportErrorKind::Io(io::ErrorKind::ConnectionRefused.into()))?;
            Ok((address, local))
        }
        None => Err(TransportErrorKind::NotSupported(address)),
    }
}

fn parse_memory_port(addr: &Multiaddr) -> Option<u64> {
    let mut iter = addr.iter();

    if let Some(Protocol::Memory(port)) = iter.next() {
        Some(port)
    } else {
        None
    }
}

#[derive(Default)]
pub struct MemoryTransport;

pub type MemoryListenFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, MemoryListener)>> + Send>>>;
pub type MemoryDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, MemorySocket)>> + Send>>>;

impl Transport for MemoryTransport {
    type ListenFuture = MemoryListenFuture;
    type DialFuture = MemoryDialFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
        let task = bind(address);
        Ok(TransportFuture::new(Box::pin(task)))
    }

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
        let task = connect(address);
        Ok(TransportFuture::new(Box::pin(task)))
    }
}

#[derive(Debug)]
pub struct MemoryListener {
    port: NonZeroU64,
    recv: Receiver<MemorySocket>,
}

impl Stream for MemoryListener {
    type Item = std::result::Result<(Multiaddr, MemorySocket), io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.recv.poll_next_unpin(cx) {
            // inbound session addr is always empty multiaddr
            Poll::Ready(Some(s)) => {
                Poll::Ready(Some(Ok((Multiaddr::try_from(Bytes::new()).unwrap(), s))))
            }
            Poll::Ready(None) => Poll::Ready(Some(Err(io::ErrorKind::BrokenPipe.into()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for MemoryListener {
    fn drop(&mut self) {
        MEMORY_HUB.lock().remove(&self.port);
    }
}

/// A memory mock socket use on `/Memory/{port}`
#[derive(Debug)]
pub struct MemorySocket {
    sender: Sender<Vec<u8>>,
    receiver: Receiver<Vec<u8>>,
    read_buffer: Vec<u8>,
}

impl MemorySocket {
    pub fn new() -> (Self, Self) {
        let (tx, rx) = channel(1024);
        let (tx_1, rx_1) = channel(1024);

        (
            MemorySocket {
                sender: tx,
                receiver: rx_1,
                read_buffer: Default::default(),
            },
            MemorySocket {
                sender: tx_1,
                receiver: rx,
                read_buffer: Default::default(),
            },
        )
    }
}

impl AsyncRead for MemorySocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.receiver.is_terminated() || !self.read_buffer.is_empty() {
                break;
            }
            match Pin::new(&mut self.receiver).poll_next(cx) {
                Poll::Ready(Some(data)) => self.read_buffer = data,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
                Poll::Pending => break,
            }
        }

        let n = ::std::cmp::min(buf.remaining(), self.read_buffer.len());

        if n == 0 {
            Poll::Pending
        } else {
            buf.put_slice(&self.read_buffer[..n]);
            self.read_buffer.drain(..n);
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for MemorySocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.sender.poll_ready(cx) {
            Poll::Ready(Ok(())) => match self.sender.try_send(buf.to_vec()) {
                Ok(_) => Poll::Ready(Ok(buf.len())),
                Err(e) => {
                    if e.is_full() {
                        Poll::Pending
                    } else {
                        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
                    }
                }
            },
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        self.receiver.close();
        self.sender.close_channel();
        Poll::Ready(Ok(()))
    }
}
