use futures::{future::ok, Sink, StreamExt, TryFutureExt};
use log::debug;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{Error, Message},
    WebSocketStream,
};

use crate::{
    error::TransportErrorKind,
    multiaddr::Multiaddr,
    runtime::TcpStream,
    service::config::TcpSocketConfig,
    transports::{tcp_dial, Result, TransportDial, TransportFuture},
    utils::{dns::DnsResolver, multiaddr_to_socketaddr},
};

/// websocket connect
async fn connect(
    address: impl Future<Output = Result<Multiaddr>>,
    timeout: Duration,
    original: Option<Multiaddr>,
    tcp_config: TcpSocketConfig,
) -> Result<(Multiaddr, WsStream)> {
    let addr = address.await?;
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let url = format!("ws://{}:{}", socket_address.ip(), socket_address.port());
            let tcp = tcp_dial(socket_address, tcp_config, timeout).await?;

            match crate::runtime::timeout(timeout, client_async_with_config(url, tcp, None)).await {
                Err(_) => Err(TransportErrorKind::Io(io::ErrorKind::TimedOut.into())),
                Ok(res) => Ok((original.unwrap_or(addr), {
                    let (stream, _) = res.map_err(|err| {
                        if let Error::Io(e) = err {
                            TransportErrorKind::Io(e)
                        } else {
                            TransportErrorKind::Io(io::ErrorKind::ConnectionAborted.into())
                        }
                    })?;
                    WsStream::new(stream)
                })),
            }
        }
        None => Err(TransportErrorKind::NotSupported(original.unwrap_or(addr))),
    }
}

pub struct WsTransport {
    timeout: Duration,
    tcp_config: TcpSocketConfig,
}

impl WsTransport {
    pub fn new(timeout: Duration, tcp_config: TcpSocketConfig) -> Self {
        WsTransport {
            timeout,
            tcp_config,
        }
    }
}

pub type WsDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, WsStream)>> + Send>>>;

impl TransportDial for WsTransport {
    type DialFuture = WsDialFuture;

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
        match DnsResolver::new(address.clone()) {
            Some(dns) => {
                // Why do this?
                // Because here need to save the original address as an index to open the specified protocol.
                let task = connect(
                    dns.map_err(|(multiaddr, io_error)| {
                        TransportErrorKind::DnsResolverError(multiaddr, io_error)
                    }),
                    self.timeout,
                    Some(address),
                    self.tcp_config,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
            None => {
                let dial = connect(ok(address), self.timeout, None, self.tcp_config);
                Ok(TransportFuture::new(Box::pin(dial)))
            }
        }
    }
}

#[derive(Debug)]
pub struct WsStream {
    inner: WebSocketStream<TcpStream>,
    recv_buf: Vec<u8>,
    pending_ping: Option<Vec<u8>>,
    already_send_close: bool,
}

impl WsStream {
    pub fn new(inner: WebSocketStream<TcpStream>) -> Self {
        WsStream {
            inner,
            recv_buf: Vec::new(),
            pending_ping: None,
            already_send_close: false,
        }
    }

    fn respond_ping(&mut self, cx: &mut Context) -> io::Result<()> {
        if self.already_send_close {
            return Ok(());
        }
        match self.pending_ping.take() {
            Some(data) => {
                let mut sink = Pin::new(&mut self.inner);
                match sink.as_mut().poll_ready(cx) {
                    Poll::Ready(Ok(_)) => {
                        sink.as_mut()
                            .start_send(Message::Pong(data))
                            .map_err::<io::Error, _>(|e| {
                                debug!("send error: {:?}", e);
                                Into::into(io::ErrorKind::BrokenPipe)
                            })?;
                        let _ignore =
                            sink.as_mut().poll_flush(cx).map_err::<io::Error, _>(|e| {
                                debug!("flush error: {:?}", e);
                                Into::into(io::ErrorKind::BrokenPipe)
                            })?;
                        Ok(())
                    }
                    Poll::Pending => {
                        self.pending_ping = Some(data);
                        Ok(())
                    }
                    Poll::Ready(Err(_)) => Err(Into::into(io::ErrorKind::BrokenPipe)),
                }
            }
            None => Ok(()),
        }
    }

    #[inline]
    fn drain(&mut self, buf: &mut ReadBuf) -> usize {
        // Return zero if there is no data remaining in the internal buffer.
        if self.recv_buf.is_empty() {
            return 0;
        }

        // calculate number of bytes that we can copy
        let n = ::std::cmp::min(buf.remaining(), self.recv_buf.len());

        // Copy data to the output buffer
        buf.put_slice(self.recv_buf.drain(..n).as_slice());

        n
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.respond_ping(cx)?;

        // when there is something in recv_buffer
        let copied = self.drain(buf);
        if copied > 0 {
            return Poll::Ready(Ok(()));
        }

        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(t))) => {
                let data = match t {
                    Message::Binary(data) => data,
                    Message::Close(_) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                    Message::Ping(data) => {
                        self.pending_ping = Some(data);
                        self.respond_ping(cx)?;
                        Vec::new()
                    }
                    Message::Pong(_) => Vec::new(),
                    Message::Text(_) => Vec::new(),
                    // never reach this branch
                    Message::Frame(_) => Vec::new(),
                };

                if data.is_empty() {
                    return Poll::Pending;
                }
                // when input buffer is big enough
                let n = data.len();
                if buf.remaining() >= n {
                    buf.put_slice(data.as_ref());
                    Poll::Ready(Ok(()))
                } else {
                    // fill internal recv buffer
                    self.recv_buf = data;
                    // drain for input buffer
                    self.drain(buf);
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(Some(Err(err))) => {
                debug!("read from websocket stream error: {:?}", err);
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            Poll::Ready(None) => {
                debug!("connection shutting down");
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.already_send_close {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        self.respond_ping(cx)?;
        let mut sink = Pin::new(&mut self.inner);
        match sink.as_mut().poll_ready(cx) {
            Poll::Ready(Ok(_)) => {
                sink.as_mut()
                    .start_send(Message::Binary(buf.to_vec()))
                    .map_err::<io::Error, _>(|_| Into::into(io::ErrorKind::BrokenPipe))?;
                let _ignore = sink
                    .as_mut()
                    .poll_flush(cx)
                    .map_err::<io::Error, _>(|_| Into::into(io::ErrorKind::BrokenPipe))?;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(Into::into(io::ErrorKind::BrokenPipe))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .as_mut()
            .poll_flush(cx)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.already_send_close {
            let mut sink = Pin::new(&mut self.inner);
            match sink.as_mut().poll_ready(cx) {
                Poll::Ready(Ok(_)) => {
                    // send a close message
                    sink.as_mut()
                        .start_send(Message::Close(None))
                        .map_err::<io::Error, _>(|_| Into::into(io::ErrorKind::BrokenPipe))?;
                    let _ignore = sink
                        .as_mut()
                        .poll_flush(cx)
                        .map_err::<io::Error, _>(|_| Into::into(io::ErrorKind::BrokenPipe))?;
                    self.already_send_close = true;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(Into::into(io::ErrorKind::BrokenPipe)))
                }
            }
        }
        Pin::new(&mut self.inner)
            .as_mut()
            .poll_close(cx)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}
