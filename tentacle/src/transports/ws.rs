use futures::{
    channel::mpsc::{channel, Receiver, Sender},
    future::ok,
    Sink, SinkExt, Stream, StreamExt, TryFutureExt,
};
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
    accept_async, client_async_with_config,
    tungstenite::{Error, Message},
    WebSocketStream,
};

use crate::{
    error::TransportErrorKind,
    multiaddr::{Multiaddr, Protocol},
    runtime::{TcpListener, TcpStream},
    service::config::TcpSocketConfig,
    transports::{tcp_dial, tcp_listen, Result, Transport, TransportFuture},
    utils::{dns::DnsResolver, multiaddr_to_socketaddr, socketaddr_to_multiaddr},
};

/// websocket listen bind
async fn bind(
    address: impl Future<Output = Result<Multiaddr>>,
    timeout: Duration,
    tcp_config: TcpSocketConfig,
) -> Result<(Multiaddr, WebsocketListener)> {
    let addr = address.await?;
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let (addr, tcp) = tcp_listen(socket_address, tcp_config).await?;
            let mut listen_addr = socketaddr_to_multiaddr(addr);
            listen_addr.push(Protocol::Ws);

            Ok((listen_addr, WebsocketListener::new(timeout, tcp)))
        }
        None => Err(TransportErrorKind::NotSupported(addr)),
    }
}

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

pub type WsListenFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, WebsocketListener)>> + Send>>>;
pub type WsDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, WsStream)>> + Send>>>;

impl Transport for WsTransport {
    type ListenFuture = WsListenFuture;
    type DialFuture = WsDialFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
        match DnsResolver::new(address.clone()) {
            Some(dns) => {
                let task = bind(
                    dns.map_err(|(multiaddr, io_error)| {
                        TransportErrorKind::DnsResolverError(multiaddr, io_error)
                    }),
                    self.timeout,
                    self.tcp_config,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
            None => {
                let task = bind(ok(address), self.timeout, self.tcp_config);
                Ok(TransportFuture::new(Box::pin(task)))
            }
        }
    }

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
pub struct WebsocketListener {
    inner: TcpListener,
    timeout: Duration,
    sender: Sender<(Multiaddr, WsStream)>,
    pending_stream: Receiver<(Multiaddr, WsStream)>,
}

impl WebsocketListener {
    fn new(timeout: Duration, listen: TcpListener) -> Self {
        let (sender, rx) = channel(24);
        WebsocketListener {
            inner: listen,
            timeout,
            sender,
            pending_stream: rx,
        }
    }

    fn poll_pending(&mut self, cx: &mut Context) -> Poll<(Multiaddr, WsStream)> {
        match Pin::new(&mut self.pending_stream).as_mut().poll_next(cx) {
            Poll::Ready(Some(res)) => Poll::Ready(res),
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }

    fn poll_listen(&mut self, cx: &mut Context) -> Poll<std::result::Result<(), io::Error>> {
        match self.inner.poll_accept(cx)? {
            Poll::Ready((stream, _)) => {
                match stream.peer_addr() {
                    Ok(remote_address) => {
                        let timeout = self.timeout;
                        let mut sender = self.sender.clone();
                        crate::runtime::spawn(async move {
                            match crate::runtime::timeout(timeout, accept_async(stream)).await {
                                Err(_) => debug!("accept websocket stream timeout"),
                                Ok(res) => match res {
                                    Ok(stream) => {
                                        let mut addr = socketaddr_to_multiaddr(remote_address);
                                        addr.push(Protocol::Ws);
                                        if sender.send((addr, WsStream::new(stream))).await.is_err()
                                        {
                                            debug!("receiver closed unexpectedly")
                                        }
                                    }
                                    Err(err) => {
                                        debug!("accept websocket stream err: {:?}", err);
                                    }
                                },
                            }
                        });
                    }
                    Err(err) => {
                        debug!("stream get peer address error: {:?}", err);
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Stream for WebsocketListener {
    type Item = std::result::Result<(Multiaddr, WsStream), io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(res) = self.poll_pending(cx) {
            return Poll::Ready(Some(Ok(res)));
        }

        loop {
            let is_pending = self.poll_listen(cx)?.is_pending();
            match self.poll_pending(cx) {
                Poll::Ready(res) => return Poll::Ready(Some(Ok(res))),
                Poll::Pending => {
                    if is_pending {
                        break;
                    }
                }
            }
        }
        Poll::Pending
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
    fn new(inner: WebSocketStream<TcpStream>) -> Self {
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
