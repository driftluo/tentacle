use crate::{
    error::TransportErrorKind,
    multiaddr::{Multiaddr, Protocol},
    service::config::TcpSocketConfig,
};

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(not(target_arch = "wasm32"))]
mod memory;
#[cfg(not(target_arch = "wasm32"))]
mod tcp;
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
mod tls;
#[cfg(all(feature = "ws", not(target_arch = "wasm32")))]
mod ws;

#[cfg(target_arch = "wasm32")]
pub use on_browser::*;
#[cfg(not(target_arch = "wasm32"))]
pub use os::*;

type Result<T> = std::result::Result<T, TransportErrorKind>;

/// Definition of transport protocol behavior
pub trait Transport {
    type ListenFuture;
    type DialFuture;

    /// Transport listen
    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture>;
    /// Transport dial
    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture>;
}

pub struct TransportFuture<T> {
    executed: T,
}

impl<T> TransportFuture<T> {
    pub fn new(executed: T) -> TransportFuture<T> {
        TransportFuture { executed }
    }
}

impl<T> Future for TransportFuture<T>
where
    T: Future,
{
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Safety: we just polled it and didn't move it
        let executed = unsafe {
            let this = self.get_unchecked_mut();
            Pin::new_unchecked(&mut this.executed)
        };
        executed.poll(cx)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportType {
    Ws,
    Wss,
    Tcp,
    Tls,
    Memory,
}

pub fn find_type(addr: &Multiaddr) -> TransportType {
    let mut iter = addr.iter();

    iter.find_map(|proto| {
        if let Protocol::Ws = proto {
            Some(TransportType::Ws)
        } else if let Protocol::Wss = proto {
            Some(TransportType::Wss)
        } else if let Protocol::Tls(_) = proto {
            Some(TransportType::Tls)
        } else if let Protocol::Memory(_) = proto {
            Some(TransportType::Memory)
        } else {
            None
        }
    })
    .unwrap_or(TransportType::Tcp)
}

#[cfg(not(target_arch = "wasm32"))]
mod os {
    use super::*;

    use crate::{
        runtime::{TcpListener, TcpStream},
        service::config::TcpConfig,
        utils::socketaddr_to_multiaddr,
    };

    use futures::{prelude::Stream, FutureExt, StreamExt};
    use log::debug;
    use std::{
        fmt,
        future::Future,
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use self::memory::{
        MemoryDialFuture, MemoryListenFuture, MemoryListener, MemorySocket, MemoryTransport,
    };
    use self::tcp::{TcpDialFuture, TcpListenFuture, TcpTransport};
    #[cfg(feature = "tls")]
    use self::tls::{TlsDialFuture, TlsListenFuture, TlsListener, TlsStream, TlsTransport};
    #[cfg(feature = "ws")]
    use self::ws::{WebsocketListener, WsDialFuture, WsListenFuture, WsStream, WsTransport};
    #[cfg(feature = "tls")]
    use crate::service::config::TlsConfig;

    #[derive(Clone)]
    pub(crate) struct MultiTransport {
        timeout: Duration,
        tcp_config: TcpConfig,
        #[cfg(feature = "tls")]
        tls_config: Option<TlsConfig>,
    }

    impl MultiTransport {
        pub fn new(timeout: Duration, tcp_config: TcpConfig) -> Self {
            MultiTransport {
                timeout,
                tcp_config,
                #[cfg(feature = "tls")]
                tls_config: None,
            }
        }

        #[cfg(feature = "tls")]
        pub fn tls_config(mut self, tls_config: Option<TlsConfig>) -> Self {
            self.tls_config = tls_config;
            self
        }
    }

    impl Transport for MultiTransport {
        type ListenFuture = MultiListenFuture;
        type DialFuture = MultiDialFuture;

        fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
            match find_type(&address) {
                TransportType::Tcp => {
                    match TcpTransport::new(self.timeout, self.tcp_config.tcp).listen(address) {
                        Ok(future) => Ok(MultiListenFuture::Tcp(future)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(feature = "ws")]
                TransportType::Ws => {
                    match WsTransport::new(self.timeout, self.tcp_config.ws).listen(address) {
                        Ok(future) => Ok(MultiListenFuture::Ws(future)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(not(feature = "ws"))]
                TransportType::Ws => Err(TransportErrorKind::NotSupported(address)),
                TransportType::Memory => match MemoryTransport::default().listen(address) {
                    Ok(future) => Ok(MultiListenFuture::Memory(future)),
                    Err(e) => Err(e),
                },
                TransportType::Wss => Err(TransportErrorKind::NotSupported(address)),
                #[cfg(feature = "tls")]
                TransportType::Tls => {
                    let tls_config = self.tls_config.ok_or_else(|| {
                        TransportErrorKind::TlsError("tls config is not set".to_string())
                    })?;
                    TlsTransport::new(self.timeout, tls_config, self.tcp_config.tls)
                        .listen(address)
                        .map(MultiListenFuture::Tls)
                }
                #[cfg(not(feature = "tls"))]
                TransportType::Tls => Err(TransportErrorKind::NotSupported(address)),
            }
        }

        fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
            match find_type(&address) {
                TransportType::Tcp => {
                    match TcpTransport::new(self.timeout, self.tcp_config.tcp).dial(address) {
                        Ok(res) => Ok(MultiDialFuture::Tcp(res)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(feature = "ws")]
                TransportType::Ws => {
                    match WsTransport::new(self.timeout, self.tcp_config.ws).dial(address) {
                        Ok(future) => Ok(MultiDialFuture::Ws(future)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(not(feature = "ws"))]
                TransportType::Ws => Err(TransportErrorKind::NotSupported(address)),
                TransportType::Memory => match MemoryTransport::default().dial(address) {
                    Ok(future) => Ok(MultiDialFuture::Memory(future)),
                    Err(e) => Err(e),
                },
                TransportType::Wss => Err(TransportErrorKind::NotSupported(address)),
                #[cfg(feature = "tls")]
                TransportType::Tls => {
                    let tls_config = self.tls_config.ok_or_else(|| {
                        TransportErrorKind::TlsError("tls config is not set".to_string())
                    })?;
                    TlsTransport::new(self.timeout, tls_config, self.tcp_config.tls)
                        .dial(address)
                        .map(MultiDialFuture::Tls)
                }
                #[cfg(not(feature = "tls"))]
                TransportType::Tls => Err(TransportErrorKind::NotSupported(address)),
            }
        }
    }

    pub enum MultiListenFuture {
        Tcp(TcpListenFuture),
        Memory(MemoryListenFuture),
        #[cfg(feature = "ws")]
        Ws(WsListenFuture),
        #[cfg(feature = "tls")]
        Tls(TlsListenFuture),
    }

    impl Future for MultiListenFuture {
        type Output = Result<(Multiaddr, MultiIncoming)>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.get_mut() {
                MultiListenFuture::Tcp(inner) => Pin::new(
                    &mut inner.map(|res| res.map(|res| (res.0, MultiIncoming::Tcp(res.1)))),
                )
                .poll(cx),
                MultiListenFuture::Memory(inner) => Pin::new(
                    &mut inner.map(|res| res.map(|res| (res.0, MultiIncoming::Memory(res.1)))),
                )
                .poll(cx),
                #[cfg(feature = "ws")]
                MultiListenFuture::Ws(inner) => {
                    Pin::new(&mut inner.map(|res| res.map(|res| (res.0, MultiIncoming::Ws(res.1)))))
                        .poll(cx)
                }
                #[cfg(feature = "tls")]
                MultiListenFuture::Tls(inner) => Pin::new(
                    &mut inner.map(|res| res.map(|res| (res.0, MultiIncoming::Tls(res.1)))),
                )
                .poll(cx),
            }
        }
    }

    pub enum MultiDialFuture {
        Tcp(TcpDialFuture),
        Memory(MemoryDialFuture),
        #[cfg(feature = "ws")]
        Ws(WsDialFuture),
        #[cfg(feature = "tls")]
        Tls(TlsDialFuture),
    }

    impl Future for MultiDialFuture {
        type Output = Result<(Multiaddr, MultiStream)>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.get_mut() {
                MultiDialFuture::Tcp(inner) => {
                    Pin::new(&mut inner.map(|res| res.map(|res| (res.0, MultiStream::Tcp(res.1)))))
                        .poll(cx)
                }
                MultiDialFuture::Memory(inner) => Pin::new(
                    &mut inner.map(|res| res.map(|res| (res.0, MultiStream::Memory(res.1)))),
                )
                .poll(cx),
                #[cfg(feature = "ws")]
                MultiDialFuture::Ws(inner) => Pin::new(
                    &mut inner.map(|res| res.map(|res| (res.0, MultiStream::Ws(Box::new(res.1))))),
                )
                .poll(cx),
                #[cfg(feature = "tls")]
                MultiDialFuture::Tls(inner) => {
                    Pin::new(&mut inner.map(|res| res.map(|res| (res.0, MultiStream::Tls(res.1)))))
                        .poll(cx)
                }
            }
        }
    }

    pub enum MultiStream {
        Tcp(TcpStream),
        Memory(MemorySocket),
        #[cfg(feature = "ws")]
        Ws(Box<WsStream>),
        #[cfg(feature = "tls")]
        Tls(TlsStream),
    }

    impl fmt::Debug for MultiStream {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                MultiStream::Tcp(_) => write!(f, "Tcp stream"),
                MultiStream::Memory(_) => write!(f, "Memory stream"),
                #[cfg(feature = "ws")]
                MultiStream::Ws(_) => write!(f, "Websocket stream"),
                #[cfg(feature = "tls")]
                MultiStream::Tls(_) => write!(f, "Tls stream"),
            }
        }
    }

    impl AsyncRead for MultiStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf,
        ) -> Poll<io::Result<()>> {
            match self.get_mut() {
                MultiStream::Tcp(inner) => Pin::new(inner).poll_read(cx, buf),
                MultiStream::Memory(inner) => Pin::new(inner).poll_read(cx, buf),
                #[cfg(feature = "ws")]
                MultiStream::Ws(inner) => Pin::new(inner).poll_read(cx, buf),
                #[cfg(feature = "tls")]
                MultiStream::Tls(inner) => Pin::new(inner).poll_read(cx, buf),
            }
        }
    }

    impl AsyncWrite for MultiStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.get_mut() {
                MultiStream::Tcp(inner) => Pin::new(inner).poll_write(cx, buf),
                MultiStream::Memory(inner) => Pin::new(inner).poll_write(cx, buf),
                #[cfg(feature = "ws")]
                MultiStream::Ws(inner) => Pin::new(inner).poll_write(cx, buf),
                #[cfg(feature = "tls")]
                MultiStream::Tls(inner) => Pin::new(inner).poll_write(cx, buf),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            match self.get_mut() {
                MultiStream::Tcp(inner) => Pin::new(inner).poll_flush(cx),
                MultiStream::Memory(inner) => Pin::new(inner).poll_flush(cx),
                #[cfg(feature = "ws")]
                MultiStream::Ws(inner) => Pin::new(inner).poll_flush(cx),
                #[cfg(feature = "tls")]
                MultiStream::Tls(inner) => Pin::new(inner).poll_flush(cx),
            }
        }

        #[inline]
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            match self.get_mut() {
                MultiStream::Tcp(inner) => Pin::new(inner).poll_shutdown(cx),
                MultiStream::Memory(inner) => Pin::new(inner).poll_shutdown(cx),
                #[cfg(feature = "ws")]
                MultiStream::Ws(inner) => Pin::new(inner).poll_shutdown(cx),
                #[cfg(feature = "tls")]
                MultiStream::Tls(inner) => Pin::new(inner).poll_shutdown(cx),
            }
        }
    }

    pub enum MultiIncoming {
        Tcp(TcpListener),
        Memory(MemoryListener),
        #[cfg(feature = "ws")]
        Ws(WebsocketListener),
        #[cfg(feature = "tls")]
        Tls(TlsListener),
    }

    impl Stream for MultiIncoming {
        type Item = std::result::Result<(Multiaddr, MultiStream), io::Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            match self.get_mut() {
                MultiIncoming::Tcp(inner) => {
                    loop {
                        match inner.poll_accept(cx)? {
                            // Why can't get the peer address of the connected stream ?
                            // Error will be "Transport endpoint is not connected",
                            // so why incoming will appear unconnected stream ?
                            Poll::Ready((stream, _)) => match stream.peer_addr() {
                                Ok(remote_address) => {
                                    break Poll::Ready(Some(Ok((
                                        socketaddr_to_multiaddr(remote_address),
                                        MultiStream::Tcp(stream),
                                    ))))
                                }
                                Err(err) => {
                                    debug!("stream get peer address error: {:?}", err);
                                }
                            },
                            Poll::Pending => break Poll::Pending,
                        }
                    }
                }
                MultiIncoming::Memory(inner) => match inner.poll_next_unpin(cx)? {
                    Poll::Ready(Some((addr, stream))) => {
                        Poll::Ready(Some(Ok((addr, MultiStream::Memory(stream)))))
                    }
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                },
                #[cfg(feature = "ws")]
                MultiIncoming::Ws(inner) => match inner.poll_next_unpin(cx)? {
                    Poll::Ready(Some((addr, stream))) => {
                        Poll::Ready(Some(Ok((addr, MultiStream::Ws(Box::new(stream))))))
                    }
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                },
                #[cfg(feature = "tls")]
                MultiIncoming::Tls(inner) => match inner.poll_next_unpin(cx)? {
                    Poll::Ready(Some((addr, stream))) => {
                        Poll::Ready(Some(Ok((addr, MultiStream::Tls(stream)))))
                    }
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                },
            }
        }
    }

    /// ws/tcp common listen realization
    #[inline(always)]
    pub async fn tcp_listen(
        addr: SocketAddr,
        tcp_config: TcpSocketConfig,
    ) -> Result<(SocketAddr, TcpListener)> {
        let tcp = crate::runtime::listen(addr, tcp_config)?;

        Ok((tcp.local_addr()?, tcp))
    }

    /// ws/tcp common dial realization
    #[inline(always)]
    pub async fn tcp_dial(
        addr: SocketAddr,
        tcp_config: TcpSocketConfig,
        timeout: Duration,
    ) -> Result<TcpStream> {
        match crate::runtime::timeout(timeout, crate::runtime::connect(addr, tcp_config)).await {
            Err(_) => Err(TransportErrorKind::Io(io::ErrorKind::TimedOut.into())),
            Ok(res) => res.map_err(Into::into),
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod on_browser {
    use super::*;

    pub use self::browser::{
        BrowserDialFuture as MultiDialFuture, BrowserStream as MultiStream,
        BrowserTransport as MultiTransport,
    };

    pub struct MultiIncoming;
}

#[cfg(test)]
mod test {
    use super::{find_type, Protocol, TransportType};
    use std::borrow::Cow;

    #[test]
    fn test_find_type() {
        let mut a = "/ip4/127.0.0.1/tcp/1337/ws".parse().unwrap();

        assert_eq!(find_type(&a), TransportType::Ws);

        a.pop();
        a.push(Protocol::Wss);

        assert_eq!(find_type(&a), TransportType::Wss);

        a.pop();

        assert_eq!(find_type(&a), TransportType::Tcp);

        a.push(Protocol::Tls(Cow::Borrowed("")));

        assert_eq!(find_type(&a), TransportType::Tls);
    }
}
