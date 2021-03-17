use crate::{
    error::TransportErrorKind,
    multiaddr::{Multiaddr, Protocol},
};

#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(not(target_arch = "wasm32"))]
mod tcp;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportType {
    Ws,
    Wss,
    Tcp,
    TLS,
}

pub fn find_type(addr: &Multiaddr) -> TransportType {
    let mut iter = addr.iter();

    iter.find_map(|proto| {
        if let Protocol::Ws = proto {
            Some(TransportType::Ws)
        } else if let Protocol::Wss = proto {
            Some(TransportType::Wss)
        } else if let Protocol::TLS(_) = proto {
            Some(TransportType::TLS)
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
        utils::socketaddr_to_multiaddr,
    };

    use futures::{prelude::Stream, FutureExt};
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

    use self::tcp::{TcpDialFuture, TcpListenFuture, TcpTransport};
    #[cfg(feature = "ws")]
    use self::ws::{WebsocketListener, WsDialFuture, WsListenFuture, WsStream, WsTransport};
    #[cfg(feature = "ws")]
    use futures::StreamExt;

    #[derive(Clone, Copy)]
    pub struct MultiTransport {
        timeout: Duration,
        tcp_bind: Option<SocketAddr>,
        #[cfg(feature = "ws")]
        ws_bind: Option<SocketAddr>,
    }

    impl MultiTransport {
        pub fn new(timeout: Duration) -> Self {
            MultiTransport {
                timeout,
                tcp_bind: None,
                #[cfg(feature = "ws")]
                ws_bind: None,
            }
        }

        pub fn tcp_bind(mut self, bind_addr: Option<SocketAddr>) -> Self {
            self.tcp_bind = bind_addr;
            self
        }

        #[cfg(feature = "ws")]
        pub fn ws_bind(mut self, bind_addr: Option<SocketAddr>) -> Self {
            self.ws_bind = bind_addr;
            self
        }
    }

    impl Transport for MultiTransport {
        type ListenFuture = MultiListenFuture;
        type DialFuture = MultiDialFuture;

        fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
            match find_type(&address) {
                TransportType::Tcp => {
                    match TcpTransport::new(self.timeout, self.tcp_bind).listen(address) {
                        Ok(future) => Ok(MultiListenFuture::Tcp(future)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(feature = "ws")]
                TransportType::Ws => {
                    match WsTransport::new(self.timeout, self.ws_bind).listen(address) {
                        Ok(future) => Ok(MultiListenFuture::Ws(future)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(not(feature = "ws"))]
                TransportType::Ws => Err(TransportErrorKind::NotSupported(address)),
                TransportType::Wss => Err(TransportErrorKind::NotSupported(address)),
                TransportType::TLS => Err(TransportErrorKind::NotSupported(address)),
            }
        }

        fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
            match find_type(&address) {
                TransportType::Tcp => {
                    match TcpTransport::new(self.timeout, self.tcp_bind).dial(address) {
                        Ok(res) => Ok(MultiDialFuture::Tcp(res)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(feature = "ws")]
                TransportType::Ws => {
                    match WsTransport::new(self.timeout, self.ws_bind).dial(address) {
                        Ok(future) => Ok(MultiDialFuture::Ws(future)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(not(feature = "ws"))]
                TransportType::Ws => Err(TransportErrorKind::NotSupported(address)),
                TransportType::Wss => Err(TransportErrorKind::NotSupported(address)),
                TransportType::TLS => Err(TransportErrorKind::NotSupported(address)),
            }
        }
    }

    pub enum MultiListenFuture {
        Tcp(TcpListenFuture),
        #[cfg(feature = "ws")]
        Ws(WsListenFuture),
    }

    impl Future for MultiListenFuture {
        type Output = Result<(Multiaddr, MultiIncoming)>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.get_mut() {
                MultiListenFuture::Tcp(inner) => Pin::new(
                    &mut inner.map(|res| res.map(|res| (res.0, MultiIncoming::Tcp(res.1)))),
                )
                .poll(cx),
                #[cfg(feature = "ws")]
                MultiListenFuture::Ws(inner) => {
                    Pin::new(&mut inner.map(|res| res.map(|res| (res.0, MultiIncoming::Ws(res.1)))))
                        .poll(cx)
                }
            }
        }
    }

    pub enum MultiDialFuture {
        Tcp(TcpDialFuture),
        #[cfg(feature = "ws")]
        Ws(WsDialFuture),
    }

    impl Future for MultiDialFuture {
        type Output = Result<(Multiaddr, MultiStream)>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.get_mut() {
                MultiDialFuture::Tcp(inner) => {
                    Pin::new(&mut inner.map(|res| res.map(|res| (res.0, MultiStream::Tcp(res.1)))))
                        .poll(cx)
                }
                #[cfg(feature = "ws")]
                MultiDialFuture::Ws(inner) => Pin::new(
                    &mut inner.map(|res| res.map(|res| (res.0, MultiStream::Ws(Box::new(res.1))))),
                )
                .poll(cx),
            }
        }
    }

    pub enum MultiStream {
        Tcp(TcpStream),
        #[cfg(feature = "ws")]
        Ws(Box<WsStream>),
    }

    impl fmt::Debug for MultiStream {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                MultiStream::Tcp(_) => write!(f, "Tcp stream"),
                #[cfg(feature = "ws")]
                MultiStream::Ws(_) => write!(f, "Websocket stream"),
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
                #[cfg(feature = "ws")]
                MultiStream::Ws(inner) => Pin::new(inner).poll_read(cx, buf),
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
                #[cfg(feature = "ws")]
                MultiStream::Ws(inner) => Pin::new(inner).poll_write(cx, buf),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            match self.get_mut() {
                MultiStream::Tcp(inner) => Pin::new(inner).poll_flush(cx),
                #[cfg(feature = "ws")]
                MultiStream::Ws(inner) => Pin::new(inner).poll_flush(cx),
            }
        }

        #[inline]
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            match self.get_mut() {
                MultiStream::Tcp(inner) => Pin::new(inner).poll_shutdown(cx),
                #[cfg(feature = "ws")]
                MultiStream::Ws(inner) => Pin::new(inner).poll_shutdown(cx),
            }
        }
    }

    #[derive(Debug)]
    pub enum MultiIncoming {
        Tcp(TcpListener),
        #[cfg(feature = "ws")]
        Ws(WebsocketListener),
    }

    impl Stream for MultiIncoming {
        type Item = std::result::Result<(Multiaddr, MultiStream), io::Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            match self.get_mut() {
                MultiIncoming::Tcp(inner) => match inner.poll_accept(cx)? {
                    // Why can't get the peer address of the connected stream ?
                    // Error will be "Transport endpoint is not connected",
                    // so why incoming will appear unconnected stream ?
                    Poll::Ready((stream, _)) => match stream.peer_addr() {
                        Ok(remote_address) => Poll::Ready(Some(Ok((
                            socketaddr_to_multiaddr(remote_address),
                            MultiStream::Tcp(stream),
                        )))),
                        Err(err) => {
                            debug!("stream get peer address error: {:?}", err);
                            Poll::Pending
                        }
                    },
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
            }
        }
    }

    /// ws/tcp common listen realization
    #[inline(always)]
    pub async fn tcp_listen(addr: SocketAddr, reuse: bool) -> Result<(SocketAddr, TcpListener)> {
        let tcp = if reuse {
            crate::runtime::reuse_listen(addr).unwrap()
        } else {
            TcpListener::bind(&addr)
                .await
                .map_err(TransportErrorKind::Io)?
        };

        Ok((tcp.local_addr()?, tcp))
    }

    /// ws/tcp common dial realization
    #[inline(always)]
    pub async fn tcp_dial(
        addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Duration,
    ) -> Result<TcpStream> {
        match crate::runtime::timeout(timeout, crate::runtime::connect(addr, bind_addr)).await {
            Err(_) => Err(TransportErrorKind::Io(io::ErrorKind::TimedOut.into())),
            Ok(res) => Ok(res?),
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

        a.push(Protocol::TLS(Cow::Owned("/".to_string())));

        assert_eq!(find_type(&a), TransportType::TLS);
    }
}
