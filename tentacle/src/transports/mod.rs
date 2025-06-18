use crate::{
    error::TransportErrorKind,
    multiaddr::{Multiaddr, Protocol},
    service::config::TcpSocketConfig,
    utils::{TransportType, find_type},
};

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(target_family = "wasm")]
mod browser;
#[cfg(not(target_family = "wasm"))]
mod memory;
#[cfg(not(target_family = "wasm"))]
mod onion;
#[cfg(not(target_family = "wasm"))]
mod tcp;
#[cfg(not(target_family = "wasm"))]
pub(crate) mod tcp_base_listen;
#[cfg(all(feature = "tls", not(target_family = "wasm")))]
mod tls;
#[cfg(all(feature = "ws", not(target_family = "wasm")))]
mod ws;

#[cfg(target_family = "wasm")]
pub use on_browser::*;
#[cfg(not(target_family = "wasm"))]
pub use os::*;

type Result<T> = std::result::Result<T, TransportErrorKind>;

/// Definition of transport listen protocol behavior
pub trait TransportListen {
    type ListenFuture;

    /// Transport listen
    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture>;
}

/// Definition of transport dial protocol behavior
pub trait TransportDial {
    type DialFuture;

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

pub(crate) fn parse_tls_domain_name(addr: &Multiaddr) -> Option<String> {
    let mut iter = addr.iter();

    iter.find_map(|proto| {
        if let Protocol::Tls(s) = proto {
            Some(s.to_string())
        } else {
            None
        }
    })
}

#[cfg(not(target_family = "wasm"))]
mod os {
    use super::*;

    use crate::{
        runtime::{TcpListener, TcpStream},
        service::config::{ServiceTimeout, TcpConfig},
    };

    use futures::{FutureExt, StreamExt, prelude::Stream};
    use multiaddr::MultiAddr;
    use onion::OnionTransport;
    use std::{
        collections::HashMap,
        fmt,
        future::Future,
        io,
        net::SocketAddr,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use self::memory::{
        MemoryDialFuture, MemoryListenFuture, MemoryListener, MemorySocket, MemoryTransport,
    };
    use self::tcp::{TcpDialFuture, TcpListenFuture, TcpTransport};
    use self::tcp_base_listen::{TcpBaseListener, TcpBaseListenerEnum, UpgradeMode};
    #[cfg(feature = "ws")]
    use self::ws::{WsDialFuture, WsStream, WsTransport};
    #[cfg(feature = "tls")]
    use {
        self::tls::{TlsDialFuture, TlsStream, TlsTransport},
        crate::service::config::TlsConfig,
    };

    #[derive(Debug, Clone, Copy)]
    pub(crate) enum TcpListenMode {
        Tcp,
        #[cfg(feature = "tls")]
        Tls,
        #[cfg(feature = "ws")]
        Ws,
    }

    #[derive(Clone)]
    pub(crate) struct MultiTransport {
        pub(crate) timeout: ServiceTimeout,
        pub(crate) tcp_config: TcpConfig,
        pub(crate) listens_upgrade_modes: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
        #[cfg(feature = "tls")]
        pub(crate) tls_config: Option<TlsConfig>,
    }

    impl MultiTransport {
        pub fn new(timeout: ServiceTimeout, tcp_config: TcpConfig) -> Self {
            MultiTransport {
                timeout,
                tcp_config,
                listens_upgrade_modes: Arc::new(crate::lock::Mutex::new(Default::default())),
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

    impl TransportListen for MultiTransport {
        type ListenFuture = MultiListenFuture;

        fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
            match find_type(&address) {
                TransportType::Tcp => {
                    match TcpTransport::from_multi_transport(self, TcpListenMode::Tcp)
                        .listen(address)
                    {
                        Ok(future) => Ok(MultiListenFuture::Tcp(future)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(feature = "ws")]
                TransportType::Ws => {
                    match TcpTransport::from_multi_transport(self, TcpListenMode::Ws)
                        .listen(address)
                    {
                        Ok(future) => Ok(MultiListenFuture::Tcp(future)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(not(feature = "ws"))]
                TransportType::Ws => Err(TransportErrorKind::NotSupported(address)),
                TransportType::Memory => match MemoryTransport.listen(address) {
                    Ok(future) => Ok(MultiListenFuture::Memory(future)),
                    Err(e) => Err(e),
                },
                TransportType::Wss => Err(TransportErrorKind::NotSupported(address)),
                #[cfg(feature = "tls")]
                TransportType::Tls => {
                    if self.tls_config.is_none() {
                        return Err(TransportErrorKind::TlsError(
                            "tls config is not set".to_string(),
                        ));
                    }
                    match TcpTransport::from_multi_transport(self, TcpListenMode::Tls)
                        .listen(address)
                    {
                        Ok(future) => Ok(MultiListenFuture::Tcp(future)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(not(feature = "tls"))]
                TransportType::Tls => Err(TransportErrorKind::NotSupported(address)),

                TransportType::Onion => Err(TransportErrorKind::NotSupported(address)),
            }
        }
    }

    impl TransportDial for MultiTransport {
        type DialFuture = MultiDialFuture;
        fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
            match find_type(&address) {
                TransportType::Tcp => {
                    match TcpTransport::new(self.timeout.timeout, self.tcp_config.tcp).dial(address)
                    {
                        Ok(res) => Ok(MultiDialFuture::Tcp(res)),
                        Err(e) => Err(e),
                    }
                }
                TransportType::Onion => {
                    match OnionTransport::new(self.timeout.onion_timeout, self.tcp_config.tcp)
                        .dial(address)
                    {
                        Ok(res) => Ok(MultiDialFuture::Tcp(res)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(feature = "ws")]
                TransportType::Ws => {
                    match WsTransport::new(self.timeout.timeout, self.tcp_config.ws).dial(address) {
                        Ok(future) => Ok(MultiDialFuture::Ws(future)),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(not(feature = "ws"))]
                TransportType::Ws => Err(TransportErrorKind::NotSupported(address)),
                TransportType::Memory => match MemoryTransport.dial(address) {
                    Ok(future) => Ok(MultiDialFuture::Memory(future)),
                    Err(e) => Err(e),
                },
                TransportType::Wss => Err(TransportErrorKind::NotSupported(address)),
                #[cfg(feature = "tls")]
                TransportType::Tls => {
                    let tls_config = self.tls_config.ok_or_else(|| {
                        TransportErrorKind::TlsError("tls config is not set".to_string())
                    })?;
                    TlsTransport::new(self.timeout.timeout, tls_config, self.tcp_config.tls)
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
    }

    impl Future for MultiListenFuture {
        type Output = Result<(Multiaddr, MultiIncoming)>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.get_mut() {
                MultiListenFuture::Tcp(inner) => Pin::new(&mut inner.map(|res| {
                    res.map(|res| match res.1 {
                        TcpBaseListenerEnum::New(i) => (res.0, MultiIncoming::Tcp(i)),
                        TcpBaseListenerEnum::Upgrade => (res.0, MultiIncoming::TcpUpgrade),
                    })
                }))
                .poll(cx),
                MultiListenFuture::Memory(inner) => Pin::new(
                    &mut inner.map(|res| res.map(|res| (res.0, MultiIncoming::Memory(res.1)))),
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
        TcpUpgrade,
        Tcp(TcpBaseListener),
        Memory(MemoryListener),
    }

    impl Stream for MultiIncoming {
        type Item = std::result::Result<(Multiaddr, MultiStream), io::Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            match self.get_mut() {
                MultiIncoming::Tcp(inner) => match inner.poll_next_unpin(cx)? {
                    Poll::Ready(Some((addr, stream))) => Poll::Ready(Some(Ok((addr, stream)))),
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                },
                MultiIncoming::TcpUpgrade => unreachable!(),
                MultiIncoming::Memory(inner) => match inner.poll_next_unpin(cx)? {
                    Poll::Ready(Some((addr, stream))) => {
                        Poll::Ready(Some(Ok((addr, MultiStream::Memory(stream)))))
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
            Ok(res) => res.map_err(|err| {
                if err.to_string().contains("connect_by_proxy") {
                    TransportErrorKind::ProxyError(err)
                } else {
                    err.into()
                }
            }),
        }
    }

    /// onion common dial realization
    #[inline(always)]
    pub async fn onion_dial(
        onion_addr: MultiAddr,
        tcp_config: TcpSocketConfig,
        timeout: Duration,
    ) -> Result<TcpStream> {
        match crate::runtime::timeout(
            timeout,
            crate::runtime::connect_onion(onion_addr, tcp_config),
        )
        .await
        {
            Err(_) => Err(TransportErrorKind::Io(io::ErrorKind::TimedOut.into())),
            Ok(res) => res.map_err(|err| {
                if err.to_string().contains("connect_by_proxy") {
                    TransportErrorKind::ProxyError(err)
                } else {
                    err.into()
                }
            }),
        }
    }
}

#[cfg(target_family = "wasm")]
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
    use super::{Protocol, TransportType, find_type};
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
