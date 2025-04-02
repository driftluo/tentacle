use super::proxy::{socks5, socks5_config::random_auth};
use multiaddr::{MultiAddr, Protocol};
pub use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
    task::{JoinHandle, block_in_place, spawn_blocking, yield_now},
};

use crate::service::config::{
    TcpSocket, TcpSocketConfig, TcpSocketTransformer, TransformerContext,
};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
use std::{io, net::SocketAddr};
use tokio::net::TcpSocket as TokioTcp;

#[cfg(feature = "tokio-timer")]
pub use {
    time::{Interval, interval},
    tokio::time::{MissedTickBehavior, Sleep as Delay, Timeout, sleep as delay_for, timeout},
};

#[cfg(feature = "tokio-timer")]
mod time {
    use futures::Stream;
    use std::{
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::time::{
        Instant, Interval as Inner, MissedTickBehavior, interval_at as inner_interval,
    };

    pub struct Interval(Inner);

    impl Interval {
        /// Same as tokio::time::interval
        pub fn new(period: Duration) -> Self {
            Self::new_at(Duration::ZERO, period)
        }

        /// Same as tokio::time::interval_at
        pub fn new_at(start_since_now: Duration, period: Duration) -> Self {
            Self(inner_interval(Instant::now() + start_since_now, period))
        }

        pub fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
            self.0.set_missed_tick_behavior(behavior);
        }
    }

    impl Stream for Interval {
        type Item = ();

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
            match self.0.poll_tick(cx) {
                Poll::Ready(_) => Poll::Ready(Some(())),
                Poll::Pending => Poll::Pending,
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (usize::MAX, None)
        }
    }

    pub fn interval(period: Duration) -> Interval {
        Interval::new(period)
    }
}

pub(crate) fn listen(addr: SocketAddr, tcp_config: TcpSocketConfig) -> io::Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP))?;

    // reuse addr and reuse port's situation on each platform
    // https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ

    let socket = {
        // On platforms with Berkeley-derived sockets, this allows to quickly
        // rebind a socket, without needing to wait for the OS to clean up the
        // previous one.
        //
        // On Windows, this allows rebinding sockets which are actively in use,
        // which allows “socket hijacking”, so we explicitly don't set it here.
        // https://docs.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
        //
        // user can disable it on tcp_config
        #[cfg(not(windows))]
        socket.set_reuse_address(true)?;
        let transformer_context = TransformerContext::new_listen(addr);
        let t = (tcp_config.socket_transformer)(TcpSocket { inner: socket }, transformer_context)?;
        t.inner.set_nonblocking(true)?;
        // safety: fd convert by socket2
        unsafe {
            #[cfg(unix)]
            let socket = TokioTcp::from_raw_fd(t.into_raw_fd());
            #[cfg(windows)]
            let socket = TokioTcp::from_raw_socket(t.into_raw_socket());
            socket
        }
    };
    // `bind` twice will return error
    //
    // code 22 means:
    // EINVAL The socket is already bound to an address.
    // ref: https://man7.org/linux/man-pages/man2/bind.2.html
    if let Err(e) = socket.bind(addr) {
        if Some(22) != e.raw_os_error() {
            return Err(e);
        }
    }

    socket.listen(1024)
}

async fn connect_direct(
    addr: SocketAddr,
    socket_transformer: TcpSocketTransformer,
) -> io::Result<TcpStream> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP))?;

    let socket = {
        let transformer_context = TransformerContext::new_dial(addr);
        let t = socket_transformer(TcpSocket { inner: socket }, transformer_context)?;
        t.inner.set_nonblocking(true)?;
        // safety: fd convert by socket2
        unsafe {
            #[cfg(unix)]
            let socket = TokioTcp::from_raw_fd(t.into_raw_fd());
            #[cfg(windows)]
            let socket = TokioTcp::from_raw_socket(t.into_raw_socket());
            socket
        }
    };

    socket.connect(addr).await
}

async fn connect_by_proxy(
    target_addr: String,
    target_port: u16,
    mut proxy_server_url: url::Url,
    proxy_random_auth: bool,
) -> io::Result<TcpStream> {
    if proxy_random_auth {
        // Generate random username and password for authentication
        if proxy_server_url.username().is_empty() {
            let (random_username, random_passwd) = random_auth();
            proxy_server_url
                .set_username(&random_username)
                .map_err(|_| io::Error::other("failed to set username"))?;
            proxy_server_url
                .set_password(Some(&random_passwd))
                .map_err(|_| io::Error::other("failed to set password"))?;
        } else {
            // if username is not empty, then use the original username and password
        }
    }

    socks5::connect(proxy_server_url.clone(), target_addr.clone(), target_port)
        .await
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "socks5_connect to target_addr: {}, target_port: {} by proxy_server: {} failed, err: {}",
                    target_addr, target_port, proxy_server_url, err
                ),
            )
        })
}

pub(crate) async fn connect(
    target_addr: SocketAddr,
    tcp_config: TcpSocketConfig,
) -> io::Result<TcpStream> {
    let TcpSocketConfig {
        socket_transformer,
        proxy_url,
        onion_url: _,
        proxy_random_auth,
    } = tcp_config;

    match proxy_url {
        Some(proxy_url) => connect_by_proxy(
            target_addr.ip().to_string(),
            target_addr.port(),
            proxy_url.clone(),
            proxy_random_auth,
        )
        .await
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("connect_by_proxy: {}, error: {}", proxy_url, err),
            )
        }),
        None => connect_direct(target_addr, socket_transformer).await,
    }
}

pub(crate) async fn connect_onion(
    onion_addr: MultiAddr,
    tcp_config: TcpSocketConfig,
) -> io::Result<TcpStream> {
    let TcpSocketConfig {
        socket_transformer: _,
        proxy_url,
        onion_url,
        proxy_random_auth,
    } = tcp_config;
    let tor_server_url = onion_url.or(proxy_url).ok_or(io::Error::other(
        "need tor proxy server to connect to onion address",
    ))?;

    let onion_protocol = onion_addr
        .iter()
        .find_map(|protocol| {
            if let Protocol::Onion3(onion_address) = protocol {
                Some(onion_address)
            } else {
                None
            }
        })
        .ok_or(io::Error::other(format!(
            "No Onion3 address found. in {}",
            onion_addr
        )))?;

    let onion_str = onion_protocol.hash_string() + ".onion";
    let onion_port = onion_protocol.port();

    connect_by_proxy(onion_str, onion_port, tor_server_url, proxy_random_auth).await
}
