pub use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
    task::{block_in_place, spawn_blocking, yield_now, JoinHandle},
};

use crate::service::config::{TcpSocket, TcpSocketConfig};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
use std::{io, net::SocketAddr};
use tokio::net::TcpSocket as TokioTcp;

#[cfg(feature = "tokio-timer")]
pub use time::{interval, Interval};
#[cfg(feature = "tokio-timer")]
pub use tokio::time::{sleep as delay_for, timeout, Sleep as Delay, Timeout};

#[cfg(feature = "tokio-timer")]
mod time {
    use futures::Stream;
    use std::{
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::time::{interval as inner_interval, Interval as Inner};

    pub struct Interval(Inner);

    impl Interval {
        pub fn new(period: Duration) -> Self {
            Self(inner_interval(period))
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
            (std::usize::MAX, None)
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
        let t = tcp_config(TcpSocket { inner: socket })?;
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

pub(crate) async fn connect(
    addr: SocketAddr,
    tcp_config: TcpSocketConfig,
) -> io::Result<TcpStream> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP))?;

    let socket = {
        let t = tcp_config(TcpSocket { inner: socket })?;
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
