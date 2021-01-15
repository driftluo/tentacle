pub use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
    task::{block_in_place, spawn_blocking, JoinHandle},
};

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::Stream;
#[cfg(feature = "tokio-timer")]
pub use tokio::time::{sleep as delay_for, timeout, Sleep as Delay, Timeout};
use tokio::{
    net::TcpSocket,
    time::{interval as inner_interval, Interval as Inner},
};

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

pub(crate) fn reuse_listen(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }?;

    // reuse addr and reuse port's situation on each platform
    // https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket.set_reuseport(true)?;

    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

pub(crate) async fn connect(
    addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
) -> io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }?;

    if let Some(addr) = bind_addr {
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket.set_reuseport(true)?;
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
    }

    socket.connect(addr).await
}
