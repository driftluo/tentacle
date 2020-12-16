pub use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
    task::{block_in_place, spawn_blocking, JoinHandle},
};

use socket2::Socket;
use std::{
    io,
    net::{SocketAddr, TcpListener as StdListen},
};

#[cfg(feature = "tokio-timer")]
pub use tokio::time::{delay_for, interval, timeout, Delay, Interval, Timeout};

pub(crate) fn from_std(listen: StdListen) -> io::Result<TcpListener> {
    TcpListener::from_std(listen)
}

pub(crate) async fn connect_std(stream: Socket, addr: &SocketAddr) -> io::Result<TcpStream> {
    // on windows, if not set reuse address, but use socket2 and tokio `connect_std` function
    // will cause a error "Os {code: 10022, kind: InvalidInput, message: "An invalid parameter was provided." }"
    // but if set, nothing happened, this is confusing behavior
    // issue: https://github.com/tokio-rs/tokio/issues/3030
    #[cfg(windows)]
    if stream.reuse_address()? {
        TcpStream::connect_std(stream.into_tcp_stream(), addr).await
    } else {
        TcpStream::connect(addr).await
    }

    #[cfg(unix)]
    TcpStream::connect_std(stream.into_tcp_stream(), addr).await
}
