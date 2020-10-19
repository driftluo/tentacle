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

pub fn from_std(listen: StdListen) -> io::Result<TcpListener> {
    TcpListener::from_std(listen)
}

pub async fn connect_std(stream: Socket, addr: &SocketAddr) -> io::Result<TcpStream> {
    TcpStream::connect_std(stream.into_tcp_stream(), addr).await
}
