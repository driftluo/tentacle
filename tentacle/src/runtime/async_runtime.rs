#[cfg(not(target_arch = "wasm32"))]
pub use async_std::task::{spawn, spawn_blocking, yield_now, JoinHandle};

pub fn block_in_place<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

#[cfg(not(target_arch = "wasm32"))]
pub use os::*;

#[cfg(not(target_arch = "wasm32"))]
mod os {
    use crate::{
        runtime::CompatStream2,
        service::config::{TcpSocket, TcpSocketConfig},
    };
    use async_io::Async;
    use async_std::net::{TcpListener as AsyncListener, TcpStream as AsyncStream, ToSocketAddrs};
    use futures::{
        channel::{
            mpsc::{channel, Receiver},
            oneshot::{self, Sender},
        },
        future::select,
        FutureExt, SinkExt, StreamExt,
    };
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Debug)]
    pub struct TcpListener {
        /// Why does this need to be handled here?
        ///
        /// https://www.driftluo.com/article/9e85ea7c-219a-4b25-ab32-e66c5d3027d0
        ///
        /// Not only because of idempotent operation reasons, at the same time,
        /// after the task is registered to the event monitor, the relationship between
        /// the task and the corresponding waker needs to be ensured. If the task is dropped
        /// immediately after registration, the waker cannot wake up the corresponding task.
        ///
        /// Since the async-std api was designed without leaving the corresponding poll interface,
        /// this will force users to ensure that they are used in an async environment
        recv: Receiver<io::Result<(AsyncStream, SocketAddr)>>,
        local_addr: SocketAddr,
        _close_sender: Sender<()>,
    }

    impl TcpListener {
        fn new(listener: AsyncListener, local_addr: SocketAddr) -> TcpListener {
            let (mut tx, rx) = channel(24);
            let (tx_c, rx_c) = oneshot::channel::<()>();
            let task = async move {
                loop {
                    let res = listener.accept().await;
                    let _ignore = tx.send(res).await;
                }
            }
            .boxed();
            crate::runtime::spawn(select(task, rx_c));
            TcpListener {
                recv: rx,
                local_addr,
                _close_sender: tx_c,
            }
        }

        pub async fn bind<A: ToSocketAddrs>(addrs: A) -> io::Result<TcpListener> {
            let listener = AsyncListener::bind(addrs).await?;
            let local_addr = listener.local_addr()?;
            Ok(Self::new(listener, local_addr))
        }

        pub fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        pub fn poll_accept(
            &mut self,
            cx: &mut Context,
        ) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
            match self.recv.poll_next_unpin(cx) {
                Poll::Ready(Some(res)) => {
                    Poll::Ready(res.map(|x| (TcpStream(CompatStream2::new(x.0)), x.1)))
                }
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
    }

    #[derive(Debug)]
    pub struct TcpStream(CompatStream2<AsyncStream>);

    impl TcpStream {
        pub fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.0.get_ref().peer_addr()
        }
    }

    impl AsyncRead for TcpStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), io::Error>> {
            AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
        }
    }

    impl AsyncWrite for TcpStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        #[inline]
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    #[cfg(feature = "async-timer")]
    pub use async_std::future::timeout;
    #[cfg(feature = "async-timer")]
    pub use time::*;

    use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
    use std::{io, net::SocketAddr};

    pub(crate) fn listen(addr: SocketAddr, tcp_config: TcpSocketConfig) -> io::Result<TcpListener> {
        let domain = Domain::for_address(addr);
        let socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP))?;

        let socket = {
            let t = tcp_config(TcpSocket { inner: socket })?;
            t.inner
        };
        // `bind` twice will return error
        //
        // code 22 means:
        // EINVAL The socket is already bound to an address.
        // ref: https://man7.org/linux/man-pages/man2/bind.2.html
        if let Err(e) = socket.bind(&addr.into()) {
            if Some(22) != e.raw_os_error() {
                return Err(e);
            }
        }
        socket.listen(1024)?;

        let listen = std::net::TcpListener::from(socket);
        let addr = listen.local_addr()?;
        Ok(TcpListener::new(AsyncListener::from(listen), addr))
    }

    pub(crate) async fn connect(
        addr: SocketAddr,
        tcp_config: TcpSocketConfig,
    ) -> io::Result<TcpStream> {
        let domain = Domain::for_address(addr);
        let socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP))?;

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
            t.inner
        };

        // Begin async connect and ignore the inevitable "in progress" error.
        socket.set_nonblocking(true)?;
        socket.connect(&addr.into()).or_else(|err| {
            // Check for EINPROGRESS on Unix and WSAEWOULDBLOCK on Windows.
            #[cfg(unix)]
            let in_progress = err.raw_os_error() == Some(libc::EINPROGRESS);
            #[cfg(windows)]
            let in_progress = err.kind() == io::ErrorKind::WouldBlock;

            // If connect results with an "in progress" error, that's not an error.
            if in_progress {
                Ok(())
            } else {
                Err(err)
            }
        })?;
        let stream = Async::new(std::net::TcpStream::from(socket))?;

        // The stream becomes writable when connected.
        stream.writable().await?;

        // Check if there was an error while connecting.
        match stream.get_ref().take_error()? {
            None => {
                let tcp = stream.into_inner().unwrap();
                Ok(TcpStream(CompatStream2::new(AsyncStream::from(tcp))))
            }
            Some(err) => Err(err),
        }
    }

    #[cfg(feature = "async-timer")]
    mod time {
        use async_io::Timer;
        use futures::{Future, Stream};
        use std::{
            pin::Pin,
            task::{Context, Poll},
            time::{Duration, Instant},
        };

        pub struct Delay(Timer);

        impl Delay {
            pub fn new(duration: Duration) -> Self {
                Delay(Timer::after(duration))
            }
        }

        impl Future for Delay {
            type Output = Instant;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                Pin::new(&mut self.0).poll(cx)
            }
        }

        pub fn delay_for(duration: Duration) -> Delay {
            Delay::new(duration)
        }

        pub struct Interval {
            delay: Delay,
            period: Duration,
        }

        impl Interval {
            fn new(period: Duration) -> Self {
                Self {
                    delay: Delay::new(period),
                    period,
                }
            }
        }

        impl Stream for Interval {
            type Item = ();

            fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
                match Pin::new(&mut self.delay).poll(cx) {
                    Poll::Ready(_) => {
                        let dur = self.period;
                        self.delay.0.set_after(dur);
                        Poll::Ready(Some(()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        pub fn interval(period: Duration) -> Interval {
            assert!(period > Duration::new(0, 0), "`period` must be non-zero.");

            Interval::new(period)
        }
    }
}
