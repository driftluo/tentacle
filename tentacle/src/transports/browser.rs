mod inner {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(module = "/src/transports/websocket.js")]
    extern "C" {
        #[wasm_bindgen(catch)]
        pub fn dial(addr: &str) -> Result<js_sys::Promise, JsValue>;

        #[wasm_bindgen(js_name = Session)]
        pub type BrowserSession;

        #[wasm_bindgen(method, catch)]
        pub fn write(this: &BrowserSession, buffer: &[u8]) -> Result<js_sys::Promise, JsValue>;

        #[wasm_bindgen(method)]
        pub fn read(this: &BrowserSession) -> js_sys::Promise;

        #[wasm_bindgen(method, catch)]
        pub fn close(this: &BrowserSession) -> Result<(), JsValue>;

        #[wasm_bindgen(method, js_name = isClose)]
        pub fn is_close(this: &BrowserSession) -> bool;
    }
}

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    error::TransportErrorKind,
    multiaddr::{Multiaddr, Protocol},
    transports::{find_type, Result, Transport, TransportFuture, TransportType},
    utils::multiaddr_to_socketaddr,
};
use futures::FutureExt;
use wasm_bindgen::JsCast;

async fn connect(addr: Multiaddr, timeout: Duration) -> Result<(Multiaddr, BrowserStream)> {
    let url = match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => format!("ws://{}:{}", socket_address.ip(), socket_address.port()),
        None => {
            let mut iter = addr.iter().peekable();

            loop {
                if iter.peek().is_none() {
                    return Err(TransportErrorKind::NotSupported(addr.clone()));
                }
                match iter.peek() {
                    Some(Protocol::Dns4(_)) | Some(Protocol::Dns6(_)) => (),
                    _ => {
                        // this ignore is true
                        let _ignore = iter.next();
                        continue;
                    }
                }

                let proto1 = iter
                    .next()
                    .ok_or(TransportErrorKind::NotSupported(addr.clone()))?;
                let proto2 = iter
                    .next()
                    .ok_or(TransportErrorKind::NotSupported(addr.clone()))?;

                match (proto1, proto2) {
                    (Protocol::Dns4(domain), Protocol::Tcp(port)) => {
                        break format!("ws://{}:{}", domain, port)
                    }
                    (Protocol::Dns6(domain), Protocol::Tcp(port)) => {
                        break format!("ws://{}:{}", domain, port)
                    }
                    _ => return Err(TransportErrorKind::NotSupported(addr.clone())),
                }
            }
        }
    };

    match crate::runtime::timeout(
        timeout,
        Into::<wasm_bindgen_futures::JsFuture>::into(inner::dial(&url)?),
    )
    .await
    {
        Err(_) => Err(TransportErrorKind::Io(io::ErrorKind::TimedOut.into())),
        Ok(res) => {
            let stream = res?;
            Ok((addr, BrowserStream::new(stream.into())))
        }
    }
}

#[derive(Copy, Clone)]
pub struct BrowserTransport {
    timeout: Duration,
}

impl BrowserTransport {
    pub fn new(timeout: Duration) -> Self {
        BrowserTransport { timeout }
    }

    pub fn tcp_bind(self, _bind_addr: Option<SocketAddr>) -> Self {
        self
    }
}

pub type BrowserDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, BrowserStream)>>>>>;

impl Transport for BrowserTransport {
    type ListenFuture = ();
    type DialFuture = BrowserDialFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
        Err(TransportErrorKind::NotSupported(address))
    }

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
        if !matches!(find_type(&address), TransportType::Ws) {
            return Err(TransportErrorKind::NotSupported(address));
        }
        let dial = connect(address, self.timeout);
        Ok(TransportFuture::new(Box::pin(dial)))
    }
}

pub struct BrowserStream {
    inner: inner::BrowserSession,
    recv_buf: Vec<u8>,
    pending_read: Option<wasm_bindgen_futures::JsFuture>,
    pending_write: Option<wasm_bindgen_futures::JsFuture>,
}

// Browser runtime is always single threaded
unsafe impl Send for BrowserStream {}

impl BrowserStream {
    fn new(stream: inner::BrowserSession) -> Self {
        BrowserStream {
            inner: stream,
            recv_buf: Vec::new(),
            pending_read: None,
            pending_write: None,
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

impl AsyncRead for BrowserStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // when there is something in recv_buffer
        let copied = self.drain(buf);
        if copied > 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(mut promise) = self.pending_read.take() {
                match Pin::new(&mut promise).poll_unpin(cx) {
                    Poll::Ready(Ok(data)) => {
                        // session closed
                        if data.is_null() {
                            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                        }

                        // when input buffer is big enough
                        // data type is arraybuffer
                        let data = js_sys::Uint8Array::new(&data);
                        let n = data.length() as usize;
                        if buf.remaining() >= n {
                            // see https://github.com/tokio-rs/tokio/issues/3417
                            let slice = unsafe {
                                let buf = buf.unfilled_mut();
                                ::std::slice::from_raw_parts_mut(
                                    buf.as_mut_ptr().cast::<u8>(),
                                    buf.len(),
                                )
                            };
                            data.copy_to(&mut slice[..n]);
                            unsafe {
                                buf.assume_init(n);
                            }
                            buf.advance(n);
                            return Poll::Ready(Ok(()));
                        } else {
                            // fill internal recv buffer
                            self.recv_buf.reserve(n);
                            unsafe {
                                self.recv_buf.set_len(n);
                            }
                            data.copy_to(&mut self.recv_buf);
                            // drain for input buffer
                            self.drain(buf);
                            return Poll::Ready(Ok(()));
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(convert_to_io_err(err))),
                    Poll::Pending => {
                        self.pending_read = Some(promise);
                        return Poll::Pending;
                    }
                }
            } else {
                self.pending_read = Some(self.inner.read().into());
                continue;
            }
        }
    }
}

impl AsyncWrite for BrowserStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut promise) = self.pending_write.take() {
            match Pin::new(&mut promise).poll_unpin(cx) {
                Poll::Ready(Ok(_)) => (),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(convert_to_io_err(err))),
                Poll::Pending => {
                    self.pending_write = Some(promise);
                    return Poll::Pending;
                }
            }
        }

        self.pending_write = Some(self.inner.write(buf).map_err(convert_to_io_err)?.into());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(self.inner.close().map_err(convert_to_io_err)?))
    }
}

impl Drop for BrowserStream {
    fn drop(&mut self) {
        let _ignore = self.inner.close();
    }
}

impl From<wasm_bindgen::JsValue> for TransportErrorKind {
    fn from(err: wasm_bindgen::JsValue) -> TransportErrorKind {
        TransportErrorKind::Io(convert_to_io_err(err))
    }
}

fn convert_to_io_err(err: wasm_bindgen::JsValue) -> io::Error {
    if let Some(s) = err.as_string() {
        io::Error::new(io::ErrorKind::Other, s)
    } else if let Some(s) = err.dyn_ref::<js_sys::Error>() {
        io::Error::new(io::ErrorKind::Other, format!("{:?}", s.message()))
    } else if let Some(obj) = err.dyn_ref::<js_sys::Object>() {
        io::Error::new(io::ErrorKind::Other, format!("{:?}", obj.to_string()))
    } else {
        io::Error::new(io::ErrorKind::Other, format!("{:?}", err))
    }
}
