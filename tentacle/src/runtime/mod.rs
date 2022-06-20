//! runtime compatible
//!
//! In order to make Tentacle multi-runtime universal, this module encapsulates some common methods needed by Tentacle.
//!
//! At the same time, these packages can also be used by users, but please note that this module is doc hidden,
//! that is, its biggest purpose is to make tentacle universal on multiple platforms, not for users to use,
//! so there may be some strangeness Trick break, this is unavoidable
//!
//! this module contains async timer, compat async read/write between futures and tokio, spawn on any runtime
//!

#[cfg(all(not(target_arch = "wasm32"), feature = "async-runtime"))]
mod async_runtime;
#[cfg(any(
    feature = "generic-timer",
    all(target_arch = "wasm32", feature = "wasm-timer")
))]
mod generic_timer;
#[cfg(all(not(target_arch = "wasm32"), feature = "tokio-runtime"))]
mod tokio_runtime;
#[cfg(target_arch = "wasm32")]
mod wasm_runtime;

#[cfg(all(not(target_arch = "wasm32"), feature = "async-runtime"))]
pub use async_runtime::*;
#[cfg(any(
    feature = "generic-timer",
    all(target_arch = "wasm32", feature = "wasm-timer")
))]
pub use generic_timer::*;
#[cfg(all(not(target_arch = "wasm32"), feature = "tokio-runtime"))]
pub use tokio_runtime::*;
#[cfg(target_arch = "wasm32")]
pub use wasm_runtime::*;

#[cfg(all(not(target_arch = "wasm32"), feature = "tokio-runtime"))]
pub use tokio::io::{split, ReadHalf, WriteHalf};

#[cfg(not(feature = "tokio-runtime"))]
pub use generic_split::*;

#[cfg(not(feature = "tokio-runtime"))]
mod generic_split {
    use super::{CompatStream, CompatStream2};
    use futures::io::{AsyncReadExt, ReadHalf as R, WriteHalf as W};
    use tokio::io::{AsyncRead, AsyncWrite};

    pub type ReadHalf<T> = CompatStream2<R<CompatStream<T>>>;
    pub type WriteHalf<T> = CompatStream2<W<CompatStream<T>>>;

    /// Splits a single value implementing `AsyncRead + AsyncWrite` into separate
    /// `AsyncRead` and `AsyncWrite` handles.
    pub fn split<T: AsyncRead + AsyncWrite + Unpin>(io: T) -> (ReadHalf<T>, WriteHalf<T>) {
        let (read, write) = CompatStream::new(io).split();
        (CompatStream2::new(read), CompatStream2::new(write))
    }
}

mod budget;
pub use budget::*;

use futures::{ready, AsyncRead as FutureAsyncRead, AsyncWrite as FutureAsyncWrite};
use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Compact tokio to future
pub struct CompatStream<T>(T);

impl<T> FutureAsyncRead for CompatStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut buf = tokio::io::ReadBuf::new(buf);
        ready!(AsyncRead::poll_read(self, cx, &mut buf))?;
        Poll::Ready(Ok(buf.filled().len()))
    }
}

impl<T> FutureAsyncWrite for CompatStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

impl<T> AsyncRead for CompatStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

impl<T> AsyncWrite for CompatStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

/// Compact future to tokio
pub struct CompatStream2<T>(T);

impl<T> AsyncRead for CompatStream2<T>
where
    T: FutureAsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // see https://github.com/tokio-rs/tokio/issues/3417
        let slice = unsafe {
            let buf = buf.unfilled_mut();
            ::std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len())
        };
        let n = ready!(FutureAsyncRead::poll_read(self, cx, slice))?;
        unsafe {
            buf.assume_init(n);
        }
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl<T> AsyncWrite for CompatStream2<T>
where
    T: FutureAsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        FutureAsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        FutureAsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        FutureAsyncWrite::poll_close(self, cx)
    }
}

impl<T> FutureAsyncRead for CompatStream2<T>
where
    T: FutureAsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        FutureAsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

impl<T> FutureAsyncWrite for CompatStream2<T>
where
    T: FutureAsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        FutureAsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        FutureAsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        FutureAsyncWrite::poll_close(Pin::new(&mut self.0), cx)
    }
}

impl<T> fmt::Debug for CompatStream2<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<T> fmt::Debug for CompatStream<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<T> CompatStream2<T> {
    /// New wrapped stream
    pub fn new(stream: T) -> Self {
        CompatStream2(stream)
    }

    /// Get a reference to the Future, Stream, AsyncRead, or AsyncWrite object contained within.
    pub fn get_ref(&self) -> &T {
        &self.0
    }

    /// Get a mutable reference to the Future, Stream, AsyncRead, or AsyncWrite object contained within.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Returns the wrapped item.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> CompatStream<T> {
    /// New wrapped stream
    pub fn new(stream: T) -> Self {
        CompatStream(stream)
    }

    /// Get a reference to the Future, Stream, AsyncRead, or AsyncWrite object contained within.
    pub fn get_ref(&self) -> &T {
        &self.0
    }

    /// Get a mutable reference to the Future, Stream, AsyncRead, or AsyncWrite object contained within.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Returns the wrapped item.
    pub fn into_inner(self) -> T {
        self.0
    }
}
