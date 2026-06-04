//! Adapter that exposes a `quinn` bidirectional stream pair (one
//! [`quinn::SendStream`] + one [`quinn::RecvStream`]) as a single tokio
//! [`AsyncRead`] + [`AsyncWrite`] handle, so it can carry the same
//! length-prefixed protocol layer used by the yamux backend.

use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

/// A `quinn` bidirectional stream packaged as a single
/// `AsyncRead + AsyncWrite` so the protocol layer (`Substream<U>`,
/// `client_select`, `server_select`, …) can sit on top of QUIC the
/// same way it sits on top of yamux.
#[derive(Debug)]
pub struct QuicBiStream {
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
}

impl QuicBiStream {
    /// Wrap a quinn bidirectional stream pair into an `AsyncRead + AsyncWrite`
    /// substream usable by the protocol layer.
    pub(crate) fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}
