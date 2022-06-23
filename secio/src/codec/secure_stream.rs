use bytes::{Buf, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use log::{debug, trace};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio_util::codec::{length_delimited::LengthDelimitedCodec, Framed};

use std::{
    cmp::min,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{crypto::BoxStreamCipher, error::SecioError};

enum RecvBuf {
    Vec(Vec<u8>),
    Byte(BytesMut),
}

impl RecvBuf {
    fn drain_to(&mut self, buf: &mut ReadBuf, size: usize) {
        match self {
            RecvBuf::Vec(ref mut b) => {
                buf.put_slice(b.drain(..size).as_slice());
            }
            RecvBuf::Byte(ref mut b) => {
                buf.put_slice(&b[..size]);
                b.advance(size);
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            RecvBuf::Vec(ref b) => b.len(),
            RecvBuf::Byte(ref b) => b.len(),
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AsRef<[u8]> for RecvBuf {
    fn as_ref(&self) -> &[u8] {
        match self {
            RecvBuf::Vec(ref b) => b.as_ref(),
            RecvBuf::Byte(ref b) => b.as_ref(),
        }
    }
}

/// Encrypted stream
pub struct SecureStream<T> {
    socket: Framed<T, LengthDelimitedCodec>,
    decode_cipher: BoxStreamCipher,
    encode_cipher: BoxStreamCipher,
    /// denotes a sequence of bytes which are expected to be
    /// found at the beginning of the stream and are checked for equality
    nonce: Vec<u8>,
    /// recv buffer
    /// internal buffer for 'message too big'
    ///
    /// when the input buffer is not big enough to hold the entire
    /// frame from the underlying Framed<>, the frame will be filled
    /// into this buffer so that multiple following 'read' will eventually
    /// get the message correctly
    recv_buf: RecvBuf,
}

impl<T> SecureStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// New a secure stream
    pub(crate) fn new(
        socket: Framed<T, LengthDelimitedCodec>,
        decode_cipher: BoxStreamCipher,
        encode_cipher: BoxStreamCipher,
        nonce: Vec<u8>,
    ) -> Self {
        let recv_buf = if decode_cipher.is_in_place() {
            RecvBuf::Byte(BytesMut::new())
        } else {
            RecvBuf::Vec(Vec::default())
        };
        SecureStream {
            socket,
            decode_cipher,
            encode_cipher,
            nonce,
            recv_buf,
        }
    }

    /// Decoding data
    #[inline]
    fn decode_buffer(&mut self, mut frame: BytesMut) -> Result<RecvBuf, SecioError> {
        if self.decode_cipher.is_in_place() {
            self.decode_cipher.decrypt_in_place(&mut frame)?;
            Ok(RecvBuf::Byte(frame))
        } else {
            Ok(RecvBuf::Vec(self.decode_cipher.decrypt(&frame)?))
        }
    }

    pub(crate) async fn verify_nonce(&mut self) -> Result<(), SecioError> {
        if !self.nonce.is_empty() {
            let mut nonce = self.nonce.clone();
            self.read_exact(&mut nonce).await?;

            trace!(
                "received nonce={}, my_nonce={}",
                nonce.len(),
                self.nonce.len()
            );

            let n = min(nonce.len(), self.nonce.len());
            if nonce[..n] != self.nonce[..n] {
                return Err(SecioError::NonceVerificationFailed);
            }
            self.nonce.drain(..n);
            self.nonce.shrink_to_fit();
        }

        Ok(())
    }

    #[inline]
    fn drain(&mut self, buf: &mut ReadBuf<'_>) -> usize {
        // Return zero if there is no data remaining in the internal buffer.
        if self.recv_buf.is_empty() {
            return 0;
        }

        // calculate number of bytes that we can copy
        let n = ::std::cmp::min(buf.remaining(), self.recv_buf.len());

        // Copy data to the output buffer
        self.recv_buf.drain_to(buf, n);

        n
    }

    #[inline]
    fn encode_buffer(&mut self, buf: &[u8]) -> Bytes {
        let out = self.encode_cipher.encrypt(buf).unwrap();
        Bytes::from(out)
    }
}

impl<T> AsyncRead for SecureStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
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

        match self.socket.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(t))) => {
                trace!("poll_read raw.len={}", t.len());
                let decoded = self
                    .decode_buffer(t)
                    .map_err::<io::Error, _>(|err| err.into())?;

                // when input buffer is big enough
                let n = decoded.len();
                trace!("poll_read decoded.len={}", n);
                if buf.remaining() >= n {
                    buf.put_slice(decoded.as_ref());
                    Poll::Ready(Ok(()))
                } else {
                    // fill internal recv buffer
                    self.recv_buf = decoded;
                    // drain for input buffer
                    self.drain(buf);
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(err)),
            Poll::Ready(None) => {
                debug!("connection shutting down");
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> AsyncWrite for SecureStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.socket.poll_ready_unpin(cx) {
            Poll::Ready(Ok(_)) => {
                trace!("poll_write buf.len={}", buf.len());
                let frame = self.encode_buffer(buf);
                self.socket.start_send_unpin(frame)?;
                let _ignore = self.socket.poll_flush_unpin(cx)?;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.poll_flush_unpin(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.poll_close_unpin(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::SecureStream;
    use crate::crypto::{cipher::CipherType, new_stream, CryptoMode};
    use bytes::BytesMut;
    use futures::channel;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_util::codec::{length_delimited::LengthDelimitedCodec, Framed};

    fn rt() -> &'static tokio::runtime::Runtime {
        static RT: once_cell::sync::OnceCell<tokio::runtime::Runtime> =
            once_cell::sync::OnceCell::new();
        RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap())
    }

    fn test_decode_encode(cipher1: CipherType, cipher2: CipherType) {
        let cipher_key = (0..cipher1.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let data = b"hello world";

        let mut encode_cipher = new_stream(cipher1, &cipher_key, CryptoMode::Encrypt);
        let mut decode_cipher = new_stream(cipher2, &cipher_key, CryptoMode::Decrypt);

        let encode_data = encode_cipher.encrypt(&data[..]).unwrap();

        let decode_data = decode_cipher.decrypt(&encode_data).unwrap();

        assert_eq!(&decode_data[..], &data[..]);
    }

    fn secure_codec_encode_then_decode(cipher: CipherType, send_nonce: bool) {
        let cipher_key: [u8; 32] = rand::random();
        let cipher_key_clone = cipher_key;
        let key_size = cipher.key_size();
        let hmac_key: [u8; 16] = rand::random();
        let _hmac_key_clone = hmac_key;
        let data = b"hello world";
        let data_clone = &*data;
        let nonce = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let nonce2 = nonce.clone();

        let (sender, receiver) = channel::oneshot::channel::<bytes::BytesMut>();
        let (addr_sender, addr_receiver) = channel::oneshot::channel::<::std::net::SocketAddr>();
        let rt = rt();

        rt.spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listener_addr = listener.local_addr().unwrap();
            let _res = addr_sender.send(listener_addr);
            let (socket, _) = listener.accept().await.unwrap();

            let mut handle = SecureStream::new(
                Framed::new(socket, LengthDelimitedCodec::new()),
                new_stream(cipher, &cipher_key_clone[..key_size], CryptoMode::Decrypt),
                new_stream(cipher, &cipher_key_clone[..key_size], CryptoMode::Encrypt),
                nonce2,
            );

            handle.verify_nonce().await.unwrap();

            let mut data = [0u8; 11];
            handle.read_exact(&mut data).await.unwrap();
            let _res = sender.send(BytesMut::from(&data[..]));
        });

        rt.spawn(async move {
            let listener_addr = addr_receiver.await.unwrap();
            let stream = TcpStream::connect(&listener_addr).await.unwrap();
            let mut handle = SecureStream::new(
                Framed::new(stream, LengthDelimitedCodec::new()),
                new_stream(cipher, &cipher_key_clone[..key_size], CryptoMode::Decrypt),
                new_stream(cipher, &cipher_key_clone[..key_size], CryptoMode::Encrypt),
                Vec::new(),
            );

            // if not send nonce to remote, handshake will unable to complete the final confirmation
            // it will return error and shutdown this session
            if send_nonce {
                let _ = handle.write_all(&nonce).await;
            }

            let _res = handle.write_all(&data_clone[..]).await;
        });

        rt.block_on(async move {
            let received = receiver.await.unwrap();
            assert_eq!(received.to_vec(), data);
        });
    }

    #[test]
    fn test_encode_decode_aes128gcm() {
        test_decode_encode(CipherType::Aes128Gcm, CipherType::Aes128Gcm);
    }

    #[test]
    fn test_encode_decode_aes256gcm() {
        test_decode_encode(CipherType::Aes256Gcm, CipherType::Aes256Gcm);
    }

    #[test]
    fn test_encode_decode_chacha20poly1305() {
        test_decode_encode(CipherType::ChaCha20Poly1305, CipherType::ChaCha20Poly1305);
    }

    #[should_panic]
    #[test]
    fn test_encode_decode_diff_cipher_1() {
        test_decode_encode(CipherType::Aes128Gcm, CipherType::Aes256Gcm);
    }

    #[should_panic]
    #[test]
    fn test_encode_decode_diff_cipher_2() {
        test_decode_encode(CipherType::Aes128Gcm, CipherType::ChaCha20Poly1305);
    }

    #[should_panic]
    #[test]
    fn test_encode_decode_diff_cipher_3() {
        test_decode_encode(CipherType::Aes256Gcm, CipherType::Aes128Gcm);
    }

    #[should_panic]
    #[test]
    fn test_encode_decode_diff_cipher_4() {
        test_decode_encode(CipherType::Aes256Gcm, CipherType::ChaCha20Poly1305);
    }

    #[should_panic]
    #[test]
    fn test_encode_decode_diff_cipher_5() {
        test_decode_encode(CipherType::ChaCha20Poly1305, CipherType::Aes128Gcm);
    }

    #[should_panic]
    #[test]
    fn test_encode_decode_diff_cipher_6() {
        test_decode_encode(CipherType::ChaCha20Poly1305, CipherType::Aes256Gcm);
    }

    #[test]
    fn secure_codec_encode_then_decode_aes128gcm() {
        secure_codec_encode_then_decode(CipherType::Aes128Gcm, true);
    }

    #[test]
    fn secure_codec_encode_then_decode_aes256gcm() {
        secure_codec_encode_then_decode(CipherType::Aes256Gcm, true);
    }

    #[test]
    fn secure_codec_encode_then_decode_chacha20poly1305() {
        secure_codec_encode_then_decode(CipherType::ChaCha20Poly1305, true);
    }

    #[should_panic]
    #[test]
    fn secure_codec_encode_then_decode_do_not_send_nonce_aes128gcm() {
        secure_codec_encode_then_decode(CipherType::Aes128Gcm, false);
    }

    #[should_panic]
    #[test]
    fn secure_codec_encode_then_decode_do_not_send_nonce_aes256gcm() {
        secure_codec_encode_then_decode(CipherType::Aes256Gcm, false);
    }

    #[should_panic]
    #[test]
    fn secure_codec_encode_then_decode_do_not_send_nonce_chacha20poly1305() {
        secure_codec_encode_then_decode(CipherType::ChaCha20Poly1305, false);
    }
}
