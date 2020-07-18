use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use log::{debug, trace};
use tokio::prelude::{AsyncRead, AsyncWrite};
use tokio_util::codec::{length_delimited::LengthDelimitedCodec, Framed};

use std::{
    cmp::min,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{codec::Hmac, crypto::BoxStreamCipher, error::SecioError};
use std::future::Future;
use tokio::io::AsyncReadExt;

/// Encrypted stream
pub struct SecureStream<T> {
    socket: Framed<T, LengthDelimitedCodec>,
    decode_cipher: BoxStreamCipher,
    decode_hmac: Option<Hmac>,
    encode_cipher: BoxStreamCipher,
    encode_hmac: Option<Hmac>,
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
    recv_buf: Vec<u8>,
}

impl<T> SecureStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// New a secure stream
    pub(crate) fn new(
        socket: Framed<T, LengthDelimitedCodec>,
        decode_cipher: BoxStreamCipher,
        decode_hmac: Option<Hmac>,
        encode_cipher: BoxStreamCipher,
        encode_hmac: Option<Hmac>,
        nonce: Vec<u8>,
    ) -> Self {
        SecureStream {
            socket,
            decode_cipher,
            decode_hmac,
            encode_cipher,
            encode_hmac,
            nonce,
            recv_buf: Vec::default(),
        }
    }

    /// Decoding data
    #[inline]
    fn decode_buffer(&mut self, mut frame: BytesMut) -> Result<Vec<u8>, SecioError> {
        if let Some(ref mut hmac) = self.decode_hmac {
            if frame.len() < hmac.num_bytes() {
                debug!("frame too short when decoding secio frame");
                return Err(SecioError::FrameTooShort);
            }

            let content_length = frame.len() - hmac.num_bytes();
            {
                let (crypted_data, expected_hash) = frame.split_at(content_length);
                debug_assert_eq!(expected_hash.len(), hmac.num_bytes());

                if !hmac.verify(crypted_data, expected_hash) {
                    debug!("hmac mismatch when decoding secio frame");
                    return Err(SecioError::HmacNotMatching);
                }
            }

            frame.truncate(content_length);
        }

        let out = self.decode_cipher.decrypt(&frame)?;

        Ok(out)
    }

    pub(crate) async fn verify_nonce(&mut self) -> Result<(), SecioError> {
        if !self.nonce.is_empty() {
            let mut nonce = self.nonce.clone();
            self.read(&mut nonce).await?;

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
    fn drain(&mut self, buf: &mut [u8]) -> usize {
        // Return zero if there is no data remaining in the internal buffer.
        if self.recv_buf.is_empty() {
            return 0;
        }

        // calculate number of bytes that we can copy
        let n = ::std::cmp::min(buf.len(), self.recv_buf.len());

        // Copy data to the output buffer
        buf[..n].copy_from_slice(self.recv_buf[..n].as_ref());

        // drain n bytes of recv_buf
        self.recv_buf = self.recv_buf.split_off(n);

        n
    }

    async fn read_socket(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // when there is somthing in recv_buffer
        let copied = self.drain(buf);
        if copied > 0 {
            return Ok(copied);
        }

        match self.socket.next().await {
            Some(Ok(t)) => {
                debug!("receive encrypted data size: {:?}", t.len());
                let decoded = self
                    .decode_buffer(t)
                    .map_err::<io::Error, _>(|err| err.into())?;

                // when input buffer is big enough
                let n = decoded.len();
                if buf.len() >= n {
                    buf[..n].copy_from_slice(decoded.as_ref());
                    Ok(n)
                } else {
                    // fill internal recv buffer
                    self.recv_buf = decoded;
                    // drain for input buffer
                    let copied = self.drain(buf);
                    Ok(copied)
                }
            }
            Some(Err(err)) => Err(err),
            None => {
                debug!("connection shutting down");
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
    }

    #[inline]
    fn encode_buffer(&mut self, buf: &[u8]) -> Bytes {
        let mut out = self.encode_cipher.encrypt(buf).unwrap();
        if let Some(ref mut hmac) = self.encode_hmac {
            let signature = hmac.sign(&out[..]);
            out.extend_from_slice(signature.as_ref());
        }
        Bytes::from(out)
    }

    async fn write_socket(&mut self, buf: &[u8]) -> io::Result<usize> {
        debug!("start sending plain data: {:?}", buf);

        let frame = self.encode_buffer(buf);
        trace!("start sending encrypted data size: {:?}", frame.len());
        match self.socket.send(frame).await {
            Ok(()) => Ok(buf.len()),
            Err(err) => Err(err),
        }
    }
}

impl<T> AsyncRead for SecureStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        poll_future(cx, self.read_socket(buf))
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
        poll_future(cx, self.write_socket(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        poll_future(cx, self.socket.flush())
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        poll_future(cx, self.socket.close())
    }
}

/// Pins a future and then polls it.
fn poll_future<T>(cx: &mut Context<'_>, fut: impl Future<Output = T>) -> Poll<T> {
    futures::pin_mut!(fut);
    fut.poll(cx)
}

#[cfg(test)]
mod tests {
    use super::{Hmac, SecureStream};
    use crate::crypto::{cipher::CipherType, new_stream, CryptoMode};
    #[cfg(unix)]
    use crate::Digest;
    use bytes::BytesMut;
    use futures::channel;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_util::codec::{length_delimited::LengthDelimitedCodec, Framed};

    fn test_decode_encode(cipher: CipherType) {
        let cipher_key = (0..cipher.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();
        let _hmac_key: [u8; 32] = rand::random();
        let iv = (0..cipher.iv_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let data = b"hello world";

        let mut encode_cipher = new_stream(cipher, &cipher_key, &iv, CryptoMode::Encrypt);
        let mut decode_cipher = new_stream(cipher, &cipher_key, &iv, CryptoMode::Decrypt);

        let (mut decode_hmac, mut encode_hmac): (Option<Hmac>, Option<Hmac>) = match cipher {
            CipherType::ChaCha20Poly1305 | CipherType::Aes128Gcm | CipherType::Aes256Gcm => {
                (None, None)
            }
            #[cfg(unix)]
            _ => {
                let encode_hmac = Hmac::from_key(Digest::Sha256, &_hmac_key);
                let decode_hmac = encode_hmac.clone();
                (Some(decode_hmac), Some(encode_hmac))
            }
        };

        let mut encode_data = encode_cipher.encrypt(&data[..]).unwrap();
        if encode_hmac.is_some() {
            let signature = encode_hmac.as_mut().unwrap().sign(&encode_data[..]);
            encode_data.extend_from_slice(signature.as_ref());
        }

        if decode_hmac.is_some() {
            let content_length = encode_data.len() - decode_hmac.as_mut().unwrap().num_bytes();

            let (crypted_data, expected_hash) = encode_data.split_at(content_length);

            assert!(decode_hmac
                .as_mut()
                .unwrap()
                .verify(crypted_data, expected_hash));

            encode_data.truncate(content_length);
        }

        let decode_data = decode_cipher.decrypt(&encode_data).unwrap();

        assert_eq!(&decode_data[..], &data[..]);
    }

    fn secure_codec_encode_then_decode(cipher: CipherType) {
        let cipher_key: [u8; 32] = rand::random();
        let cipher_key_clone = cipher_key;
        let iv = (0..cipher.iv_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();
        let iv_clone = iv.clone();
        let key_size = cipher.key_size();
        let hmac_key: [u8; 16] = rand::random();
        let _hmac_key_clone = hmac_key;
        let data = b"hello world";
        let data_clone = &*data;
        let nonce = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let (sender, receiver) = channel::oneshot::channel::<bytes::BytesMut>();
        let (addr_sender, addr_receiver) = channel::oneshot::channel::<::std::net::SocketAddr>();
        let mut rt = tokio::runtime::Runtime::new().unwrap();

        rt.spawn(async move {
            let mut listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listener_addr = listener.local_addr().unwrap();
            let _res = addr_sender.send(listener_addr);
            let (socket, _) = listener.accept().await.unwrap();
            let nonce2 = nonce.clone();
            let (decode_hmac, encode_hmac) = match cipher {
                CipherType::ChaCha20Poly1305 | CipherType::Aes128Gcm | CipherType::Aes256Gcm => {
                    (None, None)
                }
                #[cfg(unix)]
                _ => (
                    Some(Hmac::from_key(Digest::Sha256, &_hmac_key_clone)),
                    Some(Hmac::from_key(Digest::Sha256, &_hmac_key_clone)),
                ),
            };
            let mut handle = SecureStream::new(
                Framed::new(socket, LengthDelimitedCodec::new()),
                new_stream(
                    cipher,
                    &cipher_key_clone[..key_size],
                    &iv_clone,
                    CryptoMode::Decrypt,
                ),
                decode_hmac,
                new_stream(
                    cipher,
                    &cipher_key_clone[..key_size],
                    &iv_clone,
                    CryptoMode::Encrypt,
                ),
                encode_hmac,
                nonce2,
            );

            let mut data = [0u8; 11];
            handle.read_exact(&mut data).await.unwrap();
            let _res = sender.send(BytesMut::from(&data[..]));
        });

        rt.spawn(async move {
            let listener_addr = addr_receiver.await.unwrap();
            let stream = TcpStream::connect(&listener_addr).await.unwrap();
            let (decode_hmac, encode_hmac) = match cipher {
                CipherType::ChaCha20Poly1305 | CipherType::Aes128Gcm | CipherType::Aes256Gcm => {
                    (None, None)
                }
                #[cfg(unix)]
                _ => (
                    Some(Hmac::from_key(Digest::Sha256, &_hmac_key_clone)),
                    Some(Hmac::from_key(Digest::Sha256, &_hmac_key_clone)),
                ),
            };
            let mut handle = SecureStream::new(
                Framed::new(stream, LengthDelimitedCodec::new()),
                new_stream(
                    cipher,
                    &cipher_key_clone[..key_size],
                    &iv,
                    CryptoMode::Decrypt,
                ),
                decode_hmac,
                new_stream(
                    cipher,
                    &cipher_key_clone[..key_size],
                    &iv,
                    CryptoMode::Encrypt,
                ),
                encode_hmac,
                Vec::new(),
            );

            let _res = handle.write_all(&data_clone[..]).await;
        });

        rt.block_on(async move {
            let received = receiver.await.unwrap();
            assert_eq!(received.to_vec(), data);
        });
    }

    #[cfg(unix)]
    #[test]
    fn test_encode_decode_aes128ctr() {
        test_decode_encode(CipherType::Aes128Ctr);
    }

    #[cfg(unix)]
    #[test]
    fn test_encode_decode_aes256ctr() {
        test_decode_encode(CipherType::Aes256Ctr);
    }

    #[test]
    fn test_encode_decode_aes128gcm() {
        test_decode_encode(CipherType::Aes128Gcm);
    }

    #[test]
    fn test_encode_decode_aes256gcm() {
        test_decode_encode(CipherType::Aes256Gcm);
    }

    #[test]
    fn test_encode_decode_chacha20poly1305() {
        test_decode_encode(CipherType::ChaCha20Poly1305);
    }

    #[cfg(unix)]
    #[test]
    fn secure_codec_encode_then_decode_aes128ctr() {
        secure_codec_encode_then_decode(CipherType::Aes128Ctr);
    }

    #[cfg(unix)]
    #[test]
    fn secure_codec_encode_then_decode_aes256ctr() {
        secure_codec_encode_then_decode(CipherType::Aes256Ctr);
    }

    #[test]
    fn secure_codec_encode_then_decode_aes128gcm() {
        secure_codec_encode_then_decode(CipherType::Aes128Gcm);
    }

    #[test]
    fn secure_codec_encode_then_decode_aes256gcm() {
        secure_codec_encode_then_decode(CipherType::Aes256Gcm);
    }

    #[test]
    fn secure_codec_encode_then_decode_chacha20poly1305() {
        secure_codec_encode_then_decode(CipherType::ChaCha20Poly1305);
    }
}
