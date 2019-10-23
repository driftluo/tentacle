use bytes::{Bytes, BytesMut};
use futures::{
    channel::mpsc::{self, Receiver, Sender},
    stream::iter,
    SinkExt, Stream,
};
use log::{debug, trace};
use tokio::{
    codec::{length_delimited::LengthDelimitedCodec, Framed},
    prelude::Sink,
    prelude::{AsyncRead, AsyncWrite},
};

use std::{
    cmp::min,
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use crate::{
    codec::{stream_handle::StreamEvent, stream_handle::StreamHandle, Hmac},
    crypto::BoxStreamCipher,
    error::SecioError,
};

type PollResult<T, E> = Poll<Result<T, E>>;

const DELAY_TIME: Duration = Duration::from_millis(300);

/// Encrypted stream
pub struct SecureStream<T> {
    socket: Framed<T, LengthDelimitedCodec>,
    dead: bool,

    decode_cipher: BoxStreamCipher,
    decode_hmac: Option<Hmac>,

    encode_cipher: BoxStreamCipher,
    encode_hmac: Option<Hmac>,
    /// denotes a sequence of bytes which are expected to be
    /// found at the beginning of the stream and are checked for equality
    nonce: Vec<u8>,
    /// Send buffer
    pending: VecDeque<Bytes>,
    /// Read buffer
    read_buf: VecDeque<StreamEvent>,
    /// Frame sender, init on call `create_handle`
    frame_sender: Option<Sender<StreamEvent>>,
    // For receive events from sub streams (for clone to stream handle)
    event_sender: Sender<StreamEvent>,
    // For receive events from sub streams
    event_receiver: Receiver<StreamEvent>,
    /// Delay notify with abnormally poor network status
    delay: Arc<AtomicBool>,
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
        let (event_sender, event_receiver) = mpsc::channel(128);
        SecureStream {
            socket,
            dead: false,
            decode_cipher,
            decode_hmac,
            encode_cipher,
            encode_hmac,
            read_buf: VecDeque::default(),
            nonce,
            pending: VecDeque::default(),
            frame_sender: None,
            event_sender,
            event_receiver,
            delay: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a unique handle to this stream.
    /// Repeated calls will return Error.
    #[inline]
    pub fn create_handle(&mut self) -> Result<StreamHandle, ()> {
        if self.frame_sender.is_some() {
            return Err(());
        }
        let (frame_sender, frame_receiver) = mpsc::channel(128);
        self.frame_sender = Some(frame_sender);
        Ok(StreamHandle::new(frame_receiver, self.event_sender.clone()))
    }

    /// Sink `start_send` Ready -> data in buffer or send
    /// Sink `start_send` NotReady -> buffer full need poll complete
    #[inline]
    fn send_frame(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        while let Some(frame) = self.pending.pop_front() {
            let mut sink = Pin::new(&mut self.socket);

            match sink.as_mut().poll_ready(cx)? {
                Poll::Ready(()) => sink.as_mut().start_send(frame)?,
                Poll::Pending => {
                    debug!("socket not ready, can't send");
                    self.pending.push_front(frame);
                    if self.poll_complete(cx)? {
                        break;
                    }
                }
            }
        }

        self.poll_complete(cx)?;
        Ok(())
    }

    /// https://docs.rs/tokio/0.1.19/tokio/prelude/trait.Sink.html
    /// Must use poll complete to ensure data send to lower-level
    ///
    /// Sink `poll_complete` Ready -> no buffer remain, flush all
    /// Sink `poll_complete` NotReady -> there is more work left to do, may wake up next poll
    fn poll_complete(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        match Pin::new(&mut self.socket).poll_flush(cx) {
            Poll::Pending => {
                self.set_delay(cx);
                Ok(true)
            }
            Poll::Ready(res) => {
                res?;
                Ok(false)
            }
        }
    }

    #[inline]
    fn handle_event(&mut self, event: StreamEvent, cx: &mut Context) -> PollResult<(), io::Error> {
        match event {
            StreamEvent::Frame(frame) => {
                debug!("start send data: {:?}", frame);
                self.encode(frame);
                self.send_frame(cx)?;
            }
            StreamEvent::Close => {
                self.dead = true;
                let _ = self.socket.close();
            }
            StreamEvent::Flush => {
                self.flush(cx)?;
                debug!("secure stream flushed");
            }
        }
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn recv_frame(&mut self, cx: &mut Context) -> PollResult<Option<()>, SecioError> {
        let mut finished = false;
        for _ in 0..128 {
            match Pin::new(&mut self.socket).as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(t))) => {
                    trace!("receive raw data size: {:?}", t.len());
                    self.decode(t)?;
                    self.send_to_handle(cx)?;
                }
                Poll::Ready(None) => {
                    debug!("shutdown");
                    self.dead = true;
                    return Poll::Ready(Ok(None));
                }
                Poll::Pending => {
                    finished = true;
                    debug!("receive not ready");
                    break;
                }
                Poll::Ready(Some(Err(err))) => {
                    self.dead = true;
                    return Poll::Ready(Err(err.into()));
                }
            };
        }
        if !finished {
            self.set_delay(cx);
        }
        Poll::Pending
    }

    #[inline]
    fn recv_event(&mut self, cx: &mut Context) {
        let mut finished = false;
        for _ in 0..128 {
            if self.dead {
                return;
            }
            match Pin::new(&mut self.event_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(event)) => match self.handle_event(event, cx) {
                    Poll::Ready(Err(err)) => {
                        debug!("send message error: {:?}", err);
                        break;
                    }
                    Poll::Pending => break,
                    _ => (),
                },
                Poll::Ready(None) => unreachable!(),
                Poll::Pending => {
                    finished = true;
                    debug!("event not ready");
                    break;
                }
            }
        }
        if !finished {
            self.set_delay(cx);
        }
    }

    #[inline]
    fn send_to_handle(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        if let Some(ref mut sender) = self.frame_sender {
            while let Some(event) = self.read_buf.pop_front() {
                if let Err(e) = sender.try_send(event) {
                    if e.is_full() {
                        self.read_buf.push_front(e.into_inner());
                        self.set_delay(cx);
                        break;
                    } else {
                        debug!("send error: {}", e);
                        return Err(io::ErrorKind::BrokenPipe.into());
                    }
                }
            }
        };

        Ok(())
    }

    #[inline]
    fn flush(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        self.send_frame(cx)?;
        self.send_to_handle(cx)?;
        Ok(())
    }

    #[inline]
    fn set_delay(&mut self, cx: &mut Context) {
        // Why use `delay` instead of `notify`?
        //
        // In fact, on machines that can use multi-core normally, there is almost no problem with the `notify` behavior,
        // and even the efficiency will be higher.
        //
        // However, if you are on a single-core bully machine, `notify` may have a very amazing starvation behavior.
        //
        // Under a single-core machine, `notify` may fall into the loop of infinitely preemptive CPU, causing starvation.
        if !self.delay.load(Ordering::Acquire) {
            self.delay.store(true, Ordering::Release);
            let waker = cx.waker().clone();
            let delay = self.delay.clone();
            tokio::spawn(async move {
                tokio::timer::delay(Instant::now() + DELAY_TIME).await;
                waker.wake();
                delay.store(false, Ordering::Release);
            });
        }
    }

    fn close(&mut self) {
        self.read_buf.push_back(StreamEvent::Close);
        let events = self.read_buf.split_off(0);
        if let Some(mut sender) = self.frame_sender.take() {
            tokio::spawn(async move {
                let mut iter = iter(events);
                if let Err(e) = sender.send_all(&mut iter).await {
                    debug!("close event send to handle error: {:?}", e)
                }
            });
        }
    }

    /// Decoding data
    #[inline]
    fn decode_inner(&mut self, mut frame: BytesMut) -> Result<BytesMut, SecioError> {
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

        let mut out = self.decode_cipher.decrypt(&frame).map(BytesMut::from)?;

        if !self.nonce.is_empty() {
            let n = min(out.len(), self.nonce.len());
            if out[..n] != self.nonce[..n] {
                return Err(SecioError::NonceVerificationFailed);
            }
            self.nonce.drain(..n);
            out.split_to(n);
        }
        Ok(out)
    }

    fn decode(&mut self, frame: BytesMut) -> Result<(), SecioError> {
        let t = self.decode_inner(frame)?;
        debug!("receive data size: {:?}", t.len());
        self.read_buf.push_back(StreamEvent::Frame(t));
        Ok(())
    }

    /// Encoding data
    #[inline]
    fn encode_inner(&mut self, data: BytesMut) -> BytesMut {
        let mut out = self
            .encode_cipher
            .encrypt(&data[..])
            .map(BytesMut::from)
            .unwrap();
        if let Some(ref mut hmac) = self.encode_hmac {
            let signature = hmac.sign(&out[..]);
            out.extend_from_slice(signature.as_ref());
        }
        out
    }

    fn encode(&mut self, data: BytesMut) {
        let frame = self.encode_inner(data);
        self.pending.push_back(frame.freeze());
    }
}

impl<T> Stream for SecureStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Item = Result<(), io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        // Stream must ensure that the handshake is completed
        if self.dead && self.nonce.is_empty() {
            return Poll::Ready(None);
        }

        if !self.pending.is_empty() || !self.read_buf.is_empty() {
            self.flush(cx)?;
        }

        self.poll_complete(cx)?;

        match self.recv_frame(cx) {
            Poll::Ready(Ok(None)) => {
                self.close();
                return Poll::Ready(None);
            }
            Poll::Ready(Err(err)) => {
                debug!("receive frame error: {:?}", err);
                self.close();
                return Poll::Ready(Some(Err(err.into())));
            }
            _ => (),
        }

        self.recv_event(cx);

        // Double check stream state
        if self.dead && self.nonce.is_empty() {
            return Poll::Ready(None);
        }

        Poll::Pending
    }
}

impl<T> Drop for SecureStream<T> {
    fn drop(&mut self) {
        self.event_receiver.close();
    }
}

#[cfg(test)]
mod tests {
    use super::{Hmac, SecureStream};
    use crate::crypto::{cipher::CipherType, new_stream, CryptoMode};
    #[cfg(unix)]
    use crate::Digest;
    use bytes::BytesMut;
    use futures::{channel, StreamExt};
    use rand;
    use tokio::codec::{length_delimited::LengthDelimitedCodec, Framed};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

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
        let rt = tokio::runtime::Runtime::new().unwrap();

        let nonce2 = nonce.clone();
        rt.spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listener_addr = listener.local_addr().unwrap();
            let _ = addr_sender.send(listener_addr);
            let (socket, _stream) = listener.incoming().into_future().await;
            let nonce2 = nonce2.clone();
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
            let mut secure = SecureStream::new(
                Framed::new(socket.unwrap().unwrap(), LengthDelimitedCodec::new()),
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
            let mut handle = secure.create_handle().unwrap();

            tokio::spawn(async move {
                loop {
                    match secure.next().await {
                        Some(Err(_)) => {
                            break;
                        }
                        None => break,
                        _ => (),
                    }
                }
            });

            let mut data = [0u8; 11];
            handle.read_exact(&mut data).await.unwrap();
            let _ = sender.send(BytesMut::from(data.to_vec()));
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
            let mut secure = SecureStream::new(
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
            let mut handle = secure.create_handle().unwrap();

            tokio::spawn(async move {
                loop {
                    match secure.next().await {
                        Some(Err(_)) => {
                            break;
                        }
                        None => break,
                        _ => (),
                    }
                }
            });

            let _ = handle.write_all(&nonce).await;
            let _ = handle.write_all(&data_clone[..]).await;
        });

        rt.spawn(async move {
            let received = receiver.await.unwrap();
            assert_eq!(received.to_vec(), data);
        });

        rt.shutdown_on_idle()
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
