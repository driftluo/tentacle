use bytes::{Bytes, BytesMut};
use futures::sync::mpsc::{self, Receiver, Sender};
use futures::{prelude::*, sink::Sink, stream::iter_ok};
use log::{debug, trace};
use tokio::{
    codec::{length_delimited::LengthDelimitedCodec, Framed},
    prelude::{AsyncRead, AsyncWrite},
    timer::Delay,
};

use std::{
    cmp::min,
    collections::VecDeque,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::{
    codec::{stream_handle::StreamEvent, stream_handle::StreamHandle, Hmac},
    crypto::BoxStreamCipher,
    error::SecioError,
};

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
    T: AsyncRead + AsyncWrite,
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
    fn send_frame(&mut self) -> Result<(), io::Error> {
        while let Some(frame) = self.pending.pop_front() {
            if let AsyncSink::NotReady(data) = self.socket.start_send(frame)? {
                debug!("socket not ready, can't send");
                self.pending.push_front(data);
                if self.poll_complete()? {
                    break;
                }
            }
        }
        self.poll_complete()?;
        Ok(())
    }

    /// https://docs.rs/tokio/0.1.19/tokio/prelude/trait.Sink.html
    /// Must use poll complete to ensure data send to lower-level
    ///
    /// Sink `poll_complete` Ready -> no buffer remain, flush all
    /// Sink `poll_complete` NotReady -> there is more work left to do, may wake up next poll
    fn poll_complete(&mut self) -> Result<bool, io::Error> {
        if self.socket.poll_complete()?.is_not_ready() {
            self.set_delay();
            return Ok(true);
        }
        Ok(false)
    }

    #[inline]
    fn handle_event(&mut self, event: StreamEvent) -> Poll<(), io::Error> {
        match event {
            StreamEvent::Frame(frame) => {
                debug!("start send data: {:?}", frame);
                self.encode(frame);
                self.send_frame()?;
            }
            StreamEvent::Close => {
                self.dead = true;
                let _ = self.socket.close();
            }
            StreamEvent::Flush => {
                self.flush()?;
                debug!("secure stream flushed");
            }
        }
        Ok(Async::Ready(()))
    }

    #[inline]
    fn recv_frame(&mut self) -> Poll<Option<()>, SecioError> {
        let mut finished = false;
        for _ in 0..128 {
            match self.socket.poll() {
                Ok(Async::Ready(Some(t))) => {
                    trace!("receive raw data size: {:?}", t.len());
                    self.decode(t)?;
                    self.send_to_handle()?;
                }
                Ok(Async::Ready(None)) => {
                    debug!("shutdown");
                    self.dead = true;
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => {
                    finished = true;
                    debug!("receive not ready");
                    break;
                }
                Err(err) => {
                    self.dead = true;
                    return Err(err.into());
                }
            };
        }
        if !finished {
            self.set_delay();
        }
        Ok(Async::NotReady)
    }

    #[inline]
    fn recv_event(&mut self) {
        let mut finished = false;
        for _ in 0..128 {
            if self.dead {
                return;
            }
            match self.event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => match self.handle_event(event) {
                    Err(err) => {
                        debug!("send message error: {:?}", err);
                        break;
                    }
                    Ok(Async::NotReady) => break,
                    _ => (),
                },
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => {
                    finished = true;
                    debug!("event not ready");
                    break;
                }
                Err(err) => {
                    finished = true;
                    debug!("receive event error: {:?}", err);
                    break;
                }
            }
        }
        if !finished {
            self.set_delay();
        }
    }

    #[inline]
    fn send_to_handle(&mut self) -> Result<(), io::Error> {
        if let Some(ref mut sender) = self.frame_sender {
            while let Some(event) = self.read_buf.pop_front() {
                if let Err(e) = sender.try_send(event) {
                    if e.is_full() {
                        self.read_buf.push_front(e.into_inner());
                        self.set_delay();
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
    fn flush(&mut self) -> Result<(), io::Error> {
        self.send_frame()?;
        self.send_to_handle()?;
        Ok(())
    }

    #[inline]
    fn set_delay(&mut self) {
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
            let notify = futures::task::current();
            let delay = self.delay.clone();
            let delay_task = Delay::new(Instant::now() + DELAY_TIME).then(move |_| {
                notify.notify();
                delay.store(false, Ordering::Release);
                Ok(())
            });
            tokio::spawn(delay_task);
        }
    }

    fn close(&mut self) {
        self.read_buf.push_back(StreamEvent::Close);
        let events = self.read_buf.split_off(0);
        if let Some(sender) = self.frame_sender.take() {
            tokio::spawn(
                sender
                    .send_all(iter_ok(events))
                    .map(|_| ())
                    .map_err(|e| debug!("close event send to handle error: {:?}", e)),
            );
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

        let mut out = BytesMut::new();
        self.decode_cipher.decrypt(&frame, &mut out)?;

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
        let mut out = BytesMut::new();
        self.encode_cipher.encrypt(&data[..], &mut out).unwrap();
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
    T: AsyncRead + AsyncWrite,
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // Stream must ensure that the handshake is completed
        if self.dead && self.nonce.is_empty() {
            return Ok(Async::Ready(None));
        }

        if !self.pending.is_empty() || !self.read_buf.is_empty() {
            self.flush()?;
        }

        self.poll_complete()?;

        match self.recv_frame() {
            Ok(Async::Ready(None)) => {
                self.close();
                return Ok(Async::Ready(None));
            }
            Err(err) => {
                debug!("receive frame error: {:?}", err);
                self.close();
                return Err(err.into());
            }
            _ => (),
        }

        self.recv_event();

        // Double check stream state
        if self.dead && self.nonce.is_empty() {
            return Ok(Async::Ready(None));
        }

        Ok(Async::NotReady)
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
    use crate::Digest;
    use bytes::BytesMut;
    use futures::{sync, Future, Stream};
    use rand;
    use std::io::Write;
    use std::{thread, time};
    use tokio::codec::{length_delimited::LengthDelimitedCodec, Framed};
    use tokio::net::{TcpListener, TcpStream};

    fn test_decode_encode(cipher: CipherType) {
        let cipher_key = (0..cipher.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();
        let hmac_key: [u8; 32] = rand::random();
        let iv = (0..cipher.iv_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let data = b"hello world";

        let mut encode_cipher = new_stream(cipher, &cipher_key, &iv, CryptoMode::Encrypt);
        let mut decode_cipher = new_stream(cipher, &cipher_key, &iv, CryptoMode::Decrypt);

        let (mut decode_hmac, mut encode_hmac) = match cipher {
            CipherType::ChaCha20Poly1305 | CipherType::Aes128Gcm | CipherType::Aes256Gcm => {
                (None, None)
            }
            _ => {
                let encode_hmac = Hmac::from_key(Digest::Sha256, &hmac_key);
                let decode_hmac = encode_hmac.clone();
                (Some(decode_hmac), Some(encode_hmac))
            }
        };

        let mut encode_data = BytesMut::new();
        encode_cipher.encrypt(&data[..], &mut encode_data).unwrap();
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

        let mut decode_data = BytesMut::new();
        decode_cipher
            .decrypt(&encode_data, &mut decode_data)
            .unwrap();

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
        let hmac_key_clone = hmac_key;
        let data = b"hello world";
        let data_clone = &*data;
        let nonce = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let (sender, receiver) = sync::oneshot::channel::<bytes::BytesMut>();

        let nonce2 = nonce.clone();
        let server = listener
            .incoming()
            .into_future()
            .map_err(|_| ())
            .map(move |(socket, _)| {
                let nonce2 = nonce2.clone();
                let (decode_hmac, encode_hmac) = match cipher {
                    CipherType::ChaCha20Poly1305
                    | CipherType::Aes128Gcm
                    | CipherType::Aes256Gcm => (None, None),
                    _ => (
                        Some(Hmac::from_key(Digest::Sha256, &hmac_key_clone)),
                        Some(Hmac::from_key(Digest::Sha256, &hmac_key_clone)),
                    ),
                };
                let mut secure = SecureStream::new(
                    Framed::new(socket.unwrap(), LengthDelimitedCodec::new()),
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
                let handle = secure.create_handle().unwrap();

                let task = tokio::io::read_exact(handle, [0u8; 11])
                    .and_then(move |(_, data)| {
                        let _ = sender.send(BytesMut::from(data.to_vec()));
                        Ok(())
                    })
                    .map_err(|_| ());

                tokio::spawn(secure.for_each(|_| Ok(())).map_err(|_| ()));
                tokio::spawn(task);
            });

        let client = TcpStream::connect(&listener_addr)
            .map(move |stream| {
                let (decode_hmac, encode_hmac) = match cipher {
                    CipherType::ChaCha20Poly1305
                    | CipherType::Aes128Gcm
                    | CipherType::Aes256Gcm => (None, None),
                    _ => (
                        Some(Hmac::from_key(Digest::Sha256, &hmac_key_clone)),
                        Some(Hmac::from_key(Digest::Sha256, &hmac_key_clone)),
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
                tokio::spawn(secure.for_each(|_| Ok(())).map_err(|_| ()));

                let _ = handle.write_all(&nonce);
                let _ = handle.write_all(&data_clone[..]);
                // wait test finish, don't drop handle
                thread::sleep(time::Duration::from_secs(10));
            })
            .map_err(|_| ());

        thread::spawn(|| {
            tokio::run(server);
        });

        thread::spawn(|| {
            tokio::run(client);
        });

        let received = receiver.wait().unwrap();
        assert_eq!(received.to_vec(), data);
    }

    #[test]
    fn test_encode_decode_aes128ctr() {
        test_decode_encode(CipherType::Aes128Ctr);
    }

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

    #[test]
    fn secure_codec_encode_then_decode_aes128ctr() {
        secure_codec_encode_then_decode(CipherType::Aes128Ctr);
    }

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
