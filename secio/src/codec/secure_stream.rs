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
    codec::{stream_handle::StreamEvent, stream_handle::StreamHandle, Hmac, StreamCipher},
    error::SecioError,
};

const DELAY_TIME: Duration = Duration::from_millis(300);
const BLOCK_BOUNDARY: usize = 1024 * 256;

/// Encrypted stream
pub struct SecureStream<T> {
    socket: Framed<T, LengthDelimitedCodec>,
    dead: bool,

    decode_cipher: StreamCipher,
    decode_hmac: Hmac,

    encode_cipher: StreamCipher,
    encode_hmac: Hmac,
    /// denotes a sequence of bytes which are expected to be
    /// found at the beginning of the stream and are checked for equality
    nonce: Vec<u8>,

    current_decode: Option<BytesMut>,
    current_encode: Option<BytesMut>,
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
    pub fn new(
        socket: Framed<T, LengthDelimitedCodec>,
        decode_cipher: StreamCipher,
        decode_hmac: Hmac,
        encode_cipher: StreamCipher,
        encode_hmac: Hmac,
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
            current_decode: None,
            current_encode: None,
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
                self.current_encode = Some(frame);
                if let Async::NotReady = self.encode() {
                    return Ok(Async::NotReady);
                }
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
                    self.current_decode = Some(t.clone());
                    if let Async::NotReady = self.decode()? {
                        break;
                    }
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
        if frame.len() < self.decode_hmac.num_bytes() {
            debug!("frame too short when decoding secio frame");
            return Err(SecioError::FrameTooShort);
        }

        let content_length = frame.len() - self.decode_hmac.num_bytes();
        {
            let (crypted_data, expected_hash) = frame.split_at(content_length);
            debug_assert_eq!(expected_hash.len(), self.decode_hmac.num_bytes());

            if !self.decode_hmac.verify(crypted_data, expected_hash) {
                debug!("hmac mismatch when decoding secio frame");
                return Err(SecioError::HmacNotMatching);
            }
        }

        frame.truncate(content_length);
        self.decode_cipher.decrypt(&mut frame);

        if !self.nonce.is_empty() {
            let n = min(frame.len(), self.nonce.len());
            if frame[..n] != self.nonce[..n] {
                return Err(SecioError::NonceVerificationFailed);
            }
            self.nonce.drain(..n);
            frame.split_to(n);
        }
        Ok(frame)
    }

    fn decode(&mut self) -> Poll<(), SecioError> {
        if self.current_decode.is_none() {
            return Ok(Async::Ready(()));
        }
        let data = self.current_decode.clone().unwrap();
        let t = if data.len() > BLOCK_BOUNDARY {
            match tokio_threadpool::blocking(|| self.decode_inner(data.clone())) {
                Ok(Async::Ready(res)) => res?,
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(_) => self.decode_inner(data)?,
            }
        } else {
            self.decode_inner(data)?
        };

        self.current_decode.take();
        debug!("receive data size: {:?}", t.len());
        self.read_buf.push_back(StreamEvent::Frame(t));
        Ok(Async::Ready(()))
    }

    /// Encoding data
    #[inline]
    fn encode_inner(&mut self, mut data: BytesMut) -> BytesMut {
        self.encode_cipher.encrypt(&mut data[..]);
        let signature = self.encode_hmac.sign(&data[..]);
        data.extend_from_slice(signature.as_ref());
        data
    }

    fn encode(&mut self) -> Async<()> {
        if self.current_encode.is_none() {
            return Async::Ready(());
        }

        let data = self.current_encode.clone().unwrap();

        let frame = if data.len() > BLOCK_BOUNDARY {
            match tokio_threadpool::blocking(|| self.encode_inner(data.clone())) {
                Ok(Async::Ready(res)) => res,
                Ok(Async::NotReady) => return Async::NotReady,
                Err(_) => self.encode_inner(data),
            }
        } else {
            self.encode_inner(data)
        };

        self.pending.push_back(frame.freeze());
        self.current_encode.take();

        Async::Ready(())
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

        if let Async::NotReady = self.decode().map_err::<io::Error, _>(Into::into)? {
            self.set_delay();
            return Ok(Async::NotReady);
        }

        if let Async::NotReady = self.encode() {
            self.set_delay();
            return Ok(Async::NotReady);
        }

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
    use crate::stream_cipher::{ctr_init, Cipher};
    use crate::Digest;
    use bytes::BytesMut;
    use futures::{sync, Future, Stream};
    use rand;
    use std::io::Write;
    use std::{thread, time};
    use tokio::codec::{length_delimited::LengthDelimitedCodec, Framed};
    use tokio::net::{TcpListener, TcpStream};

    const NULL_IV: [u8; 16] = [0; 16];

    fn test_decode_encode(cipher: Cipher) {
        let cipher_key = (0..cipher.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();
        let hmac_key: [u8; 32] = rand::random();

        let data = b"hello world";

        let mut encode_data = BytesMut::from(data.to_vec());

        let mut encode_cipher = ctr_init(cipher, &cipher_key, &NULL_IV);
        let mut encode_hmac = Hmac::from_key(Digest::Sha256, &hmac_key);
        let mut decode_cipher = ctr_init(cipher, &cipher_key, &NULL_IV);
        let mut decode_hmac = encode_hmac.clone();

        encode_cipher.encrypt(&mut encode_data[..]);
        let signature = encode_hmac.sign(&encode_data[..]);
        encode_data.extend_from_slice(signature.as_ref());

        let content_length = encode_data.len() - decode_hmac.num_bytes();

        let (crypted_data, expected_hash) = encode_data.split_at(content_length);

        assert!(decode_hmac.verify(crypted_data, expected_hash));

        let mut decode_data = encode_data.to_vec();
        decode_data.truncate(content_length);
        decode_cipher.decrypt(&mut decode_data);

        assert_eq!(&decode_data[..], &data[..]);
    }

    fn secure_codec_encode_then_decode(cipher: Cipher) {
        let cipher_key: [u8; 32] = rand::random();
        let cipher_key_clone = cipher_key;
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
                let mut secure = SecureStream::new(
                    Framed::new(socket.unwrap(), LengthDelimitedCodec::new()),
                    ctr_init(cipher, &cipher_key_clone[..key_size], &NULL_IV[..]),
                    Hmac::from_key(Digest::Sha256, &hmac_key_clone),
                    ctr_init(cipher, &cipher_key_clone[..key_size], &NULL_IV[..]),
                    Hmac::from_key(Digest::Sha256, &hmac_key_clone),
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
                let mut secure = SecureStream::new(
                    Framed::new(stream, LengthDelimitedCodec::new()),
                    ctr_init(cipher, &cipher_key_clone[..key_size], &NULL_IV[..]),
                    Hmac::from_key(Digest::Sha256, &hmac_key_clone),
                    ctr_init(cipher, &cipher_key_clone[..key_size], &NULL_IV[..]),
                    Hmac::from_key(Digest::Sha256, &hmac_key_clone),
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
    fn test_encode_decode_aes128() {
        test_decode_encode(Cipher::Aes128);
    }

    #[test]
    fn test_encode_decode_aes256() {
        test_decode_encode(Cipher::Aes256);
    }

    #[test]
    fn test_encode_decode_twofish() {
        test_decode_encode(Cipher::TwofishCtr);
    }

    #[test]
    fn secure_codec_encode_then_decode_aes128() {
        secure_codec_encode_then_decode(Cipher::Aes128);
    }

    #[test]
    fn secure_codec_encode_then_decode_aes256() {
        secure_codec_encode_then_decode(Cipher::Aes256);
    }

    #[test]
    fn secure_codec_encode_then_decode_twofish() {
        secure_codec_encode_then_decode(Cipher::TwofishCtr);
    }
}
