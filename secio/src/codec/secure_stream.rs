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
/// Default max buffer size
const MAX_BUF_SIZE: usize = 24 * 1024 * 1024;
/// Default max frame size
const MAX_FRAME_SIZE: usize = 256 * 1024;

/// Stream config
#[derive(Debug, Clone, Copy)]
pub struct StreamConfig {
    /// default is 1Mb
    pub recv_buffer_size: usize,
    /// default is 1Mb
    pub send_buffer_size: usize,
    /// default is 256kb
    pub frame_size: usize,
}

impl StreamConfig {
    /// new a default config
    pub const fn new() -> Self {
        StreamConfig {
            recv_buffer_size: MAX_BUF_SIZE,
            send_buffer_size: MAX_BUF_SIZE,
            frame_size: MAX_FRAME_SIZE,
        }
    }

    /// see https://github.com/rust-lang/rust/issues/57563
    /// can't use `if` to filter out 0, so add one to avoid this case
    const fn recv_event_size(&self) -> usize {
        (self.recv_buffer_size / self.frame_size) + 1
    }

    /// see https://github.com/rust-lang/rust/issues/57563
    /// can't use `if` to filter out 0, so add one to avoid this case
    const fn send_event_size(&self) -> usize {
        (self.send_buffer_size / self.frame_size) + 1
    }
}

/// Encrypted stream
pub struct SecureStream<T> {
    socket: Framed<T, LengthDelimitedCodec>,
    dead: bool,

    config: StreamConfig,

    decode_cipher: StreamCipher,
    decode_hmac: Hmac,

    encode_cipher: StreamCipher,
    encode_hmac: Hmac,
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
            config: StreamConfig::new(),
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

    /// Set the config of this stream
    pub fn set_config(mut self, config: StreamConfig) -> Self {
        self.config = config;
        self
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
    fn handle_event(&mut self, event: StreamEvent) -> Result<(), io::Error> {
        match event {
            StreamEvent::Frame(mut frame) => {
                debug!("start send data: {:?}", frame);
                self.encode(&mut frame);
                self.pending.push_back(frame.freeze());
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
        Ok(())
    }

    #[inline]
    fn recv_frame(&mut self) -> Poll<Option<()>, SecioError> {
        let mut finished = false;
        for _ in 0..128 {
            if self.read_buf.len() > self.config.recv_event_size() {
                self.set_delay();
                break;
            }

            match self.socket.poll() {
                Ok(Async::Ready(Some(mut t))) => {
                    trace!("receive raw data size: {:?}", t.len());
                    self.decode(&mut t)?;
                    debug!("receive data size: {:?}", t.len());
                    self.read_buf.push_back(StreamEvent::Frame(t));
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
            if self.pending.len() > self.config.send_event_size() {
                self.set_delay();
                break;
            }
            match self.event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => {
                    if let Err(err) = self.handle_event(event) {
                        debug!("send message error: {:?}", err);
                        break;
                    }
                }
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
    fn decode(&mut self, frame: &mut BytesMut) -> Result<(), SecioError> {
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
        self.decode_cipher.decrypt(frame);

        if !self.nonce.is_empty() {
            let n = min(frame.len(), self.nonce.len());
            if frame[..n] != self.nonce[..n] {
                return Err(SecioError::NonceVerificationFailed);
            }
            self.nonce.drain(..n);
            frame.split_to(n);
        }
        Ok(())
    }

    /// Encoding data
    #[inline]
    fn encode(&mut self, data: &mut BytesMut) {
        self.encode_cipher.encrypt(&mut data[..]);
        let signature = self.encode_hmac.sign(&data[..]);
        data.extend_from_slice(signature.as_ref());
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
