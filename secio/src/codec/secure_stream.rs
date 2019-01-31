use bytes::{Bytes, BytesMut};
use futures::sync::mpsc::{self, Receiver, Sender};
use futures::{
    prelude::*,
    sink::Sink,
    task::{self, Task},
};
use log::{debug, error, trace, warn};
use tokio::codec::{length_delimited::LengthDelimitedCodec, Framed};
use tokio::prelude::{AsyncRead, AsyncWrite};

use std::cmp::min;
use std::collections::VecDeque;
use std::io;

use crate::{
    codec::{stream_handle::StreamEvent, stream_handle::StreamHandle, Hmac, StreamCipher},
    error::SecioError,
};

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

    notify: Option<Task>,
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
            pending: VecDeque::default(),
            frame_sender: None,
            event_sender,
            event_receiver,
            notify: None,
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

    #[inline]
    fn send_frame(&mut self) -> Result<(), io::Error> {
        while let Some(frame) = self.pending.pop_front() {
            if let AsyncSink::NotReady(data) = self.socket.start_send(frame)? {
                debug!("can't send");
                self.pending.push_front(data);
                self.notify();
                break;
            }
        }
        // TODO: not ready???
        self.socket.poll_complete()?;
        Ok(())
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
                self.send_frame()?;
                debug!("secure stream flushed");
            }
        }
        Ok(())
    }

    #[inline]
    fn recv_frame(&mut self) -> Poll<Option<()>, SecioError> {
        loop {
            match self.socket.poll() {
                Ok(Async::Ready(Some(t))) => {
                    trace!("receive raw data size: {:?}", t.len());
                    let data = self.decode(&t)?;
                    debug!("receive data size: {:?}", data.len());
                    self.read_buf
                        .push_back(StreamEvent::Frame(BytesMut::from(data)));
                    self.send_to_handle()?;
                }
                Ok(Async::Ready(None)) => {
                    debug!("shutdown");
                    self.dead = true;
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => {
                    debug!("receive not ready");
                    break;
                }
                Err(err) => {
                    self.dead = true;
                    return Err(err.into());
                }
            };
        }
        Ok(Async::NotReady)
    }

    #[inline]
    fn send_to_handle(&mut self) -> Result<(), io::Error> {
        let mut notify = false;
        if let Some(ref mut sender) = self.frame_sender {
            while let Some(event) = self.read_buf.pop_front() {
                if let Err(e) = sender.try_send(event) {
                    if e.is_full() {
                        self.read_buf.push_back(e.into_inner());
                        notify = true;
                        break;
                    } else {
                        error!("send error: {}", e);
                        return Err(io::ErrorKind::BrokenPipe.into());
                    }
                }
            }
        };

        if notify {
            self.notify();
        }
        Ok(())
    }

    #[inline]
    fn flush(&mut self) -> Result<(), io::Error> {
        self.send_frame()?;
        self.send_to_handle()?;
        Ok(())
    }

    #[inline]
    fn notify(&mut self) {
        if let Some(task) = self.notify.take() {
            task.notify();
        }
    }

    /// Decoding data
    #[inline]
    fn decode(&mut self, frame: &BytesMut) -> Result<Vec<u8>, SecioError> {
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

        let mut data_buf = frame.to_vec();
        data_buf.truncate(content_length);
        self.decode_cipher.decrypt(&mut data_buf);

        if !self.nonce.is_empty() {
            let n = min(data_buf.len(), self.nonce.len());
            if data_buf[..n] != self.nonce[..n] {
                return Err(SecioError::NonceVerificationFailed);
            }
            self.nonce.drain(..n);
            data_buf.drain(..n);
        }
        Ok(data_buf)
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

        match self.recv_frame() {
            Ok(Async::Ready(None)) => {
                if let Some(mut sender) = self.frame_sender.take() {
                    let _ = sender.try_send(StreamEvent::Close);
                }
                return Ok(Async::Ready(None));
            }
            Err(err) => {
                warn!("receive frame error: {:?}", err);
                if let Some(mut sender) = self.frame_sender.take() {
                    let _ = sender.try_send(StreamEvent::Close);
                }
                return Err(err.into());
            }
            _ => (),
        }

        loop {
            match self.event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => {
                    if let Err(err) = self.handle_event(event) {
                        warn!("send message error: {:?}", err);
                        break;
                    }
                }
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => {
                    debug!("event not ready");
                    break;
                }
                Err(err) => {
                    warn!("receive event error: {:?}", err);
                    break;
                }
            }
        }

        // Double check stream state
        if self.dead && self.nonce.is_empty() {
            return Ok(Async::Ready(None));
        }

        self.notify = Some(task::current());
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
