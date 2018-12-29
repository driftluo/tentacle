use bytes::BytesMut;
use futures::prelude::*;
use futures::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};
use tokio::prelude::{AsyncRead, AsyncWrite};

use std::io;

/// Stream handle
pub struct StreamHandle {
    read_buf: BytesMut,

    frame_receiver: Receiver<StreamEvent>,

    event_sender: Sender<StreamEvent>,
}

impl StreamHandle {
    pub(crate) fn new(
        frame_receiver: Receiver<StreamEvent>,
        event_sender: Sender<StreamEvent>,
    ) -> Self {
        StreamHandle {
            frame_receiver,
            event_sender,
            read_buf: BytesMut::default(),
        }
    }

    fn handle_event(&mut self, event: StreamEvent) -> Result<(), io::Error> {
        match event {
            StreamEvent::Frame(frame) => self.read_buf.extend_from_slice(&frame),
            StreamEvent::Close => {
                let _ = self.shutdown()?;
            }
            _ => (),
        }
        Ok(())
    }

    /// Receive frames from secure stream
    fn recv_frames(&mut self) -> Poll<(), io::Error> {
        loop {
            match self.frame_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_event(event)?,
                Ok(Async::Ready(None)) => {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                Ok(Async::NotReady) => {
                    return Ok(Async::NotReady);
                }
                Err(_) => return Err(io::ErrorKind::BrokenPipe.into()),
            }
        }
    }
}

impl io::Read for StreamHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_frames()?;

        let n = ::std::cmp::min(buf.len(), self.read_buf.len());

        if n == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        let b = self.read_buf.split_to(n);

        buf[..n].copy_from_slice(&b);
        Ok(n)
    }
}

impl io::Write for StreamHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.recv_frames()?;

        let byte = BytesMut::from(buf);
        match self.event_sender.try_send(StreamEvent::Frame(byte)) {
            Ok(_) => Ok(buf.len()),
            Err(e) => {
                if e.is_full() {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Err(io::ErrorKind::BrokenPipe.into())
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.recv_frames()?;

        let (sender, receiver) = oneshot::channel();
        match self.event_sender.try_send(StreamEvent::Flush(sender)) {
            Ok(_) => {
                let _ = receiver.wait();
                Ok(())
            }
            Err(e) => {
                if e.is_full() {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Err(io::ErrorKind::BrokenPipe.into())
                }
            }
        }
    }
}

impl AsyncRead for StreamHandle {}

impl AsyncWrite for StreamHandle {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        if let Err(e) = self.event_sender.try_send(StreamEvent::Close) {
            if e.is_full() {
                return Err(io::ErrorKind::WouldBlock.into());
            } else {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
        }
        Ok(Async::Ready(()))
    }
}

pub(crate) enum StreamEvent {
    Frame(BytesMut),
    Close,
    Flush(oneshot::Sender<()>),
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        self.frame_receiver.close();
    }
}
