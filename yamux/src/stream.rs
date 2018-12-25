//! The substream, the main interface is AsyncRead/AsyncWrite

use std::io;

use bytes::{Bytes, BytesMut};
use futures::{
    sync::mpsc::{Receiver, Sender},
    sync::oneshot,
    Async, Future, Poll, Stream,
};
use log::debug;
use tokio::prelude::{AsyncRead, AsyncWrite};

use crate::{
    error::Error,
    frame::{Flag, Flags, Frame, Type},
    StreamId,
};

/// The substream
pub struct StreamHandle {
    id: StreamId,
    state: StreamState,

    max_recv_window: u32,
    recv_window: u32,
    send_window: u32,
    data_buf: BytesMut,

    // Send stream event to parent session
    event_sender: Sender<StreamEvent>,

    // Receive frame of current stream from parent session
    // (if the sender closed means session closed the stream should close too)
    frame_receiver: Receiver<Frame>,
}

impl StreamHandle {
    // Create a StreamHandle from session
    pub(crate) fn new(
        id: StreamId,
        event_sender: Sender<StreamEvent>,
        frame_receiver: Receiver<Frame>,
        state: StreamState,
        recv_window_size: u32,
        send_window_size: u32,
    ) -> StreamHandle {
        assert!(state == StreamState::Init || state == StreamState::SynReceived);
        StreamHandle {
            id,
            state,
            max_recv_window: recv_window_size,
            recv_window: recv_window_size,
            send_window: send_window_size,
            data_buf: BytesMut::default(),
            event_sender,
            frame_receiver,
        }
    }

    /// Get the stream id
    pub fn id(&self) -> StreamId {
        self.id
    }
    /// Get the stream state
    pub fn state(&self) -> StreamState {
        self.state
    }
    /// Get the receive window size
    pub fn recv_window(&self) -> u32 {
        self.recv_window
    }
    /// Get the send window size
    pub fn send_window(&self) -> u32 {
        self.send_window
    }

    fn close(&mut self) -> Result<(), Error> {
        match self.state {
            StreamState::SynSent | StreamState::SynReceived | StreamState::Established => {
                self.state = StreamState::LocalClosing;
                self.send_close()?;
            }
            StreamState::RemoteClosing => {
                self.state = StreamState::Closed;
                self.send_close()?;
                let event = StreamEvent::StateChanged((self.id, self.state));
                self.send_event(event)?;
            }
            StreamState::Reset | StreamState::Closed => {
                self.state = StreamState::Closed;
                let event = StreamEvent::StateChanged((self.id, self.state));
                self.send_event(event)?;
            }
            _ => {}
        }
        Ok(())
    }

    #[inline]
    fn send_event(&mut self, event: StreamEvent) -> Result<(), Error> {
        debug!("[{}] StreamHandle.send_event({:?})", self.id, event);
        // TODO: should handle send error
        self.event_sender
            .try_send(event)
            .map_err(|_| Error::SessionShutdown)
    }

    #[inline]
    fn send_frame(&mut self, frame: Frame) -> Result<(), Error> {
        let event = StreamEvent::Frame(frame);
        self.send_event(event)
    }

    // Send a window update
    pub(crate) fn send_window_update(&mut self) -> Result<(), Error> {
        let buf_len = self.data_buf.len() as u32;
        let delta = self.max_recv_window - buf_len - self.recv_window;

        // Check if we can omit the update
        let flags = self.get_flags();
        if delta < (self.max_recv_window / 2) && flags.value() == 0 {
            return Ok(());
        }
        // Update our window
        self.recv_window += delta;
        let frame = Frame::new_window_update(flags, self.id, delta);
        self.send_frame(frame)
    }

    fn send_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let flags = self.get_flags();
        let frame = Frame::new_data(flags, self.id, Bytes::from(data));
        self.send_frame(frame)
    }

    fn send_close(&mut self) -> Result<(), Error> {
        let mut flags = self.get_flags();
        flags.add(Flag::Fin);
        let frame = Frame::new_window_update(flags, self.id, 0);
        self.send_frame(frame)
    }

    fn process_flags(&mut self, flags: Flags) -> Result<(), Error> {
        if flags.contains(Flag::Ack) && self.state == StreamState::SynSent {
            self.state = StreamState::SynReceived;
        }
        let mut close_stream = false;
        if flags.contains(Flag::Fin) {
            match self.state {
                StreamState::Init
                | StreamState::SynSent
                | StreamState::SynReceived
                | StreamState::Established => {
                    self.state = StreamState::RemoteClosing;
                }
                StreamState::LocalClosing => {
                    self.state = StreamState::Closed;
                    close_stream = true;
                }
                _ => return Err(Error::UnexpectedFlag),
            }
        }
        if flags.contains(Flag::Rst) {
            self.state = StreamState::Reset;
            close_stream = true;
        }

        if close_stream {
            self.close()?;
        }
        Ok(())
    }

    fn get_flags(&mut self) -> Flags {
        match self.state {
            StreamState::Init => {
                self.state = StreamState::SynSent;
                Flags::from(Flag::Syn)
            }
            StreamState::SynReceived => {
                self.state = StreamState::Established;
                Flags::from(Flag::Ack)
            }
            _ => Flags::default(),
        }
    }

    fn handle_frame(&mut self, frame: Frame) -> Result<(), Error> {
        debug!("[{}] StreamHandle.handle_frame({:?})", self.id, frame);
        match frame.ty() {
            Type::WindowUpdate => {
                self.handle_window_update(&frame)?;
            }
            Type::Data => {
                self.handle_data(frame)?;
            }
            _ => {
                return Err(Error::InvalidMsgType);
            }
        }
        Ok(())
    }

    fn handle_window_update(&mut self, frame: &Frame) -> Result<(), Error> {
        self.process_flags(frame.flags())?;
        self.send_window += frame.length();
        Ok(())
    }

    fn handle_data(&mut self, frame: Frame) -> Result<(), Error> {
        self.process_flags(frame.flags())?;
        let length = frame.length();
        if length > self.recv_window {
            return Err(Error::RecvWindowExceeded);
        }

        let (_, body) = frame.into_parts();
        if let Some(data) = body {
            self.data_buf.extend_from_slice(&data);
        }
        self.recv_window -= length;
        Ok(())
    }

    fn recv_frames(&mut self) -> Poll<(), Error> {
        loop {
            match self.state {
                StreamState::RemoteClosing => {
                    return Err(Error::SubStreamRemoteClosing);
                }
                StreamState::Reset | StreamState::Closed => {
                    return Err(Error::SessionShutdown);
                }
                _ => {}
            }

            match self
                .frame_receiver
                .poll()
                .map_err(|()| Error::SessionShutdown)?
            {
                Async::Ready(Some(frame)) => self.handle_frame(frame)?,
                Async::Ready(None) => {
                    return Err(Error::SessionShutdown);
                }
                Async::NotReady => {
                    return Ok(Async::NotReady);
                }
            }
        }
    }
}

impl io::Read for StreamHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // TODO: error handling
        // TODO: check stream state
        match self.state {
            StreamState::RemoteClosing | StreamState::Closed => {
                debug!("closed(EOF)");
                let _ = self.close();
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            StreamState::Reset => {
                debug!("connection reset");
                let _ = self.close();
                return Err(io::ErrorKind::ConnectionReset.into());
            }
            _ => {}
        }

        let rv = self.recv_frames();
        debug!(
            "[{}] StreamHandle.read() recv_frames() => {:?}, state: {:?}",
            self.id, rv, self.state
        );

        match self.state {
            StreamState::RemoteClosing | StreamState::Closed => {
                debug!("closed(EOF)");
                let _ = self.close();
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            StreamState::Reset => {
                debug!("connection reset");
                let _ = self.close();
                return Err(io::ErrorKind::ConnectionReset.into());
            }
            _ => {}
        }

        let n = ::std::cmp::min(buf.len(), self.data_buf.len());
        if n == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let b = self.data_buf.split_to(n);
        debug!(
            "[{}] StreamHandle.read({}), buf.len()={}, data_buf.len()={}",
            self.id,
            n,
            buf.len(),
            self.data_buf.len()
        );
        buf[..n].copy_from_slice(&b);
        if self.send_window_update().is_err() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(n)
    }
}

impl io::Write for StreamHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        debug!("[{}] StreamHandle.write({:?})", self.id, buf);
        if let Err(e) = self.recv_frames() {
            match e {
                Error::SessionShutdown => return Err(io::ErrorKind::BrokenPipe.into()),
                // read flag error or read data error
                Error::UnexpectedFlag | Error::RecvWindowExceeded => {
                    return Err(io::ErrorKind::InvalidData.into())
                }
                Error::SubStreamRemoteClosing => (),
                _ => unimplemented!(),
            }
        }
        if self.state == StreamState::LocalClosing || self.state == StreamState::Closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "The local is closed and data cannot be written.",
            ));
        }
        if self.send_window == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        // Allow n = 0, send an empty frame to remote
        let n = ::std::cmp::min(self.send_window as usize, buf.len());
        let data = &buf[0..n];
        if self.send_data(data).is_err() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.send_window -= n as u32;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        debug!("[{}] StreamHandle.flush()", self.id);
        if let Err(e) = self.recv_frames() {
            match e {
                Error::SessionShutdown => return Err(io::ErrorKind::BrokenPipe.into()),
                // read flag error or read data error
                Error::UnexpectedFlag | Error::RecvWindowExceeded => {
                    return Err(io::ErrorKind::InvalidData.into())
                }
                Error::SubStreamRemoteClosing => (),
                _ => unimplemented!(),
            }
        }
        let (sender, receiver) = oneshot::channel();
        let event = StreamEvent::Flush((self.id, sender));
        match self.send_event(event) {
            Err(_) => Err(io::ErrorKind::BrokenPipe.into()),
            Ok(()) => {
                let _ = receiver.wait();
                Ok(())
            }
        }
    }
}

impl AsyncRead for StreamHandle {}

impl AsyncWrite for StreamHandle {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        debug!("[{}] StreamHandle.shutdown()", self.id);
        if self.close().is_err() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(Async::Ready(()))
    }
}

// Stream event
#[derive(Debug)]
pub(crate) enum StreamEvent {
    Frame(Frame),
    StateChanged((StreamId, StreamState)),
    // Flush stream's frames to remote stream, with a channel for sync
    Flush((StreamId, oneshot::Sender<()>)),
}

/// The stream state
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StreamState {
    /// Just created
    Init,
    /// We sent a Syn message
    SynSent,
    /// We received a Syn message
    SynReceived,
    /// Stream established
    Established,
    /// We closed the stream
    LocalClosing,
    /// Remote closed the stream
    RemoteClosing,
    /// Both side of the stream closed
    Closed,
    /// Stream rejected by remote
    Reset,
}
