//! The substream, the main interface is AsyncRead/AsyncWrite

use bytes::Bytes;
use futures::{
    channel::mpsc::{Receiver, UnboundedSender},
    stream::FusedStream,
    task::Waker,
    Stream,
};

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use log::{debug, trace};
use tokio::prelude::{AsyncRead, AsyncWrite};

use crate::{
    error::Error,
    frame::{Flag, Flags, Frame, Type},
    StreamId,
};

/// The substream
#[derive(Debug)]
pub struct StreamHandle {
    id: StreamId,
    state: StreamState,

    max_recv_window: u32,
    recv_window: u32,
    send_window: u32,
    read_buf: Bytes,

    // Send stream event to parent session
    unbound_event_sender: UnboundedSender<StreamEvent>,

    // Receive frame of current stream from parent session
    // (if the sender closed means session closed the stream should close too)
    frame_receiver: Receiver<Frame>,

    // when the cache is sent, a writable notification is issued
    writeable_wake: Option<Waker>,
}

impl StreamHandle {
    // Create a StreamHandle from session
    pub(crate) fn new(
        id: StreamId,
        unbound_event_sender: UnboundedSender<StreamEvent>,
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
            read_buf: Bytes::default(),
            unbound_event_sender,
            frame_receiver,
            writeable_wake: None,
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
            StreamState::SynSent
            | StreamState::SynReceived
            | StreamState::Established
            | StreamState::Init => {
                self.state = StreamState::LocalClosing;
                self.send_close()?;
            }
            StreamState::RemoteClosing => {
                self.state = StreamState::Closed;
                self.send_close()?;
                let event = StreamEvent::Closed(self.id);
                self.unbound_send_event(event)?;
            }
            StreamState::Reset | StreamState::Closed => {
                self.state = StreamState::Closed;
                let event = StreamEvent::Closed(self.id);
                self.unbound_send_event(event)?;
            }
            StreamState::LocalClosing => {
                self.state = StreamState::Closed;
                let event = StreamEvent::Closed(self.id);
                self.unbound_send_event(event)?;
            }
        }
        Ok(())
    }

    fn send_go_away(&mut self) {
        self.state = StreamState::LocalClosing;
        let _ignore = self
            .unbound_event_sender
            .unbounded_send(StreamEvent::GoAway);
    }

    fn unbound_send_event(&mut self, event: StreamEvent) -> Result<(), Error> {
        self.unbound_event_sender
            .unbounded_send(event)
            .map_err(|_| Error::SessionShutdown)
    }

    #[inline]
    fn unbound_send_frame(&mut self, frame: Frame) -> Result<(), Error> {
        trace!(
            "stream-handle({}) send_frame ty={:?}, size={}",
            self.id,
            frame.ty(),
            frame.size()
        );
        let event = StreamEvent::Frame(frame);
        self.unbound_send_event(event)
    }

    // Send a window update
    pub(crate) fn send_window_update(&mut self) -> Result<(), Error> {
        let buf_len = self.read_buf.len() as u32;
        let delta = self.max_recv_window - buf_len - self.recv_window;

        // Check if we can omit the update
        let flags = self.get_flags();
        if delta < (self.max_recv_window / 2) && flags.value() == 0 {
            return Ok(());
        }
        // Update our window
        self.recv_window += delta;
        let frame = Frame::new_window_update(flags, self.id, delta);
        self.unbound_event_sender
            .unbounded_send(StreamEvent::Frame(frame))
            .map_err(|_| Error::SessionShutdown)
    }

    fn send_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let flags = self.get_flags();
        let frame = Frame::new_data(flags, self.id, Bytes::from(data.to_owned()));
        self.unbound_send_frame(frame)
    }

    fn send_close(&mut self) -> Result<(), Error> {
        let mut flags = self.get_flags();
        flags.add(Flag::Fin);
        let frame = Frame::new_window_update(flags, self.id, 0);
        self.unbound_send_frame(frame)
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
        trace!(
            "stream-handle({}) handle_frame ty={:?}, size={}",
            self.id,
            frame.ty(),
            frame.size()
        );
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
        self.send_window = self
            .send_window
            .checked_add(frame.length())
            .ok_or(Error::InvalidMsgType)?;
        // wake writer continue
        if let Some(waker) = self.writeable_wake.take() {
            waker.wake()
        }
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
            // only when buf is empty, poll read can read from remote
            self.read_buf = data;
        }
        self.recv_window -= length;
        Ok(())
    }

    fn recv_frames(&mut self, cx: &mut Context) -> Result<(), Error> {
        trace!("stream-handle({}) recv_frames", self.id);
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

            // After get data, break here
            // if not, it will never wake upstream here have some cache buffer
            // buffer will left here, waiting for the next session wake
            // this will cause the message to be delayed, unable to read, etc.
            if !self.read_buf.is_empty() {
                trace!(
                    "stream-handle({}) recv_frames break since buf is not empty",
                    self.id
                );
                break;
            }

            if self.frame_receiver.is_terminated() {
                self.state = StreamState::RemoteClosing;
                return Err(Error::SessionShutdown);
            }

            match Pin::new(&mut self.frame_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(frame)) => self.handle_frame(frame)?,
                Poll::Ready(None) => {
                    self.state = StreamState::RemoteClosing;
                    return Err(Error::SessionShutdown);
                }
                Poll::Pending => break,
            }
        }
        Ok(())
    }

    fn check_self_state(&mut self) -> Result<(), io::Error> {
        // if read buf is empty and state is close, return close error
        if self.read_buf.is_empty() {
            match self.state {
                StreamState::RemoteClosing => {
                    debug!("closed(EOF)");
                    let _ignore = self.send_close();
                    Err(io::ErrorKind::UnexpectedEof.into())
                }
                StreamState::Reset => {
                    debug!("connection reset");
                    let _ignore = self.send_close();
                    Err(io::ErrorKind::ConnectionReset.into())
                }
                StreamState::Closed => Err(io::ErrorKind::BrokenPipe.into()),
                _ => Ok(()),
            }
        } else {
            Ok(())
        }
    }
}

impl AsyncRead for StreamHandle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.check_self_state()?;

        if let Err(e) = self.recv_frames(cx) {
            match e {
                // read flag error or read data error
                Error::UnexpectedFlag | Error::RecvWindowExceeded | Error::InvalidMsgType => {
                    self.send_go_away();
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                _ => (),
            }
        }

        self.check_self_state()?;

        let n = ::std::cmp::min(buf.len(), self.read_buf.len());
        trace!(
            "stream-handle({}) poll_read self.read_buf.len={}, buf.len={}, n={}",
            self.id,
            self.read_buf.len(),
            buf.len(),
            n,
        );
        if n == 0 {
            return Poll::Pending;
        }
        let b = self.read_buf.split_to(n);

        buf[..n].copy_from_slice(&b);
        match self.state {
            StreamState::RemoteClosing | StreamState::Closed | StreamState::Reset => (),
            StreamState::LocalClosing => {
                if self.close().is_err() {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
            }
            _ => {
                if self.send_window_update().is_err() {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
            }
        }

        Poll::Ready(Ok(n))
    }

    unsafe fn prepare_uninitialized_buffer(&self, _buf: &mut [std::mem::MaybeUninit<u8>]) -> bool {
        false
    }
}

impl AsyncWrite for StreamHandle {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.state {
            StreamState::RemoteClosing | StreamState::Reset => {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            StreamState::LocalClosing | StreamState::Closed => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "The local is closed and data cannot be written.",
                )));
            }
            _ => (),
        }

        if self.send_window == 0 {
            // register writer context waker
            // when write buf become empty, it can wake the upper layer to write the message again
            self.writeable_wake = Some(cx.waker().clone());
            return Poll::Pending;
        }
        // Allow n = 0, send an empty frame to remote
        let n = ::std::cmp::min(self.send_window as usize, buf.len());
        trace!(
            "stream-hanlde({}) poll_write self.send_window={}, buf.len={}, n={}",
            self.id,
            self.send_window,
            buf.len(),
            n,
        );
        let data = &buf[0..n];
        match self.send_data(data) {
            Ok(_) => {
                self.send_window -= n as u32;

                Poll::Ready(Ok(n))
            }
            Err(Error::WouldBlock) => Poll::Pending,
            _ => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        debug!("[{}] StreamHandle.shutdown()", self.id);
        match self.close() {
            Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Ok(()) => Poll::Ready(Ok(())),
        }
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        if !self.unbound_event_sender.is_closed()
            && self.state != StreamState::Closed
            && self.state != StreamState::LocalClosing
        {
            let mut flags = self.get_flags();
            flags.add(Flag::Rst);
            let frame = Frame::new_window_update(flags, self.id, 0);
            let rst_event = StreamEvent::Frame(frame);
            let event = StreamEvent::Closed(self.id);
            // Always successful unless the session is dropped
            let _ignore = self.unbound_event_sender.unbounded_send(rst_event);
            let _ignore = self.unbound_event_sender.unbounded_send(event);
        }
    }
}

// Stream event
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum StreamEvent {
    Frame(Frame),
    Closed(StreamId),
    // Only use on protocol error
    GoAway,
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

#[cfg(test)]
mod test {
    use super::{StreamEvent, StreamHandle, StreamState};
    use crate::{
        config::INITIAL_STREAM_WINDOW,
        frame::{Flag, Flags, Frame, Type},
    };
    use bytes::Bytes;
    use futures::{
        channel::mpsc::{channel, unbounded},
        SinkExt, StreamExt,
    };
    use std::io::ErrorKind;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_drop() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (_frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, mut unbound_receiver) = unbounded();
            let stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
                INITIAL_STREAM_WINDOW,
                INITIAL_STREAM_WINDOW,
            );

            drop(stream);
            let event = unbound_receiver.next().await.unwrap();
            match event {
                StreamEvent::Frame(frame) => assert!(frame.flags().contains(Flag::Rst)),
                _ => panic!("must be a frame msg contain RST"),
            }
            let event = unbound_receiver.next().await.unwrap();
            match event {
                StreamEvent::Closed(_) => (),
                _ => panic!("must be state closed"),
            }
        });
    }

    #[test]
    fn test_drop_with_state_reset() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (mut frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, mut unbound_receiver) = unbounded();
            let mut stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
                INITIAL_STREAM_WINDOW,
                INITIAL_STREAM_WINDOW,
            );

            let mut flags = Flags::from(Flag::Syn);
            flags.add(Flag::Rst);
            let frame = Frame::new_window_update(flags, 0, 0);
            frame_sender.send(frame).await.unwrap();
            let mut b = [0; 1024];

            // try poll stream handle, then it will recv RST frame and set self state to reset
            assert_eq!(
                stream.read(&mut b).await.unwrap_err().kind(),
                ErrorKind::BrokenPipe
            );

            drop(stream);
            let event = unbound_receiver.next().await.unwrap();
            match event {
                StreamEvent::Closed(_) => (),
                _ => panic!("must be state closed"),
            }
        });
    }

    #[test]
    fn test_data_large_than_recv_window() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (mut frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, mut unbound_receiver) = unbounded();
            let mut stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
                2,
                INITIAL_STREAM_WINDOW,
            );

            let flags = Flags::from(Flag::Syn);
            let frame = Frame::new_data(flags, 0, Bytes::from("1234"));
            frame_sender.send(frame).await.unwrap();
            let mut b = [0; 1024];

            // try poll stream handle, then it will recv data frame and return Err
            assert_eq!(
                stream.read(&mut b).await.unwrap_err().kind(),
                ErrorKind::InvalidData
            );

            let event = unbound_receiver.next().await.unwrap();
            match event {
                StreamEvent::GoAway => (),
                _ => panic!("must be go away"),
            }
        });
    }

    // https://github.com/nervosnetwork/tentacle/issues/297
    //
    // As you can see from the description, the real cause of the problem
    // is that the two channels cannot guarantee the consistency of the sending
    // order, that is, the order of the message to start the stream and the
    // message to send data is reversed, causing the remote end to receive
    // an unowned message , Silently discarded, causing the problem that
    // the protocol cannot be opened
    #[test]
    fn test_open_stream_with_data() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (_frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, mut unbound_receiver) = unbounded();
            let mut stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
                2,
                INITIAL_STREAM_WINDOW,
            );

            let data = [0; 8];

            stream.send_window_update().unwrap();
            stream.write(&data).await.unwrap();

            let event = unbound_receiver.next().await.unwrap();
            match event {
                StreamEvent::Frame(frame) => assert!(frame.ty() == Type::WindowUpdate),
                _ => panic!("must be a window update msg"),
            }

            let event = unbound_receiver.next().await.unwrap();
            match event {
                StreamEvent::Frame(frame) => assert!(frame.ty() == Type::Data),
                _ => panic!("must be a frame msg"),
            }
        });
    }
}
