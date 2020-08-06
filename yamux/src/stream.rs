//! The substream, the main interface is AsyncRead/AsyncWrite

use bytes::{Bytes, BytesMut};
use futures::{
    channel::mpsc::{Receiver, Sender},
    stream::FusedStream,
    SinkExt, Stream,
};

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use log::debug;
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
    read_buf: BytesMut,
    write_buf: BytesMut,
    window_update_frame_buf: VecDeque<(Flags, u32)>,

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
            read_buf: BytesMut::default(),
            write_buf: BytesMut::default(),
            window_update_frame_buf: VecDeque::default(),
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

    fn close(&mut self, cx: &mut Context) -> Result<(), Error> {
        match self.state {
            StreamState::SynSent | StreamState::SynReceived | StreamState::Established => {
                self.state = StreamState::LocalClosing;
                self.send_close(cx)?;
            }
            StreamState::RemoteClosing => {
                self.state = StreamState::Closed;
                self.send_close(cx)?;
                let event = StreamEvent::StateChanged((self.id, self.state));
                self.send_event(cx, event)?;
            }
            StreamState::Reset | StreamState::Closed => {
                self.state = StreamState::Closed;
                let event = StreamEvent::StateChanged((self.id, self.state));
                self.send_event(cx, event)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn send_go_away(&mut self) {
        let mut sender = self.event_sender.clone();
        self.state = StreamState::LocalClosing;
        tokio::spawn(async move { sender.send(StreamEvent::GoAway).await });
    }

    #[inline]
    fn send_event(&mut self, cx: &mut Context, event: StreamEvent) -> Result<(), Error> {
        debug!("[{}] StreamHandle.send_event()", self.id);
        while let Some((flag, delta)) = self.window_update_frame_buf.pop_front() {
            let event = StreamEvent::Frame(Frame::new_window_update(flag, self.id, delta));
            match self.event_sender.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    if let Err(e) = self.event_sender.try_send(event) {
                        if e.is_full() {
                            self.window_update_frame_buf.push_front((flag, delta));
                            return Err(Error::WouldBlock);
                        } else {
                            return Err(Error::SessionShutdown);
                        }
                    }
                }
                Poll::Pending => {
                    self.window_update_frame_buf.push_front((flag, delta));
                    return Err(Error::WouldBlock);
                }
                Poll::Ready(Err(_)) => {
                    return Err(Error::SessionShutdown);
                }
            }
        }

        if let Err(e) = self.event_sender.try_send(event) {
            if e.is_full() {
                return Err(Error::WouldBlock);
            } else {
                return Err(Error::SessionShutdown);
            }
        }

        Ok(())
    }

    #[inline]
    fn send_frame(&mut self, cx: &mut Context, frame: Frame) -> Result<(), Error> {
        let event = StreamEvent::Frame(frame);
        self.send_event(cx, event)
    }

    // Send a window update
    pub(crate) fn send_window_update(&mut self, cx: Option<&mut Context>) -> Result<(), Error> {
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
        match cx {
            Some(cx) => match self.send_frame(cx, frame) {
                Err(Error::WouldBlock) => self.window_update_frame_buf.push_back((flags, delta)),
                Err(e) => return Err(e),
                _ => (),
            },
            None => {
                // init sub stream, this channel is empty
                let _ignore = self.event_sender.try_send(StreamEvent::Frame(frame));
            }
        }

        Ok(())
    }

    fn send_data(&mut self, cx: &mut Context, data: &[u8]) -> Result<(), Error> {
        let flags = self.get_flags();
        let frame = Frame::new_data(flags, self.id, Bytes::from(data.to_owned()));
        self.send_frame(cx, frame)
    }

    fn send_close(&mut self, cx: &mut Context) -> Result<(), Error> {
        let mut flags = self.get_flags();
        flags.add(Flag::Fin);
        let frame = Frame::new_window_update(flags, self.id, 0);
        self.send_frame(cx, frame)
    }

    fn process_flags(&mut self, cx: &mut Context, flags: Flags) -> Result<(), Error> {
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
            self.close(cx)?;
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

    fn handle_frame(&mut self, cx: &mut Context, frame: Frame) -> Result<(), Error> {
        debug!("[{}] StreamHandle.handle_frame({:?})", self.id, frame);
        match frame.ty() {
            Type::WindowUpdate => {
                self.handle_window_update(cx, &frame)?;
            }
            Type::Data => {
                self.handle_data(cx, frame)?;
            }
            _ => {
                return Err(Error::InvalidMsgType);
            }
        }
        Ok(())
    }

    fn handle_window_update(&mut self, cx: &mut Context, frame: &Frame) -> Result<(), Error> {
        self.process_flags(cx, frame.flags())?;
        self.send_window = self
            .send_window
            .checked_add(frame.length())
            .ok_or(Error::InvalidMsgType)?;
        let n = ::std::cmp::min(self.send_window as usize, self.write_buf.len());
        // Send cached data
        if n != 0 {
            let b = self.write_buf.split_to(n);
            // don't care about result here
            let _ignore = Pin::new(self).poll_write(cx, &b);
        } else {
            cx.waker().wake_by_ref();
        }
        Ok(())
    }

    fn handle_data(&mut self, cx: &mut Context, frame: Frame) -> Result<(), Error> {
        self.process_flags(cx, frame.flags())?;
        let length = frame.length();
        if length > self.recv_window {
            return Err(Error::RecvWindowExceeded);
        }

        let (_, body) = frame.into_parts();
        if let Some(data) = body {
            self.read_buf.extend_from_slice(&data);
        }
        self.recv_window -= length;
        Ok(())
    }

    fn recv_frames(&mut self, cx: &mut Context) -> Result<(), Error> {
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

            if self.frame_receiver.is_terminated() {
                return Err(Error::SessionShutdown);
            }

            match Pin::new(&mut self.frame_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(frame)) => self.handle_frame(cx, frame)?,
                Poll::Ready(None) => {
                    return Err(Error::SessionShutdown);
                }
                Poll::Pending => break,
            }
        }
        Ok(())
    }

    fn check_self_state(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        // if read buf is empty and state is close, return close error
        if self.read_buf.is_empty() {
            match self.state {
                StreamState::RemoteClosing | StreamState::Closed => {
                    debug!("closed(EOF)");
                    match Pin::new(self).poll_shutdown(cx) {
                        Poll::Ready(res) => res?,
                        Poll::Pending => (),
                    }
                    Err(io::ErrorKind::UnexpectedEof.into())
                }
                StreamState::Reset => {
                    debug!("connection reset");
                    match Pin::new(self).poll_shutdown(cx) {
                        Poll::Ready(res) => res?,
                        Poll::Pending => (),
                    }
                    Err(io::ErrorKind::ConnectionReset.into())
                }
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
        self.check_self_state(cx)?;

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

        debug!("[{}] StreamHandle.read(), state: {:?}", self.id, self.state);

        self.check_self_state(cx)?;

        debug!(
            "send window size: {}, receive window size: {}, send buf: {}, read buf: {}",
            self.send_window,
            self.recv_window,
            self.write_buf.len(),
            self.read_buf.len()
        );

        let n = ::std::cmp::min(buf.len(), self.read_buf.len());
        if n == 0 {
            return Poll::Pending;
        }
        let b = self.read_buf.split_to(n);
        debug!(
            "[{}] StreamHandle.read({}), buf.len()={}, read_buf.len()={}",
            self.id,
            n,
            buf.len(),
            self.read_buf.len()
        );
        buf[..n].copy_from_slice(&b);
        match self.state {
            StreamState::RemoteClosing | StreamState::Closed | StreamState::Reset => (),
            _ => {
                if self.send_window_update(Some(cx)).is_err() {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
            }
        }

        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for StreamHandle {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        debug!("[{}] StreamHandle.write({:?})", self.id, buf.len());
        if let Err(e) = self.recv_frames(cx) {
            match e {
                Error::SessionShutdown => {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
                }
                // read flag error or read data error
                Error::UnexpectedFlag | Error::RecvWindowExceeded | Error::InvalidMsgType => {
                    self.send_go_away();
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                Error::SubStreamRemoteClosing => (),
                Error::WouldBlock => return Poll::Pending,
                _ => (),
            }
        }
        if self.state == StreamState::LocalClosing || self.state == StreamState::Closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "The local is closed and data cannot be written.",
            )));
        }

        debug!(
            "send window size: {}, receive window size: {}, send buf: {}, read buf: {}",
            self.send_window,
            self.recv_window,
            self.write_buf.len(),
            self.read_buf.len()
        );

        if self.send_window == 0 {
            return Poll::Pending;
        }
        // Allow n = 0, send an empty frame to remote
        let n = ::std::cmp::min(self.send_window as usize, buf.len());
        let data = &buf[0..n];
        match self.send_data(cx, data) {
            Ok(_) => {
                self.send_window -= n as u32;
                // Cache unsent data
                self.write_buf.extend_from_slice(&buf[n..]);

                Poll::Ready(Ok(buf.len()))
            }
            Err(Error::WouldBlock) => Poll::Pending,
            _ => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        debug!("[{}] StreamHandle.flush()", self.id);
        if let Err(e) = self.recv_frames(cx) {
            match e {
                Error::SessionShutdown => {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
                }
                // read flag error or read data error
                Error::UnexpectedFlag | Error::RecvWindowExceeded | Error::InvalidMsgType => {
                    self.send_go_away();
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                Error::SubStreamRemoteClosing => (),
                Error::WouldBlock => return Poll::Pending,
                _ => (),
            }
        }
        let event = StreamEvent::Flush(self.id);
        match self.send_event(cx, event) {
            Err(Error::WouldBlock) => Poll::Pending,
            Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Ok(()) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        debug!("[{}] StreamHandle.shutdown()", self.id);
        match self.close(cx) {
            Err(Error::WouldBlock) => Poll::Pending,
            Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Ok(()) => Poll::Ready(Ok(())),
        }
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        if !self.event_sender.is_closed()
            && self.state != StreamState::Closed
            && self.state != StreamState::LocalClosing
        {
            let mut flags = self.get_flags();
            flags.add(Flag::Rst);
            let frame = Frame::new_window_update(flags, self.id, 0);
            let rst_event = StreamEvent::Frame(frame);
            let event = StreamEvent::StateChanged((self.id, StreamState::Closed));
            let mut sender = self.event_sender.clone();

            tokio::spawn(async move {
                let _ignore = sender.send(rst_event).await;
                let _ignore = sender.send(event).await;
            });
        }
    }
}

// Stream event
#[derive(Debug)]
pub(crate) enum StreamEvent {
    Frame(Frame),
    StateChanged((StreamId, StreamState)),
    // Flush stream's frames to remote stream, with a channel for sync
    Flush(StreamId),
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
        frame::{Flag, Flags, Frame},
    };
    use bytes::Bytes;
    use futures::{channel::mpsc::channel, SinkExt};
    use std::io::ErrorKind;
    use tokio::{io::AsyncWriteExt, stream::StreamExt};

    #[test]
    fn test_drop() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (event_sender, mut event_receiver) = channel(2);
            let (_frame_sender, frame_receiver) = channel(2);
            let stream = StreamHandle::new(
                0,
                event_sender,
                frame_receiver,
                StreamState::Init,
                INITIAL_STREAM_WINDOW,
                INITIAL_STREAM_WINDOW,
            );

            drop(stream);
            let event = event_receiver.next().await.unwrap();
            match event {
                StreamEvent::Frame(frame) => assert!(frame.flags().contains(Flag::Rst)),
                _ => panic!("must be a frame msg contain RST"),
            }
            let event = event_receiver.next().await.unwrap();
            match event {
                StreamEvent::StateChanged((_, state)) => assert_eq!(state, StreamState::Closed),
                _ => panic!("must be state change"),
            }
        });
    }

    #[test]
    fn test_drop_with_state_reset() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (event_sender, mut event_receiver) = channel(2);
            let (mut frame_sender, frame_receiver) = channel(2);
            let mut stream = StreamHandle::new(
                0,
                event_sender,
                frame_receiver,
                StreamState::Init,
                INITIAL_STREAM_WINDOW,
                INITIAL_STREAM_WINDOW,
            );

            let mut flags = Flags::from(Flag::Syn);
            flags.add(Flag::Rst);
            let frame = Frame::new_window_update(flags, 0, 0);
            frame_sender.send(frame).await.unwrap();

            // try poll stream handle, then it will recv RST frame and set self state to reset
            assert_eq!(
                stream.write(b"hello").await.unwrap_err().kind(),
                ErrorKind::BrokenPipe
            );

            drop(stream);
            let event = event_receiver.next().await.unwrap();
            match event {
                StreamEvent::StateChanged((_, state)) => assert_eq!(state, StreamState::Closed),
                _ => panic!("must be state change"),
            }
        });
    }

    #[test]
    fn test_data_large_than_recv_window() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (event_sender, mut event_receiver) = channel(2);
            let (mut frame_sender, frame_receiver) = channel(2);
            let mut stream = StreamHandle::new(
                0,
                event_sender,
                frame_receiver,
                StreamState::Init,
                2,
                INITIAL_STREAM_WINDOW,
            );

            let flags = Flags::from(Flag::Syn);
            let frame = Frame::new_data(flags, 0, Bytes::from("1234"));
            frame_sender.send(frame).await.unwrap();

            // try poll stream handle, then it will recv data frame and return Err
            assert_eq!(
                stream.write(b"hello").await.unwrap_err().kind(),
                ErrorKind::InvalidData
            );

            let event = event_receiver.next().await.unwrap();
            match event {
                StreamEvent::GoAway => (),
                _ => panic!("must be go away"),
            }
        });
    }
}
