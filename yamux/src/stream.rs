//! The substream, the main interface is AsyncRead/AsyncWrite

use bytes::{Bytes, BytesMut};
use futures::{
    channel::mpsc::{Receiver, Sender},
    stream::FusedStream,
    Stream,
};

use std::{
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

    delay: Arc<AtomicBool>,
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
            delay: Arc::new(AtomicBool::new(false)),
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
        debug!("[{}] StreamHandle.send_event()", self.id);
        while let Some((flag, delta)) = self.window_update_frame_buf.pop_front() {
            let event = StreamEvent::Frame(Frame::new_window_update(flag, self.id, delta));
            if let Err(e) = self.event_sender.try_send(event) {
                if e.is_full() {
                    self.window_update_frame_buf.push_front((flag, delta));
                    return Err(Error::WouldBlock);
                } else {
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
    fn send_frame(&mut self, frame: Frame) -> Result<(), Error> {
        let event = StreamEvent::Frame(frame);
        self.send_event(event)
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
        match self.send_frame(frame) {
            Err(ref e) if e == &Error::WouldBlock => {
                self.window_update_frame_buf.push_back((flags, delta))
            }
            Err(e) => return Err(e),
            _ => (),
        }
        Ok(())
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

    fn handle_frame(&mut self, cx: &mut Context, frame: Frame) -> Result<(), Error> {
        debug!("[{}] StreamHandle.handle_frame({:?})", self.id, frame);
        match frame.ty() {
            Type::WindowUpdate => {
                self.handle_window_update(cx, &frame)?;
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

    fn handle_window_update(&mut self, cx: &mut Context, frame: &Frame) -> Result<(), Error> {
        self.process_flags(frame.flags())?;
        self.send_window = self
            .send_window
            .checked_add(frame.length())
            .ok_or(Error::InvalidMsgType)?;
        let n = ::std::cmp::min(self.send_window as usize, self.write_buf.len());
        // Send cached data
        if n != 0 {
            let b = self.write_buf.split_to(n);
            let _ = Pin::new(self).poll_write(cx, &b);
        } else {
            cx.waker().clone().wake();
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
            self.read_buf.extend_from_slice(&data);
        }
        self.recv_window -= length;
        Ok(())
    }

    fn recv_frames(&mut self, cx: &mut Context) -> Result<(), Error> {
        for _ in 0..64 {
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
                Poll::Pending => {
                    return Ok(());
                }
            }
        }
        self.set_delay(cx);
        Ok(())
    }

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
                tokio::timer::delay(Instant::now() + Duration::from_millis(200)).await;
                waker.wake();
                delay.store(false, Ordering::Release);
            });
        }
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

        let rv = self.recv_frames(cx);
        debug!(
            "[{}] StreamHandle.read() recv_frames() => {:?}, state: {:?}",
            self.id, rv, self.state
        );

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
                if self.send_window_update().is_err() {
                    return Poll::Pending;
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
        match self.send_data(data) {
            Ok(_) => {
                self.send_window -= n as u32;
                // Cache unsent data
                self.write_buf.extend_from_slice(&buf[n..]);

                Poll::Ready(Ok(buf.len()))
            }
            Err(ref e) if e == &Error::WouldBlock => Poll::Pending,
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
                Error::UnexpectedFlag | Error::RecvWindowExceeded | Error::InvalidMsgType=> {
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                Error::SubStreamRemoteClosing => (),
                Error::WouldBlock => return Poll::Pending,
                _ => (),
            }
        }
        let event = StreamEvent::Flush(self.id);
        match self.send_event(event) {
            Err(ref e) if e == &Error::WouldBlock => Poll::Pending,
            Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Ok(()) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        debug!("[{}] StreamHandle.shutdown()", self.id);
        match self.close() {
            Err(ref e) if e == &Error::WouldBlock => Poll::Pending,
            Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Ok(()) => Poll::Ready(Ok(())),
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
