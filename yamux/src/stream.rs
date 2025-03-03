//! The substream, the main interface is AsyncRead/AsyncWrite

use bytes::BytesMut;
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

use futures::future;
use log::{debug, trace};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    config::INITIAL_STREAM_WINDOW,
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
    pub(crate) recv_window: u32,
    send_window: u32,
    read_buf: Vec<BytesMut>,

    // Send stream event to parent session
    unbound_event_sender: UnboundedSender<StreamEvent>,

    // Receive frame of current stream from parent session
    // (if the sender closed means session closed the stream should close too)
    frame_receiver: Receiver<Frame>,

    // when the cache is sent, a writable notification is issued
    writeable_wake: Option<Waker>,

    // when the cache is received by write, a readable notification is issued
    readable_wake: Option<Waker>,
}

impl StreamHandle {
    // Create a StreamHandle from session
    pub(crate) fn new(
        id: StreamId,
        unbound_event_sender: UnboundedSender<StreamEvent>,
        frame_receiver: Receiver<Frame>,
        state: StreamState,
        max_window_size: u32,
    ) -> StreamHandle {
        assert!(state == StreamState::Init || state == StreamState::SynReceived);
        StreamHandle {
            id,
            state,
            max_recv_window: max_window_size,
            recv_window: INITIAL_STREAM_WINDOW,
            send_window: INITIAL_STREAM_WINDOW,
            read_buf: Vec::new(),
            unbound_event_sender,
            frame_receiver,
            writeable_wake: None,
            readable_wake: None,
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
        let buf_len = self.read_buf.iter().map(|b| b.len()).sum::<usize>() as u32;
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
        let frame = Frame::new_data(flags, self.id, BytesMut::from(data));
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
                }
                _ => return Err(Error::UnexpectedFlag),
            }
        }
        if flags.contains(Flag::Rst) {
            self.state = StreamState::Reset;
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
            // yamux allows empty data frame
            // but here we just drop it
            if length > 0 {
                self.read_buf.push(data);
            }
        }
        self.recv_window -= length;
        Ok(())
    }

    fn recv_frames(&mut self, cx: &mut Context) -> Result<bool, Error> {
        trace!("stream-handle({}) recv_frames", self.id);
        let mut has_new_frame = false;
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
                self.state = StreamState::RemoteClosing;
                return Err(Error::SubStreamRemoteClosing);
            }

            match Pin::new(&mut self.frame_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(frame)) => {
                    self.handle_frame(frame)?;
                    has_new_frame = true;
                }
                Poll::Ready(None) => {
                    self.state = StreamState::RemoteClosing;
                    return Err(Error::SubStreamRemoteClosing);
                }
                Poll::Pending => break,
            }
        }
        Ok(has_new_frame)
    }

    fn recv_frames_wake(&mut self, cx: &mut Context) -> Result<(), Error> {
        let buf_len = self.read_buf.len();
        let state = self.state;
        match self.recv_frames(cx) {
            Ok(should_wake_read) => {
                // if state change to RemoteClosing, wake read
                // if read buf len change, wake read
                if (self.state == StreamState::RemoteClosing && state != StreamState::RemoteClosing)
                    || (should_wake_read && buf_len != self.read_buf.len())
                {
                    if let Some(waker) = self.readable_wake.take() {
                        waker.wake();
                    }
                }

                Ok(())
            }
            Err(e) => {
                // if state change to RemoteClosing, wake read
                if self.state == StreamState::RemoteClosing && state != StreamState::RemoteClosing {
                    if let Some(waker) = self.readable_wake.take() {
                        waker.wake();
                    }
                }

                Err(e)
            }
        }
    }

    // Returns Ok(true) only if eof is reached.
    fn check_self_state(&mut self) -> io::Result<bool> {
        // if read buf is empty and state is close, return close error
        if self.read_buf.is_empty() {
            match self.state {
                StreamState::RemoteClosing | StreamState::Closed => {
                    debug!("closed(EOF)");
                    // an empty read indicates that EOF is reached.
                    Ok(true)
                }
                StreamState::Reset => {
                    debug!("connection reset");
                    Err(io::ErrorKind::ConnectionReset.into())
                }
                _ => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    /// Attempts to receive data on the socket, without removing that data from the queue,
    /// registering the current task for wakeup if data is not yet available.
    pub fn poll_peek(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<usize>> {
        if self.check_self_state()? {
            return Poll::Ready(Ok(0));
        }

        if let Err(Error::UnexpectedFlag | Error::RecvWindowExceeded | Error::InvalidMsgType) =
            self.recv_frames(cx)
        {
            // read flag error or read data error
            self.send_go_away();
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }

        if self.check_self_state()? {
            return Poll::Ready(Ok(0));
        }

        if self.read_buf.is_empty() {
            self.readable_wake = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let mut total_read = 0;
        for read_buf in self.read_buf.iter() {
            let n = ::std::cmp::min(buf.remaining(), read_buf.len());
            if n == 0 {
                break;
            }
            total_read += n;
            let b = &read_buf[..n];
            buf.put_slice(b);
        }

        trace!(
            "stream-handle({}) poll_peek self.read_buf.len={}, buf.len={}, n={}",
            self.id,
            self.read_buf.len(),
            buf.remaining(),
            total_read,
        );

        Poll::Ready(Ok(total_read))
    }

    /// Receives data on the socket from the remote address to which it is connected,
    /// without removing that data from the queue. On success, returns the number of bytes peeked.
    pub async fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        future::poll_fn(|cx| self.poll_peek(cx, &mut read_buf)).await
    }
}

impl AsyncRead for StreamHandle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.check_self_state()? {
            return Poll::Ready(Ok(()));
        }

        if let Err(Error::UnexpectedFlag | Error::RecvWindowExceeded | Error::InvalidMsgType) =
            self.recv_frames(cx)
        {
            // read flag error or read data error
            self.send_go_away();
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }

        if self.check_self_state()? {
            return Poll::Ready(Ok(()));
        }

        if self.read_buf.is_empty() {
            self.readable_wake = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let mut offset = 0;
        let mut total_read = 0;
        let mut need_drain = false;
        for (index, read_buf) in self.read_buf.iter_mut().enumerate() {
            let n = ::std::cmp::min(buf.remaining(), read_buf.len());
            if n == 0 {
                break;
            }
            total_read += n;
            if n == read_buf.len() {
                let b = &read_buf[..n];
                buf.put_slice(b);
                offset = index;
                need_drain = true;
            } else {
                let b = read_buf.split_to(n);
                buf.put_slice(&b);
            }
        }

        if need_drain {
            self.read_buf.drain(..=offset);
            // drain does not shrink the capacity, if the capacity is too large, shrink it
            if self.read_buf.capacity() > 24
                && self.read_buf.capacity() / (self.read_buf.len() + 1) > 4
            {
                self.read_buf.shrink_to_fit();
            }
        }

        trace!(
            "stream-handle({}) poll_read self.read_buf.len={}, buf.len={}, n={}",
            self.id,
            self.read_buf.len(),
            buf.remaining(),
            total_read,
        );

        match self.state {
            StreamState::RemoteClosing | StreamState::Closed | StreamState::Reset => {
                debug!("this branch should be unreachable")
            }
            _ => {
                if self.send_window_update().is_err() {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for StreamHandle {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // https://github.com/driftluo/tentacle/issues/33
        // read frame from session is necessary.
        // The window update message of Yamux must be updated normally.
        // If the user only writes but does not read, the entire stream will be stuck.
        // To avoid this, read operations are required when there is a frame in the session.
        //
        // Another solution to avoid this problem is to let the session and stream share the state.
        // In the rust implementation, at least the following three states are required:
        // 1. writeable_wake
        // 2. send_window
        // 3. state
        //
        // When the session receives a window update frame, it can update the state of the stream.
        // In the implementation here, we try not to share state between the session and the stream.
        if let Err(Error::UnexpectedFlag | Error::RecvWindowExceeded | Error::InvalidMsgType) =
            self.recv_frames_wake(cx)
        {
            // read flag error or read data error
            self.send_go_away();
        }

        match self.state {
            StreamState::Reset => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
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
        if !self.unbound_event_sender.is_closed() && self.state != StreamState::Closed {
            match self.state {
                // LocalClosing means that local have sent Fin to the remote and waiting for a response.
                StreamState::LocalClosing | StreamState::Reset => (),
                // if not, we should send Rst first
                StreamState::Established
                | StreamState::Init
                | StreamState::RemoteClosing
                | StreamState::SynReceived
                | StreamState::SynSent => {
                    let mut flags = self.get_flags();
                    flags.add(Flag::Rst);
                    let frame = Frame::new_window_update(flags, self.id, 0);
                    let rst_event = StreamEvent::Frame(frame);

                    // Always successful unless the session is dropped
                    let _ignore = self.unbound_event_sender.unbounded_send(rst_event);
                }
                StreamState::Closed => unreachable!(),
            }

            let event = StreamEvent::Closed(self.id);
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
        session::rt,
    };
    use bytes::BytesMut;
    use futures::{
        channel::mpsc::{channel, unbounded},
        SinkExt, StreamExt,
    };
    use std::io::ErrorKind;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_drop() {
        let rt = rt();
        rt.block_on(async {
            let (_frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, mut unbound_receiver) = unbounded();
            let stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
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
        let rt = rt();
        rt.block_on(async {
            let (mut frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, mut unbound_receiver) = unbounded();
            let mut stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
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
                ErrorKind::ConnectionReset
            );

            assert_eq!(stream.state, StreamState::Reset);

            drop(stream);

            let event = unbound_receiver.next().await.unwrap();
            match event {
                StreamEvent::Closed(_) => (),
                _ => panic!("must be state closed"),
            }
        });
    }

    #[test]
    fn test_drop_with_state_local_close() {
        let rt = rt();
        rt.block_on(async {
            let (_frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, mut unbound_receiver) = unbounded();
            let mut stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
                INITIAL_STREAM_WINDOW,
            );

            let _ignore = stream.shutdown().await;

            let event = unbound_receiver.next().await.unwrap();
            match event {
                StreamEvent::Frame(frame) => {
                    assert!(frame.flags().contains(Flag::Fin));
                    assert_eq!(frame.ty(), Type::WindowUpdate);
                }
                _ => panic!("must be fin window update"),
            }

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
        let rt = rt();
        rt.block_on(async {
            let (mut frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, mut unbound_receiver) = unbounded();
            let mut stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
                INITIAL_STREAM_WINDOW,
            );

            stream.recv_window = 2;

            let flags = Flags::from(Flag::Syn);
            let frame = Frame::new_data(flags, 0, BytesMut::from("1234"));
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
        let rt = rt();
        rt.block_on(async {
            let (_frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, mut unbound_receiver) = unbounded();
            let mut stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
                INITIAL_STREAM_WINDOW,
            );

            let data = [0; 8];

            stream.send_window_update().unwrap();
            stream.write_all(&data).await.unwrap();

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

    #[test]
    fn test_read_with_half_close() {
        let rt = rt();
        rt.block_on(async {
            let (mut frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, _unbound_receiver) = unbounded();
            let mut stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
                INITIAL_STREAM_WINDOW,
            );

            stream.shutdown().await.unwrap();

            assert_eq!(stream.state, StreamState::LocalClosing);

            let flags = Flags::from(Flag::Syn);
            let frame = Frame::new_data(flags, 0, BytesMut::from("1234"));
            frame_sender.send(frame).await.unwrap();
            let mut b = [0; 1024];

            assert_eq!(stream.read(&mut b).await.unwrap(), 4);
            assert_eq!(&b[..4], b"1234");

            assert_eq!(stream.state, StreamState::LocalClosing);
        });
    }

    #[test]
    fn test_write_with_half_close() {
        let rt = rt();
        rt.block_on(async {
            let (mut frame_sender, frame_receiver) = channel(2);
            let (unbound_sender, mut unbound_receiver) = unbounded();
            let mut stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
                INITIAL_STREAM_WINDOW,
            );

            let flags = Flags::from(Flag::Fin);
            let frame = Frame::new_window_update(flags, 0, 0);
            frame_sender.send(frame).await.unwrap();
            let mut b = [0; 1024];

            assert_eq!(stream.read(&mut b).await.unwrap(), 0);
            assert_eq!(stream.state, StreamState::RemoteClosing);

            const TEXT: &[u8] = b"testtext";

            let jh = tokio::spawn(tokio::time::timeout(std::time::Duration::from_secs(4), async move {
                loop {
                    match unbound_receiver.try_next() {
                        Ok(Some(ref event)) if matches!(event, StreamEvent::Frame(frame) if frame.length() == TEXT.len() as u32) => break,
                        Err(_) => (),
                        _ => panic!("must be frame with written text"),
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }));

            stream.write_all(TEXT).await.unwrap();

            jh.await.unwrap().expect("not tiemout");

            assert_eq!(stream.state, StreamState::RemoteClosing);
        });
    }

    #[test]
    fn test_frame_read_more_than_one() {
        let rt = rt();
        rt.block_on(async {
            let (mut frame_sender, frame_receiver) = channel(3);
            let (unbound_sender, _unbound_receiver) = unbounded();
            let mut stream = StreamHandle::new(
                0,
                unbound_sender,
                frame_receiver,
                StreamState::Init,
                INITIAL_STREAM_WINDOW,
            );

            let flags = Flags::from(Flag::Syn);
            let frame = Frame::new_data(flags, 0, BytesMut::from("1234"));
            frame_sender.send(frame).await.unwrap();
            let flags = Flags::from(Flag::Syn);
            let frame = Frame::new_data(flags, 0, BytesMut::default());
            frame_sender.send(frame).await.unwrap();
            let flags = Flags::from(Flag::Syn);
            let frame = Frame::new_data(flags, 0, BytesMut::from("5678"));
            frame_sender.send(frame).await.unwrap();
            let mut b = [0; 2];

            assert_eq!(stream.read(&mut b).await.unwrap(), 2);
            assert_eq!(&b[..2], b"12");
            assert_eq!(stream.read_buf.len(), 2);
            assert_eq!(stream.read_buf.capacity(), 4);

            assert_eq!(stream.read(&mut b).await.unwrap(), 2);
            assert_eq!(&b[..2], b"34");
            assert_eq!(stream.read_buf.len(), 1);
            // Drain does not shrink the capacity
            assert_eq!(stream.read_buf.capacity(), 4);

            let flags = Flags::from(Flag::Syn);
            let frame = Frame::new_data(flags, 0, BytesMut::default());
            frame_sender.send(frame).await.unwrap();
            let flags = Flags::from(Flag::Syn);
            let frame = Frame::new_data(flags, 0, BytesMut::from("1234"));
            frame_sender.send(frame).await.unwrap();
            let mut c = [0; 5];

            assert_eq!(stream.read(&mut c).await.unwrap(), 5);
            assert_eq!(&c[..5], b"56781");
            assert_eq!(stream.read_buf.len(), 1);
            assert_eq!(stream.read_buf.capacity(), 4);

            assert_eq!(stream.read(&mut b).await.unwrap(), 2);
            assert_eq!(&b[..2], b"23");
            assert_eq!(stream.read_buf.len(), 1);
            assert_eq!(stream.read_buf.capacity(), 4);
        });
    }
}
