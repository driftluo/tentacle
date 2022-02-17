//! The session, can open and manage substreams

#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet, VecDeque},
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
#[cfg(target_arch = "wasm32")]
use timer::Instant;

use futures::{
    channel::mpsc::{channel, unbounded, Receiver, Sender, UnboundedReceiver, UnboundedSender},
    Sink, Stream,
};
use log::{debug, log_enabled, trace};
use nohash_hasher::IntMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::{
    config::Config,
    control::{Command, Control},
    error::Error,
    frame::{Flag, Flags, Frame, FrameCodec, GoAwayCode, Type},
    stream::{StreamEvent, StreamHandle, StreamState},
    StreamId,
};

use timer::{interval, Interval};

const BUF_SHRINK_THRESHOLD: usize = u8::MAX as usize;
const TIMEOUT: Duration = Duration::from_secs(30);

/// wasm doesn't support time get, must use browser timer instead
/// But we can simulate it with `futures-timer`.
/// So, I implemented a global time dependent on `futures-timer`,
/// Because in the browser environment, it is always single-threaded, so feel free to be unsafe
#[cfg(target_arch = "wasm32")]
static mut TIME: Instant = Instant::from_u64(0);

/// The session
pub struct Session<T> {
    // Framed low level raw stream
    framed_stream: Framed<T, FrameCodec>,

    // Got EOF from low level raw stream
    eof: bool,

    // remoteGoAway indicates the remote side does
    // not want further connections. Must be first for alignment.
    remote_go_away: bool,

    // localGoAway indicates that we should stop
    // accepting further connections. Must be first for alignment.
    local_go_away: bool,

    // nextStreamID is the next stream we should
    // send. This depends if we are a client/server.
    next_stream_id: StreamId,
    ty: SessionType,

    // config holds our configuration
    config: Config,

    // pings is used to track inflight pings
    pings: BTreeMap<u32, Instant>,
    ping_id: u32,

    // streams maps a stream id to a sender of stream,
    streams: IntMap<StreamId, Sender<Frame>>,
    // The StreamHandle not yet been polled
    pending_streams: VecDeque<StreamHandle>,
    // The buffer which will send to underlying network
    write_pending_frames: VecDeque<Frame>,
    // The buffer which will distribute to sub streams
    read_pending_frames: VecDeque<Frame>,

    // Why can unbound channel be used here?
    //
    // The only reason for the unbound channel being rejected is
    // that there is a potential memory explosion problem.
    // We just need to prove that there is no potential infinite
    // write problem here to use it safely.
    //
    // As a network library, it has two influencers, remote behavior and local behavior,
    // we discuss separately:
    //
    // remote:
    // This unbound channel cannot be used by the remote end, only for local transmission
    //
    // local:
    // Since each stream has a limit such as `send window`, when the upper limit is reached,
    // it will return to pending and can no longer send data to the channel
    //
    // The only problem is that if the stream is opened infinitely, the upper limit of the total
    // buffer will increase linearly. This behavior can be controlled by the user

    // For receive events from sub streams (for clone to new stream)
    event_sender: UnboundedSender<StreamEvent>,
    // For receive events from sub streams
    event_receiver: UnboundedReceiver<StreamEvent>,

    /// use to async open stream/close session
    control_sender: Sender<Command>,
    control_receiver: Receiver<Command>,

    keepalive: Option<Interval>,
}

/// Session type, client or server
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SessionType {
    /// The session is a client
    Client,
    /// The session is a server (typical low level stream is an accepted TcpStream)
    Server,
}

impl SessionType {
    /// If this is a client type (inbound connection)
    pub fn is_client(self) -> bool {
        self == SessionType::Client
    }

    /// If this is a server type (outbound connection)
    pub fn is_server(self) -> bool {
        self == SessionType::Server
    }
}

impl<T> Session<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new session from a low level stream
    pub fn new(raw_stream: T, config: Config, ty: SessionType) -> Session<T> {
        assert!(config.max_stream_window_size >= crate::config::INITIAL_STREAM_WINDOW);
        let next_stream_id = match ty {
            SessionType::Client => 1,
            SessionType::Server => 2,
        };
        let (event_sender, event_receiver) = unbounded();
        let (control_sender, control_receiver) = channel(32);
        let framed_stream = Framed::new(
            raw_stream,
            FrameCodec::default().max_frame_size(config.max_stream_window_size),
        );
        let keepalive = if config.enable_keepalive {
            Some(interval(config.keepalive_interval))
        } else {
            None
        };

        Session {
            framed_stream,
            eof: false,
            remote_go_away: false,
            local_go_away: false,
            next_stream_id,
            ty,
            config,
            pings: BTreeMap::default(),
            ping_id: 0,
            streams: HashMap::default(),
            pending_streams: VecDeque::default(),
            write_pending_frames: VecDeque::default(),
            read_pending_frames: VecDeque::default(),
            event_sender,
            event_receiver,
            control_sender,
            control_receiver,
            keepalive,
        }
    }

    /// Create a server session (typical raw_stream is an accepted TcpStream)
    pub fn new_server(raw_stream: T, config: Config) -> Session<T> {
        Self::new(raw_stream, config, SessionType::Server)
    }

    /// Create a client session
    pub fn new_client(raw_stream: T, config: Config) -> Session<T> {
        Self::new(raw_stream, config, SessionType::Client)
    }

    /// shutdown is used to close the session and all streams.
    /// Attempts to send a GoAway before closing the connection.
    pub fn shutdown(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        if self.is_dead() {
            return Ok(());
        }

        // Ignore frames remaining in pending queue
        self.write_pending_frames.clear();
        self.send_go_away(cx)?;
        Ok(())
    }

    // Send all pending frames to remote streams
    fn flush(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        if !self.read_pending_frames.is_empty() || !self.write_pending_frames.is_empty() {
            self.send_all(cx)?;
            self.distribute_to_substream(cx)?;
        }
        Ok(())
    }

    fn is_dead(&self) -> bool {
        self.remote_go_away && self.local_go_away || self.eof
    }

    fn send_ping(&mut self, cx: &mut Context, ping_id: Option<u32>) -> Result<u32, io::Error> {
        let (flag, ping_id) = match ping_id {
            Some(ping_id) => (Flag::Ack, ping_id),
            None => {
                self.ping_id = self.ping_id.overflowing_add(1).0;
                (Flag::Syn, self.ping_id)
            }
        };
        let frame = Frame::new_ping(Flags::from(flag), ping_id);
        self.send_frame(cx, frame).map(|_| ping_id)
    }

    /// GoAway can be used to prevent accepting further
    /// connections. It does not close the underlying conn.
    pub fn send_go_away(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        self.send_go_away_with_code(cx, GoAwayCode::Normal)
    }

    fn send_go_away_with_code(
        &mut self,
        cx: &mut Context,
        code: GoAwayCode,
    ) -> Result<(), io::Error> {
        // clear all pending write and then send go away to close session
        self.write_pending_frames.clear();
        let frame = Frame::new_go_away(code);
        self.send_frame(cx, frame)?;
        self.local_go_away = true;
        let mut new_timer = interval(self.config.connection_write_timeout);
        // force registration of new timer to driver
        let _ignore = Pin::new(&mut new_timer).as_mut().poll_next(cx);
        // Reuse the keepalive timer to set a time out. If remote peer does not respond
        // within the time out, consider this session as remote gone away.
        self.keepalive = Some(new_timer);
        Ok(())
    }

    /// Open a new stream to remote session
    pub fn open_stream(&mut self) -> Result<StreamHandle, Error> {
        if self.is_dead() {
            Err(Error::SessionShutdown)
        } else if self.remote_go_away {
            Err(Error::RemoteGoAway)
        } else {
            let stream = self.create_stream(None)?;
            Ok(stream)
        }
    }

    /// Return a control to async open stream/close session
    pub fn control(&self) -> Control {
        Control::new(self.control_sender.clone())
    }

    fn keep_alive(&mut self, cx: &mut Context, ping_at: Instant) -> Result<(), io::Error> {
        // If the remote peer does not follow the protocol, doesn't ack ping message,
        // there may be a memory leak, yamux does not clearly define how this should be handled.
        // According to the authoritative [spec](https://tools.ietf.org/html/rfc6455#section-5.5.2)
        // of websocket, the keep alive message **must** respond. If it is not responding,
        // it is a protocol exception and should be disconnected.
        if self
            .pings
            .iter()
            .any(|(_id, time)| Instant::now().saturating_duration_since(*time) > TIMEOUT)
        {
            return Err(io::ErrorKind::TimedOut.into());
        }

        let ping_id = self.send_ping(cx, None)?;
        debug!("[{:?}] sent keep_alive ping (id={:?})", self.ty, ping_id);
        self.pings.insert(ping_id, ping_at);
        Ok(())
    }

    fn create_stream(&mut self, stream_id: Option<StreamId>) -> Result<StreamHandle, Error> {
        let (stream_id, state) = match stream_id {
            Some(stream_id) => (stream_id, StreamState::SynReceived),
            None => {
                let next_id = self.next_stream_id;
                self.next_stream_id = self
                    .next_stream_id
                    .checked_add(2)
                    .ok_or(Error::StreamsExhausted)?;
                (next_id, StreamState::Init)
            }
        };
        let (frame_sender, frame_receiver) = channel(8);

        match self.streams.entry(stream_id) {
            Entry::Occupied(_) => return Err(Error::DuplicateStream),
            Entry::Vacant(entry) => entry.insert(frame_sender),
        };
        let mut stream = StreamHandle::new(
            stream_id,
            self.event_sender.clone(),
            frame_receiver,
            state,
            self.config.max_stream_window_size,
        );
        if let Err(err) = stream.send_window_update() {
            debug!("[{:?}] stream.send_window_update error={:?}", self.ty, err);
        }
        Ok(stream)
    }

    /// Sink `start_send` Ready -> data send to buffer
    /// Sink `start_send` NotReady -> buffer full need poll complete
    #[inline]
    fn send_all(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        while let Some(frame) = self.write_pending_frames.pop_front() {
            if self.is_dead() {
                break;
            }

            let mut sink = Pin::new(&mut self.framed_stream);

            match sink.as_mut().poll_ready(cx)? {
                Poll::Ready(()) => {
                    sink.as_mut().start_send(frame)?;
                }
                Poll::Pending => {
                    debug!("[{:?}] framed_stream NotReady, frame: {:?}", self.ty, frame);
                    self.write_pending_frames.push_front(frame);

                    if self.poll_complete(cx)? {
                        return Ok(true);
                    }
                }
            }
        }
        self.poll_complete(cx)?;
        Ok(false)
    }

    /// https://docs.rs/tokio/0.1.19/tokio/prelude/trait.Sink.html
    /// Must use poll complete to ensure data send to lower-level
    ///
    /// Sink `poll_complete` Ready -> no buffer remain, flush all
    /// Sink `poll_complete` NotReady -> there is more work left to do, may wake up next poll
    fn poll_complete(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        match Pin::new(&mut self.framed_stream).poll_flush(cx) {
            Poll::Pending => Ok(true),
            Poll::Ready(res) => res.map(|_| false),
        }
    }

    fn send_frame(&mut self, cx: &mut Context, frame: Frame) -> Result<(), io::Error> {
        self.write_pending_frames.push_back(frame);
        if self.send_all(cx)? {
            debug!("[{:?}] Session::send_frame() finished", self.ty);
        }
        Ok(())
    }

    fn handle_frame(&mut self, cx: &mut Context, frame: Frame) -> Result<(), io::Error> {
        match frame.ty() {
            Type::Data | Type::WindowUpdate => {
                self.handle_stream_message(cx, frame)?;
            }
            Type::Ping => {
                self.handle_ping(cx, &frame)?;
            }
            Type::GoAway => {
                self.handle_go_away(cx, &frame)?;
            }
        }
        Ok(())
    }

    /// Try send buffer to all sub streams
    fn distribute_to_substream(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        let mut block_substream = HashSet::new();
        let new = if self.read_pending_frames.len() > BUF_SHRINK_THRESHOLD {
            VecDeque::with_capacity(BUF_SHRINK_THRESHOLD)
        } else {
            VecDeque::new()
        };

        let buf = ::std::mem::replace(&mut self.read_pending_frames, new);
        for frame in buf {
            let stream_id = frame.stream_id();
            // Guarantee the order in which messages are sent
            if block_substream.contains(&stream_id) {
                trace!("substream({}) blocked", stream_id);
                self.read_pending_frames.push_back(frame);
                continue;
            }
            if frame.flags().contains(Flag::Syn) {
                if self.local_go_away {
                    let flags = Flags::from(Flag::Rst);
                    let frame = Frame::new_window_update(flags, stream_id, 0);
                    self.send_frame(cx, frame)?;
                    debug!(
                        "substream({}) local go away send Reset to remote, session.ty={:?}",
                        stream_id, self.ty
                    );
                    // TODO: should report error?
                    return Ok(());
                }
                if self.streams.len() < self.config.max_stream_count
                    && self.pending_streams.len() < self.config.accept_backlog
                {
                    debug!(
                        "substream({}) accepted, session.ty={:?}",
                        stream_id, self.ty
                    );
                    let stream = match self.create_stream(Some(stream_id)) {
                        Ok(stream) => stream,
                        Err(_) => {
                            self.send_go_away_with_code(cx, GoAwayCode::ProtocolError)?;
                            return Ok(());
                        }
                    };
                    self.pending_streams.push_back(stream);
                } else {
                    // close the stream immediately
                    debug!("substream({}) closed, session.ty={:?}", stream_id, self.ty);
                    let mut flags = Flags::from(Flag::Ack);
                    flags.add(Flag::Rst);
                    let frame = Frame::new_window_update(flags, stream_id, 0);
                    self.write_pending_frames.push_back(frame);
                }
            }
            let disconnected = {
                if let Some(frame_sender) = self.streams.get_mut(&stream_id) {
                    match frame_sender.poll_ready(cx) {
                        Poll::Ready(Ok(())) => match frame_sender.try_send(frame) {
                            Ok(_) => false,
                            Err(err) => {
                                if err.is_full() {
                                    trace!("substream({}) try_send but full", stream_id);
                                    self.read_pending_frames.push_back(err.into_inner());
                                    block_substream.insert(stream_id);
                                    false
                                } else {
                                    debug!("substream({}) try_send but failed: {}", stream_id, err);
                                    true
                                }
                            }
                        },
                        Poll::Pending => {
                            trace!("substream({}) poll_ready but pending", stream_id);
                            self.read_pending_frames.push_back(frame);
                            block_substream.insert(stream_id);
                            false
                        }
                        Poll::Ready(Err(err)) => {
                            debug!("substream({}) poll_ready but failed: {}", stream_id, err);
                            true
                        }
                    }
                } else {
                    // TODO: stream already closed ?
                    debug!(
                        "substream({}) should exist but not, may drop by self",
                        stream_id
                    );
                    false
                }
            };
            if disconnected {
                debug!("substream({}) removed, session.ty={:?}", stream_id, self.ty);
                self.streams.remove(&stream_id);
            }
        }

        Ok(())
    }

    // Send message to stream (Data/WindowUpdate)
    fn handle_stream_message(&mut self, cx: &mut Context, frame: Frame) -> Result<(), io::Error> {
        self.read_pending_frames.push_back(frame);
        self.distribute_to_substream(cx)?;
        Ok(())
    }

    fn handle_ping(&mut self, cx: &mut Context, frame: &Frame) -> Result<(), io::Error> {
        let flags = frame.flags();
        if flags.contains(Flag::Syn) {
            // Send ping back
            self.send_ping(cx, Some(frame.length()))?;
        } else if flags.contains(Flag::Ack) {
            self.pings.remove(&frame.length());
            // If the remote peer does not follow the protocol,
            // there may be a memory leak, so here need to discard all ping ids below the ack.
            self.pings = self.pings.split_off(&frame.length());
        } else {
            // TODO: unexpected case, send a GoAwayCode::ProtocolError ?
        }
        Ok(())
    }

    fn handle_go_away(&mut self, cx: &mut Context, frame: &Frame) -> Result<(), io::Error> {
        let mut close = || -> Result<(), io::Error> {
            self.remote_go_away = true;
            self.write_pending_frames.clear();
            if !self.local_go_away {
                self.send_go_away(cx)?;
            }
            Ok(())
        };
        match GoAwayCode::from(frame.length()) {
            GoAwayCode::Normal => close(),
            GoAwayCode::ProtocolError => {
                // TODO: report error
                close()
            }
            GoAwayCode::InternalError => {
                // TODO: report error
                close()
            }
        }
    }

    // Receive frames from low level stream
    fn recv_frames(&mut self, cx: &mut Context) -> Poll<Option<Result<(), io::Error>>> {
        trace!("[{:?}] poll from framed_stream", self.ty);
        match Pin::new(&mut self.framed_stream).as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                self.handle_frame(cx, frame)?;
                Poll::Ready(Some(Ok(())))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(None)
            }
            Poll::Pending => {
                trace!("[{:?}] poll framed_stream NotReady", self.ty);
                Poll::Pending
            }
            Poll::Ready(Some(Err(err))) => {
                debug!("[{:?}] Session recv_frames error: {:?}", self.ty, err);
                Poll::Ready(Some(Err(err)))
            }
        }
    }

    fn handle_event(&mut self, cx: &mut Context, event: StreamEvent) -> Result<(), io::Error> {
        match event {
            StreamEvent::Frame(frame) => {
                self.send_frame(cx, frame)?;
            }
            StreamEvent::Closed(stream_id) => {
                self.streams.remove(&stream_id);
                if self.streams.capacity() - self.streams.len() > BUF_SHRINK_THRESHOLD {
                    self.streams.shrink_to_fit();
                }
            }
            StreamEvent::GoAway => self.send_go_away_with_code(cx, GoAwayCode::ProtocolError)?,
        }
        Ok(())
    }

    // Receive events from sub streams
    fn recv_events(&mut self, cx: &mut Context) -> Poll<Option<Result<(), io::Error>>> {
        match Pin::new(&mut self.event_receiver).as_mut().poll_next(cx) {
            Poll::Ready(Some(event)) => {
                self.handle_event(cx, event)?;
                Poll::Ready(Some(Ok(())))
            }
            Poll::Ready(None) => {
                // Since session hold one event sender,
                // the channel can not be disconnected.
                unreachable!()
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn control_poll(&mut self, cx: &mut Context) -> Poll<Option<Result<(), io::Error>>> {
        match Pin::new(&mut self.control_receiver).as_mut().poll_next(cx) {
            Poll::Ready(Some(event)) => {
                match event {
                    Command::OpenStream(tx) => {
                        let _ignore = tx.send(self.open_stream());
                    }
                    Command::Shutdown(tx) => {
                        self.shutdown(cx)?;
                        let _ignore = tx.send(());
                    }
                }
                Poll::Ready(Some(Ok(())))
            }
            Poll::Ready(None) => {
                // Since session hold one event sender,
                // the channel can not be disconnected.
                unreachable!()
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> Stream for Session<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Item = Result<StreamHandle, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if self.is_dead() {
            debug!("yamux::Session finished because is_dead");
            return Poll::Ready(None);
        }

        if log_enabled!(log::Level::Trace)
            && !(self.write_pending_frames.is_empty() && self.read_pending_frames.is_empty())
        {
            trace!(
                "yamux::Session write_pending_frames: {}, read_pending_frames: {}",
                self.write_pending_frames.len(),
                self.read_pending_frames.len()
            );
        }

        if let Some(ref mut interval) = self.keepalive {
            match Pin::new(interval).as_mut().poll_next(cx) {
                Poll::Ready(Some(_)) => {
                    if self.local_go_away {
                        // The remote peer has not responded to our sent go away code.
                        // Assume that remote peer has gone away and this session should be closed.
                        self.remote_go_away = true;
                    } else {
                        self.keep_alive(cx, Instant::now())?;
                    }
                }
                Poll::Ready(None) => {
                    debug!("yamux::Session poll keepalive interval finished");
                }
                Poll::Pending => (),
            }
        }

        let mut need_wake = false;

        for _ in 0..16 {
            if self.is_dead() {
                debug!("yamux::Session finished because is_dead, end");
                return Poll::Ready(None);
            }

            // Reset initial value
            need_wake = false;

            self.flush(cx)?;
            self.poll_complete(cx)?;

            // Open stream as soon as possible
            if let Some(stream) = self.pending_streams.pop_front() {
                debug!("yamux::Session [{:?}] A stream is ready", self.ty);
                return Poll::Ready(Some(Ok(stream)));
            }

            let mut is_pending = self.control_poll(cx)?.is_pending();
            is_pending &= self.recv_frames(cx)?.is_pending();
            is_pending &= self.recv_events(cx)?.is_pending();

            if is_pending {
                break;
            } else {
                need_wake = true;
            }
        }

        if need_wake {
            // To ensure we do not starve other tasks waiting on the executor,
            // we yield here, but immediately wake ourselves up to continue.
            cx.waker().wake_by_ref()
        }

        Poll::Pending
    }
}

mod timer {
    #[cfg(feature = "generic-timer")]
    pub use generic_time::{interval, Interval};
    #[cfg(feature = "tokio-timer")]
    pub use inter::{interval, Interval};

    #[cfg(feature = "tokio-timer")]
    mod inter {
        use futures::Stream;
        use std::{
            pin::Pin,
            task::{Context, Poll},
            time::Duration,
        };
        use tokio::time::{interval_at, Instant, Interval as Inner};

        pub struct Interval(Inner);

        impl Interval {
            fn new(period: Duration) -> Self {
                Self(interval_at(Instant::now() + period, period))
            }
        }

        impl Stream for Interval {
            type Item = ();

            fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
                match self.0.poll_tick(cx) {
                    Poll::Ready(_) => Poll::Ready(Some(())),
                    Poll::Pending => Poll::Pending,
                }
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                (std::usize::MAX, None)
            }
        }

        pub fn interval(period: Duration) -> Interval {
            Interval::new(period)
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub use wasm_mock::Instant;

    #[cfg(feature = "generic-timer")]
    mod generic_time {
        use futures::{Future, Stream};
        use futures_timer::Delay;
        use std::{
            pin::Pin,
            task::{Context, Poll},
            time::Duration,
        };

        pub struct Interval {
            delay: Delay,
            period: Duration,
        }

        impl Interval {
            fn new(period: Duration) -> Self {
                Self {
                    delay: Delay::new(period),
                    period,
                }
            }
        }

        impl Stream for Interval {
            type Item = ();

            fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
                match Pin::new(&mut self.delay).poll(cx) {
                    Poll::Ready(_) => {
                        let dur = self.period;
                        self.delay.reset(dur);
                        #[cfg(target_arch = "wasm32")]
                        unsafe {
                            super::super::TIME += dur;
                        }
                        Poll::Ready(Some(()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        pub fn interval(period: Duration) -> Interval {
            assert!(period > Duration::new(0, 0), "`period` must be non-zero.");

            Interval::new(period)
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    mod wasm_mock {
        use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
        use std::ops::{Add, AddAssign, Sub};
        use std::time::Duration;

        #[derive(Debug, Copy, Clone)]
        pub struct Instant {
            /// mock
            inner: u64,
        }

        impl PartialEq for Instant {
            fn eq(&self, other: &Instant) -> bool {
                // Note that this will most likely only compare equal if we clone an `Instant`,
                // but that's ok.
                self.inner == other.inner
            }
        }

        impl Eq for Instant {}

        impl PartialOrd for Instant {
            fn partial_cmp(&self, other: &Instant) -> Option<Ordering> {
                self.inner.partial_cmp(&other.inner)
            }
        }

        impl Ord for Instant {
            fn cmp(&self, other: &Self) -> Ordering {
                self.inner.partial_cmp(&other.inner).unwrap()
            }
        }

        impl Instant {
            pub const fn from_u64(val: u64) -> Self {
                Instant { inner: val }
            }

            pub fn now() -> Instant {
                unsafe { super::super::TIME }
            }

            pub fn duration_since(&self, earlier: Instant) -> Duration {
                *self - earlier
            }

            pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
                *self - earlier
            }

            pub fn elapsed(&self) -> Duration {
                Instant::now() - *self
            }
        }

        impl Add<Duration> for Instant {
            type Output = Instant;

            fn add(self, other: Duration) -> Instant {
                let new_val = self.inner + other.as_millis() as u64;
                Instant { inner: new_val }
            }
        }

        impl Sub<Duration> for Instant {
            type Output = Instant;

            fn sub(self, other: Duration) -> Instant {
                let new_val = self
                    .inner
                    .checked_sub(other.as_millis() as u64)
                    .unwrap_or_default();
                Instant { inner: new_val }
            }
        }

        impl Sub<Instant> for Instant {
            type Output = Duration;

            fn sub(self, other: Instant) -> Duration {
                let ms = self.inner.checked_sub(other.inner).unwrap_or_default();
                Duration::from_millis(ms)
            }
        }

        impl AddAssign<Duration> for Instant {
            fn add_assign(&mut self, rhs: Duration) {
                *self = *self + rhs;
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn rt() -> &'static tokio::runtime::Runtime {
    static RT: once_cell::sync::OnceCell<tokio::runtime::Runtime> =
        once_cell::sync::OnceCell::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap())
}

#[cfg(test)]
mod test {
    use super::{rt, Session};
    use crate::{
        config::Config,
        frame::{Flag, Flags, Frame, FrameCodec, GoAwayCode, Type},
    };
    use futures::{
        channel::mpsc::{channel, Receiver, Sender},
        stream::FusedStream,
        SinkExt, Stream, StreamExt,
    };
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio_util::codec::Framed;

    struct MockSocket {
        sender: Sender<Vec<u8>>,
        receiver: Receiver<Vec<u8>>,
        read_buffer: Vec<u8>,
    }

    impl MockSocket {
        fn new() -> (Self, Self) {
            let (tx, rx) = channel(25);
            let (tx_1, rx_1) = channel(25);

            (
                MockSocket {
                    sender: tx,
                    receiver: rx_1,
                    read_buffer: Default::default(),
                },
                MockSocket {
                    sender: tx_1,
                    receiver: rx,
                    read_buffer: Default::default(),
                },
            )
        }
    }

    impl AsyncRead for MockSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                if self.receiver.is_terminated() {
                    break;
                }
                match Pin::new(&mut self.receiver).poll_next(cx) {
                    Poll::Ready(Some(data)) => self.read_buffer.extend(data),
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                    }
                    Poll::Pending => break,
                }
            }

            let n = ::std::cmp::min(buf.remaining(), self.read_buffer.len());

            if n == 0 {
                Poll::Pending
            } else {
                buf.put_slice(&self.read_buffer[..n]);
                self.read_buffer.drain(..n);
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for MockSocket {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.sender.poll_ready(cx) {
                Poll::Ready(Ok(())) => match self.sender.try_send(buf.to_vec()) {
                    Ok(_) => Poll::Ready(Ok(buf.len())),
                    Err(e) => {
                        if e.is_full() {
                            Poll::Pending
                        } else {
                            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
                        }
                    }
                },
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            self.receiver.close();
            self.sender.close_channel();
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn test_open_exist_stream() {
        let rt = rt();

        rt.block_on(async {
            let (remote, local) = MockSocket::new();
            let config = Config {
                enable_keepalive: false,
                ..Default::default()
            };

            let mut session = Session::new_server(local, config);

            tokio::spawn(async move {
                while let Some(Ok(mut stream)) = session.next().await {
                    tokio::spawn(async move {
                        let mut buf = [0; 100];
                        let _ignore = stream.read(&mut buf).await;
                    });
                }
            });

            let mut client = Framed::new(
                remote,
                FrameCodec::default().max_frame_size(config.max_stream_window_size),
            );

            let next_stream_id = 3;
            // open stream
            let frame = Frame::new_window_update(Flags::from(Flag::Syn), next_stream_id, 0);
            client.send(frame).await.unwrap();
            // stream window respond
            assert_eq!(
                Frame::new_window_update(Flags::from(Flag::Ack), next_stream_id, 0),
                client.next().await.unwrap().unwrap()
            );

            // open stream with duplicate stream id
            let frame = Frame::new_window_update(Flags::from(Flag::Syn), next_stream_id, 0);
            client.send(frame).await.unwrap();

            // get go away with protocol error
            let go_away = client.next().await.unwrap().unwrap();

            assert_eq!(go_away.ty(), Type::GoAway);
            assert_eq!(
                GoAwayCode::from(go_away.length()),
                GoAwayCode::ProtocolError
            )
        })
    }

    // issue: https://github.com/nervosnetwork/tentacle/issues/259
    // The reason for the problem is that when the session is closed,
    // all stream states are not set to `RemoteClosed`
    //
    // This test can simulate a stuck state. If it is not set,
    // the test will remain stuck and cannot be finished.
    #[test]
    fn test_close_session_on_stream_opened() {
        let rt = rt();

        rt.block_on(async {
            let (remote, local) = MockSocket::new();
            let config = Config::default();

            let mut session = Session::new_server(local, config);

            tokio::spawn(async move {
                while let Some(Ok(mut stream)) = session.next().await {
                    tokio::spawn(async move {
                        let mut buf = [0; 100];
                        let _ignore = stream.read(&mut buf).await;
                    });
                }
            });

            let mut client = Session::new_client(remote, config);

            let mut control = client.control();

            let mut stream = client.open_stream().unwrap();

            tokio::spawn(async move {
                loop {
                    match client.next().await {
                        Some(Ok(_)) => (),
                        Some(Err(_)) => {
                            break;
                        }
                        None => {
                            break;
                        }
                    }
                }
            });
            tokio::spawn(async move {
                control.close().await;
            });
            let mut buf = [0; 100];
            let _ignore = stream.read(&mut buf).await;
        })
    }

    #[test]
    fn test_open_too_many_stream() {
        let rt = rt();

        rt.block_on(async {
            let (remote, local) = MockSocket::new();
            let config = Config {
                enable_keepalive: false,
                max_stream_count: 1,
                ..Default::default()
            };

            let mut session = Session::new_server(local, config);

            tokio::spawn(async move {
                while let Some(Ok(mut stream)) = session.next().await {
                    tokio::spawn(async move {
                        let mut buf = [0; 100];
                        let _ignore = stream.read(&mut buf).await;
                    });
                }
            });

            let mut client = Framed::new(
                remote,
                FrameCodec::default().max_frame_size(config.max_stream_window_size),
            );

            let next_stream_id = 3;
            // open stream
            let frame = Frame::new_window_update(Flags::from(Flag::Syn), next_stream_id, 0);
            client.send(frame).await.unwrap();
            // stream window respond
            assert_eq!(
                Frame::new_window_update(Flags::from(Flag::Ack), next_stream_id, 0),
                client.next().await.unwrap().unwrap()
            );

            let frame = Frame::new_window_update(Flags::from(Flag::Syn), next_stream_id + 2, 0);
            client.send(frame).await.unwrap();

            // get reset msg
            let reset_msg = client.next().await.unwrap().unwrap();

            assert_eq!(reset_msg.ty(), Type::WindowUpdate);
            assert!(!reset_msg.flags().contains(Flag::Syn));
            assert!(reset_msg.flags().contains(Flag::Ack));
            assert!(reset_msg.flags().contains(Flag::Rst));
            assert_eq!(reset_msg.stream_id(), 5)
        });
    }

    #[test]
    fn test_remote_does_not_respond_go_away() {
        let rt = rt();

        rt.block_on(async {
            let (_remote, local) = MockSocket::new();
            let config = Config {
                enable_keepalive: false,
                connection_write_timeout: Duration::from_secs(1),
                ..Default::default()
            };

            let mut session = Session::new_server(local, config);

            let mut control = session.control();
            tokio::spawn(async move {
                let _ignore = control.close().await;
            });

            // The purpose of this test is to ensure that if the remote does not respond to the
            // go away message, it must be able to actively disconnect the session instead of hanging.
            // So, if the test fails to exit, it means there has a problem
            while let Some(Ok(mut stream)) = session.next().await {
                tokio::spawn(async move {
                    let mut buf = [0; 100];
                    let _ignore = stream.read(&mut buf).await;
                });
            }
        });
    }

    #[test]
    fn test_dynamically_config_the_window_size() {
        let rt = rt();
        rt.block_on(async {
            let (remote, local) = MockSocket::new();

            let config = Config::default();

            let mut session = Session::new_server(local, config);

            tokio::spawn(async move {
                while let Some(Ok(mut stream)) = session.next().await {
                    tokio::spawn(async move {
                        let _ignore = stream.read_exact(&mut [0]).await;
                        assert!(stream.send_window() == 1024 * 1024);
                        assert!(stream.recv_window() == 256 * 1024 - 1);
                        let mut buf = vec![1; 1024 * 1024];
                        let _ignore = stream.write_all(&buf).await;
                        let _ignore = stream.read(&mut buf).await;
                    });
                }
            });

            let config = Config {
                max_stream_window_size: 1024 * 1024,
                ..Default::default()
            };

            let mut client = Session::new_client(remote, config);

            let mut control = client.control();

            let mut stream = client.open_stream().unwrap();

            tokio::spawn(async move {
                loop {
                    match client.next().await {
                        Some(Ok(_)) => (),
                        Some(Err(_)) => {
                            break;
                        }
                        None => {
                            break;
                        }
                    }
                }
            });

            let _ignore = stream.write_all(&[1]).await;
            assert!(stream.send_window() == 256 * 1024 - 1);
            assert!(stream.recv_window() == 1024 * 1024);
            let mut buf = vec![0; 1024 * 1024];
            let _ignore = stream.read_exact(&mut buf).await;

            tokio::spawn(async move {
                control.close().await;
            });

            assert_eq!(vec![1; 1024 * 1024], buf)
        })
    }
}
