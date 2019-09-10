//! The session, can open and manage substreams

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{
    channel::mpsc::{channel, Receiver, Sender},
    Sink, SinkExt, Stream,
};
use log::{debug, warn};
use tokio::codec::Framed;
use tokio::prelude::{AsyncRead, AsyncWrite};
use tokio::timer::Interval;

use crate::{
    config::Config,
    error::Error,
    frame::{Flag, Flags, Frame, FrameCodec, GoAwayCode, Type},
    stream::{StreamEvent, StreamHandle, StreamState},
    StreamId,
};

const BUF_SHRINK_THRESHOLD: usize = u8::max_value() as usize;
const DELAY_TIME: Duration = Duration::from_millis(300);
const TIMEOUT: Duration = Duration::from_secs(30);

/// The session
pub struct Session<T> {
    // Framed low level raw stream
    framed_stream: Framed<T, FrameCodec>,

    // Got EOF from low level raw stream
    eof: bool,

    // remoteGoAway indicates the remote side does
    // not want futher connections. Must be first for alignment.
    remote_go_away: bool,

    // localGoAway indicates that we should stop
    // accepting futher connections. Must be first for alignment.
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
    streams: HashMap<StreamId, Sender<Frame>>,
    // inflight has an entry for any outgoing stream that has not yet been established.
    inflight: HashSet<StreamId>,
    // The StreamHandle not yet been polled
    pending_streams: VecDeque<StreamHandle>,
    // The buffer which will send to underlying network
    write_pending_frames: VecDeque<Frame>,
    // The buffer which will distribute to sub streams
    read_pending_frames: VecDeque<Frame>,

    // For receive events from sub streams (for clone to new stream)
    event_sender: Sender<StreamEvent>,
    // For receive events from sub streams
    event_receiver: Receiver<StreamEvent>,

    keepalive_receiver: Option<Receiver<()>>,
    /// Delay notify with abnormally poor network status
    delay: Arc<AtomicBool>,
    /// Last successful send time
    last_send_success: Instant,
    /// Last successful read time
    last_read_success: Instant,
    /// Last ping time
    last_ping_time: Instant,
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
        let next_stream_id = match ty {
            SessionType::Client => 1,
            SessionType::Server => 2,
        };
        let (event_sender, event_receiver) = channel(32);
        let framed_stream = Framed::new(
            raw_stream,
            FrameCodec::default().max_frame_size(config.max_stream_window_size),
        );
        let keepalive_receiver = if config.enable_keepalive {
            let (mut interval_sender, interval_receiver) = channel(2);
            // NOTE: Set a 300ms interval because we want shutdown service quick.
            //       A Interval/Delay will block tokio runtime from gracefully shutdown.
            let mut interval = Interval::new_interval(Duration::from_millis(300));
            tokio::spawn(async move {
                loop {
                    match interval.next().await {
                        Some(_) => (),
                        None => break,
                    }
                    match interval_sender.send(()).await {
                        Ok(_) => (),
                        Err(e) => {
                            if !e.is_full() {
                                break;
                            }
                        }
                    }
                }
            });
            Some(interval_receiver)
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
            inflight: HashSet::default(),
            pending_streams: VecDeque::default(),
            write_pending_frames: VecDeque::default(),
            read_pending_frames: VecDeque::default(),
            event_sender,
            event_receiver,
            keepalive_receiver,
            delay: Arc::new(AtomicBool::new(false)),
            last_send_success: Instant::now(),
            last_read_success: Instant::now(),
            last_ping_time: Instant::now(),
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
        self.recv_events(cx)?;
        self.send_all(cx)?;
        self.distribute_to_substream(cx)?;
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
        self.local_go_away = true;
        let frame = Frame::new_go_away(GoAwayCode::Normal);
        self.send_frame(cx, frame)
    }

    /// Open a new stream to remote session
    pub fn open_stream(&mut self) -> Result<StreamHandle, Error> {
        if self.is_dead() {
            Err(Error::SessionShutdown)
        } else if self.remote_go_away {
            Err(Error::RemoteGoAway)
        } else {
            let stream = self.create_stream(None)?;
            self.inflight.insert(stream.id());
            Ok(stream)
        }
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
            .any(|(_id, time)| time.elapsed() > TIMEOUT)
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
        self.streams.entry(stream_id).or_insert(frame_sender);
        let mut stream = StreamHandle::new(
            stream_id,
            self.event_sender.clone(),
            frame_receiver,
            state,
            self.config.max_stream_window_size,
            self.config.max_stream_window_size,
        );
        if let Err(err) = stream.send_window_update() {
            debug!("[{:?}] stream.send_window_update error={:?}", self.ty, err);
        }
        Ok(stream)
    }

    /// Sink `start_send` Ready -> data in buffer or send
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
                    self.last_send_success = Instant::now();
                }
                Poll::Pending => {
                    debug!("[{:?}] framed_stream NotReady, frame: {:?}", self.ty, frame);
                    self.write_pending_frames.push_front(frame);
                    // No message has been sent for 30 seconds,
                    // we believe the connection is no longer valid
                    if self.last_send_success.elapsed() > TIMEOUT {
                        return Err(io::ErrorKind::TimedOut.into());
                    }

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
            Poll::Pending => {
                self.set_delay(cx);
                Ok(true)
            }
            Poll::Ready(res) => {
                res?;
                Ok(false)
            }
        }
    }

    fn send_frame(&mut self, cx: &mut Context, frame: Frame) -> Result<(), io::Error> {
        debug!("[{:?}] Session::send_frame()", self.ty);
        self.write_pending_frames.push_back(frame);
        if self.send_all(cx)? {
            debug!("[{:?}] Session::send_frame() finished", self.ty);
        }
        Ok(())
    }

    fn handle_frame(&mut self, cx: &mut Context, frame: Frame) -> Result<(), io::Error> {
        debug!("[{:?}] Session::handle_frame({:?})", self.ty, frame.ty());
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

        for frame in self.read_pending_frames.split_off(0) {
            let stream_id = frame.stream_id();
            // Guarantee the order in which messages are sent
            if block_substream.contains(&stream_id) {
                self.read_pending_frames.push_back(frame);
                continue;
            }
            if frame.flags().contains(Flag::Syn) {
                if self.local_go_away {
                    let flags = Flags::from(Flag::Rst);
                    let frame = Frame::new_window_update(flags, stream_id, 0);
                    self.send_frame(cx, frame)?;
                    debug!(
                        "[{:?}] local go away send Reset to remote stream_id={}",
                        self.ty, stream_id
                    );
                    // TODO: should report error?
                    return Ok(());
                }
                debug!("[{:?}] Accept a stream id={}", self.ty, stream_id);
                let stream = self
                    .create_stream(Some(stream_id))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                self.pending_streams.push_back(stream);
            }
            let disconnected = {
                if let Some(frame_sender) = self.streams.get_mut(&stream_id) {
                    debug!("@> sending frame to stream: {}", stream_id);
                    match frame_sender.try_send(frame) {
                        Ok(_) => false,
                        Err(err) => {
                            if err.is_full() {
                                self.read_pending_frames.push_back(err.into_inner());
                                self.set_delay(cx);
                                block_substream.insert(stream_id);
                                false
                            } else {
                                debug!("send to stream error: {:?}", err);
                                true
                            }
                        }
                    }
                } else {
                    // TODO: stream already closed ?
                    false
                }
            };
            if disconnected {
                debug!("[{:?}] remove a stream id={}", self.ty, stream_id);
                self.streams.remove(&stream_id);
            }
        }

        if self.read_pending_frames.capacity() > BUF_SHRINK_THRESHOLD {
            self.read_pending_frames.shrink_to_fit();
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
    fn recv_frames(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        for _ in 0..64 {
            if self.is_dead() {
                return Ok(());
            }

            debug!("[{:?}] poll from framed_stream", self.ty);
            match Pin::new(&mut self.framed_stream).as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    self.handle_frame(cx, frame)?;
                    self.last_read_success = Instant::now();
                }
                Poll::Ready(None) => {
                    self.eof = true;
                }
                Poll::Pending => {
                    debug!("[{:?}] poll framed_stream NotReady", self.ty);
                    return Ok(());
                }
                Poll::Ready(Some(Err(err))) => {
                    debug!("[{:?}] Session recv_frames error: {:?}", self.ty, err);
                    return Err(err);
                }
            }
        }
        self.set_delay(cx);
        Ok(())
    }

    fn handle_event(&mut self, cx: &mut Context, event: StreamEvent) -> Result<(), io::Error> {
        debug!("[{:?}] Session::handle_event()", self.ty);
        match event {
            StreamEvent::Frame(frame) => {
                self.send_frame(cx, frame)?;
            }
            StreamEvent::StateChanged((stream_id, state)) => {
                match state {
                    StreamState::Closed => {
                        self.streams.remove(&stream_id);
                    }
                    StreamState::Established => {
                        self.inflight.remove(&stream_id);
                    }
                    // For further functions
                    _ => {}
                }
            }
            StreamEvent::Flush(stream_id) => {
                debug!("[{}] session flushing.....", stream_id);
                self.flush(cx)?;
                debug!("[{}] session flushed", stream_id);
            }
        }
        Ok(())
    }

    // Receive events from sub streams
    // TODO: should handle error
    fn recv_events(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        for _ in 0..64 {
            if self.is_dead() {
                return Ok(());
            }

            match Pin::new(&mut self.event_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(event)) => self.handle_event(cx, event)?,
                Poll::Ready(None) => {
                    // Since session hold one event sender,
                    // the channel can not be disconnected.
                    unreachable!()
                }
                Poll::Pending => {
                    return Ok(());
                }
            }
        }
        self.set_delay(cx);
        Ok(())
    }

    #[inline]
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
                tokio::timer::delay(Instant::now() + DELAY_TIME).await;
                waker.wake();
                delay.store(false, Ordering::Release);
            });
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

        if !self.read_pending_frames.is_empty() || !self.write_pending_frames.is_empty() {
            self.flush(cx)?;
        }

        self.poll_complete(cx)?;

        debug!(
            "send buf: {}, read buf: {}",
            self.write_pending_frames.len(),
            self.read_pending_frames.len()
        );

        while let Some(ref mut receiver) = self.keepalive_receiver {
            match Pin::new(receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(_)) => {
                    if self.last_ping_time.elapsed() > self.config.keepalive_interval {
                        self.keep_alive(cx, Instant::now())?;
                        self.last_ping_time = Instant::now();
                    }
                }
                Poll::Ready(None) => {
                    debug!("poll keepalive_receiver finished");
                    break;
                }
                Poll::Pending => break,
            }
        }

        // Interval broken or Stream error on here, just break this pipe
        if self.last_read_success.elapsed()
            > self.config.keepalive_interval + Duration::from_secs(15)
        {
            warn!("yamux timeout");
            self.shutdown(cx)?;
            return Poll::Ready(Some(Err(io::ErrorKind::TimedOut.into())));
        }

        self.recv_frames(cx)?;
        self.recv_events(cx)?;

        if self.is_dead() {
            debug!("yamux::Session finished because is_dead, end");
            return Poll::Ready(None);
        } else if let Some(stream) = self.pending_streams.pop_front() {
            debug!("[{:?}] A stream is ready", self.ty);
            return Poll::Ready(Some(Ok(stream)));
        }

        Poll::Pending
    }
}
