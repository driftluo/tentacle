//! The session, can open and manage substreams

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::time::Instant;

use fnv::{FnvHashMap, FnvHashSet};
use futures::{
    sync::mpsc::{channel, Receiver, Sender},
    task::{self, Task},
    try_ready, Async, AsyncSink, Poll, Sink, Stream,
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
    streams: FnvHashMap<StreamId, Sender<Frame>>,
    // inflight has an entry for any outgoing stream that has not yet been established.
    inflight: FnvHashSet<StreamId>,
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

    keepalive_future: Option<Interval>,

    notify: Option<Task>,
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
    T: AsyncRead + AsyncWrite,
{
    /// Create a new session from a low level stream
    pub fn new(raw_stream: T, config: Config, ty: SessionType) -> Session<T> {
        let next_stream_id = match ty {
            SessionType::Client => 1,
            SessionType::Server => 2,
        };
        let (event_sender, event_receiver) = channel(32);
        let framed_stream = Framed::new(raw_stream, FrameCodec::default());
        let keepalive_future = if config.enable_keepalive {
            Some(Interval::new_interval(config.keepalive_interval))
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
            streams: FnvHashMap::default(),
            inflight: FnvHashSet::default(),
            pending_streams: VecDeque::default(),
            write_pending_frames: VecDeque::default(),
            read_pending_frames: VecDeque::default(),
            event_sender,
            event_receiver,
            keepalive_future,
            notify: None,
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
    pub fn shutdown(&mut self) -> Poll<(), io::Error> {
        if self.is_dead() {
            return Ok(Async::Ready(()));
        }
        if !self.write_pending_frames.is_empty() {
            self.send_all()?;
        }
        self.send_go_away()?;
        Ok(Async::Ready(()))
    }

    // Send all pending frames to remote streams
    fn flush(&mut self) -> Result<(), io::Error> {
        self.recv_events()?;
        self.send_all()?;
        self.distribute_to_substream()?;
        Ok(())
    }

    fn is_dead(&self) -> bool {
        self.remote_go_away && self.local_go_away || self.eof
    }

    fn send_ping(&mut self, ping_id: Option<u32>) -> Poll<u32, io::Error> {
        let (flag, ping_id) = match ping_id {
            Some(ping_id) => (Flag::Ack, ping_id),
            None => {
                self.ping_id = self.ping_id.overflowing_add(1).0;
                (Flag::Syn, self.ping_id)
            }
        };
        let frame = Frame::new_ping(Flags::from(flag), ping_id);
        self.send_frame(frame).map(|_| Async::Ready(ping_id))
    }

    /// GoAway can be used to prevent accepting further
    /// connections. It does not close the underlying conn.
    pub fn send_go_away(&mut self) -> Poll<(), io::Error> {
        self.local_go_away = true;
        let frame = Frame::new_go_away(GoAwayCode::Normal);
        self.send_frame(frame)
    }

    /// Open a new stream to remote session
    pub fn open_stream(&mut self) -> Result<StreamHandle, Error> {
        if self.is_dead() {
            Err(Error::SessionShutdown)
        } else if self.remote_go_away {
            Err(Error::RemoteGoAway)
        } else {
            let stream = self.create_stream(None);
            self.inflight.insert(stream.id());
            Ok(stream)
        }
    }

    fn keep_alive(&mut self, ping_at: Instant) -> Poll<(), io::Error> {
        let ping_id = try_ready!(self.send_ping(None));
        debug!("[{:?}] sent keep_alive ping (id={:?})", self.ty, ping_id);
        self.pings.insert(ping_id, ping_at);
        Ok(Async::Ready(()))
    }

    fn create_stream(&mut self, stream_id: Option<StreamId>) -> StreamHandle {
        let (stream_id, state) = match stream_id {
            Some(stream_id) => (stream_id, StreamState::SynReceived),
            None => {
                let next_id = self.next_stream_id;
                self.next_stream_id += 2;
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
        stream
    }

    #[inline]
    fn send_all(&mut self) -> Poll<(), io::Error> {
        while let Some(frame) = self.write_pending_frames.pop_front() {
            if self.is_dead() {
                break;
            }

            match self.framed_stream.start_send(frame) {
                Ok(AsyncSink::NotReady(frame)) => {
                    debug!("[{:?}] framed_stream NotReady, frame: {:?}", self.ty, frame);
                    self.write_pending_frames.push_front(frame);
                    self.notify();
                    return Ok(Async::NotReady);
                }
                Ok(AsyncSink::Ready) => {}
                Err(err) => {
                    debug!("[{:?}] framed_stream error: {:?}", self.ty, err);
                    return Err(err);
                }
            }
        }
        // TODO: not ready???
        self.framed_stream.poll_complete()?;
        Ok(Async::Ready(()))
    }

    fn send_frame(&mut self, frame: Frame) -> Poll<(), io::Error> {
        debug!("[{:?}] Session::send_frame({:?})", self.ty, frame);
        self.write_pending_frames.push_back(frame);
        if let Async::NotReady = self.send_all()? {
            return Ok(Async::NotReady);
        }
        debug!("[{:?}] Session::send_frame() finished", self.ty);
        Ok(Async::Ready(()))
    }

    fn handle_frame(&mut self, frame: Frame) -> Result<(), io::Error> {
        debug!("[{:?}] Session::handle_frame({:?})", self.ty, frame);
        match frame.ty() {
            Type::Data | Type::WindowUpdate => {
                self.handle_stream_message(frame)?;
            }
            Type::Ping => {
                self.handle_ping(&frame)?;
            }
            Type::GoAway => {
                self.handle_go_away(&frame)?;
            }
        }
        Ok(())
    }

    /// Try send buffer to all sub streams
    fn distribute_to_substream(&mut self) -> Result<(), io::Error> {
        for frame in self.read_pending_frames.split_off(0) {
            let stream_id = frame.stream_id();
            if frame.flags().contains(Flag::Syn) {
                if self.local_go_away {
                    let flags = Flags::from(Flag::Rst);
                    let frame = Frame::new_window_update(flags, stream_id, 0);
                    self.send_frame(frame)?;
                    debug!(
                        "[{:?}] local go away send Reset to remote stream_id={}",
                        self.ty, stream_id
                    );
                    // TODO: should report error?
                    return Ok(());
                }
                debug!("[{:?}] Accept a stream id={}", self.ty, stream_id);
                let stream = self.create_stream(Some(stream_id));
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
                                self.notify();
                                false
                            } else {
                                warn!("send to stream error: {:?}", err);
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
                warn!("[{:?}] !!!!! remove a stream id={}", self.ty, stream_id);
                self.streams.remove(&stream_id);
            }
        }
        Ok(())
    }

    // Send message to stream (Data/WindowUpdate)
    fn handle_stream_message(&mut self, frame: Frame) -> Result<(), io::Error> {
        self.read_pending_frames.push_back(frame);
        self.distribute_to_substream()?;
        Ok(())
    }

    fn handle_ping(&mut self, frame: &Frame) -> Result<(), io::Error> {
        let flags = frame.flags();
        if flags.contains(Flag::Syn) {
            // Send ping back
            self.send_ping(Some(frame.length()))?;
        } else if flags.contains(Flag::Ack) {
            self.pings.remove(&frame.length());
        } else {
            // TODO: unexpected case, send a GoAwayCode::ProtocolError ?
        }
        Ok(())
    }

    fn handle_go_away(&mut self, frame: &Frame) -> Result<(), io::Error> {
        let mut close = || -> Result<(), io::Error> {
            self.remote_go_away = true;
            self.write_pending_frames.clear();
            if !self.local_go_away {
                self.send_go_away()?;
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
    fn recv_frames(&mut self) -> Poll<(), io::Error> {
        loop {
            if self.is_dead() {
                return Ok(Async::Ready(()));
            }

            debug!("[{:?}] poll from framed_stream", self.ty);
            match self.framed_stream.poll() {
                Ok(Async::Ready(Some(frame))) => {
                    self.handle_frame(frame)?;
                }
                Ok(Async::Ready(None)) => {
                    self.eof = true;
                }
                Ok(Async::NotReady) => {
                    debug!("[{:?}] poll framed_stream NotReady", self.ty);
                    return Ok(Async::NotReady);
                }
                Err(err) => {
                    warn!("[{:?}] Session recv_frames error: {:?}", self.ty, err);
                    return Err(err);
                }
            }
        }
    }

    fn handle_event(&mut self, event: StreamEvent) -> Result<(), io::Error> {
        debug!("[{:?}] Session::handle_event({:?})", self.ty, event);
        match event {
            StreamEvent::Frame(frame) => {
                self.send_frame(frame)?;
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
                self.flush()?;
                debug!("[{}] session flushed", stream_id);
            }
        }
        Ok(())
    }

    // Receive events from sub streams
    // TODO: should handle error
    fn recv_events(&mut self) -> Poll<(), io::Error> {
        loop {
            if self.is_dead() {
                return Ok(Async::Ready(()));
            }

            match self.event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_event(event)?,
                Ok(Async::Ready(None)) => {
                    // Since session hold one event sender,
                    // the channel can not be disconnected.
                    unreachable!()
                }
                Ok(Async::NotReady) => {
                    return Ok(Async::NotReady);
                }
                Err(()) => {
                    // TODO: When would happend?
                }
            }
        }
    }

    #[inline]
    fn notify(&mut self) {
        if let Some(task) = self.notify.take() {
            task.notify();
        }
    }
}

impl<T> Stream for Session<T>
where
    T: AsyncRead + AsyncWrite,
{
    type Item = StreamHandle;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if self.is_dead() {
            return Ok(Async::Ready(None));
        }

        if !self.read_pending_frames.is_empty() || !self.write_pending_frames.is_empty() {
            self.flush()?;
        }

        if let Some(ref mut fut) = self.keepalive_future {
            match fut.poll() {
                Ok(Async::Ready(Some(ping_at))) => {
                    // TODO: Handle not ready
                    let _ = self.keep_alive(ping_at)?;
                }
                Ok(Async::Ready(None)) => {}
                Ok(Async::NotReady) => {}
                Err(err) => {
                    warn!("poll keepalive_future error: {}", err);
                }
            }
        }

        self.recv_frames()?;
        self.recv_events()?;

        if let Some(stream) = self.pending_streams.pop_front() {
            debug!("[{:?}] A stream is ready", self.ty);
            return Ok(Async::Ready(Some(stream)));
        } else if self.is_dead() {
            return Ok(Async::Ready(None));
        }

        self.notify = Some(task::current());
        Ok(Async::NotReady)
    }
}
