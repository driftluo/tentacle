use futures::{channel::mpsc, prelude::*, stream::iter};
use log::debug;
use std::{
    collections::VecDeque,
    io::{self, ErrorKind},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::prelude::AsyncWrite;
use tokio_util::codec::{length_delimited::LengthDelimitedCodec, Framed};

use crate::{
    builder::BeforeReceive,
    context::SessionContext,
    error::Error,
    protocol_handle_stream::{ServiceProtocolEvent, SessionProtocolEvent},
    service::{event::Priority, DELAY_TIME},
    traits::Codec,
    yamux::{Config, StreamHandle},
    ProtocolId, StreamId,
};

/// Event generated/received by the protocol stream
#[derive(Debug)]
pub(crate) enum ProtocolEvent {
    /// The protocol is normally open
    Open {
        /// Protocol name
        proto_name: String,
        /// Yamux sub stream handle handshake framed
        sub_stream: Box<Framed<StreamHandle, LengthDelimitedCodec>>,
        /// Protocol version
        version: String,
    },
    /// The protocol close
    Close {
        /// Stream id
        id: StreamId,
        /// Protocol id
        proto_id: ProtocolId,
    },
    /// Protocol data outbound and inbound
    Message {
        /// Stream id
        id: StreamId,
        /// Protocol id
        proto_id: ProtocolId,
        /// priority
        priority: Priority,
        /// Data
        data: bytes::Bytes,
    },
    SelectError {
        proto_name: Option<String>,
    },
    /// Codec error
    Error {
        /// Stream id
        id: StreamId,
        /// Protocol id
        proto_id: ProtocolId,
        /// Codec error
        error: Error,
    },
    TimeoutCheck,
}

/// Each custom protocol in a session corresponds to a sub stream
/// Can be seen as the route of each protocol
pub(crate) struct SubStream<U> {
    sub_stream: Framed<StreamHandle, U>,
    id: StreamId,
    proto_id: ProtocolId,

    context: Arc<SessionContext>,
    event: bool,

    config: Config,
    /// The buffer will be prioritized for send to underlying network
    high_write_buf: VecDeque<bytes::Bytes>,
    // The buffer which will send to underlying network
    write_buf: VecDeque<bytes::Bytes>,
    // The buffer which will send to user
    read_buf: VecDeque<ProtocolEvent>,
    service_proto_buf: VecDeque<ServiceProtocolEvent>,
    session_proto_buf: VecDeque<SessionProtocolEvent>,
    dead: bool,
    keep_buffer: bool,

    /// Send event to session
    event_sender: mpsc::Sender<ProtocolEvent>,
    /// Receive events from session
    event_receiver: mpsc::Receiver<ProtocolEvent>,

    service_proto_sender: Option<mpsc::Sender<ServiceProtocolEvent>>,
    session_proto_sender: Option<mpsc::Sender<SessionProtocolEvent>>,
    before_receive: Option<BeforeReceive>,

    /// Delay notify with abnormally poor machines
    delay: Arc<AtomicBool>,

    closed: Arc<AtomicBool>,
}

impl<U> SubStream<U>
where
    U: Codec + Unpin,
{
    pub fn proto_open(&mut self, version: String) {
        if self.service_proto_sender.is_some() {
            self.service_proto_buf
                .push_back(ServiceProtocolEvent::Connected {
                    session: self.context.clone(),
                    version: version.clone(),
                })
        }

        if self.session_proto_sender.is_some() {
            self.session_proto_buf
                .push_back(SessionProtocolEvent::Connected { version })
        }
    }

    fn push_front(&mut self, priority: Priority, frame: bytes::Bytes) {
        if priority.is_high() {
            self.high_write_buf.push_front(frame);
        } else {
            self.write_buf.push_front(frame);
        }
    }

    fn push_back(&mut self, priority: Priority, frame: bytes::Bytes) {
        if priority.is_high() {
            self.high_write_buf.push_back(frame);
        } else {
            self.write_buf.push_back(frame);
        }
    }

    /// Sink `start_send` Ready -> data in buffer or send
    /// Sink `start_send` NotReady -> buffer full need poll complete
    #[inline]
    fn send_inner(
        &mut self,
        cx: &mut Context,
        frame: bytes::Bytes,
        priority: Priority,
    ) -> Result<bool, io::Error> {
        let data_size = frame.len();
        let mut sink = Pin::new(&mut self.sub_stream);

        match sink.as_mut().poll_ready(cx)? {
            Poll::Ready(()) => {
                sink.as_mut().start_send(frame)?;
                self.context.decr_pending_data_size(data_size);
                Ok(false)
            }
            Poll::Pending => {
                debug!("framed_stream NotReady, frame len: {:?}", frame.len());
                self.push_front(priority, frame);
                Ok(true)
            }
        }
    }

    /// Send data to the lower `yamux` sub stream
    fn send_data(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        while let Some(frame) = self.high_write_buf.pop_front() {
            if self.send_inner(cx, frame, Priority::High)? && self.poll_complete(cx)? {
                return Ok(());
            }
        }

        while let Some(frame) = self.write_buf.pop_front() {
            if self.send_inner(cx, frame, Priority::Normal)? && self.poll_complete(cx)? {
                return Ok(());
            }
        }

        self.poll_complete(cx)?;

        debug!("send success, proto_id: {}", self.proto_id);
        Ok(())
    }

    /// https://docs.rs/tokio/0.1.19/tokio/prelude/trait.Sink.html
    /// Must use poll complete to ensure data send to lower-level
    ///
    /// Sink `poll_complete` Ready -> no buffer remain, flush all
    /// Sink `poll_complete` NotReady -> there is more work left to do, may wake up next poll
    fn poll_complete(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        match Pin::new(&mut self.sub_stream).poll_flush(cx) {
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

    /// Close protocol sub stream
    fn close_proto_stream(&mut self, cx: &mut Context) {
        self.event_receiver.close();
        let _ = Pin::new(self.sub_stream.get_mut()).poll_shutdown(cx);

        if self.service_proto_sender.is_some() {
            self.service_proto_buf
                .push_back(ServiceProtocolEvent::Disconnected {
                    id: self.context.id,
                });
            let events = self.service_proto_buf.split_off(0);
            let mut sender = self.service_proto_sender.take().unwrap();
            tokio::spawn(async move {
                let mut iter = iter(events).map(Ok);
                if let Err(e) = sender.send_all(&mut iter).await {
                    debug!("stream close event send to proto handle error: {:?}", e)
                }
            });
        }

        if self.session_proto_sender.is_some() {
            self.session_proto_buf
                .push_back(SessionProtocolEvent::Disconnected);
            let events = self.session_proto_buf.split_off(0);
            let mut sender = self.session_proto_sender.take().unwrap();
            tokio::spawn(async move {
                let mut iter = iter(events).map(Ok);
                if let Err(e) = sender.send_all(&mut iter).await {
                    debug!("stream close event send to proto handle error: {:?}", e)
                }
            });
        }

        self.read_buf.push_back(ProtocolEvent::Close {
            id: self.id,
            proto_id: self.proto_id,
        });

        if !self.closed.load(Ordering::SeqCst) {
            let events = self.read_buf.split_off(0);
            let mut sender = self.event_sender.clone();

            tokio::spawn(async move {
                let mut iter = iter(events).map(Ok);
                if let Err(e) = sender.send_all(&mut iter).await {
                    debug!("stream close event send to session error: {:?}", e)
                }
            });
        } else {
            self.output(cx);
        }
    }

    /// When send or receive message error, output error and close stream
    fn error_close(&mut self, cx: &mut Context, error: io::Error) {
        self.dead = true;
        if !self.keep_buffer {
            self.read_buf.clear()
        }
        self.read_buf.push_back(ProtocolEvent::Error {
            id: self.id,
            proto_id: self.proto_id,
            error: error.into(),
        });
        self.close_proto_stream(cx);
    }

    /// Handling commands send by session
    fn handle_proto_event(&mut self, cx: &mut Context, event: ProtocolEvent) {
        match event {
            ProtocolEvent::Message { data, priority, .. } => {
                debug!("proto [{}] send data: {}", self.proto_id, data.len());
                self.push_back(priority, data);

                if let Err(err) = self.send_data(cx) {
                    // Whether it is a read send error or a flush error,
                    // the most essential problem is that there is a problem with the external network.
                    // Close the protocol stream directly.
                    debug!(
                        "protocol [{}] close because of extern network",
                        self.proto_id
                    );
                    self.output_event(
                        cx,
                        ProtocolEvent::Error {
                            id: self.id,
                            proto_id: self.proto_id,
                            error: err.into(),
                        },
                    );
                    self.dead = true;
                }
            }
            ProtocolEvent::Close { .. } => {
                self.write_buf.clear();
                self.dead = true;
            }
            _ => (),
        }
    }

    fn distribute_to_user_level(&mut self, cx: &mut Context) {
        if let Some(ref mut sender) = self.service_proto_sender {
            while let Some(event) = self.service_proto_buf.pop_front() {
                if let Err(e) = sender.try_send(event) {
                    if e.is_full() {
                        debug!("service proto [{}] handle is full", self.proto_id);
                        self.service_proto_buf.push_front(e.into_inner());
                        self.set_delay(cx);
                        break;
                    } else {
                        self.dead = true;
                    }
                }
            }
        }

        if let Some(ref mut sender) = self.session_proto_sender {
            while let Some(event) = self.session_proto_buf.pop_front() {
                if let Err(e) = sender.try_send(event) {
                    if e.is_full() {
                        debug!("service proto [{}] handle is full", self.proto_id);
                        self.session_proto_buf.push_front(e.into_inner());
                        self.set_delay(cx);
                        break;
                    } else {
                        self.dead = true;
                    }
                }
            }
        }
        if self.dead {
            self.output(cx);
        }
    }

    /// Send event to user
    #[inline]
    fn output_event(&mut self, cx: &mut Context, event: ProtocolEvent) {
        self.read_buf.push_back(event);
        self.output(cx);
    }

    #[inline]
    fn output(&mut self, cx: &mut Context) {
        while let Some(event) = self.read_buf.pop_front() {
            if let Err(e) = self.event_sender.try_send(event) {
                if e.is_full() {
                    self.read_buf.push_front(e.into_inner());
                    self.set_delay(cx);
                } else {
                    debug!("proto send to session error: {}, may be kill by remote", e);
                    self.dead = true;
                }
                break;
            }
        }
    }

    fn recv_event(&mut self, cx: &mut Context) {
        let mut finished = false;
        for _ in 0..64 {
            if self.dead {
                break;
            }

            if self.write_buf.len() > self.config.send_event_size() {
                self.set_delay(cx);
                break;
            }

            match Pin::new(&mut self.event_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(event)) => self.handle_proto_event(cx, event),
                Poll::Ready(None) => {
                    // Must be session close
                    self.dead = true;
                    let _ = Pin::new(self.sub_stream.get_mut()).poll_shutdown(cx);
                    return;
                }
                Poll::Pending => {
                    finished = true;
                    break;
                }
            }
        }
        if !finished {
            self.set_delay(cx);
        }
    }

    fn recv_frame(&mut self, cx: &mut Context) {
        let mut finished = false;
        for _ in 0..64 {
            if self.dead {
                break;
            }

            if self.read_buf.len() > self.config.recv_event_size() {
                self.set_delay(cx);
                break;
            }

            match Pin::new(&mut self.sub_stream).as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    debug!(
                        "protocol [{}] receive data len: {}",
                        self.proto_id,
                        data.len()
                    );

                    let data = match self.before_receive {
                        Some(ref function) => match function(data) {
                            Ok(data) => data,
                            Err(err) => {
                                self.error_close(cx, err);
                                return;
                            }
                        },
                        None => data.freeze(),
                    };

                    if self.service_proto_sender.is_some() {
                        self.service_proto_buf
                            .push_back(ServiceProtocolEvent::Received {
                                id: self.context.id,
                                data: data.clone(),
                            })
                    }

                    if self.session_proto_sender.is_some() {
                        self.session_proto_buf
                            .push_back(SessionProtocolEvent::Received { data: data.clone() })
                    }

                    self.distribute_to_user_level(cx);

                    if self.event {
                        self.output_event(
                            cx,
                            ProtocolEvent::Message {
                                id: self.id,
                                proto_id: self.proto_id,
                                data,
                                priority: Priority::Normal,
                            },
                        )
                    }
                }
                Poll::Ready(None) => {
                    debug!("protocol [{}] close", self.proto_id);
                    self.dead = true;
                    return;
                }
                Poll::Pending => {
                    finished = true;
                    break;
                }
                Poll::Ready(Some(Err(err))) => {
                    finished = true;
                    debug!("sub stream codec error: {:?}", err);
                    match err.kind() {
                        ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::NotConnected
                        | ErrorKind::UnexpectedEof => self.dead = true,
                        _ => {
                            self.error_close(cx, err);
                            return;
                        }
                    }
                }
            }
        }
        if !finished {
            self.set_delay(cx);
        }
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
                tokio::time::delay_until(tokio::time::Instant::now() + DELAY_TIME).await;
                waker.wake();
                delay.store(false, Ordering::Release);
            });
        }
    }

    #[inline]
    fn flush(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        self.output(cx);

        match self.send_data(cx) {
            Ok(()) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

impl<U> Stream for SubStream<U>
where
    U: Codec + Unpin,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        // double check here
        if self.dead || self.closed.load(Ordering::SeqCst) {
            debug!(
                "SubStream({}) finished, self.dead || self.closed.load(Ordering::SeqCst), head",
                self.id
            );
            self.close_proto_stream(cx);
            return Poll::Ready(None);
        }

        if !self.service_proto_buf.is_empty() || !self.session_proto_buf.is_empty() {
            self.distribute_to_user_level(cx);
        }

        if !self.read_buf.is_empty()
            || !self.write_buf.is_empty()
            || !self.high_write_buf.is_empty()
        {
            if let Err(err) = self.flush(cx) {
                debug!(
                    "SubStream({}) finished with flush error: {:?}",
                    self.id, err
                );
                self.error_close(cx, err);
                return Poll::Ready(None);
            }
        }

        if let Err(err) = self.poll_complete(cx) {
            debug!(
                "SubStream({}) finished with poll_complete error: {:?}",
                self.id, err
            );
            self.error_close(cx, err);
            return Poll::Ready(None);
        }

        debug!(
            "write buf: {}, read buf: {}",
            self.write_buf.len(),
            self.read_buf.len()
        );

        self.recv_frame(cx);

        self.recv_event(cx);

        if self.dead || self.closed.load(Ordering::SeqCst) {
            debug!(
                "SubStream({}) finished, self.dead || self.closed.load(Ordering::SeqCst), tail",
                self.id
            );
            if !self.keep_buffer {
                self.read_buf.clear()
            }
            self.close_proto_stream(cx);
            return Poll::Ready(None);
        }

        Poll::Pending
    }
}

pub(crate) struct SubstreamBuilder {
    id: StreamId,
    proto_id: ProtocolId,
    keep_buffer: bool,
    config: Config,
    event: bool,

    context: Arc<SessionContext>,

    service_proto_sender: Option<mpsc::Sender<ServiceProtocolEvent>>,
    session_proto_sender: Option<mpsc::Sender<SessionProtocolEvent>>,
    before_receive: Option<BeforeReceive>,

    /// Send event to session
    event_sender: mpsc::Sender<ProtocolEvent>,
    /// Receive events from session
    event_receiver: mpsc::Receiver<ProtocolEvent>,
    closed: Arc<AtomicBool>,
}

impl SubstreamBuilder {
    pub fn new(
        event_sender: mpsc::Sender<ProtocolEvent>,
        event_receiver: mpsc::Receiver<ProtocolEvent>,
        closed: Arc<AtomicBool>,
        context: Arc<SessionContext>,
    ) -> Self {
        SubstreamBuilder {
            service_proto_sender: None,
            session_proto_sender: None,
            before_receive: None,
            event_receiver,
            event_sender,
            closed,
            context,
            id: 0,
            proto_id: 0.into(),
            keep_buffer: false,
            config: Config::default(),
            event: false,
        }
    }

    pub fn stream_id(mut self, id: StreamId) -> Self {
        self.id = id;
        self
    }

    pub fn proto_id(mut self, id: ProtocolId) -> Self {
        self.proto_id = id;
        self
    }

    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    pub fn keep_buffer(mut self, keep: bool) -> Self {
        self.keep_buffer = keep;
        self
    }

    pub fn event(mut self, event: bool) -> Self {
        self.event = event;
        self
    }

    pub fn service_proto_sender(
        mut self,
        sender: Option<mpsc::Sender<ServiceProtocolEvent>>,
    ) -> Self {
        self.service_proto_sender = sender;
        self
    }

    pub fn session_proto_sender(
        mut self,
        sender: Option<mpsc::Sender<SessionProtocolEvent>>,
    ) -> Self {
        self.session_proto_sender = sender;
        self
    }

    pub fn before_receive(mut self, f: Option<BeforeReceive>) -> Self {
        self.before_receive = f;
        self
    }

    pub fn build<U>(self, sub_stream: Framed<StreamHandle, U>) -> SubStream<U>
    where
        U: Codec,
    {
        SubStream {
            sub_stream,
            id: self.id,
            proto_id: self.proto_id,
            config: self.config,
            context: self.context,
            event: self.event,

            high_write_buf: VecDeque::new(),

            write_buf: VecDeque::new(),
            read_buf: VecDeque::new(),
            service_proto_buf: VecDeque::new(),
            session_proto_buf: VecDeque::new(),
            dead: false,
            keep_buffer: self.keep_buffer,

            event_sender: self.event_sender,
            event_receiver: self.event_receiver,

            service_proto_sender: self.service_proto_sender,
            session_proto_sender: self.session_proto_sender,
            before_receive: self.before_receive,

            delay: Arc::new(AtomicBool::new(false)),

            closed: self.closed,
        }
    }
}
