use futures::{channel::mpsc, prelude::*, stream::iter, SinkExt, StreamExt};
use log::debug;
use std::{
    collections::VecDeque,
    io::{self, ErrorKind},
    pin::Pin,
    sync::{atomic::Ordering, Arc},
    task::{Context, Poll},
};
use tokio::io::AsyncWrite;
use tokio_util::codec::{length_delimited::LengthDelimitedCodec, Framed, FramedRead, FramedWrite};

use crate::{
    buffer::{Buffer, SendResult},
    builder::BeforeReceive,
    channel::{mpsc as priority_mpsc, mpsc::Priority},
    context::SessionContext,
    protocol_handle_stream::{ServiceProtocolEvent, SessionProtocolEvent},
    service::config::SessionConfig,
    traits::Codec,
    yamux::StreamHandle,
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
        substream: Box<Framed<StreamHandle, LengthDelimitedCodec>>,
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
        /// Data
        data: bytes::Bytes,
    },
    SelectError {
        proto_name: Option<String>,
    },
    /// Codec error
    Error {
        /// Protocol id
        proto_id: ProtocolId,
        /// Codec error
        error: std::io::Error,
    },
    TimeoutCheck,
}

/// Each custom protocol in a session corresponds to a sub stream
/// Can be seen as the route of each protocol
pub(crate) struct Substream<U> {
    substream: Framed<StreamHandle, U>,
    id: StreamId,
    proto_id: ProtocolId,

    context: Arc<SessionContext>,

    config: SessionConfig,
    /// The buffer will be prioritized for send to underlying network
    high_write_buf: VecDeque<bytes::Bytes>,
    // The buffer which will send to underlying network
    write_buf: VecDeque<bytes::Bytes>,
    dead: bool,
    keep_buffer: bool,

    /// Send event to session
    event_sender: Buffer<ProtocolEvent>,
    /// Receive events from session
    event_receiver: priority_mpsc::Receiver<ProtocolEvent>,

    service_proto_sender: Option<Buffer<ServiceProtocolEvent>>,
    session_proto_sender: Option<Buffer<SessionProtocolEvent>>,
    before_receive: Option<BeforeReceive>,
}

impl<U> Substream<U>
where
    U: Codec + Unpin,
{
    pub fn proto_open(&mut self, version: String) {
        if let Some(ref mut buffer) = self.service_proto_sender {
            buffer.push(ServiceProtocolEvent::Connected {
                session: self.context.clone(),
                version: version.clone(),
            })
        }

        if let Some(ref mut buffer) = self.session_proto_sender {
            buffer.push(SessionProtocolEvent::Opened { version })
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

    /// Sink `start_send` Ready -> data send to buffer
    /// Sink `start_send` NotReady -> buffer full need poll complete
    #[inline]
    fn send_inner(
        &mut self,
        cx: &mut Context,
        frame: bytes::Bytes,
        priority: Priority,
    ) -> Result<bool, io::Error> {
        let data_size = frame.len();
        let mut sink = Pin::new(&mut self.substream);

        match sink.as_mut().poll_ready(cx)? {
            Poll::Ready(()) => {
                sink.as_mut().start_send(frame)?;
                self.context.decr_pending_data_size(data_size);
                Ok(false)
            }
            Poll::Pending => {
                self.push_front(priority, frame);
                self.poll_complete(cx)?;
                Ok(true)
            }
        }
    }

    /// Send data to the lower `yamux` sub stream
    fn send_data(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        while let Some(frame) = self.high_write_buf.pop_front() {
            if self.send_inner(cx, frame, Priority::High)? {
                return Ok(());
            }
        }

        while let Some(frame) = self.write_buf.pop_front() {
            if self.send_inner(cx, frame, Priority::Normal)? {
                return Ok(());
            }
        }

        self.poll_complete(cx)?;

        Ok(())
    }

    /// https://docs.rs/tokio/0.1.19/tokio/prelude/trait.Sink.html
    /// Must use poll complete to ensure data send to lower-level
    ///
    /// Sink `poll_complete` Ready -> no buffer remain, flush all
    /// Sink `poll_complete` NotReady -> there is more work left to do, may wake up next poll
    fn poll_complete(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        match Pin::new(&mut self.substream).poll_flush(cx) {
            Poll::Pending => Ok(true),
            Poll::Ready(res) => res.map(|_| false),
        }
    }

    /// Close protocol sub stream
    fn close_proto_stream(&mut self, cx: &mut Context) {
        self.event_receiver.close();
        if let Poll::Ready(Err(e)) = Pin::new(self.substream.get_mut()).poll_shutdown(cx) {
            log::trace!("sub stream poll shutdown err {}", e)
        }

        if !self.keep_buffer {
            self.event_sender.clear()
        }

        if let Some(ref mut service_proto_sender) = self.service_proto_sender {
            let (mut sender, mut events) = service_proto_sender.take();
            events.push_back(ServiceProtocolEvent::Disconnected {
                id: self.context.id,
            });
            crate::runtime::spawn(async move {
                let mut iter = iter(events).map(Ok);
                if let Err(e) = sender.send_all(&mut iter).await {
                    debug!("stream close event send to proto handle error: {:?}", e)
                }
            });
        }

        if let Some(ref mut session_proto_sender) = self.session_proto_sender {
            let (mut sender, mut events) = session_proto_sender.take();
            events.push_back(SessionProtocolEvent::Closed);
            if self.context.closed.load(Ordering::SeqCst) {
                events.push_back(SessionProtocolEvent::Disconnected);
            }
            crate::runtime::spawn(async move {
                let mut iter = iter(events).map(Ok);
                if let Err(e) = sender.send_all(&mut iter).await {
                    debug!("stream close event send to proto handle error: {:?}", e)
                }
            });
        }

        if !self.context.closed.load(Ordering::SeqCst) {
            let (mut sender, mut events) = self.event_sender.take();
            events.push_back(ProtocolEvent::Close {
                id: self.id,
                proto_id: self.proto_id,
            });
            crate::runtime::spawn(async move {
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
        match error.kind() {
            ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof => return,
            _ => (),
        }
        self.event_sender.push(ProtocolEvent::Error {
            proto_id: self.proto_id,
            error,
        });
        self.close_proto_stream(cx);
    }

    /// Handling commands send by session
    fn handle_proto_event(&mut self, cx: &mut Context, event: ProtocolEvent, priority: Priority) {
        match event {
            ProtocolEvent::Message { data } => {
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
                            proto_id: self.proto_id,
                            error: err,
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
        if let Some(ref mut buffer) = self.service_proto_sender {
            match buffer.try_send(cx) {
                SendResult::Disconnect => self.dead = true,
                SendResult::Pending => debug!("service proto [{}] handle is full", self.proto_id),
                SendResult::Ok => (),
            }
        }

        if let Some(ref mut buffer) = self.session_proto_sender {
            match buffer.try_send(cx) {
                SendResult::Disconnect => self.dead = true,
                SendResult::Pending => debug!("session proto [{}] handle is full", self.proto_id),
                SendResult::Ok => (),
            }
        }
        if self.dead {
            self.output(cx);
        }
    }

    /// Send event to user
    #[inline]
    fn output_event(&mut self, cx: &mut Context, event: ProtocolEvent) {
        self.event_sender.push(event);
        self.output(cx);
    }

    #[inline]
    fn output(&mut self, cx: &mut Context) {
        if let SendResult::Disconnect = self.event_sender.try_send(cx) {
            debug!("proto send to session error: disconnect, may be kill by remote");
            self.dead = true;
        }
    }

    fn recv_event(&mut self, cx: &mut Context) -> Poll<Option<()>> {
        if self.dead {
            return Poll::Ready(None);
        }

        if self.write_buf.len() > self.config.send_event_size() {
            return Poll::Pending;
        }

        match Pin::new(&mut self.event_receiver).as_mut().poll_next(cx) {
            Poll::Ready(Some((priority, event))) => {
                self.handle_proto_event(cx, event, priority);
                Poll::Ready(Some(()))
            }
            Poll::Ready(None) => {
                // Must be session close
                self.dead = true;
                if let Poll::Ready(Err(e)) = Pin::new(self.substream.get_mut()).poll_shutdown(cx) {
                    log::trace!("sub stream poll shutdown err {}", e)
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn recv_frame(&mut self, cx: &mut Context) -> Poll<Option<()>> {
        if self.dead {
            return Poll::Ready(None);
        }

        if self
            .service_proto_sender
            .as_ref()
            .map(Buffer::len)
            .unwrap_or_default()
            > self.config.recv_event_size()
            || self
                .session_proto_sender
                .as_ref()
                .map(Buffer::len)
                .unwrap_or_default()
                > self.config.recv_event_size()
        {
            return Poll::Pending;
        }

        match Pin::new(&mut self.substream).as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let data = match self.before_receive {
                    Some(ref function) => match function(data) {
                        Ok(data) => data,
                        Err(err) => {
                            self.error_close(cx, err);
                            return Poll::Ready(None);
                        }
                    },
                    None => data.freeze(),
                };

                if let Some(ref mut buffer) = self.session_proto_sender {
                    buffer.push(SessionProtocolEvent::Received { data: data.clone() })
                }

                if let Some(ref mut buffer) = self.service_proto_sender {
                    buffer.push(ServiceProtocolEvent::Received {
                        id: self.context.id,
                        data,
                    })
                }

                self.distribute_to_user_level(cx);

                Poll::Ready(Some(()))
            }
            Poll::Ready(None) => {
                debug!("protocol [{}] close", self.proto_id);
                self.dead = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(err))) => {
                debug!("sub stream codec error: {:?}", err);
                self.error_close(cx, err);
                Poll::Ready(None)
            }
        }
    }

    #[inline]
    fn flush(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        self.poll_complete(cx)?;
        if !self
            .service_proto_sender
            .as_ref()
            .map(|buffer| buffer.is_empty())
            .unwrap_or(true)
            || !self
                .session_proto_sender
                .as_ref()
                .map(|buffer| buffer.is_empty())
                .unwrap_or(true)
        {
            self.distribute_to_user_level(cx);
        }

        if !self.event_sender.is_empty()
            || !self.write_buf.is_empty()
            || !self.high_write_buf.is_empty()
        {
            self.output(cx);

            match self.send_data(cx) {
                Ok(()) => Ok(()),
                Err(err) => Err(err),
            }
        } else {
            Ok(())
        }
    }
}

impl<U> Stream for Substream<U>
where
    U: Codec + Unpin,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        // double check here
        if self.dead || self.context.closed.load(Ordering::SeqCst) {
            debug!(
                "Substream({}) finished, self.dead || self.context.closed.load(Ordering::SeqCst), head",
                self.id
            );
            self.close_proto_stream(cx);
            return Poll::Ready(None);
        }

        if let Err(err) = self.flush(cx) {
            debug!(
                "Substream({}) finished with flush error: {:?}",
                self.id, err
            );
            self.error_close(cx, err);
            return Poll::Ready(None);
        }

        debug!(
            "Substream({}) write buf: {}, read buf: {}",
            self.id,
            self.write_buf.len(),
            self.event_sender.len()
        );

        futures::ready!(crate::runtime::poll_proceed(cx));

        let mut is_pending = self.recv_frame(cx).is_pending();

        is_pending &= self.recv_event(cx).is_pending();

        if is_pending {
            Poll::Pending
        } else {
            Poll::Ready(Some(()))
        }
    }
}

pub(crate) struct SubstreamBuilder {
    id: StreamId,
    proto_id: ProtocolId,
    keep_buffer: bool,
    config: SessionConfig,

    context: Arc<SessionContext>,

    service_proto_sender: Option<Buffer<ServiceProtocolEvent>>,
    session_proto_sender: Option<Buffer<SessionProtocolEvent>>,
    before_receive: Option<BeforeReceive>,

    /// Send event to session
    event_sender: mpsc::Sender<ProtocolEvent>,
    /// Receive events from session
    event_receiver: priority_mpsc::Receiver<ProtocolEvent>,
}

impl SubstreamBuilder {
    pub fn new(
        event_sender: mpsc::Sender<ProtocolEvent>,
        event_receiver: priority_mpsc::Receiver<ProtocolEvent>,
        context: Arc<SessionContext>,
    ) -> Self {
        SubstreamBuilder {
            service_proto_sender: None,
            session_proto_sender: None,
            before_receive: None,
            event_receiver,
            event_sender,
            context,
            id: 0,
            proto_id: 0.into(),
            keep_buffer: false,
            config: SessionConfig::default(),
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

    pub fn config(mut self, config: SessionConfig) -> Self {
        self.config = config;
        self
    }

    pub fn keep_buffer(mut self, keep: bool) -> Self {
        self.keep_buffer = keep;
        self
    }

    pub fn service_proto_sender(mut self, sender: Option<Buffer<ServiceProtocolEvent>>) -> Self {
        self.service_proto_sender = sender;
        self
    }

    pub fn session_proto_sender(mut self, sender: Option<Buffer<SessionProtocolEvent>>) -> Self {
        self.session_proto_sender = sender;
        self
    }

    pub fn before_receive(mut self, f: Option<BeforeReceive>) -> Self {
        self.before_receive = f;
        self
    }

    pub fn build<U>(self, substream: Framed<StreamHandle, U>) -> Substream<U>
    where
        U: Codec,
    {
        Substream {
            substream,
            id: self.id,
            proto_id: self.proto_id,
            config: self.config,
            context: self.context,

            high_write_buf: VecDeque::new(),

            write_buf: VecDeque::new(),
            dead: false,
            keep_buffer: self.keep_buffer,

            event_sender: Buffer::new(self.event_sender),
            event_receiver: self.event_receiver,

            service_proto_sender: self.service_proto_sender,
            session_proto_sender: self.session_proto_sender,
            before_receive: self.before_receive,
        }
    }
}

/* Code organization under read-write separation */

pub(crate) struct SubstreamWritePart<U> {
    substream: FramedWrite<crate::runtime::WriteHalf<StreamHandle>, U>,
    id: StreamId,
    proto_id: ProtocolId,

    dead: bool,
    config: SessionConfig,

    /// The buffer will be prioritized for send to underlying network
    high_write_buf: VecDeque<bytes::Bytes>,
    // The buffer which will send to underlying network
    write_buf: VecDeque<bytes::Bytes>,

    /// Send event to session
    event_sender: Buffer<ProtocolEvent>,
    /// Receive events from session
    event_receiver: priority_mpsc::Receiver<ProtocolEvent>,

    context: Arc<SessionContext>,
}

impl<U> SubstreamWritePart<U>
where
    U: Codec + Unpin,
{
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

    /// Sink `start_send` Ready -> data send to buffer
    /// Sink `start_send` NotReady -> buffer full need poll complete
    #[inline]
    fn send_inner(
        &mut self,
        cx: &mut Context,
        frame: bytes::Bytes,
        priority: Priority,
    ) -> Result<bool, io::Error> {
        let data_size = frame.len();
        let mut sink = Pin::new(&mut self.substream);

        match sink.as_mut().poll_ready(cx)? {
            Poll::Ready(()) => {
                sink.as_mut().start_send(frame)?;
                self.context.decr_pending_data_size(data_size);
                Ok(false)
            }
            Poll::Pending => {
                self.push_front(priority, frame);
                self.poll_complete(cx)?;
                Ok(true)
            }
        }
    }

    fn poll_complete(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        match Pin::new(&mut self.substream).poll_flush(cx) {
            Poll::Pending => Ok(true),
            Poll::Ready(res) => res.map(|_| false),
        }
    }

    /// Send data to the lower `yamux` sub stream
    fn send_data(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        while let Some(frame) = self.high_write_buf.pop_front() {
            if self.send_inner(cx, frame, Priority::High)? {
                return Ok(());
            }
        }

        while let Some(frame) = self.write_buf.pop_front() {
            if self.send_inner(cx, frame, Priority::Normal)? {
                return Ok(());
            }
        }

        self.poll_complete(cx)?;

        Ok(())
    }

    #[inline]
    fn flush(&mut self, cx: &mut Context) -> Result<(), io::Error> {
        self.poll_complete(cx)?;
        if !self.event_sender.is_empty()
            || !self.write_buf.is_empty()
            || !self.high_write_buf.is_empty()
        {
            self.output(cx);

            match self.send_data(cx) {
                Ok(()) => Ok(()),
                Err(err) => Err(err),
            }
        } else {
            Ok(())
        }
    }

    /// Handling commands send by session
    fn handle_proto_event(&mut self, cx: &mut Context, event: ProtocolEvent, priority: Priority) {
        match event {
            ProtocolEvent::Message { data } => {
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
                            proto_id: self.proto_id,
                            error: err,
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

    fn recv_event(&mut self, cx: &mut Context) -> Poll<Option<()>> {
        if self.dead {
            return Poll::Ready(None);
        }

        if self.write_buf.len() > self.config.send_event_size() {
            return Poll::Pending;
        }

        match Pin::new(&mut self.event_receiver).as_mut().poll_next(cx) {
            Poll::Ready(Some((priority, event))) => {
                self.handle_proto_event(cx, event, priority);
                Poll::Ready(Some(()))
            }
            Poll::Ready(None) => {
                // Must be session close
                self.dead = true;
                if let Poll::Ready(Err(e)) = Pin::new(self.substream.get_mut()).poll_shutdown(cx) {
                    log::trace!("sub stream poll shutdown err {}", e)
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// When send or receive message error, output error and close stream
    fn error_close(&mut self, cx: &mut Context, error: io::Error) {
        self.dead = true;
        match error.kind() {
            ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof => return,
            _ => (),
        }
        self.event_sender.push(ProtocolEvent::Error {
            proto_id: self.proto_id,
            error,
        });
        self.close_proto_stream(cx);
    }

    fn close_proto_stream(&mut self, cx: &mut Context) {
        self.event_receiver.close();
        if let Poll::Ready(Err(e)) = Pin::new(self.substream.get_mut()).poll_shutdown(cx) {
            log::trace!("sub stream poll shutdown err {}", e)
        }
        if !self.context.closed.load(Ordering::SeqCst) {
            let (mut sender, mut events) = self.event_sender.take();
            events.push_back(ProtocolEvent::Close {
                id: self.id,
                proto_id: self.proto_id,
            });
            crate::runtime::spawn(async move {
                let mut iter = iter(events).map(Ok);
                if let Err(e) = sender.send_all(&mut iter).await {
                    debug!("stream close event send to session error: {:?}", e)
                }
            });
        } else {
            self.output(cx);
        }
    }

    /// Send event to user
    #[inline]
    fn output_event(&mut self, cx: &mut Context, event: ProtocolEvent) {
        self.event_sender.push(event);
        self.output(cx);
    }

    #[inline]
    fn output(&mut self, cx: &mut Context) {
        if let SendResult::Disconnect = self.event_sender.try_send(cx) {
            debug!("proto send to session error: disconnect, may be kill by remote");
            self.dead = true;
        }
    }
}

impl<U> Stream for SubstreamWritePart<U>
where
    U: Codec + Unpin,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        // double check here
        if self.dead || self.context.closed.load(Ordering::SeqCst) {
            debug!(
                "Substream({}) finished, self.dead || self.context.closed.load(Ordering::SeqCst), head",
                self.id
            );
            self.close_proto_stream(cx);
            return Poll::Ready(None);
        }

        if let Err(err) = self.flush(cx) {
            debug!(
                "Substream({}) finished with flush error: {:?}",
                self.id, err
            );
            self.error_close(cx, err);
            return Poll::Ready(None);
        }

        debug!(
            "Substream({}) write buf: {}, read buf: {}",
            self.id,
            self.write_buf.len(),
            self.event_sender.len()
        );

        futures::ready!(crate::runtime::poll_proceed(cx));

        let is_pending = self.recv_event(cx).is_pending();

        if is_pending {
            Poll::Pending
        } else {
            Poll::Ready(Some(()))
        }
    }
}

/// Protocol Stream read part
pub struct SubstreamReadPart {
    pub(crate) substream:
        FramedRead<crate::runtime::ReadHalf<StreamHandle>, Box<dyn Codec + Send + 'static>>,
    pub(crate) before_receive: Option<BeforeReceive>,
    pub(crate) proto_id: ProtocolId,
    pub(crate) stream_id: StreamId,
    pub(crate) version: String,
    pub(crate) close_sender: priority_mpsc::Sender<ProtocolEvent>,
}

impl SubstreamReadPart {
    /// protocol id of this stream
    pub fn protocol_id(&self) -> ProtocolId {
        self.proto_id
    }
    /// protocol version
    pub fn version(&self) -> &str {
        self.version.as_str()
    }
}

impl Drop for SubstreamReadPart {
    fn drop(&mut self) {
        let mut sender = self.close_sender.clone();
        let id = self.stream_id;
        let pid = self.proto_id;
        crate::runtime::spawn(async move {
            let _ignore = sender
                .send(ProtocolEvent::Close { id, proto_id: pid })
                .await;
        });
    }
}

impl Stream for SubstreamReadPart {
    type Item = Result<bytes::Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        futures::ready!(crate::runtime::poll_proceed(cx));
        match self.substream.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let data = match self.before_receive {
                    Some(ref function) => match function(data) {
                        Ok(data) => data,
                        Err(err) => {
                            return Poll::Ready(Some(Err(err)));
                        }
                    },
                    None => data.freeze(),
                };
                Poll::Ready(Some(Ok(data)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(crate) struct SubstreamWritePartBuilder {
    id: StreamId,
    proto_id: ProtocolId,
    config: SessionConfig,

    context: Arc<SessionContext>,

    /// Send event to session
    event_sender: mpsc::Sender<ProtocolEvent>,
    /// Receive events from session
    event_receiver: priority_mpsc::Receiver<ProtocolEvent>,
}

impl SubstreamWritePartBuilder {
    pub fn new(
        event_sender: mpsc::Sender<ProtocolEvent>,
        event_receiver: priority_mpsc::Receiver<ProtocolEvent>,
        context: Arc<SessionContext>,
    ) -> Self {
        SubstreamWritePartBuilder {
            event_receiver,
            event_sender,
            context,
            id: 0,
            proto_id: 0.into(),
            config: SessionConfig::default(),
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

    pub fn config(mut self, config: SessionConfig) -> Self {
        self.config = config;
        self
    }

    pub fn build<U>(
        self,
        substream: FramedWrite<crate::runtime::WriteHalf<StreamHandle>, U>,
    ) -> SubstreamWritePart<U>
    where
        U: Codec,
    {
        SubstreamWritePart {
            substream,
            id: self.id,
            proto_id: self.proto_id,
            config: self.config,
            context: self.context,

            high_write_buf: VecDeque::new(),

            write_buf: VecDeque::new(),
            dead: false,

            event_sender: Buffer::new(self.event_sender),
            event_receiver: self.event_receiver,
        }
    }
}
