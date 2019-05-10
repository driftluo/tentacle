use futures::{prelude::*, stream::iter_ok, sync::mpsc};
use log::debug;
use std::{
    collections::VecDeque,
    io::{self, ErrorKind},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::{
    codec::{length_delimited::LengthDelimitedCodec, Framed},
    prelude::AsyncWrite,
    timer::Delay,
};

use crate::{
    error::Error,
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

    config: Config,
    /// The buffer will be prioritized for send to underlying network
    high_write_buf: VecDeque<bytes::Bytes>,
    // The buffer which will send to underlying network
    write_buf: VecDeque<bytes::Bytes>,
    // The buffer which will send to user
    read_buf: VecDeque<ProtocolEvent>,
    dead: bool,

    /// Send event to session
    event_sender: mpsc::Sender<ProtocolEvent>,
    /// Receive events from session
    event_receiver: mpsc::Receiver<ProtocolEvent>,
    /// Delay notify with abnormally poor machines
    delay: Arc<AtomicBool>,
}

impl<U> SubStream<U>
where
    U: Codec,
{
    /// New a protocol sub stream
    pub fn new(
        sub_stream: Framed<StreamHandle, U>,
        event_sender: mpsc::Sender<ProtocolEvent>,
        event_receiver: mpsc::Receiver<ProtocolEvent>,
        id: StreamId,
        proto_id: ProtocolId,
        config: Config,
    ) -> Self {
        SubStream {
            sub_stream,
            id,
            proto_id,
            config,
            event_sender,
            event_receiver,
            high_write_buf: VecDeque::new(),
            write_buf: VecDeque::new(),
            read_buf: VecDeque::new(),
            delay: Arc::new(AtomicBool::new(false)),
            dead: false,
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
    fn send_inner(&mut self, frame: bytes::Bytes, priority: Priority) -> Result<bool, io::Error> {
        match self.sub_stream.start_send(frame) {
            Ok(AsyncSink::NotReady(frame)) => {
                debug!("framed_stream NotReady, frame len: {:?}", frame.len());
                self.push_front(priority, frame);
                Ok(true)
            }
            Ok(AsyncSink::Ready) => Ok(false),
            Err(err) => {
                debug!("framed_stream send error: {:?}", err);
                Err(err)
            }
        }
    }

    /// Send data to the lower `yamux` sub stream
    fn send_data(&mut self) -> Result<(), io::Error> {
        while let Some(frame) = self.high_write_buf.pop_front() {
            if self.send_inner(frame, Priority::High)? && self.poll_complete()? {
                return Ok(());
            }
        }

        while let Some(frame) = self.write_buf.pop_front() {
            if self.send_inner(frame, Priority::Normal)? && self.poll_complete()? {
                return Ok(());
            }
        }

        self.poll_complete()?;

        debug!("send success, proto_id: {}", self.proto_id);
        Ok(())
    }

    /// https://docs.rs/tokio/0.1.19/tokio/prelude/trait.Sink.html
    /// Must use poll complete to ensure data send to lower-level
    ///
    /// Sink `poll_complete` Ready -> no buffer remain, flush all
    /// Sink `poll_complete` NotReady -> there is more work left to do, may wake up next poll
    fn poll_complete(&mut self) -> Result<bool, io::Error> {
        if self.sub_stream.poll_complete()?.is_not_ready() {
            self.set_delay();
            return Ok(true);
        }
        Ok(false)
    }

    /// Close protocol sub stream
    fn close_proto_stream(&mut self) {
        self.event_receiver.close();
        let _ = self.sub_stream.get_mut().shutdown();

        self.read_buf.push_back(ProtocolEvent::Close {
            id: self.id,
            proto_id: self.proto_id,
        });
        let events = self.read_buf.split_off(0);

        tokio::spawn(
            self.event_sender
                .clone()
                .send_all(iter_ok(events))
                .map(|_| ())
                .map_err(|e| debug!("stream close event send to session error: {:?}", e)),
        );
    }

    /// When send or receive message error, output error and close stream
    fn error_close(&mut self, error: io::Error) {
        self.dead = true;
        self.read_buf.push_back(ProtocolEvent::Error {
            id: self.id,
            proto_id: self.proto_id,
            error: error.into(),
        });
        self.close_proto_stream();
    }

    /// Handling commands send by session
    fn handle_proto_event(&mut self, event: ProtocolEvent) {
        match event {
            ProtocolEvent::Message { data, priority, .. } => {
                debug!("proto [{}] send data: {}", self.proto_id, data.len());
                self.push_back(priority, data);

                if let Err(err) = self.send_data() {
                    // Whether it is a read send error or a flush error,
                    // the most essential problem is that there is a problem with the external network.
                    // Close the protocol stream directly.
                    debug!(
                        "protocol [{}] close because of extern network",
                        self.proto_id
                    );
                    self.output_event(ProtocolEvent::Error {
                        id: self.id,
                        proto_id: self.proto_id,
                        error: err.into(),
                    });
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

    /// Send event to user
    #[inline]
    fn output_event(&mut self, event: ProtocolEvent) {
        self.read_buf.push_back(event);
        self.output();
    }

    #[inline]
    fn output(&mut self) {
        while let Some(event) = self.read_buf.pop_front() {
            if let Err(e) = self.event_sender.try_send(event) {
                if e.is_full() {
                    self.read_buf.push_front(e.into_inner());
                    self.set_delay();
                } else {
                    debug!("proto send to session error: {}, may be kill by remote", e);
                    self.dead = true;
                }
                break;
            }
        }
    }

    fn recv_event(&mut self) -> Option<()> {
        loop {
            if self.dead {
                break;
            }

            if self.write_buf.len() > self.config.send_event_size() {
                self.set_delay();
                break;
            }

            match self.event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_proto_event(event),
                Ok(Async::Ready(None)) => {
                    // Must be session close
                    self.dead = true;
                    let _ = self.sub_stream.get_mut().shutdown();
                    return None;
                }
                Ok(Async::NotReady) => break,
                Err(_) => {
                    break;
                }
            }
        }
        Some(())
    }

    fn recv_frame(&mut self) -> Option<()> {
        loop {
            if self.dead {
                break;
            }

            if self.read_buf.len() > self.config.recv_event_size() {
                self.set_delay();
                break;
            }

            match self.sub_stream.poll() {
                Ok(Async::Ready(Some(data))) => {
                    debug!(
                        "protocol [{}] receive data len: {}",
                        self.proto_id,
                        data.len()
                    );
                    self.output_event(ProtocolEvent::Message {
                        id: self.id,
                        proto_id: self.proto_id,
                        data: data.into(),
                        priority: Priority::Normal,
                    })
                }
                Ok(Async::Ready(None)) => {
                    debug!("protocol [{}] close", self.proto_id);
                    self.dead = true;
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    debug!("sub stream codec error: {:?}", err);
                    match err.kind() {
                        ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::NotConnected
                        | ErrorKind::UnexpectedEof => self.dead = true,
                        _ => {
                            self.error_close(err);
                            return None;
                        }
                    }
                }
            }
        }
        Some(())
    }

    #[inline]
    fn set_delay(&mut self) {
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
            let notify = futures::task::current();
            let delay = self.delay.clone();
            let delay_task = Delay::new(Instant::now() + DELAY_TIME).then(move |_| {
                notify.notify();
                delay.store(false, Ordering::Release);
                Ok(())
            });
            tokio::spawn(delay_task);
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), io::Error> {
        self.output();

        match self.send_data() {
            Ok(()) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

impl<U> Stream for SubStream<U>
where
    U: Codec,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // double check here
        if self.dead {
            return Ok(Async::Ready(None));
        }

        if !self.read_buf.is_empty()
            || !self.write_buf.is_empty()
            || !self.high_write_buf.is_empty()
        {
            if let Err(err) = self.flush() {
                self.error_close(err);
                return Err(());
            }
        }

        self.poll_complete()
            .map_err(|e| debug!("poll complete error: {}", e))?;

        debug!(
            "write buf: {}, read buf: {}",
            self.write_buf.len(),
            self.read_buf.len()
        );

        if self.recv_frame().is_none() {
            return Ok(Async::Ready(None));
        }

        if self.recv_event().is_none() {
            return Ok(Async::Ready(None));
        }

        if self.dead {
            self.close_proto_stream();
            return Ok(Async::Ready(None));
        }

        Ok(Async::NotReady)
    }
}
