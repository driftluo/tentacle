use futures::{
    prelude::*,
    sync::mpsc,
    task::{self, Task},
};
use log::{debug, warn};
use std::collections::VecDeque;
use std::{
    error,
    io::{self, ErrorKind},
};
use tokio::{
    codec::{length_delimited::LengthDelimitedCodec, Decoder, Encoder, Framed},
    prelude::AsyncWrite,
};

use crate::{error::Error, service::ServiceTask, yamux::StreamHandle, ProtocolId, StreamId};

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
        error: Error<ServiceTask>,
    },
}

/// Each custom protocol in a session corresponds to a sub stream
/// Can be seen as the route of each protocol
pub(crate) struct SubStream<U> {
    sub_stream: Framed<StreamHandle, U>,
    id: StreamId,
    proto_id: ProtocolId,
    // The buffer which will send to underlying network
    write_buf: VecDeque<bytes::Bytes>,
    // The buffer which will send to user
    read_buf: VecDeque<ProtocolEvent>,
    dead: bool,

    /// Send event to session
    event_sender: mpsc::Sender<ProtocolEvent>,
    /// Receive events from session
    event_receiver: mpsc::Receiver<ProtocolEvent>,

    notify: Option<Task>,
}

impl<U> SubStream<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error + Into<io::Error>,
    <U as Encoder>::Error: error::Error + Into<io::Error>,
{
    /// New a protocol sub stream
    pub fn new(
        sub_stream: Framed<StreamHandle, U>,
        event_sender: mpsc::Sender<ProtocolEvent>,
        event_receiver: mpsc::Receiver<ProtocolEvent>,
        id: StreamId,
        proto_id: ProtocolId,
    ) -> Self {
        SubStream {
            sub_stream,
            id,
            proto_id,
            event_sender,
            event_receiver,
            write_buf: VecDeque::new(),
            read_buf: VecDeque::new(),
            notify: None,
            dead: false,
        }
    }

    /// Send data to the lower `yamux` sub stream
    fn send_data(&mut self) -> Poll<(), ()> {
        while let Some(frame) = self.write_buf.pop_front() {
            match self.sub_stream.start_send(frame) {
                Ok(AsyncSink::NotReady(frame)) => {
                    debug!("framed_stream NotReady, frame: {:?}", frame);
                    self.write_buf.push_front(frame);
                    self.notify();
                    return Ok(Async::NotReady);
                }
                Ok(AsyncSink::Ready) => {}
                Err(err) => {
                    debug!("framed_stream send error: {:?}", err);
                    return Err(());
                }
            }
        }
        match self.sub_stream.poll_complete() {
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Ok(Async::Ready(_)) => (),
            Err(err) => {
                debug!("poll complete error: {:?}", err);
                return Err(());
            }
        };
        debug!("send success, proto_id: {}", self.proto_id);
        Ok(Async::Ready(()))
    }

    /// Close protocol sub stream
    fn close_proto_stream(&mut self) {
        self.event_receiver.close();
        let _ = self.sub_stream.get_mut().shutdown();
        self.output_event(ProtocolEvent::Close {
            id: self.id,
            proto_id: self.proto_id,
        });
    }

    /// Handling commands send by session
    fn handle_proto_event(&mut self, event: ProtocolEvent) {
        match event {
            ProtocolEvent::Message { data, .. } => {
                debug!("proto [{}] send data: {}", self.proto_id, data.len());
                self.write_buf.push_back(data);
                match self.send_data() {
                    Err(_) => {
                        // Whether it is a read send error or a flush error,
                        // the most essential problem is that there is a problem with the external network.
                        // Close the protocol stream directly.
                        warn!(
                            "protocol [{}] close because of extern network",
                            self.proto_id
                        );
                        self.dead = true;
                    }
                    Ok(Async::NotReady) => (),
                    Ok(Async::Ready(_)) => (),
                }
            }
            ProtocolEvent::Close { .. } => {
                self.write_buf.clear();
                self.dead = true;
            }
            _ => (),
        }
    }

    #[inline]
    fn output_event(&mut self, event: ProtocolEvent) {
        self.read_buf.push_back(event);
        let _ = self.output();
    }

    #[inline]
    fn output(&mut self) -> Result<(), ()> {
        while let Some(event) = self.read_buf.pop_front() {
            if let Err(e) = self.event_sender.try_send(event) {
                if e.is_full() {
                    self.read_buf.push_front(e.into_inner());
                    self.notify();
                    break;
                } else {
                    warn!("proto send to session error: {}, may be kill by remote", e);
                    return Err(());
                }
            }
        }
        Ok(())
    }

    #[inline]
    fn notify(&mut self) {
        if let Some(task) = self.notify.take() {
            task.notify();
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), ()> {
        self.output()?;

        match self.send_data() {
            Ok(Async::Ready(_)) => (),
            Ok(Async::NotReady) => (),
            Err(_) => return Err(()),
        }

        Ok(())
    }
}

impl<U> Stream for SubStream<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error + Into<io::Error>,
    <U as Encoder>::Error: error::Error + Into<io::Error>,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if !self.read_buf.is_empty() || !self.write_buf.is_empty() {
            if let Err(()) = self.flush() {
                return Err(());
            }
        }

        loop {
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
                    })
                }
                Ok(Async::Ready(None)) => {
                    warn!("protocol [{}] close", self.proto_id);
                    self.dead = true;
                    break;
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("sub stream codec error: {:?}", err);
                    let err = err.into();
                    match err.kind() {
                        ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::NotConnected
                        | ErrorKind::UnexpectedEof => self.dead = true,
                        _ => {
                            self.output_event(ProtocolEvent::Error {
                                id: self.id,
                                proto_id: self.proto_id,
                                error: err.into(),
                            });
                        }
                    }
                    break;
                }
            }
        }

        loop {
            match self.event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_proto_event(event),
                Ok(Async::Ready(None)) => {
                    // Must be session close
                    self.dead = true;
                    break;
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("{:?}", err);
                    break;
                }
            }
        }

        if self.dead {
            self.close_proto_stream();
            return Ok(Async::Ready(None));
        }

        self.notify = Some(task::current());
        Ok(Async::NotReady)
    }
}
