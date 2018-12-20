use futures::{prelude::*, sync::mpsc};
use log::{debug, error, warn};
use std::collections::VecDeque;
use std::error;
use tokio::codec::{Decoder, Encoder, Framed};
use yamux::StreamHandle;

use crate::sessions::{ProtocolId, StreamId};

pub enum ProtocolEvent {
    ProtocolOpen {
        proto_name: Vec<u8>,
        sub_stream: StreamHandle,
    },
    ProtocolClose {
        id: StreamId,
        proto_id: ProtocolId,
    },
    ProtocolMessage {
        id: StreamId,
        proto_id: ProtocolId,
        data: bytes::Bytes,
    },
}

pub struct SubStream<U> {
    sub_stream: Framed<StreamHandle, U>,
    id: StreamId,
    proto_id: ProtocolId,
    data_buf: VecDeque<bytes::Bytes>,

    /// send event to session
    event_sender: mpsc::Sender<ProtocolEvent>,
    /// receive events from session
    event_receiver: mpsc::Receiver<ProtocolEvent>,
}

impl<U> SubStream<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error,
    <U as Encoder>::Error: error::Error,
{
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
            data_buf: VecDeque::new(),
        }
    }

    fn send_data(&mut self, data: bytes::Bytes) -> Poll<(), ()> {
        self.data_buf.push_back(data);
        while let Some(frame) = self.data_buf.pop_front() {
            match self.sub_stream.start_send(frame) {
                Ok(AsyncSink::NotReady(frame)) => {
                    debug!("framed_stream NotReady, frame: {:?}", frame);
                    self.data_buf.push_front(frame);
                    return Ok(Async::NotReady);
                }
                Ok(AsyncSink::Ready) => {}
                Err(err) => {
                    debug!("framed_stream error: {:?}", err);
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
}

impl<U> Stream for SubStream<U>
where
    U: Decoder<Item = bytes::BytesMut> + Encoder<Item = bytes::Bytes> + Send + 'static,
    <U as Decoder>::Error: error::Error,
    <U as Encoder>::Error: error::Error,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match self.sub_stream.poll() {
                Ok(Async::Ready(Some(data))) => {
                    debug!("protocol [{}] receive data: {:?}", self.proto_id, data);
                    if let Err(e) = self.event_sender.try_send(ProtocolEvent::ProtocolMessage {
                        id: self.id,
                        proto_id: self.proto_id,
                        data: data.into(),
                    }) {
                        error!("proto send to session error: {}", e);
                    }
                }
                Ok(Async::Ready(None)) => {
                    let _ = self.event_sender.try_send(ProtocolEvent::ProtocolClose {
                        id: self.id,
                        proto_id: self.proto_id,
                    });
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("{:?}", err);
                    break;
                }
            }
        }

        loop {
            match self.event_receiver.poll() {
                Ok(Async::Ready(Some(event))) => {
                    if let ProtocolEvent::ProtocolMessage { data, .. } = event {
                        if let Ok(Async::NotReady) = self.send_data(data) {
                            break;
                        }
                    }
                }
                Ok(Async::Ready(None)) => {
                    // Must be session close
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!("{:?}", err);
                    break;
                }
            }
        }

        Ok(Async::NotReady)
    }
}
