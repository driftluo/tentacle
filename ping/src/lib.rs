mod protocol_builder;
mod protocol_generated;

use crate::protocol_generated::p2p::ping::*;
use flatbuffers::{get_root, FlatBufferBuilder};
use fnv::FnvHashMap;
use futures::sync::mpsc::Sender;
use log::debug;
use p2p::{
    context::{ServiceContext, SessionContext},
    traits::{ProtocolMeta, ServiceProtocol},
    ProtocolId, SessionId,
};
use std::{
    str,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::codec::length_delimited::LengthDelimitedCodec;

const SEND_PING_TOKEN: u64 = 0;
const CHECK_TIMEOUT_TOKEN: u64 = 1;
// TODO: replace this with real PeerId
type PeerId = SessionId;

#[derive(Debug)]
pub enum Event {
    Ping(PeerId),
    Pong(PeerId, Duration),
    Timeout(PeerId),
    UnexpectedError(PeerId),
}

pub struct PingProtocol {
    id: ProtocolId,
    interval: Duration,
    timeout: Duration,
    event_sender: Sender<Event>,
}

impl PingProtocol {
    pub fn new(
        id: ProtocolId,
        interval: Duration,
        timeout: Duration,
        event_sender: Sender<Event>,
    ) -> Self {
        PingProtocol {
            id,
            interval,
            timeout,
            event_sender,
        }
    }
}

impl ProtocolMeta<LengthDelimitedCodec> for PingProtocol {
    fn id(&self) -> ProtocolId {
        self.id
    }
    fn codec(&self) -> LengthDelimitedCodec {
        LengthDelimitedCodec::new()
    }

    fn service_handle(&self) -> Option<Box<dyn ServiceProtocol + Send + 'static>> {
        let handle = Box::new(PingHandler {
            proto_id: self.id,
            interval: self.interval,
            timeout: self.timeout,
            connected_session_ids: Default::default(),
            event_sender: self.event_sender.clone(),
        });
        Some(handle)
    }
}

struct PingHandler {
    proto_id: ProtocolId,
    interval: Duration,
    timeout: Duration,
    connected_session_ids: FnvHashMap<SessionId, PingStatus>,
    event_sender: Sender<Event>,
}

#[derive(Copy, Clone, Debug)]
struct PingStatus {
    processing: bool,
    last_ping: SystemTime,
}

impl PingStatus {
    fn nonce(&self) -> u32 {
        self.last_ping
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_secs())
            .unwrap_or(0) as u32
    }

    fn elapsed(&self) -> Duration {
        self.last_ping.elapsed().unwrap_or(Duration::from_secs(0))
    }
}

impl ServiceProtocol for PingHandler {
    fn init(&mut self, control: &mut ServiceContext) {
        // periodicly send ping to peers
        control.set_service_notify(self.proto_id, self.interval, SEND_PING_TOKEN);
        control.set_service_notify(self.proto_id, self.timeout, CHECK_TIMEOUT_TOKEN);
    }

    fn connected(
        &mut self,
        _control: &mut ServiceContext,
        session: &SessionContext,
        version: &str,
    ) {
        self.connected_session_ids
            .entry(session.id)
            .or_insert_with(|| PingStatus {
                last_ping: SystemTime::now(),
                processing: false,
            });
        debug!(
            "proto id [{}] open on session [{}], address: [{}], type: [{:?}], version: {}",
            self.proto_id, session.id, session.address, session.ty, version
        );
        debug!("connected sessions are: {:?}", self.connected_session_ids);
    }

    fn disconnected(&mut self, _control: &mut ServiceContext, session: &SessionContext) {
        self.connected_session_ids.remove(&session.id);
        debug!(
            "proto id [{}] close on session [{}]",
            self.proto_id, session.id
        );
    }

    fn received(&mut self, control: &mut ServiceContext, session: &SessionContext, data: Vec<u8>) {
        let msg = get_root::<PingMessage>(&data);
        match msg.payload_type() {
            PingPayload::Ping => {
                let ping_msg = msg.payload_as_ping().unwrap();
                let mut fbb = FlatBufferBuilder::new();
                let msg = PingMessage::build_pong(&mut fbb, ping_msg.nonce());
                fbb.finish(msg, None);
                let _ = control.send_message(
                    Some(vec![session.id]),
                    self.proto_id,
                    fbb.finished_data().to_vec(),
                );
                let _ = self.event_sender.try_send(Event::Ping(session.id));
            }
            PingPayload::Pong => {
                let pong_msg = msg.payload_as_pong().unwrap();
                if self
                    .connected_session_ids
                    .get(&session.id)
                    .map(|ps| (ps.processing, ps.nonce()))
                    == Some((true, pong_msg.nonce()))
                {
                    if let Some(ps) = self.connected_session_ids.get_mut(&session.id) {
                        ps.processing = false;
                        let _ = self
                            .event_sender
                            .try_send(Event::Pong(session.id, ps.elapsed()));
                    }
                } else {
                    // ignore if nonce is incorrect
                    let _ = self
                        .event_sender
                        .try_send(Event::UnexpectedError(session.id));
                }
            }
            PingPayload::NONE => {
                // can't decode msg
                let _ = self
                    .event_sender
                    .try_send(Event::UnexpectedError(session.id));
            }
        }
    }

    fn notify(&mut self, control: &mut ServiceContext, token: u64) {
        match token {
            SEND_PING_TOKEN => {
                debug!("proto [{}] start ping peers", self.proto_id);
                let now = SystemTime::now();
                let peers: Vec<(SessionId, u32)> = self
                    .connected_session_ids
                    .iter_mut()
                    .filter_map(|(session_id, ps)| {
                        if ps.processing {
                            None
                        } else {
                            ps.processing = true;
                            ps.last_ping = now;
                            Some((*session_id, ps.nonce()))
                        }
                    })
                    .collect();
                if !peers.is_empty() {
                    let mut fbb = FlatBufferBuilder::new();
                    let msg = PingMessage::build_ping(&mut fbb, peers[0].1);
                    fbb.finish(msg, None);
                    let peer_ids: Vec<SessionId> = peers
                        .into_iter()
                        .map(|(session_id, _)| session_id)
                        .collect();
                    let _ = control.send_message(
                        Some(peer_ids),
                        self.proto_id,
                        fbb.finished_data().to_vec(),
                    );
                }
            }
            CHECK_TIMEOUT_TOKEN => {
                debug!("proto [{}] check ping timeout", self.proto_id);
                let timeout = self.timeout;
                for (session_id, _) in self
                    .connected_session_ids
                    .iter()
                    .filter(|(_, ps)| ps.processing && ps.elapsed() >= timeout)
                {
                    let _ = self.event_sender.try_send(Event::Timeout(*session_id));
                }
            }
            _ => panic!("unknown token {}", token),
        }
    }
}
