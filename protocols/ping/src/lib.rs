#[cfg(all(feature = "flatc", feature = "molc"))]
compile_error!("features `flatc` and `molc` are mutually exclusive");
#[cfg(all(not(feature = "flatc"), not(feature = "molc")))]
compile_error!("Please choose a serialization format via feature. Possible choices: flatc, molc");

#[cfg(feature = "flatc")]
#[rustfmt::skip]
#[allow(clippy::all)]
mod protocol_generated;
#[cfg(feature = "flatc")]
#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod protocol_generated_verifier;

#[cfg(feature = "molc")]
#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod protocol_mol;
#[cfg(feature = "molc")]
use molecule::prelude::{Builder, Entity, Reader};

use bytes::Bytes;
use generic_channel::Sender;
use log::{debug, error, warn};
use p2p::{
    context::{ProtocolContext, ProtocolContextMutRef},
    secio::PeerId,
    service::TargetSession,
    traits::ServiceProtocol,
    SessionId,
};
use std::{
    collections::HashMap,
    str,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SEND_PING_TOKEN: u64 = 0;
const CHECK_TIMEOUT_TOKEN: u64 = 1;

/// Ping protocol events
#[derive(Debug)]
pub enum Event {
    /// Peer send ping to us.
    Ping(PeerId),
    /// Peer send pong to us.
    Pong(PeerId, Duration),
    /// Peer is timeout.
    Timeout(PeerId),
    /// Peer cause a unexpected error.
    UnexpectedError(PeerId),
}

/// Ping protocol handler.
///
/// The interval means that we send ping to peers.
/// The timeout means that consider peer is timeout if during a timeout we still have not received pong from a peer
pub struct PingHandler<S: Sender<Event>> {
    interval: Duration,
    timeout: Duration,
    connected_session_ids: HashMap<SessionId, PingStatus>,
    event_sender: S,
}

impl<S: Sender<Event>> PingHandler<S> {
    pub fn new(interval: Duration, timeout: Duration, event_sender: S) -> PingHandler<S> {
        PingHandler {
            interval,
            timeout,
            connected_session_ids: Default::default(),
            event_sender,
        }
    }

    pub fn send_event(&mut self, event: Event) {
        if let Err(err) = self.event_sender.try_send(event) {
            error!("send ping event error: {}", err);
        }
    }
}

/// PingStatus of a peer
#[derive(Clone, Debug)]
struct PingStatus {
    /// Are we currently pinging this peer?
    processing: bool,
    /// The time we last send ping to this peer.
    last_ping: SystemTime,
    peer_id: PeerId,
}

impl PingStatus {
    /// A meaningless value, peer must send a pong has same nonce to respond a ping.
    fn nonce(&self) -> u32 {
        self.last_ping
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_secs())
            .unwrap_or(0) as u32
    }

    /// Time duration since we last send ping.
    fn elapsed(&self) -> Duration {
        self.last_ping.elapsed().unwrap_or(Duration::from_secs(0))
    }
}

impl<S> ServiceProtocol for PingHandler<S>
where
    S: Sender<Event>,
{
    fn init(&mut self, context: &mut ProtocolContext) {
        // periodicly send ping to peers
        let proto_id = context.proto_id;
        if context
            .set_service_notify(proto_id, self.interval, SEND_PING_TOKEN)
            .is_err()
        {
            warn!("start ping fail");
        }
        if context
            .set_service_notify(proto_id, self.timeout, CHECK_TIMEOUT_TOKEN)
            .is_err()
        {
            warn!("start ping fail");
        }
    }

    fn connected(&mut self, context: ProtocolContextMutRef, version: &str) {
        let session = context.session;
        match session.remote_pubkey {
            Some(ref pubkey) => {
                let peer_id = pubkey.peer_id();
                self.connected_session_ids
                    .entry(session.id)
                    .or_insert_with(|| PingStatus {
                        last_ping: SystemTime::now(),
                        processing: false,
                        peer_id,
                    });
                debug!(
                    "proto id [{}] open on session [{}], address: [{}], type: [{:?}], version: {}",
                    context.proto_id, session.id, session.address, session.ty, version
                );
                debug!("connected sessions are: {:?}", self.connected_session_ids);
            }
            None => {
                if context.disconnect(session.id).is_err() {
                    debug!("disconnect fail");
                }
            }
        }
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        let session = context.session;
        self.connected_session_ids.remove(&session.id);
        debug!(
            "proto id [{}] close on session [{}]",
            context.proto_id, session.id
        );
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        let session = context.session;
        if let Some(peer_id) = self
            .connected_session_ids
            .get(&session.id)
            .map(|ps| ps.peer_id.clone())
        {
            match PingMessage::decode(data.as_ref()) {
                None => {
                    error!("decode message error");
                    self.send_event(Event::UnexpectedError(peer_id));
                }
                Some(msg) => {
                    match msg {
                        PingPayload::Ping(nonce) => {
                            if context
                                .send_message(PingMessage::build_pong(nonce))
                                .is_err()
                            {
                                debug!("send message fail");
                            }
                            self.send_event(Event::Ping(peer_id));
                        }
                        PingPayload::Pong(nonce) => {
                            // check pong
                            if self
                                .connected_session_ids
                                .get(&session.id)
                                .map(|ps| (ps.processing, ps.nonce()))
                                == Some((true, nonce))
                            {
                                let ping_time =
                                    match self.connected_session_ids.get_mut(&session.id) {
                                        Some(ps) => {
                                            ps.processing = false;
                                            ps.elapsed()
                                        }
                                        None => return,
                                    };
                                self.send_event(Event::Pong(peer_id, ping_time));
                            } else {
                                // ignore if nonce is incorrect
                                self.send_event(Event::UnexpectedError(peer_id));
                            }
                        }
                    }
                }
            }
        }
    }

    fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        match token {
            SEND_PING_TOKEN => {
                debug!("proto [{}] start ping peers", context.proto_id);
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
                    let ping_msg = PingMessage::build_ping(peers[0].1);
                    let peer_ids: Vec<SessionId> = peers
                        .into_iter()
                        .map(|(session_id, _)| session_id)
                        .collect();
                    let proto_id = context.proto_id;
                    if context
                        .filter_broadcast(TargetSession::Multi(peer_ids), proto_id, ping_msg)
                        .is_err()
                    {
                        debug!("send message fail");
                    }
                }
            }
            CHECK_TIMEOUT_TOKEN => {
                debug!("proto [{}] check ping timeout", context.proto_id);
                let timeout = self.timeout;
                for peer_id in self
                    .connected_session_ids
                    .values()
                    .filter(|ps| ps.processing && ps.elapsed() >= timeout)
                    .map(|ps| ps.peer_id.clone())
                    .collect::<Vec<PeerId>>()
                {
                    self.send_event(Event::Timeout(peer_id));
                }
            }
            _ => panic!("unknown token {}", token),
        }
    }
}

enum PingPayload {
    Ping(u32),
    Pong(u32),
}

struct PingMessage;

impl PingMessage {
    #[cfg(feature = "flatc")]
    fn build_ping(nonce: u32) -> Bytes {
        let mut fbb = flatbuffers::FlatBufferBuilder::new();
        let ping = {
            let mut ping = protocol_generated::p2p::ping::PingBuilder::new(&mut fbb);
            ping.add_nonce(nonce);
            ping.finish()
        };

        let mut builder = protocol_generated::p2p::ping::PingMessageBuilder::new(&mut fbb);
        builder.add_payload_type(protocol_generated::p2p::ping::PingPayload::Ping);
        builder.add_payload(ping.as_union_value());
        let data = builder.finish();
        fbb.finish(data, None);
        Bytes::from(fbb.finished_data())
    }

    #[cfg(feature = "flatc")]
    fn build_pong(nonce: u32) -> Bytes {
        let mut fbb = flatbuffers::FlatBufferBuilder::new();
        let pong = {
            let mut pong = protocol_generated::p2p::ping::PongBuilder::new(&mut fbb);
            pong.add_nonce(nonce);
            pong.finish()
        };
        let mut builder = protocol_generated::p2p::ping::PingMessageBuilder::new(&mut fbb);
        builder.add_payload_type(protocol_generated::p2p::ping::PingPayload::Pong);
        builder.add_payload(pong.as_union_value());
        let data = builder.finish();
        fbb.finish(data, None);
        Bytes::from(fbb.finished_data())
    }

    #[cfg(feature = "flatc")]
    fn decode(data: &[u8]) -> Option<PingPayload> {
        let msg =
            flatbuffers_verifier::get_root::<protocol_generated::p2p::ping::PingMessage>(data)
                .ok()?;
        match msg.payload_type() {
            protocol_generated::p2p::ping::PingPayload::Ping => {
                Some(PingPayload::Ping(msg.payload_as_ping().unwrap().nonce()))
            }
            protocol_generated::p2p::ping::PingPayload::Pong => {
                Some(PingPayload::Pong(msg.payload_as_pong().unwrap().nonce()))
            }
            protocol_generated::p2p::ping::PingPayload::NONE => None,
        }
    }

    #[cfg(feature = "molc")]
    fn build_ping(nonce: u32) -> Bytes {
        let nonce = protocol_mol::Uint32::new_builder()
            .set(nonce.to_le_bytes())
            .build();
        let ping = protocol_mol::Ping::new_builder().nonce(nonce).build();
        let payload = protocol_mol::PingPayload::new_builder().set(ping).build();
        protocol_mol::PingMessage::new_builder()
            .payload(payload)
            .build()
            .as_bytes()
    }

    #[cfg(feature = "molc")]
    fn build_pong(nonce: u32) -> Bytes {
        let nonce = protocol_mol::Uint32::new_builder()
            .set(nonce.to_le_bytes())
            .build();
        let pong = protocol_mol::Pong::new_builder().nonce(nonce).build();
        let payload = protocol_mol::PingPayload::new_builder().set(pong).build();
        protocol_mol::PingMessage::new_builder()
            .payload(payload)
            .build()
            .as_bytes()
    }

    #[cfg(feature = "molc")]
    #[allow(clippy::cast_ptr_alignment)]
    fn decode(data: &[u8]) -> Option<PingPayload> {
        let reader = protocol_mol::PingMessageReader::from_compatible_slice(data).ok()?;
        match reader.payload().to_enum() {
            protocol_mol::PingPayloadUnionReader::Ping(reader) => {
                let le = reader.nonce().raw_data().as_ptr() as *const u32;
                Some(PingPayload::Ping(u32::from_le(unsafe { *le })))
            }
            protocol_mol::PingPayloadUnionReader::Pong(reader) => {
                let le = reader.nonce().raw_data().as_ptr() as *const u32;
                Some(PingPayload::Pong(u32::from_le(unsafe { *le })))
            }
            protocol_mol::PingPayloadUnionReader::NotSet => None,
        }
    }
}
