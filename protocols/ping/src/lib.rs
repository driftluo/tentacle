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

use log::{debug, error, trace, warn};
use p2p::{
    bytes::Bytes,
    context::{ProtocolContext, ProtocolContextMutRef},
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

pub trait Callback {
    fn received_ping(&mut self, context: ProtocolContextMutRef);
    fn received_pong(&mut self, context: ProtocolContextMutRef, time: Duration);
    fn timeout(&mut self, context: &mut ProtocolContext, id: SessionId);
    fn unexpected_error(&mut self, context: ProtocolContextMutRef);
}

/// Ping protocol handler.
///
/// The interval means that we send ping to peers.
/// The timeout means that consider peer is timeout if during a timeout we still have not received pong from a peer
pub struct PingHandler<T> {
    interval: Duration,
    timeout: Duration,
    connected_session_ids: HashMap<SessionId, PingStatus>,
    callback: T,
}

impl<T> PingHandler<T>
where
    T: Callback,
{
    pub fn new(interval: Duration, timeout: Duration, callback: T) -> PingHandler<T> {
        PingHandler {
            interval,
            timeout,
            connected_session_ids: Default::default(),
            callback,
        }
    }
}

fn nonce(t: &SystemTime) -> u32 {
    t.duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .unwrap_or_default() as u32
}

/// PingStatus of a peer
#[derive(Clone, Debug)]
struct PingStatus {
    /// Are we currently pinging this peer?
    processing: bool,
    /// The time we last send ping to this peer.
    last_ping: SystemTime,
}

impl PingStatus {
    /// A meaningless value, peer must send a pong has same nonce to respond a ping.
    fn nonce(&self) -> u32 {
        nonce(&self.last_ping)
    }

    /// Time duration since we last send ping.
    fn elapsed(&self) -> Duration {
        self.last_ping.elapsed().unwrap_or(Duration::from_secs(0))
    }
}

impl<T> ServiceProtocol for PingHandler<T>
where
    T: Callback,
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
            Some(_) => {
                self.connected_session_ids
                    .entry(session.id)
                    .or_insert_with(|| PingStatus {
                        last_ping: SystemTime::now(),
                        processing: false,
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

    fn received(&mut self, context: ProtocolContextMutRef, data: Bytes) {
        let session = context.session;
        match PingMessage::decode(data.as_ref()) {
            None => {
                error!("decode message error");
                self.callback.unexpected_error(context);
            }
            Some(msg) => {
                match msg {
                    PingPayload::Ping(nonce) => {
                        trace!("get ping from: {:?}", context.session.id);
                        if context
                            .send_message(PingMessage::build_pong(nonce))
                            .is_err()
                        {
                            debug!("send message fail");
                        }
                        self.callback.received_ping(context);
                    }
                    PingPayload::Pong(nonce) => {
                        // check pong
                        if let Some(status) = self.connected_session_ids.get_mut(&session.id) {
                            if (true, nonce) == (status.processing, status.nonce()) {
                                status.processing = false;
                                let ping_time = status.elapsed();
                                self.callback.received_pong(context, ping_time);
                                return;
                            }
                        }
                        // if nonce is incorrect or can't find ping info
                        if let Err(err) = context.disconnect(session.id) {
                            debug!("Disconnect failed {:?}, error: {:?}", session.id, err);
                        }
                    }
                }
            }
        }
    }

    fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        match token {
            SEND_PING_TOKEN => {
                let now = SystemTime::now();
                let peers: Vec<SessionId> = self
                    .connected_session_ids
                    .iter_mut()
                    .filter_map(|(session_id, ps)| {
                        if ps.processing {
                            None
                        } else {
                            ps.processing = true;
                            ps.last_ping = now;
                            Some(*session_id)
                        }
                    })
                    .collect();
                if !peers.is_empty() {
                    debug!("start ping peers: {:?}", peers);
                    let ping_msg = PingMessage::build_ping(nonce(&now));
                    let proto_id = context.proto_id;
                    if context
                        .filter_broadcast(TargetSession::Multi(peers), proto_id, ping_msg)
                        .is_err()
                    {
                        debug!("send message fail");
                    }
                }
            }
            CHECK_TIMEOUT_TOKEN => {
                let timeout = self.timeout;
                for id in self.connected_session_ids.iter().filter_map(|(id, ps)| {
                    if ps.processing && ps.elapsed() >= timeout {
                        Some(id)
                    } else {
                        None
                    }
                }) {
                    debug!("ping timeout, {:?}", id);
                    self.callback.timeout(context, *id);
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
        Bytes::from(fbb.finished_data().to_owned())
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
        Bytes::from(fbb.finished_data().to_owned())
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
        let nonce_le = nonce.to_le_bytes();
        let nonce = protocol_mol::Uint32::new_builder()
            .nth0(nonce_le[0].into())
            .nth1(nonce_le[1].into())
            .nth2(nonce_le[2].into())
            .nth3(nonce_le[3].into())
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
        let nonce_le = nonce.to_le_bytes();
        let nonce = protocol_mol::Uint32::new_builder()
            .nth0(nonce_le[0].into())
            .nth1(nonce_le[1].into())
            .nth2(nonce_le[2].into())
            .nth3(nonce_le[3].into())
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
        }
    }
}
