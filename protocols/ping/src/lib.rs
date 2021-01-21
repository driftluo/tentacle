#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod protocol_mol;
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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
    unix_epoch: Instant,
}

impl<T> PingHandler<T>
where
    T: Callback,
{
    pub fn new(interval: Duration, timeout: Duration, callback: T) -> PingHandler<T> {
        let now = Instant::now();
        PingHandler {
            interval,
            timeout,
            connected_session_ids: Default::default(),
            callback,
            unix_epoch: now
                .checked_sub(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Convert system time fail"),
                )
                .unwrap_or(now),
        }
    }
}

fn nonce(t: &Instant, unix_epoch: Instant) -> u32 {
    t.duration_since(unix_epoch).as_secs() as u32
}

/// PingStatus of a peer
#[derive(Clone, Debug)]
struct PingStatus {
    /// Are we currently pinging this peer?
    processing: bool,
    /// The time we last send ping to this peer.
    last_ping: Instant,
    nonce: u32,
}

impl PingStatus {
    /// A meaningless value, peer must send a pong has same nonce to respond a ping.
    fn nonce(&self) -> u32 {
        self.nonce
    }

    /// Time duration since we last send ping.
    fn elapsed(&self) -> Duration {
        self.last_ping.elapsed()
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
                        last_ping: Instant::now(),
                        processing: false,
                        nonce: 0,
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
                let mut now = None;
                let mut send_nonce = 0;
                let unix_epoch = self.unix_epoch;
                let peers: Vec<SessionId> = self
                    .connected_session_ids
                    .iter_mut()
                    .filter_map(|(session_id, ps)| {
                        if ps.processing {
                            None
                        } else {
                            match now {
                                Some(t) => {
                                    ps.last_ping = t;
                                    if send_nonce == 0 {
                                        send_nonce = nonce(&t, unix_epoch);
                                    }
                                }
                                None => {
                                    let t = Instant::now();
                                    now = Some(t);
                                    ps.last_ping = t;
                                    if send_nonce == 0 {
                                        send_nonce = nonce(&t, unix_epoch);
                                    }
                                }
                            }
                            ps.nonce = send_nonce;
                            Some(*session_id)
                        }
                    })
                    .collect();
                if !peers.is_empty() {
                    debug!("start ping peers: {:?}", peers);
                    let ping_msg = PingMessage::build_ping(send_nonce);
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
                for (id, _ps) in self
                    .connected_session_ids
                    .iter()
                    .filter(|(_id, ps)| ps.processing && ps.elapsed() >= timeout)
                {
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
