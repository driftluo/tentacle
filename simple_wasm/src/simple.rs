use futures::{prelude::*};
use std::{str, time::Duration};
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    bytes::{self, Bytes},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, TargetProtocol, TargetSession
    },
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId, SessionId,
};

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            // All protocol use the same handle.
            // This is just an example. In the actual environment, this should be a different handle.
            let handle = Box::new(PHandle {
                count: 0,
                connected_session_ids: Vec::new(),
            });
            ProtocolHandle::Callback(handle)
        })
        .build()
}

#[derive(Default)]
struct PHandle {
    count: usize,
    connected_session_ids: Vec<SessionId>,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, context: &mut ProtocolContext) {
        if context.proto_id == 0.into() {
            let _ = context.set_service_notify(0.into(), Duration::from_secs(5), 3);
        }
    }

    fn connected(&mut self, context: ProtocolContextMutRef, version: &str) {
        let session = context.session;
        self.connected_session_ids.push(session.id);
        web_sys::console::log_1(
            &format!(
                "proto id [{}] open on session [{}], address: [{}], type: [{:?}], version: {}",
                context.proto_id, session.id, session.address, session.ty, version
            )
            .into(),
        );
    }

    fn disconnected(&mut self, context: ProtocolContextMutRef) {
        let new_list = self
            .connected_session_ids
            .iter()
            .filter(|&id| id != &context.session.id)
            .cloned()
            .collect();
        self.connected_session_ids = new_list;

        web_sys::console::log_1(
            &format!(
                "proto id [{}] close on session [{}]",
                context.proto_id, context.session.id
            )
            .into(),
        );
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: bytes::Bytes) {
        self.count += 1;
        web_sys::console::log_1(
            &format!(
                "received from [{}]: proto [{}] data {:?}, message count: {}",
                context.session.id,
                context.proto_id,
                str::from_utf8(data.as_ref()).unwrap(),
                self.count
            )
            .into(),
        );
    }

    fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        web_sys::console::log_1(
            &format!(
                "proto [{}] received notify token: {}",
                context.proto_id, token
            )
            .into(),
        );

        let _ = context.filter_broadcast(TargetSession::All, 1.into(), Bytes::from("I am a interval message"));
    }
}

struct SHandle;

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _context: &mut ServiceContext, error: ServiceError) {
        web_sys::console::log_1(&format!("service error: {:?}", error).into());
    }
    fn handle_event(&mut self, _context: &mut ServiceContext, event: ServiceEvent) {
        web_sys::console::log_1(&format!("service event: {:?}", event).into());
    }
}

/// Proto 0 open success
/// Proto 1 open success
/// Proto 2 open failure
///
/// Because server only supports 0,1
fn create_client() -> Service<SHandle> {
    ServiceBuilder::default()
        .insert_protocol(create_meta(0.into()))
        .insert_protocol(create_meta(1.into()))
        .insert_protocol(create_meta(2.into()))
        .key_pair(SecioKeyPair::secp256k1_generated())
        .build(SHandle)
}

pub fn client() {
    wasm_bindgen_futures::spawn_local(async {
        let mut service = create_client();
        service
            .dial(
                "/ip4/127.0.0.1/tcp/1338/ws".parse().unwrap(),
                TargetProtocol::All,
            )
            .await
            .unwrap();
        loop {
            if service.next().await.is_none() {
                break;
            }
        }
    });
}
