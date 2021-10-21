#![cfg(feature = "unstable")]

/// Implement simple.rs example using `ProtocolSpawn`.
use bytes::Bytes;
use env_logger;
use futures::StreamExt;
use log::info;
use std::{str, sync::Arc, time::Duration};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ServiceContext, SessionContext},
    secio::SecioKeyPair,
    service::{
        ProtocolMeta, Service, ServiceAsyncControl, ServiceError, ServiceEvent, TargetProtocol,
        TargetSession,
    },
    traits::{ProtocolSpawn, ServiceHandle},
    ProtocolId, SubstreamReadPart,
};

struct ProtocolStream;

impl ProtocolSpawn for ProtocolStream {
    fn spawn(
        &self,
        context: Arc<SessionContext>,
        control: &ServiceAsyncControl,
        mut read_part: SubstreamReadPart,
    ) {
        let control = control.clone();
        tokio::spawn(async move {
            info!(
                "{}, {:?}, {}, opened",
                context.id,
                context.ty,
                read_part.protocol_id()
            );
            if read_part.protocol_id() == 1.into() {
                let c = control.clone();
                let pid = read_part.protocol_id();
                let mut interval =
                    tokio::time::interval_at(tokio::time::Instant::now(), Duration::from_secs(5));
                tokio::spawn(async move {
                    loop {
                        interval.tick().await;
                        let _ = c
                            .filter_broadcast(
                                TargetSession::All,
                                pid,
                                Bytes::from("I am a interval message"),
                            )
                            .await;
                    }
                });
            }
            loop {
                if let Some(Ok(data)) = read_part.next().await {
                    info!(
                        "received from [{}]: proto [{}] data {:?}",
                        context.id,
                        read_part.protocol_id(),
                        str::from_utf8(data.as_ref()).unwrap(),
                    );
                    if context.ty.is_outbound() {
                        let pid = read_part.protocol_id();
                        let _ = control.send_message_to(context.id, pid, data).await;
                    }
                } else {
                    break;
                }
            }
            info!(
                "{}, {:?}, {}, closed",
                context.id,
                context.ty,
                read_part.protocol_id()
            );
        });
    }
}

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .protocol_spawn(ProtocolStream)
        .build()
}

struct SHandle;

#[async_trait]
impl ServiceHandle for SHandle {
    async fn handle_error(&mut self, _context: &mut ServiceContext, error: ServiceError) {
        info!("service error: {:?}", error);
    }
    async fn handle_event(&mut self, context: &mut ServiceContext, event: ServiceEvent) {
        info!("service event: {:?}", event);
        if let ServiceEvent::SessionOpen { .. } = event {
            let delay_sender = context.control().clone();

            let _ = context
                .future_task(async move {
                    tokio::time::sleep_until(tokio::time::Instant::now() + Duration::from_secs(3))
                        .await;
                    let _ = delay_sender.filter_broadcast(
                        TargetSession::All,
                        0.into(),
                        Bytes::from("I am a delayed message"),
                    );
                })
                .await;
        }
    }
}

fn main() {
    env_logger::init();

    if std::env::args().nth(1) == Some("server".to_string()) {
        info!("Starting server ......");
        server();
    } else {
        info!("Starting client ......");
        client();
    }
}

fn create_server() -> Service<SHandle> {
    ServiceBuilder::default()
        .insert_protocol(create_meta(0.into()))
        .insert_protocol(create_meta(1.into()))
        .key_pair(SecioKeyPair::secp256k1_generated())
        .build(SHandle)
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

fn server() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let mut service = create_server();
        service
            .listen("/ip4/127.0.0.1/tcp/1337".parse().unwrap())
            .await
            .unwrap();
        #[cfg(feature = "ws")]
        service
            .listen("/ip4/127.0.0.1/tcp/1338/ws".parse().unwrap())
            .await
            .unwrap();
        service.run().await
    });
}

fn client() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let mut service = create_client();
        service
            .dial(
                "/ip4/127.0.0.1/tcp/1337".parse().unwrap(),
                TargetProtocol::All,
            )
            .await
            .unwrap();
        service.run().await
    });
}
