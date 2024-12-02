#![cfg(feature = "tls")]
use futures::channel;
use std::{str::FromStr, thread};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    error::{DialerErrorKind, ListenErrorKind},
    multiaddr::Multiaddr,
    secio::NoopKeyProvider,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, SessionType,
        TargetProtocol, TlsConfig,
    },
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId, SessionId,
};

#[path = "./tls_common.rs"]
mod tls;

use tls::{make_client_config, make_server_config, NetConfig};

pub fn create<F>(meta: ProtocolMeta, shandle: F, cert_path: String) -> Service<F, NoopKeyProvider>
where
    F: ServiceHandle + Unpin + 'static,
{
    let mut builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true);

    let tls_config = TlsConfig::new(
        Some(make_server_config(&NetConfig::example(cert_path.clone()))),
        Some(make_client_config(&NetConfig::example(cert_path))),
    );
    builder = builder.tls_config(tls_config);

    builder.build(shandle)
}

#[derive(Clone, Copy, Debug)]
enum ServiceErrorType {
    Dialer,
    Listen,
}

#[derive(Clone)]
pub struct SHandle {
    sender: crossbeam_channel::Sender<ServiceErrorType>,
    session_id: SessionId,
    kind: SessionType,
}

#[async_trait]
impl ServiceHandle for SHandle {
    async fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        let error_type = match error {
            ServiceError::DialerError { error, .. } => {
                match error {
                    DialerErrorKind::HandshakeError(_) => (),
                    DialerErrorKind::RepeatedConnection(id) => assert_eq!(id, self.session_id),
                    err => panic!(
                        "test fail, expected DialerErrorKind::RepeatedConnection, got {:?}",
                        err
                    ),
                }
                ServiceErrorType::Dialer
            }
            ServiceError::ListenError { error, .. } => {
                match error {
                    ListenErrorKind::RepeatedConnection(id) => assert_eq!(id, self.session_id),
                    err => panic!(
                        "test fail, expected ListenErrorKind::RepeatedConnection, got {:?}",
                        err
                    ),
                }
                ServiceErrorType::Listen
            }
            e => panic!("test fail, error: {:?}", e),
        };

        let _res = self.sender.try_send(error_type);
    }

    async fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { session_context } = event {
            self.session_id = session_context.id;
            self.kind = session_context.ty;
        }
    }
}

struct PHandle {
    sender: crossbeam_channel::Sender<bytes::Bytes>,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        context
            .send_message(bytes::Bytes::from("hello world"))
            .await
            .unwrap();
    }

    async fn received(&mut self, _context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        self.sender.try_send(data).unwrap();
    }
}

fn create_meta(id: ProtocolId) -> (ProtocolMeta, crossbeam_channel::Receiver<bytes::Bytes>) {
    // NOTE: channel size must large, otherwise send will failed.
    let (sender, receiver) = crossbeam_channel::unbounded();

    let meta = MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle { sender });
                ProtocolHandle::Callback(handle)
            }
        })
        .build();

    (meta, receiver)
}

fn create_shandle() -> (
    Box<dyn ServiceHandle + Send>,
    crossbeam_channel::Receiver<ServiceErrorType>,
) {
    // NOTE: channel size must large, otherwise send will failed.
    let (sender, receiver) = crossbeam_channel::unbounded();

    (
        Box::new(SHandle {
            sender,
            session_id: 0.into(),
            kind: SessionType::Inbound,
        }),
        receiver,
    )
}

fn test_tls_dial() {
    let (meta_1, receiver_1) = create_meta(1.into());
    let (meta_2, receiver_2) = create_meta(1.into());
    let (shandle, _error_receiver_1) = create_shandle();
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    thread::spawn(move || {
        let multi_addr_1 = Multiaddr::from_str(
            "/dns4/127.0.0.1/tcp/0/tls/0x09cbaa785348dabd54c61f5f9964474f7bfad7df",
        )
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(meta_1, shandle, "tests/certificates/node0/".to_string());
        rt.block_on(async move {
            let listen_addr = service.listen(multi_addr_1).await.unwrap();
            let _res = addr_sender.send(listen_addr);
            service.run().await
        });
    });

    let (shandle, _error_receiver_2) = create_shandle();

    thread::spawn(move || {
        let _multi_addr_2 = Multiaddr::from_str(
            "/ip4/127.0.0.1/tcp/0/tls/0x388f042dd011824b91ecda56c85eeec993894f88",
        )
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(meta_2, shandle, "tests/certificates/node1/".to_string());
        rt.block_on(async move {
            let listen_addr = addr_receiver.await.unwrap();
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();
            service.run().await
        });
    });

    assert_eq!(receiver_1.recv(), Ok(bytes::Bytes::from("hello world")));
    assert_eq!(receiver_2.recv(), Ok(bytes::Bytes::from("hello world")));
}

#[test]
fn test_tls_message_send() {
    test_tls_dial()
}
