#![cfg(all(feature = "tls", feature = "ws"))]

use futures::channel;
use multiaddr::Protocol;
use std::{
    collections::HashSet,
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
};
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ServiceContext},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceEvent, TargetProtocol, TlsConfig},
    traits::{ServiceHandle, ServiceProtocol},
    utils::{TransportType, find_type},
};

#[path = "./tls_common.rs"]
mod tls;

pub fn create<F>(
    secio: bool,
    meta: ProtocolMeta,
    shandle: F,
    cert_path: String,
) -> Service<F, SecioKeyPair>
where
    F: ServiceHandle + Unpin + 'static,
{
    let tls_config = TlsConfig::new(
        Some(tls::make_server_config(&tls::NetConfig::example(
            cert_path.clone(),
        ))),
        Some(tls::make_client_config(&tls::NetConfig::example(cert_path))),
    );
    let builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .tls_config(tls_config);

    if secio {
        builder
            .handshake_type(SecioKeyPair::secp256k1_generated().into())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

fn create_meta(id: impl Into<ProtocolId> + Copy + Send + 'static) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id.into())
        .service_handle(move || {
            if id.into() == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle);
                ProtocolHandle::Callback(handle)
            }
        })
        .build()
}

struct PHandle;

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}
}

struct SHandle {
    count: Arc<Mutex<HashSet<TransportType>>>,
}

#[async_trait]
impl ServiceHandle for SHandle {
    async fn handle_event(&mut self, _control: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { session_context } = event {
            self.count
                .lock()
                .unwrap()
                .insert(find_type(&session_context.address));
            let _ignore = _control.disconnect(session_context.id).await;
        }
    }
}

fn test_tcp_upgrade_mod(secio: bool) {
    let meta_1 = create_meta(1);
    let meta_2 = create_meta(1);
    let meta_3 = create_meta(1);
    let meta_4 = create_meta(1);
    let count = Arc::new(Mutex::new(Default::default()));
    let shandle = SHandle {
        count: count.clone(),
    };
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let rt = tokio::runtime::Runtime::new().unwrap();
    thread::spawn(move || {
        let multi_addr_1 = Multiaddr::from_str(
            "/dns4/127.0.0.1/tcp/0/tls/0x09cbaa785348dabd54c61f5f9964474f7bfad7df",
        )
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(
            secio,
            meta_1,
            shandle,
            "tests/certificates/node0/".to_string(),
        );
        rt.block_on(async move {
            let tls_addr = service.listen(multi_addr_1).await.unwrap();
            let tcp_listen = {
                let mut tcp_listen = tls_addr.clone();
                tcp_listen.pop();
                tcp_listen
            };
            let ws_listen = {
                let mut t = tcp_listen.clone();
                t.push(Protocol::Ws);
                t
            };
            let _ = service.listen(tcp_listen).await.unwrap();
            let _ = service.listen(ws_listen).await.unwrap();
            let _res = addr_sender.send(tls_addr);
            service.run().await
        });
    });

    let tls_addr = rt.block_on(async move { addr_receiver.await.unwrap() });
    let tcp_listen = {
        let mut tcp_listen = tls_addr.clone();
        tcp_listen.pop();
        tcp_listen
    };
    let ws_listen = {
        let mut t = tcp_listen.clone();
        t.push(Protocol::Ws);
        t
    };

    let handle_1 = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta_2, (), "tests/certificates/node1/".to_string());
        rt.block_on(async move {
            service.dial(tls_addr, TargetProtocol::All).await.unwrap();
            service.run().await
        });
    });

    let handle_2 = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta_3, (), "tests/certificates/node1/".to_string());
        rt.block_on(async move {
            service.dial(tcp_listen, TargetProtocol::All).await.unwrap();
            service.run().await
        });
    });

    let handle_3 = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta_4, (), "tests/certificates/node1/".to_string());
        rt.block_on(async move {
            service.dial(ws_listen, TargetProtocol::All).await.unwrap();
            service.run().await
        });
    });

    handle_1.join().unwrap();
    handle_2.join().unwrap();
    handle_3.join().unwrap();

    let inner = count.lock().unwrap();
    assert_eq!(inner.len(), 3);
    assert_eq!(
        &*inner,
        &HashSet::from_iter([TransportType::Tcp, TransportType::Ws, TransportType::Tls])
    )
}

#[test]
fn test_tcp_upgrade_mod_tls_tcp_ws_with_secio() {
    test_tcp_upgrade_mod(true);
}

#[test]
fn test_tcp_upgrade_mod_tls_tcp_ws_with_no_secio() {
    test_tcp_upgrade_mod(false);
}
