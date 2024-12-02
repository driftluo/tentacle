#![cfg(feature = "tls")]
use crossbeam_channel::Receiver;
use std::{str::FromStr, thread, time::Duration};
use tentacle::bytes::Bytes;
use tentacle::service::ServiceControl;
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    secio::NoopKeyProvider,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol, TlsConfig},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
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

struct PHandle {
    sender: crossbeam_channel::Sender<bytes::Bytes>,
    send: bool,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        if !self.send {
            context
                .send_message(bytes::Bytes::from("hello world"))
                .await
                .unwrap();
        }
    }

    async fn received(&mut self, _context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        if self.send {
            self.sender.try_send(data).unwrap();
        }
    }
}

fn create_meta(
    id: ProtocolId,
    send: bool,
) -> (ProtocolMeta, crossbeam_channel::Receiver<bytes::Bytes>) {
    // NOTE: channel size must large, otherwise send will failed.
    let (sender, receiver) = crossbeam_channel::unbounded();

    let meta = MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle { sender, send });
                ProtocolHandle::Callback(handle)
            }
        })
        .build();

    (meta, receiver)
}

fn create_shandle() -> Box<dyn ServiceHandle + Send> {
    // NOTE: channel size must large, otherwise send will failed.
    Box::new(())
}

fn server_node(path: String, listen_address: Multiaddr) -> (Receiver<Bytes>, Multiaddr) {
    let (meta, receiver) = create_meta(1.into(), true);
    let shandle = create_shandle();
    let (addr_sender, addr_receiver) = crossbeam_channel::unbounded();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(meta, shandle, path);
        rt.block_on(async move {
            let listen_addr = service.listen(listen_address).await.unwrap();
            let _res = addr_sender.send(listen_addr);
            service.run().await
        });
    });

    (receiver, addr_receiver.recv().unwrap())
}

fn clint_node_connect(path: String, dial_address: Multiaddr) {
    let (meta, _) = create_meta(1.into(), false);
    let shandle = create_shandle();

    let mut service = create(meta, shandle, path);
    let control: ServiceControl = service.control().clone().into();
    let handle = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let _ignore = service.dial(dial_address, TargetProtocol::All).await;
            service.run().await
        });
    });
    thread::sleep(Duration::from_secs(3));

    let _ignore = control.shutdown();
    handle.join().expect("test fail");
}

#[test]
// only node1 connect node0
fn test_tls_reconnect_ok() {
    let (receiver, dail_addr) = server_node(
        "tests/certificates/node0/".to_string(),
        Multiaddr::from_str("/ip4/127.0.0.1/tcp/0/tls/0x09cbaa785348dabd54c61f5f9964474f7bfad7df")
            .unwrap(),
    );

    for _ in 0..2 {
        clint_node_connect("tests/certificates/node1/".to_string(), dail_addr.clone());
        assert_eq!(receiver.recv(), Ok(bytes::Bytes::from("hello world")));
    }
}

#[test]
// node1 and node2-wrong connect node1
fn test_tls_reconnect_wrong() {
    let (receiver, dail_addr) = server_node(
        "tests/certificates/node0/".to_string(),
        Multiaddr::from_str("/ip4/127.0.0.1/tcp/0/tls/0x09cbaa785348dabd54c61f5f9964474f7bfad7df")
            .unwrap(),
    );

    // the first round everything is ok, but the second round node1 can't connect node0, and the
    // test blocked
    for _ in 0..2 {
        clint_node_connect("tests/certificates/node1/".to_string(), dail_addr.clone());
        // due to error certificates the node2 would connect error
        clint_node_connect(
            "tests/certificates/node2-wrong/".to_string(),
            dail_addr.clone(),
        );
        assert_eq!(receiver.recv(), Ok(bytes::Bytes::from("hello world")));
    }
}
