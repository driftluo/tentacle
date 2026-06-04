//! QUIC end-to-end integration tests.
//!
//! These tests build full `Service` instances with the QUIC transport
//! enabled (via `ServiceBuilder::quic_config`) and verify that:
//!
//! 1. two peers can complete a QUIC handshake, open a protocol, and
//!    exchange messages bidirectionally;
//! 2. multiple protocols can be multiplexed over a single QUIC session
//!    without crosstalk;
//! 3. an outbound shutdown propagates to the peer's `disconnected`
//!    callback;
//! 4. dialing with a mismatched `/p2p/<peer_id>` is rejected at
//!    handshake time;
//! 5. enabling QUIC does not regress the classic TCP path — a
//!    QUIC-enabled service still routes plain `/tcp/` addresses through
//!    the secio + yamux pipeline and can dial / listen on TCP normally;
//! 6. a `HandshakeType::Secio` service that did **not** call
//!    `quic_config(...)` dialing a `/quic-v1` address surfaces
//!    `QuicError(NotConfigured)` — a precise, actionable hint instead
//!    of the generic `NotSupported`.
//!
//! Each test runs the server and client on dedicated tokio runtimes in
//! their own threads, communicating over crossbeam / oneshot channels.

#![cfg(feature = "quic")]

use bytes::Bytes;
use futures::channel::oneshot;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    error::TransportErrorKind,
    multiaddr::Multiaddr,
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
};

// ────────────────────────────── service helpers ──────────────────────────────

fn build_service<F>(
    key: SecioKeyPair,
    metas: Vec<ProtocolMeta>,
    handle: F,
    enable_quic: bool,
) -> Service<F, SecioKeyPair>
where
    F: ServiceHandle + Unpin + 'static,
{
    let mut builder = ServiceBuilder::default().forever(true);
    for meta in metas {
        builder = builder.insert_protocol(meta);
    }
    builder = builder.handshake_type(key.into());
    if enable_quic {
        builder = builder.quic_config(QuicConfig::default());
    }
    builder.build(handle)
}

// ─────────────────────────────── protocol handles ───────────────────────────────

struct EchoCounter {
    sender: crossbeam_channel::Sender<(ProtocolId, Bytes)>,
    target: usize,
    seen: usize,
}

#[async_trait]
impl ServiceProtocol for EchoCounter {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        if context.session.ty.is_outbound() {
            // Outbound side starts the conversation.
            let _ignore = context.send_message(Bytes::from_static(b"ping-0")).await;
        }
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: Bytes) {
        if let Err(_) = self.sender.try_send((context.proto_id, data.clone())) {
            return;
        }
        self.seen += 1;
        if self.seen >= self.target {
            return;
        }
        // Server echoes back; client also echoes a few times to drive a
        // continuous exchange.
        let _ignore = context.send_message(data).await;
    }
}

fn make_echo_meta(
    id: ProtocolId,
    target: usize,
) -> (
    ProtocolMeta,
    crossbeam_channel::Receiver<(ProtocolId, Bytes)>,
) {
    let (sender, receiver) = crossbeam_channel::unbounded();
    let meta = MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            let handle = Box::new(EchoCounter {
                sender: sender.clone(),
                target,
                seen: 0,
            });
            ProtocolHandle::Callback(handle)
        })
        .build();
    (meta, receiver)
}

struct DisconnectTracker {
    connect_count: Arc<AtomicUsize>,
    disconnect_count: Arc<AtomicUsize>,
    notify: oneshot::Sender<()>,
}

impl DisconnectTracker {
    fn into_meta(self, id: ProtocolId) -> ProtocolMeta {
        let connect = self.connect_count.clone();
        let disconnect = self.disconnect_count.clone();
        let notify = std::sync::Mutex::new(Some(self.notify));
        MetaBuilder::new()
            .id(id)
            .service_handle(move || {
                let handle = Box::new(DisconnectInner {
                    connect_count: connect.clone(),
                    disconnect_count: disconnect.clone(),
                    notify_tx: notify.lock().unwrap().take(),
                });
                ProtocolHandle::Callback(handle)
            })
            .build()
    }
}

struct DisconnectInner {
    connect_count: Arc<AtomicUsize>,
    disconnect_count: Arc<AtomicUsize>,
    notify_tx: Option<oneshot::Sender<()>>,
}

#[async_trait]
impl ServiceProtocol for DisconnectInner {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, _context: ProtocolContextMutRef<'_>, _version: &str) {
        self.connect_count.fetch_add(1, Ordering::SeqCst);
    }

    async fn disconnected(&mut self, _context: ProtocolContextMutRef<'_>) {
        self.disconnect_count.fetch_add(1, Ordering::SeqCst);
        if let Some(tx) = self.notify_tx.take() {
            let _ignore = tx.send(());
        }
    }
}

#[derive(Default)]
struct CollectingHandle {
    errors: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait]
impl ServiceHandle for CollectingHandle {
    async fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        let summary = format!("{:?}", error);
        self.errors.lock().unwrap().push(summary);
    }

    async fn handle_event(&mut self, _env: &mut ServiceContext, _event: ServiceEvent) {}
}

// ───────────────────────────── basic connectivity ─────────────────────────────

/// Test 1: two QUIC services exchange messages over a single protocol.
#[test]
fn test_quic_basic_connectivity() {
    let (server_meta, server_rx) = make_echo_meta(1.into(), 50);
    let (client_meta, client_rx) = make_echo_meta(1.into(), 50);

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();

    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(server_key, vec![server_meta], (), true);
        rt.block_on(async move {
            let listen = service
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("server listen");
            let _ignore = addr_tx.send(listen);
            service.run().await
        });
    });

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![client_meta],
            (),
            true,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
                .parse()
                .unwrap();
            service.dial(dial, TargetProtocol::All).await.expect("dial");
            service.run().await
        });
    });

    // Wait for both sides to observe at least 10 messages each. The
    // continuous ping/pong drives more than that quickly.
    let collect = |rx: &crossbeam_channel::Receiver<(ProtocolId, Bytes)>, n: usize| {
        let mut got = 0;
        while got < n {
            match rx.recv_timeout(Duration::from_secs(15)) {
                Ok(_) => got += 1,
                Err(_) => break,
            }
        }
        got
    };

    assert!(
        collect(&server_rx, 10) >= 10,
        "server should receive at least 10 messages over quic"
    );
    assert!(
        collect(&client_rx, 10) >= 10,
        "client should receive at least 10 messages over quic"
    );
}

// ────────────────────────────── multi-protocol ──────────────────────────────

/// Test 2: open three protocols on a single QUIC session, exchange
/// messages on each, and assert no crosstalk (each receiver only sees
/// messages tagged with its own protocol id).
#[test]
fn test_quic_multi_protocol() {
    let (s0, s0_rx) = make_echo_meta(0.into(), 30);
    let (s1, s1_rx) = make_echo_meta(1.into(), 30);
    let (s2, s2_rx) = make_echo_meta(2.into(), 30);
    let (c0, c0_rx) = make_echo_meta(0.into(), 30);
    let (c1, c1_rx) = make_echo_meta(1.into(), 30);
    let (c2, c2_rx) = make_echo_meta(2.into(), 30);

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(server_key, vec![s0, s1, s2], (), true);
        rt.block_on(async move {
            let listen = service
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("server listen");
            let _ignore = addr_tx.send(listen);
            service.run().await
        });
    });

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![c0, c1, c2],
            (),
            true,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
                .parse()
                .unwrap();
            service.dial(dial, TargetProtocol::All).await.expect("dial");
            service.run().await
        });
    });

    let collect_for = |rx: &crossbeam_channel::Receiver<(ProtocolId, Bytes)>,
                       expected_id: ProtocolId,
                       n: usize| {
        let mut got = 0;
        while got < n {
            match rx.recv_timeout(Duration::from_secs(15)) {
                Ok((pid, _)) => {
                    assert_eq!(pid, expected_id, "crosstalk between protocols");
                    got += 1;
                }
                Err(_) => break,
            }
        }
        got
    };

    assert!(collect_for(&s0_rx, 0.into(), 5) >= 5);
    assert!(collect_for(&s1_rx, 1.into(), 5) >= 5);
    assert!(collect_for(&s2_rx, 2.into(), 5) >= 5);
    assert!(collect_for(&c0_rx, 0.into(), 5) >= 5);
    assert!(collect_for(&c1_rx, 1.into(), 5) >= 5);
    assert!(collect_for(&c2_rx, 2.into(), 5) >= 5);
}

// ─────────────────────────────── graceful close ───────────────────────────────

/// Test 3: client `disconnect`s its session, and the server's
/// `disconnected` callback fires.
#[test]
fn test_quic_graceful_close() {
    let server_disconnect_count = Arc::new(AtomicUsize::new(0));
    let server_connect_count = Arc::new(AtomicUsize::new(0));
    let (server_done_tx, server_done_rx) = oneshot::channel::<()>();
    let server_meta = DisconnectTracker {
        connect_count: server_connect_count.clone(),
        disconnect_count: server_disconnect_count.clone(),
        notify: server_done_tx,
    }
    .into_meta(1.into());

    // Client just connects, then disconnects after `connected`.
    struct ClientCloser;
    #[async_trait]
    impl ServiceProtocol for ClientCloser {
        async fn init(&mut self, _context: &mut ProtocolContext) {}
        async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
            let _ignore = context.disconnect(context.session.id).await;
        }
    }
    let client_meta = MetaBuilder::new()
        .id(1.into())
        .service_handle(|| ProtocolHandle::Callback(Box::new(ClientCloser)))
        .build();

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(server_key, vec![server_meta], (), true);
        rt.block_on(async move {
            let listen = service
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("server listen");
            let _ignore = addr_tx.send(listen);
            service.run().await
        });
    });

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![client_meta],
            (),
            true,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
                .parse()
                .unwrap();
            service.dial(dial, TargetProtocol::All).await.expect("dial");
            service.run().await
        });
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let _ignore = tokio::time::timeout(Duration::from_secs(15), server_done_rx).await;
    });

    assert!(
        server_connect_count.load(Ordering::SeqCst) >= 1,
        "server must have observed connected"
    );
    assert!(
        server_disconnect_count.load(Ordering::SeqCst) >= 1,
        "server must have observed disconnected"
    );
}

// ─────────────────────────────── peer-id mismatch ───────────────────────────────

/// Test 4: dialing with a `/p2p/<wrong>` is rejected at the QUIC TLS
/// handshake; the dial result surfaces as `DialerError::TransportError(QuicError(...))`.
#[test]
fn test_quic_peer_id_mismatch() {
    let server_key = SecioKeyPair::secp256k1_generated();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();
    let (s_meta, _) = make_echo_meta(1.into(), 1);

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(server_key, vec![s_meta], (), true);
        rt.block_on(async move {
            let listen = service
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("server listen");
            let _ignore = addr_tx.send(listen);
            service.run().await
        });
    });

    // Use a peer id from a different key so the verifier rejects it.
    let wrong_pid = SecioKeyPair::secp256k1_generated().peer_id();
    let errors: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let errors_clone = errors.clone();
    let (c_meta, _) = make_echo_meta(1.into(), 1);

    let client_thread = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = CollectingHandle {
            errors: errors_clone,
        };
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![c_meta],
            handle,
            true,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, wrong_pid.to_base58())
                .parse()
                .unwrap();
            service.dial(dial, TargetProtocol::All).await.expect("dial");

            // The dial result is delivered to `ServiceHandle::handle_error`
            // via the service main loop, so it must be running to observe
            // the failure.
            let run = tokio::spawn(async move { service.run().await });

            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if !errors.lock().unwrap().is_empty() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("dial error must surface");
            run.abort();
        });
    });

    client_thread.join().expect("client thread join");
}

// ─────────────────────────────── cross-transport ───────────────────────────────

/// Test 5a: a QUIC-enabled service still routes plain TCP addresses
/// through the classic TCP stack and can complete a normal TCP+secio
/// session — proving that enabling QUIC does not regress non-QUIC
/// transports.
#[test]
fn test_quic_cross_transport_tcp_still_works() {
    let (server_meta, server_rx) = make_echo_meta(1.into(), 5);
    let (client_meta, client_rx) = make_echo_meta(1.into(), 5);

    let server_key = SecioKeyPair::secp256k1_generated();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // QUIC enabled, but server listens on TCP.
        let mut service = build_service(server_key, vec![server_meta], (), true);
        rt.block_on(async move {
            let listen = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .expect("server listen tcp");
            let _ignore = addr_tx.send(listen);
            service.run().await
        });
    });

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // QUIC also enabled on client; the dial address is TCP.
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![client_meta],
            (),
            true,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .expect("client dial tcp");
            service.run().await
        });
    });

    let collect = |rx: &crossbeam_channel::Receiver<(ProtocolId, Bytes)>, n: usize| {
        let mut got = 0;
        while got < n {
            match rx.recv_timeout(Duration::from_secs(15)) {
                Ok(_) => got += 1,
                Err(_) => break,
            }
        }
        got
    };
    assert!(collect(&server_rx, 3) >= 3, "server tcp echo");
    assert!(collect(&client_rx, 3) >= 3, "client tcp echo");
}

/// Test 6: a `HandshakeType::Secio` service that did NOT call
/// `ServiceBuilder::quic_config(...)` dialing a `/quic-v1` address must
/// surface `QuicError(NotConfigured)` (not the misleading generic
/// `NotSupported`). The user has a valid tentacle identity and the
/// address shape is fine — they just forgot to opt into QUIC, and the
/// error should hint exactly that.
#[test]
fn test_quic_not_enabled_rejected() {
    use tentacle::quic::error::QuicErrorKind;

    let (c_meta, _) = make_echo_meta(1.into(), 1);
    let mut service = build_service(
        SecioKeyPair::secp256k1_generated(),
        vec![c_meta],
        (),
        false, // no quic_config(...)
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let res = service
            .dial(
                "/ip4/127.0.0.1/udp/4433/quic-v1".parse().unwrap(),
                TargetProtocol::All,
            )
            .await;
        match res {
            Err(TransportErrorKind::QuicError(QuicErrorKind::NotConfigured)) => (),
            other => panic!(
                "expected TransportErrorKind::QuicError(NotConfigured), got {:?}",
                other
                    .map(|_| "Ok".to_string())
                    .unwrap_or_else(|e| format!("{:?}", e))
            ),
        }
    });
}
