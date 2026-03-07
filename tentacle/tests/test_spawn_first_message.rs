#![cfg(feature = "unstable")]

use futures::StreamExt;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::channel,
    },
    thread,
    time::Duration,
};
use tentacle::{
    SubstreamReadPart,
    builder::{MetaBuilder, ServiceBuilder},
    context::SessionContext,
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolMeta, Service, ServiceAsyncControl, TargetProtocol},
    traits::{ProtocolSpawn, ServiceHandle},
};

// --- Helpers ---

fn create_service<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F, SecioKeyPair>
where
    F: ServiceHandle + Unpin + 'static,
{
    let builder = ServiceBuilder::default().insert_protocol(meta);
    if secio {
        builder
            .handshake_type(SecioKeyPair::secp256k1_generated().into())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

/// Run a listener + dialer pair.
///
/// Each probe is responsible for calling `control.shutdown()` on its own
/// service after finishing its work. When a side shuts down and the TCP
/// connection closes, the remote side's inner service detects the
/// disconnect, exits its event loop, and `service.run()` returns
/// naturally (no explicit shutdown needed on that side).
///
/// A hard timeout (`Duration`) on `service.run()` prevents infinite hangs.
fn run_pair(
    secio: bool,
    listener_meta: ProtocolMeta,
    dialer_meta: ProtocolMeta,
    timeout: Duration,
) {
    let (addr_sender, addr_receiver) = channel::<Multiaddr>();

    let listener_thread = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut service = create_service(secio, listener_meta, ());
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            let _ignore = tokio::time::timeout(timeout, service.run()).await;
        });
    });

    let dialer_thread = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut service = create_service(secio, dialer_meta, ());
        rt.block_on(async move {
            let listen_addr = addr_receiver.recv().unwrap();
            service
                .dial(listen_addr, TargetProtocol::Single(1.into()))
                .await
                .unwrap();
            let _ignore = tokio::time::timeout(timeout, service.run()).await;
        });
    });

    listener_thread.join().unwrap();
    dialer_thread.join().unwrap();
}

// ========================================================================
// Test 1: First message exchange
//
// Both sides send a single "init" message immediately on spawn and verify
// they receive it. This tests that the very first message written by one
// side is correctly forwarded through the read channel to the other
// side's SubstreamReadPart — the exact path where the yamux waker-
// overwrite bug manifested.
//
// Each probe calls `control.shutdown()` after receiving its init message.
// The remote side detects the connection drop and its `service.run()`
// returns naturally through the event loop.
// ========================================================================

#[derive(Clone)]
struct FirstMessageProbe {
    received: Arc<AtomicUsize>,
}

impl ProtocolSpawn for FirstMessageProbe {
    fn spawn(
        &self,
        context: Arc<SessionContext>,
        control: &ServiceAsyncControl,
        mut read_part: SubstreamReadPart,
    ) {
        let session_id = context.id;
        let proto_id = read_part.protocol_id();

        // Send one "init" message to the remote side.
        let send_control = control.clone();
        tokio::spawn(async move {
            let _ignore = send_control
                .send_message_to(session_id, proto_id, b"init".to_vec().into())
                .await;
        });

        // Read the "init" message, then shut down.
        let received = self.received.clone();
        let shutdown_control = control.clone();
        tokio::spawn(async move {
            let _ignore = tokio::time::timeout(Duration::from_secs(10), async {
                while let Some(Ok(data)) = read_part.next().await {
                    if data.as_ref() == b"init" {
                        received.fetch_add(1, Ordering::SeqCst);
                        break;
                    }
                }
            })
            .await;
            // Brief delay so the remote side also has time to receive *our*
            // init before we tear down the connection.
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ignore = shutdown_control.shutdown().await;
        });
    }
}

fn run_first_message_test(secio: bool, iterations: usize) {
    for _i in 0..iterations {
        let listener_received = Arc::new(AtomicUsize::new(0));
        let dialer_received = Arc::new(AtomicUsize::new(0));

        let meta_listener = MetaBuilder::new()
            .id(1.into())
            .protocol_spawn(FirstMessageProbe {
                received: listener_received.clone(),
            })
            .build();

        let meta_dialer = MetaBuilder::new()
            .id(1.into())
            .protocol_spawn(FirstMessageProbe {
                received: dialer_received.clone(),
            })
            .build();

        run_pair(secio, meta_listener, meta_dialer, Duration::from_secs(15));

        let lr = listener_received.load(Ordering::SeqCst);
        let dr = dialer_received.load(Ordering::SeqCst);
        assert_eq!(lr, 1, "listener did not receive first message");
        assert_eq!(dr, 1, "dialer did not receive first message");
    }
}

#[test]
fn test_spawn_first_message_with_no_secio() {
    run_first_message_test(false, 3);
}

#[test]
fn test_spawn_first_message_with_secio() {
    run_first_message_test(true, 3);
}

// ========================================================================
// Test 2: Multi-message bidirectional exchange
//
// Both sides send N messages and read until they've received all N.
// This tests sustained bidirectional data flow through the spawn model,
// exercising the channel-based read forwarding under load.
// ========================================================================

const MULTI_MSG_COUNT: usize = 100;

#[derive(Clone)]
struct MultiMessageProbe {
    received: Arc<AtomicUsize>,
    total_done: Arc<AtomicUsize>,
}

impl ProtocolSpawn for MultiMessageProbe {
    fn spawn(
        &self,
        context: Arc<SessionContext>,
        control: &ServiceAsyncControl,
        mut read_part: SubstreamReadPart,
    ) {
        let session_id = context.id;
        let proto_id = read_part.protocol_id();

        // Send N messages
        let send_control = control.clone();
        tokio::spawn(async move {
            for i in 0..MULTI_MSG_COUNT {
                let msg = format!("msg-{i}");
                if let Err(_e) = send_control
                    .send_message_to(session_id, proto_id, msg.into_bytes().into())
                    .await
                {
                    break;
                }
            }
        });

        // Receive N messages, wait for peer, then shut down.
        let received = self.received.clone();
        let total_done = self.total_done.clone();
        let shutdown_control = control.clone();
        tokio::spawn(async move {
            let _ignore = tokio::time::timeout(Duration::from_secs(30), async {
                let mut count = 0usize;
                while let Some(Ok(_data)) = read_part.next().await {
                    count += 1;
                    received.fetch_add(1, Ordering::SeqCst);
                    if count >= MULTI_MSG_COUNT {
                        break;
                    }
                }
            })
            .await;

            // Signal this side is done receiving.
            total_done.fetch_add(1, Ordering::SeqCst);

            // Wait for the other side to also finish (max 10s).
            for _ in 0..200 {
                if total_done.load(Ordering::SeqCst) >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            let _ignore = shutdown_control.shutdown().await;
        });
    }
}

fn run_multi_message_test(secio: bool, iterations: usize) {
    for _i in 0..iterations {
        let listener_received = Arc::new(AtomicUsize::new(0));
        let dialer_received = Arc::new(AtomicUsize::new(0));
        let total_done = Arc::new(AtomicUsize::new(0));

        let meta_listener = MetaBuilder::new()
            .id(1.into())
            .protocol_spawn(MultiMessageProbe {
                received: listener_received.clone(),
                total_done: total_done.clone(),
            })
            .build();

        let meta_dialer = MetaBuilder::new()
            .id(1.into())
            .protocol_spawn(MultiMessageProbe {
                received: dialer_received.clone(),
                total_done: total_done.clone(),
            })
            .build();

        run_pair(secio, meta_listener, meta_dialer, Duration::from_secs(60));

        let lr = listener_received.load(Ordering::SeqCst);
        let dr = dialer_received.load(Ordering::SeqCst);
        assert_eq!(
            lr, MULTI_MSG_COUNT,
            "listener received {lr}/{MULTI_MSG_COUNT} messages",
        );
        assert_eq!(
            dr, MULTI_MSG_COUNT,
            "dialer received {dr}/{MULTI_MSG_COUNT} messages",
        );
    }
}

#[test]
fn test_spawn_multi_message_with_no_secio() {
    run_multi_message_test(false, 3);
}

#[test]
fn test_spawn_multi_message_with_secio() {
    run_multi_message_test(true, 3);
}
