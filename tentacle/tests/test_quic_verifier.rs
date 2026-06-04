//! End-to-end integration tests for the Tentacle QUIC verifiers.
//!
//! These tests spin up a real `quinn` server and client over loopback,
//! plug in [`TentacleQuicServerCertVerifier`] / [`TentacleQuicClientCertVerifier`],
//! and verify that:
//!
//! - a positive handshake works when both sides present a tentacle-bound
//!   certificate built by [`build_self_signed`], and each peer can recover
//!   the counterpart's `PeerId` via [`extract_identity`];
//! - a negative handshake is rejected when the client presents a plain
//!   self-signed Ed25519 certificate without the tentacle private extension.
//!
//! Unit tests for the verifier logic itself live next to the implementation
//! in `src/quic/verifier.rs`.

#![cfg(feature = "quic")]

use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, ServerConfig};

use tentacle::quic::identity::{TentacleQuicCert, build_self_signed, extract_identity};
use tentacle::quic::verifier::{TentacleQuicClientCertVerifier, TentacleQuicServerCertVerifier};
use tentacle::secio::SecioKeyPair;

// ───────────────────────────────── helpers ─────────────────────────────────

/// Build a `rustls::ServerConfig` that authenticates clients via
/// [`TentacleQuicClientCertVerifier`] and presents `cert` as its own identity.
fn tentacle_server_config(key: SecioKeyPair, cert: TentacleQuicCert) -> ServerConfig {
    let cert_der = CertificateDer::from(cert.cert_der);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_der);
    ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(TentacleQuicClientCertVerifier::new(key)))
        .with_single_cert(vec![cert_der], key_der.into())
        .expect("server rustls config")
}

/// Build a `rustls::ClientConfig` that verifies the server via
/// [`TentacleQuicServerCertVerifier`] and presents `cert` as its own identity.
fn tentacle_client_config(
    key: SecioKeyPair,
    cert: TentacleQuicCert,
    expected_peer_id: Option<tentacle::secio::PeerId>,
) -> ClientConfig {
    let cert_der = CertificateDer::from(cert.cert_der);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_der);
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TentacleQuicServerCertVerifier::new(
            key,
            expected_peer_id,
        )))
        .with_client_auth_cert(vec![cert_der], key_der.into())
        .expect("client rustls config")
}

/// Plain Ed25519 self-signed cert/key with NO tentacle extension. Used to
/// exercise the negative path.
fn build_plain_cert_and_key() -> (Vec<u8>, Vec<u8>) {
    let tls_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(vec!["tentacle.invalid".to_string()]).unwrap();
    let cert = params.self_signed(&tls_keypair).unwrap();
    (cert.der().to_vec(), tls_keypair.serialize_der())
}

/// Stand up a quinn server endpoint configured with the given rustls config.
fn spawn_quinn_server(rustls_cfg: ServerConfig) -> (quinn::Endpoint, std::net::SocketAddr) {
    let quinn_cfg =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_cfg).unwrap()));
    let endpoint = quinn::Endpoint::server(quinn_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    (endpoint, addr)
}

/// Stand up a quinn client and start connecting to `server_addr`.
///
/// Returns both the `Endpoint` and the `Connecting`. The caller MUST keep the
/// `Endpoint` alive until the handshake completes — quinn's `Connecting` does
/// not hold a clone of the `Endpoint`, so dropping the last `Endpoint` clone
/// terminates the `EndpointDriver` that routes inbound UDP datagrams, which
/// would silently break the handshake (or just make the test flaky).
fn connect_quinn_client(
    rustls_cfg: ClientConfig,
    server_addr: std::net::SocketAddr,
) -> (quinn::Endpoint, quinn::Connecting) {
    let quinn_cfg =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_cfg).unwrap()));
    let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    let connecting = endpoint
        .connect_with(quinn_cfg, server_addr, "tentacle.invalid")
        .expect("connect_with");
    (endpoint, connecting)
}

/// Pull the peer certificate chain from a quinn connection and derive the
/// peer's `PeerId` the same way the verifier does — from the `secio_pubkey`
/// field of the tentacle identity extension. The `PeerId` is **not** stored
/// in the extension; it is a deterministic derivation.
fn peer_identity_peer_id_bytes(conn: &quinn::Connection) -> Vec<u8> {
    let any = conn.peer_identity().expect("peer_identity present");
    let chain = any
        .downcast::<Vec<CertificateDer<'static>>>()
        .expect("cert chain downcast");
    let identity = extract_identity(chain[0].as_ref()).expect("extract identity");
    let secio_pubkey = tentacle::secio::PublicKey::from_raw_key(identity.secio_pubkey);
    secio_pubkey.peer_id().into_bytes()
}

// ────────────────────────── end-to-end test cases ──────────────────────────

/// Both sides carry valid tentacle certs → TLS handshake succeeds and each
/// peer can recover the other's `PeerId` from the presented certificate.
#[tokio::test]
async fn e2e_handshake_succeeds_with_tentacle_identities() {
    let server_key = SecioKeyPair::secp256k1_generated();
    let server_cert = build_self_signed(&server_key).unwrap();
    let server_peer_id = server_key.public_key().peer_id();
    let server_peer_id_bytes = server_peer_id.clone().into_bytes();

    let client_key = SecioKeyPair::secp256k1_generated();
    let client_cert = build_self_signed(&client_key).unwrap();
    let client_peer_id_bytes = client_key.public_key().peer_id().into_bytes();

    let rustls_server = tentacle_server_config(server_key.clone(), server_cert);
    let (server_endpoint, server_addr) = spawn_quinn_server(rustls_server);

    // Server task: accept the connection and report the client's PeerId.
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.expect("incoming");
        let conn = incoming.await.expect("server handshake ok");
        let observed = peer_identity_peer_id_bytes(&conn);
        // Keep the connection alive until the client closes it.
        conn.closed().await;
        observed
    });

    // Client connects with the expected server PeerId pinned. We bind the
    // endpoint to a local so it stays alive for the lifetime of the handshake.
    let rustls_client = tentacle_client_config(client_key, client_cert, Some(server_peer_id));
    let (_client_endpoint, client_connecting) = connect_quinn_client(rustls_client, server_addr);
    let client_conn = client_connecting.await.expect("client handshake ok");

    // Client sees the server's PeerId in the presented cert.
    let observed_server = peer_identity_peer_id_bytes(&client_conn);
    assert_eq!(observed_server, server_peer_id_bytes);

    // Close the client side and let the server task observe the client cert.
    client_conn.close(0u32.into(), b"done");

    let observed_client = server_task.await.expect("server join");
    assert_eq!(observed_client, client_peer_id_bytes);
}

/// Client presents a plain Ed25519 cert with no tentacle extension. The
/// server's [`TentacleQuicClientCertVerifier`] must reject the handshake.
#[tokio::test]
async fn e2e_handshake_fails_when_client_has_no_extension() {
    let server_key = SecioKeyPair::secp256k1_generated();
    let server_cert = build_self_signed(&server_key).unwrap();

    let rustls_server = tentacle_server_config(server_key, server_cert);
    let (server_endpoint, server_addr) = spawn_quinn_server(rustls_server);

    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.expect("incoming");
        // Expected to fail at handshake time.
        incoming.await
    });

    // Client presents a plain Ed25519 cert — no tentacle extension.
    let (plain_cert, plain_key) = build_plain_cert_and_key();
    let local_key = SecioKeyPair::secp256k1_generated();

    let rustls_client = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TentacleQuicServerCertVerifier::new(
            local_key, None,
        )))
        .with_client_auth_cert(
            vec![CertificateDer::from(plain_cert)],
            PrivatePkcs8KeyDer::from(plain_key).into(),
        )
        .expect("client rustls config");

    let (_client_endpoint, client_connecting) = connect_quinn_client(rustls_client, server_addr);
    let client_result = client_connecting.await;
    let server_result = server_task.await.expect("server join");

    // Either side may surface the failure first; we only require that the
    // handshake does NOT succeed end-to-end.
    assert!(
        client_result.is_err() || server_result.is_err(),
        "handshake must fail when client lacks tentacle identity extension; \
         client_result = {:?}, server_result_ok = {}",
        client_result.as_ref().err(),
        server_result.is_ok(),
    );
}
