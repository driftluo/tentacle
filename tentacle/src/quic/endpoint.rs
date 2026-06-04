//! QUIC endpoint, listener, and dial entry points.
//!
//! - [`QuicEndpoint`] is a factory holding the local TLS certificate
//!   (carrying the tentacle identity extension), the local secio key, and a
//!   pre-built `quinn::ServerConfig`. It is the user-facing entry point that
//!   the higher-level service builder hands to the transport layer.
//! - [`QuicEndpoint::listen`] binds a UDP socket and returns a
//!   [`QuicListener`] that yields accepted [`QuicHandshake`]s (each one with
//!   its TLS handshake already completed and verified).
//! - [`QuicEndpoint::dial`] opens a one-shot client endpoint and dials the
//!   given multiaddr, returning a fully-handshaken [`QuicHandshake`].
//! - [`parse_quic_multiaddr`] enforces the legal address shape.
//!
//! Endpoint reuse / pooling is left to a future manager layer; this module
//! deliberately keeps `dial` to a fresh client endpoint per call so the
//! basic flow can be unit-tested in isolation.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::{
    multiaddr::{Multiaddr, Protocol},
    quic::{
        config::QuicConfig,
        error::QuicErrorKind,
        identity::{TentacleQuicCert, build_self_signed, extract_identity},
        session::QuicHandshake,
        verifier::{TentacleQuicClientCertVerifier, TentacleQuicServerCertVerifier},
    },
    secio::{KeyProvider, PeerId, PublicKey},
};

/// `ServerName` passed to quinn when dialing — hostname checks are skipped by
/// our verifier (see [`crate::quic::verifier`]) so any RFC 2606-reserved name
/// works. `.invalid` will not collide with real DNS.
const TENTACLE_QUIC_SNI: &str = "tentacle.invalid";

// ─────────────────────────────────── QuicEndpoint ──────────────────────────────────

/// Factory for QUIC listeners and outgoing dials.
///
/// One [`QuicEndpoint`] corresponds to a single local secio identity and a
/// single self-signed TLS certificate. It is intended to be kept around for
/// the lifetime of the tentacle service.
pub struct QuicEndpoint<K: KeyProvider> {
    local_key: K,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    server_config: quinn::ServerConfig,
    config: Arc<QuicConfig>,
}

impl<K: KeyProvider> QuicEndpoint<K> {
    /// Build a new QUIC endpoint factory from a secio `KeyProvider` and a
    /// transport-level [`QuicConfig`].
    ///
    /// This generates a fresh self-signed Ed25519 TLS certificate carrying the
    /// tentacle identity extension (see [`crate::quic::identity`]) and
    /// pre-builds a `quinn::ServerConfig` that authenticates clients via
    /// [`TentacleQuicClientCertVerifier`]. Outgoing client configs are built
    /// per-dial so that a per-dial `expected_peer_id` can be wired into the
    /// server-cert verifier.
    pub fn new(local_key: K, config: QuicConfig) -> Result<Self, QuicErrorKind> {
        let cert = build_self_signed(&local_key)?;
        let server_config = build_quinn_server_config(local_key.clone(), &cert, &config)?;
        Ok(Self {
            local_key,
            cert_der: cert.cert_der,
            key_der: cert.key_der,
            server_config,
            config: Arc::new(config),
        })
    }

    /// Bind a server-capable QUIC endpoint to the UDP address described by
    /// `addr` and return a [`QuicListener`] yielding accepted sessions.
    ///
    /// `addr` must match the shape accepted by [`parse_quic_multiaddr`].
    pub fn listen(&self, addr: Multiaddr) -> Result<QuicListener, QuicErrorKind> {
        let (socket_addr, _peer_id) = parse_quic_multiaddr(&addr)?;
        let endpoint = quinn::Endpoint::server(self.server_config.clone(), socket_addr)?;
        let local_addr = endpoint.local_addr()?;
        Ok(QuicListener {
            endpoint,
            listen_addr: socketaddr_to_quic_multiaddr(local_addr),
        })
    }

    /// Dial a remote QUIC peer and complete the TLS handshake.
    ///
    /// On success the returned [`QuicHandshake`] holds a `quinn::Connection`
    /// whose peer certificate has already passed the tentacle verifier
    /// checks. The remote secio public key is recovered from the peer cert's
    /// identity extension and made available via
    /// [`QuicHandshake::remote_pubkey`].
    pub async fn dial(&self, addr: Multiaddr) -> Result<QuicHandshake, QuicErrorKind> {
        let (socket_addr, expected_peer_id) = parse_quic_multiaddr(&addr)?;

        let client_config = build_quinn_client_config(
            self.local_key.clone(),
            &self.cert_der,
            &self.key_der,
            expected_peer_id,
            &self.config,
        )?;

        // One-shot client-only endpoint per dial. Pooling/reuse is deferred
        // to a future manager layer.
        let bind_addr: SocketAddr = match socket_addr {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let endpoint = quinn::Endpoint::client(bind_addr)?;

        let connecting = endpoint.connect_with(client_config, socket_addr, TENTACLE_QUIC_SNI)?;
        let conn = connecting.await?;

        let remote_pubkey = peer_pubkey_from_connection(&conn)?;

        // The connection holds a clone of the endpoint's UDP driver, but the
        // endpoint itself must stay alive to keep routing inbound datagrams.
        // Attach a guard task that holds the endpoint until the connection
        // closes. The full session machinery will own this directly once it
        // is implemented.
        spawn_endpoint_keepalive(endpoint, conn.clone());

        Ok(QuicHandshake::new(conn, remote_pubkey))
    }

    /// Read-only access to the configured transport parameters.
    pub fn config(&self) -> &QuicConfig {
        &self.config
    }
}

// ─────────────────────────────────── QuicListener ──────────────────────────────────

/// Server-side QUIC listener, wrapping a bound `quinn::Endpoint`.
///
/// Each call to [`QuicListener::accept`] yields a fully-handshaken
/// [`QuicHandshake`] together with the multiaddr of the remote peer.
pub struct QuicListener {
    endpoint: quinn::Endpoint,
    listen_addr: Multiaddr,
}

impl QuicListener {
    /// The actual local listen address (resolved after bind, so e.g.
    /// `/udp/0/quic-v1` becomes `/udp/<picked-port>/quic-v1`).
    pub fn listen_addr(&self) -> &Multiaddr {
        &self.listen_addr
    }

    /// Accept the next incoming connection, drive its TLS handshake to
    /// completion, and return the resulting [`QuicHandshake`] paired with the
    /// remote peer's multiaddr.
    ///
    /// Returns `Ok(None)` when the endpoint has been closed. `Err(_)` means
    /// **this particular handshake attempt** failed (bad cert, peer-id
    /// mismatch, dropped client, …); the underlying UDP endpoint is still
    /// alive and the caller is expected to call `accept()` again to take
    /// the next connection.
    pub async fn accept(&self) -> Result<Option<(Multiaddr, QuicHandshake)>, QuicErrorKind> {
        let incoming = match self.endpoint.accept().await {
            Some(i) => i,
            None => return Ok(None),
        };
        let remote_addr = incoming.remote_address();
        let conn = incoming.await?;
        let remote_pubkey = peer_pubkey_from_connection(&conn)?;
        Ok(Some((
            socketaddr_to_quic_multiaddr(remote_addr),
            QuicHandshake::new(conn, remote_pubkey),
        )))
    }

    /// Stop accepting new connections and close the underlying UDP socket.
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.endpoint.close(error_code.into(), reason);
    }

    /// Borrow the underlying `quinn::Endpoint` (for tests / integration).
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }
}

// ──────────────────────────────── address parsing ────────────────────────────────

/// Parse a tentacle QUIC multiaddr.
///
/// Accepts:
/// - `/ip4/<addr>/udp/<port>/quic-v1`
/// - `/ip6/<addr>/udp/<port>/quic-v1`
/// - either form followed by an optional `/p2p/<peer_id>` suffix
///
/// Rejects (with `QuicErrorKind::InvalidAddress`):
/// - DNS-form addresses (`/dns4/...`, `/dns6/...`)
/// - missing `/quic-v1` suffix
/// - non-UDP intermediate (e.g. `/tcp/...`)
/// - any other unexpected protocol stack
pub fn parse_quic_multiaddr(
    addr: &Multiaddr,
) -> Result<(SocketAddr, Option<PeerId>), QuicErrorKind> {
    let mut iter = addr.iter();

    let ip = match iter.next() {
        Some(Protocol::Ip4(ip)) => std::net::IpAddr::V4(ip),
        Some(Protocol::Ip6(ip)) => std::net::IpAddr::V6(ip),
        _ => {
            return Err(QuicErrorKind::InvalidAddress(format!(
                "expected /ip4/.../udp/<port>/quic-v1 or /ip6/.../udp/<port>/quic-v1, got {}",
                addr
            )));
        }
    };

    let port = match iter.next() {
        Some(Protocol::Udp(p)) => p,
        _ => {
            return Err(QuicErrorKind::InvalidAddress(format!(
                "QUIC multiaddr must use /udp/<port> after the IP, got {}",
                addr
            )));
        }
    };

    match iter.next() {
        Some(Protocol::QuicV1) => {}
        _ => {
            return Err(QuicErrorKind::InvalidAddress(format!(
                "QUIC multiaddr must end with /quic-v1 after /udp/<port>, got {}",
                addr
            )));
        }
    }

    // Optional /p2p/<peer_id> tail. Anything else is a malformed address.
    let mut peer_id = None;
    for proto in iter {
        match proto {
            Protocol::P2P(raw) => {
                if peer_id.is_some() {
                    return Err(QuicErrorKind::InvalidAddress(format!(
                        "QUIC multiaddr contains multiple /p2p/ components: {}",
                        addr
                    )));
                }
                peer_id = Some(PeerId::from_bytes(raw.to_vec()).map_err(|e| {
                    QuicErrorKind::InvalidAddress(format!(
                        "invalid /p2p/ component in {}: {:?}",
                        addr, e
                    ))
                })?);
            }
            other => {
                return Err(QuicErrorKind::InvalidAddress(format!(
                    "unexpected protocol {:?} after /quic-v1 in {}",
                    other, addr
                )));
            }
        }
    }

    Ok((SocketAddr::new(ip, port), peer_id))
}

/// Inverse of [`parse_quic_multiaddr`] (peer_id-less): build
/// `/ip{4,6}/<addr>/udp/<port>/quic-v1` from a `SocketAddr`.
fn socketaddr_to_quic_multiaddr(addr: SocketAddr) -> Multiaddr {
    let ip_proto = match addr.ip() {
        std::net::IpAddr::V4(ip) => Protocol::Ip4(ip),
        std::net::IpAddr::V6(ip) => Protocol::Ip6(ip),
    };
    [ip_proto, Protocol::Udp(addr.port()), Protocol::QuicV1]
        .into_iter()
        .collect()
}

// ────────────────────────────────── helpers ──────────────────────────────────

/// Build the `quinn::ServerConfig` used by [`QuicEndpoint`].
fn build_quinn_server_config<K: KeyProvider>(
    local_key: K,
    cert: &TentacleQuicCert,
    config: &QuicConfig,
) -> Result<quinn::ServerConfig, QuicErrorKind> {
    let cert_der = CertificateDer::from(cert.cert_der.clone());
    let key_der: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(cert.key_der.clone());

    let rustls_cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(TentacleQuicClientCertVerifier::new(local_key)))
        .with_single_cert(vec![cert_der], key_der.into())
        .map_err(|e| QuicErrorKind::TlsConfig(e.to_string()))?;

    let quic_crypto = QuicServerConfig::try_from(rustls_cfg)
        .map_err(|e| QuicErrorKind::TlsConfig(e.to_string()))?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_cfg.transport_config(Arc::new(build_transport_config(config)?));
    Ok(server_cfg)
}

/// Build a fresh `quinn::ClientConfig` for a single dial.
///
/// `expected_peer_id` is the `/p2p/<peer_id>` from the dial target multiaddr,
/// if any. The resulting client config is single-use because the verifier
/// captures `expected_peer_id`.
///
/// The same [`QuicConfig`]-derived transport parameters used by the listen
/// side are applied here, so idle timeout, keep-alive interval, and stream
/// limits behave symmetrically on dials.
fn build_quinn_client_config<K: KeyProvider>(
    local_key: K,
    cert_der: &[u8],
    key_der: &[u8],
    expected_peer_id: Option<PeerId>,
    config: &QuicConfig,
) -> Result<quinn::ClientConfig, QuicErrorKind> {
    let cert = CertificateDer::from(cert_der.to_vec());
    let key: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(key_der.to_vec());

    let rustls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TentacleQuicServerCertVerifier::new(
            local_key,
            expected_peer_id,
        )))
        .with_client_auth_cert(vec![cert], key.into())
        .map_err(|e| QuicErrorKind::TlsConfig(e.to_string()))?;

    let quic_crypto = QuicClientConfig::try_from(rustls_cfg)
        .map_err(|e| QuicErrorKind::TlsConfig(e.to_string()))?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client_cfg.transport_config(Arc::new(build_transport_config(config)?));
    Ok(client_cfg)
}

/// Convert a [`QuicConfig`] into a `quinn::TransportConfig`.
fn build_transport_config(config: &QuicConfig) -> Result<quinn::TransportConfig, QuicErrorKind> {
    let mut tc = quinn::TransportConfig::default();

    let idle: quinn::IdleTimeout =
        quinn::VarInt::from_u64(config.max_idle_timeout.as_millis() as u64)
            .map_err(|e| QuicErrorKind::TlsConfig(format!("max_idle_timeout out of range: {}", e)))?
            .into();
    tc.max_idle_timeout(Some(idle));
    tc.keep_alive_interval(config.keep_alive_interval);
    tc.max_concurrent_bidi_streams(
        quinn::VarInt::from_u64(config.max_concurrent_bidi_streams).map_err(|e| {
            QuicErrorKind::TlsConfig(format!("max_concurrent_bidi_streams out of range: {}", e))
        })?,
    );

    // Disable QUIC features not supported by tentacle v1: uni-streams and
    // datagrams are deliberately turned off — only bidi streams are used.
    tc.max_concurrent_uni_streams(0u32.into());
    tc.datagram_receive_buffer_size(None);
    tc.datagram_send_buffer_size(0);

    Ok(tc)
}

/// Recover the remote secio `PublicKey` from the leaf certificate that the
/// peer presented during the QUIC handshake.
///
/// The verifier (`crate::quic::verifier`) has already validated the cert and
/// the binding signature by the time this is called, so the only remaining
/// failure modes here are "no cert at all" (impossible under mutual auth, but
/// defensive) and re-decoding the molecule payload.
fn peer_pubkey_from_connection(conn: &quinn::Connection) -> Result<PublicKey, QuicErrorKind> {
    let any = conn.peer_identity().ok_or(QuicErrorKind::NoPeerCert)?;
    let chain: Box<Vec<CertificateDer<'static>>> = any
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| QuicErrorKind::NoPeerCert)?;
    let leaf = chain.first().ok_or(QuicErrorKind::NoPeerCert)?;
    let identity = extract_identity(leaf.as_ref())?;
    Ok(PublicKey::from_raw_key(identity.secio_pubkey))
}

/// Drop guard that keeps a `quinn::Endpoint` alive for the lifetime of a
/// `quinn::Connection`. quinn's `Connection` does not retain a clone of the
/// `Endpoint`, so without this the inbound UDP driver would be torn down as
/// soon as `dial()` returns.
fn spawn_endpoint_keepalive(endpoint: quinn::Endpoint, conn: quinn::Connection) {
    crate::runtime::spawn(async move {
        let _ = conn.closed().await;
        endpoint.close(0u32.into(), b"closed");
        let _ = tokio::time::timeout(Duration::from_millis(100), endpoint.wait_idle())
            .await
            // Panicking in tokio tasks will terminate the task, and in here termination the task is acceptable.
            // QUIC related code will only work on native tokio runtime.
            .unwrap();
    });
}

// ─────────────────────────── type-erased dyn dispatch ───────────────────────────

/// Object-safe view of a [`QuicEndpoint`].
///
/// Used by the service layer so that `InnerService<K>` does not have to
/// thread the `K: KeyProvider` bound through types that otherwise have no
/// reason to know about it (e.g. when `quic` is feature-disabled).
pub trait QuicEndpointHandle: Send + Sync {
    /// Bind a server-capable QUIC endpoint to the given multiaddr.
    fn listen_dyn(&self, addr: Multiaddr) -> Result<QuicListener, QuicErrorKind>;

    /// Dial a remote QUIC peer and complete the TLS handshake.
    fn dial_dyn<'a>(
        &'a self,
        addr: Multiaddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<QuicHandshake, QuicErrorKind>> + Send + 'a>,
    >;
}

impl<K> QuicEndpointHandle for QuicEndpoint<K>
where
    K: KeyProvider,
{
    fn listen_dyn(&self, addr: Multiaddr) -> Result<QuicListener, QuicErrorKind> {
        self.listen(addr)
    }

    fn dial_dyn<'a>(
        &'a self,
        addr: Multiaddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<QuicHandshake, QuicErrorKind>> + Send + 'a>,
    > {
        Box::pin(self.dial(addr))
    }
}

// ──────────────────────────────────── tests ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secio::SecioKeyPair;
    use std::str::FromStr;

    // ────────────── address parsing ──────────────

    #[test]
    fn parse_ip4_quic_ok() {
        let addr = Multiaddr::from_str("/ip4/127.0.0.1/udp/4433/quic-v1").unwrap();
        let (sock, peer) = parse_quic_multiaddr(&addr).unwrap();
        assert_eq!(sock, "127.0.0.1:4433".parse::<SocketAddr>().unwrap());
        assert!(peer.is_none());
    }

    #[test]
    fn parse_ip6_quic_ok() {
        let addr = Multiaddr::from_str("/ip6/::1/udp/4433/quic-v1").unwrap();
        let (sock, peer) = parse_quic_multiaddr(&addr).unwrap();
        assert_eq!(sock, "[::1]:4433".parse::<SocketAddr>().unwrap());
        assert!(peer.is_none());
    }

    #[test]
    fn parse_ip4_quic_with_peer() {
        let key = SecioKeyPair::secp256k1_generated();
        let pid = key.peer_id().to_base58();
        let addr =
            Multiaddr::from_str(&format!("/ip4/127.0.0.1/udp/4433/quic-v1/p2p/{}", pid)).unwrap();
        let (sock, peer) = parse_quic_multiaddr(&addr).unwrap();
        assert_eq!(sock, "127.0.0.1:4433".parse::<SocketAddr>().unwrap());
        assert_eq!(peer.unwrap(), key.peer_id());
    }

    #[test]
    fn reject_dns4_quic() {
        let addr = Multiaddr::from_str("/dns4/example.com/udp/4433/quic-v1").unwrap();
        assert!(matches!(
            parse_quic_multiaddr(&addr),
            Err(QuicErrorKind::InvalidAddress(_))
        ));
    }

    #[test]
    fn reject_dns6_quic() {
        let addr = Multiaddr::from_str("/dns6/example.com/udp/4433/quic-v1").unwrap();
        assert!(matches!(
            parse_quic_multiaddr(&addr),
            Err(QuicErrorKind::InvalidAddress(_))
        ));
    }

    #[test]
    fn reject_tcp_quic() {
        let addr = Multiaddr::from_str("/ip4/127.0.0.1/tcp/4433/quic-v1").unwrap();
        assert!(matches!(
            parse_quic_multiaddr(&addr),
            Err(QuicErrorKind::InvalidAddress(_))
        ));
    }

    #[test]
    fn reject_missing_quic_suffix() {
        let addr = Multiaddr::from_str("/ip4/127.0.0.1/udp/4433").unwrap();
        assert!(matches!(
            parse_quic_multiaddr(&addr),
            Err(QuicErrorKind::InvalidAddress(_))
        ));
    }

    #[test]
    fn reject_plain_tcp() {
        let addr = Multiaddr::from_str("/ip4/127.0.0.1/tcp/4433").unwrap();
        assert!(matches!(
            parse_quic_multiaddr(&addr),
            Err(QuicErrorKind::InvalidAddress(_))
        ));
    }

    #[test]
    fn reject_trailing_garbage() {
        let key = SecioKeyPair::secp256k1_generated();
        let pid = key.peer_id().to_base58();
        let addr = Multiaddr::from_str(&format!(
            "/ip4/127.0.0.1/udp/4433/quic-v1/p2p/{}/p2p/{}",
            pid, pid
        ))
        .unwrap();
        assert!(matches!(
            parse_quic_multiaddr(&addr),
            Err(QuicErrorKind::InvalidAddress(_))
        ));
    }

    // ────────────── round-trip ──────────────

    #[test]
    fn socketaddr_round_trip() {
        let original: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let ma = socketaddr_to_quic_multiaddr(original);
        let (back, _) = parse_quic_multiaddr(&ma).unwrap();
        assert_eq!(back, original);
    }

    // ────────────── endpoint construction ──────────────

    #[test]
    fn endpoint_new_succeeds() {
        let key = SecioKeyPair::secp256k1_generated();
        QuicEndpoint::new(key, QuicConfig::default()).expect("endpoint construction");
    }

    // ────────────── end-to-end smoke ──────────────

    /// One server + one client, both built from `QuicEndpoint`. The client
    /// dials with the server's PeerId pinned, opens a bidi stream, and
    /// expects the server to echo a short message back. Validates that the
    /// listener / dial / handshake / pubkey extraction wiring works in concert.
    #[tokio::test]
    async fn end_to_end_dial_and_echo() {
        let server_key = SecioKeyPair::secp256k1_generated();
        let server_pid = server_key.peer_id();
        let server_endpoint = QuicEndpoint::new(server_key.clone(), QuicConfig::default()).unwrap();

        let listener = server_endpoint
            .listen(Multiaddr::from_str("/ip4/127.0.0.1/udp/0/quic-v1").unwrap())
            .expect("listen");
        let server_addr = listener.listen_addr().clone();

        // Server task: accept, read up to 64 bytes from a bidi stream, echo back.
        let server_task = tokio::spawn(async move {
            let (_remote_addr, session) = listener
                .accept()
                .await
                .expect("accept ok")
                .expect("not closed");
            let conn = session.connection().clone();
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
            let mut buf = vec![0u8; 64];
            let n = recv.read(&mut buf).await.expect("read").expect("data");
            buf.truncate(n);
            send.write_all(&buf).await.expect("write echo");
            send.finish().expect("finish");
            // Hold the conn until client closes.
            conn.closed().await;
            buf
        });

        // Client dials with the server's PeerId pinned, exchanges one message.
        let client_key = SecioKeyPair::secp256k1_generated();
        let client_endpoint = QuicEndpoint::new(client_key, QuicConfig::default()).unwrap();

        let dial_addr_with_peer: Multiaddr =
            format!("{}/p2p/{}", server_addr, server_pid.to_base58())
                .parse()
                .unwrap();
        let session = client_endpoint
            .dial(dial_addr_with_peer)
            .await
            .expect("client dial ok");

        assert_eq!(*session.remote_pubkey(), server_key.public_key());

        let conn = session.connection().clone();
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(b"hello").await.expect("write");
        send.finish().expect("finish");
        let mut echo = vec![0u8; 64];
        let n = recv.read(&mut echo).await.expect("read").expect("data");
        echo.truncate(n);
        assert_eq!(echo, b"hello");
        conn.close(0u32.into(), b"done");

        let server_observed = server_task.await.expect("server join");
        assert_eq!(server_observed, b"hello");
    }

    /// Dial fails when the dial target multiaddr pins a `/p2p/<peer_id>` that
    /// does not match the server's actual identity. The server-cert verifier
    /// rejects the handshake at TLS level, surfacing as a connection error.
    #[tokio::test]
    async fn dial_rejects_wrong_peer_id() {
        let server_key = SecioKeyPair::secp256k1_generated();
        let server_endpoint = QuicEndpoint::new(server_key.clone(), QuicConfig::default()).unwrap();

        let listener = server_endpoint
            .listen(Multiaddr::from_str("/ip4/127.0.0.1/udp/0/quic-v1").unwrap())
            .expect("listen");
        let server_addr = listener.listen_addr().clone();

        // Drive the listener so the handshake can progress (the server-side
        // failure is fine; we only need the listener task to keep polling).
        let _server_task = tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        let client_key = SecioKeyPair::secp256k1_generated();
        let client_endpoint = QuicEndpoint::new(client_key, QuicConfig::default()).unwrap();

        // Pin a peer_id that the server does NOT have.
        let wrong_pid = SecioKeyPair::secp256k1_generated().peer_id();
        let dial_addr: Multiaddr = format!("{}/p2p/{}", server_addr, wrong_pid.to_base58())
            .parse()
            .unwrap();

        let result = client_endpoint.dial(dial_addr).await;
        assert!(
            result.is_err(),
            "dial with wrong /p2p/ must fail, got Ok({:?})",
            result.as_ref().ok().map(|s| s.remote_pubkey().clone()),
        );
    }
}
