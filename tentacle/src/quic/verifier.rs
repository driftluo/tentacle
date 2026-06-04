//! # Tentacle QUIC certificate verifiers
//!
//! Custom `rustls` verifiers that replace the conventional CA / hostname model
//! with the Tentacle identity binding described in [plan.md §4.4].
//!
//! A peer certificate is accepted if and only if all of the following hold:
//!
//! 1. The presented certificate chain contains **exactly one** leaf. No
//!    intermediate certificates are allowed.
//! 2. The leaf certificate's validity period covers the current time.
//! 3. The leaf contains **exactly one** X.509 extension with OID
//!    [`TENTACLE_QUIC_IDENT_OID`]. The payload decodes as a
//!    molecule `TentacleQuicIdentityV1 { version, secio_pubkey, binding_sig }`
//!    with `version == 1`. The peer's `PeerId` is **not** stored in the
//!    payload — it is deterministically derived from `secio_pubkey` by both
//!    sides at verification time.
//! 4. The secp256k1 signature in `binding_sig` is valid for
//!    `sha256(BINDING_DOMAIN || leaf_spki_der)` under `secio_pubkey`,
//!    proving the TLS key and the secio identity share an owner.
//! 5. For a client dialling a target address that contains `/p2p/<expected>`,
//!    `expected` must equal `PeerId::from_public_key(secio_pubkey)`
//!    (server-side verifier skips this step).
//!
//! SAN and hostname are never checked.
//!
//! Once the certificate passes the above checks, per-TLS-message signature
//! verification (`verify_tls12_signature` / `verify_tls13_signature`) and the
//! advertised signature-scheme list are delegated to the `rustls` default
//! crypto provider (currently `aws_lc_rs`, matching the `tls` feature).
//!
//! [plan.md §4.4]: https://github.com/nervosnetwork/tentacle/blob/master/plan.md
//! [`TENTACLE_QUIC_IDENT_OID`]: crate::quic::identity::TENTACLE_QUIC_IDENT_OID

use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use secio::KeyProvider;

use crate::quic::identity::{extract_identity, verify_binding};

// ─────────────────────────────────────── server side ────────────────────────────────────────

/// Verifies a **server** certificate presented during the TLS handshake of a
/// client-initiated QUIC connection.
///
/// Holds a reference to the local `KeyProvider` so it can dispatch the
/// secp256k1 signature verification in [`verify_binding`] — no private key
/// material is ever read, only `KeyProvider::verify_ecdsa` is used.
///
/// If the dial target multiaddr contains `/p2p/<peer_id>`, construct the
/// verifier with `Some(peer_id)` so the TLS handshake fails with
/// `rustls::Error::General` when the server's certificate does not bind to the
/// expected peer.
pub struct TentacleQuicServerCertVerifier<K: KeyProvider> {
    /// PeerId extracted from the dial target multiaddr (`/p2p/<peer_id>`).
    /// `None` means the dialer did not pin a specific peer.
    expected_peer_id: Option<secio::PeerId>,

    /// Local `KeyProvider`, used only to dispatch `verify_ecdsa`.
    local_key: K,

    /// Crypto provider used for TLS signature verification and to populate
    /// `supported_verify_schemes`.
    crypto_provider: Arc<CryptoProvider>,
}

impl<K: KeyProvider> TentacleQuicServerCertVerifier<K> {
    /// Build a new verifier with the default `aws_lc_rs` crypto provider.
    pub fn new(local_key: K, expected_peer_id: Option<secio::PeerId>) -> Self {
        Self {
            expected_peer_id,
            local_key,
            crypto_provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }
}

impl<K: KeyProvider> std::fmt::Debug for TentacleQuicServerCertVerifier<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TentacleQuicServerCertVerifier")
            .field("expected_peer_id", &self.expected_peer_id)
            .finish_non_exhaustive()
    }
}

impl<K: KeyProvider> ServerCertVerifier for TentacleQuicServerCertVerifier<K> {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        verify_tentacle_cert(
            &self.local_key,
            end_entity,
            intermediates,
            now,
            self.expected_peer_id.as_ref(),
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ─────────────────────────────────────── client side ────────────────────────────────────────

/// Verifies a **client** certificate presented during the TLS handshake of an
/// incoming QUIC connection on a server.
///
/// Identity extraction and binding checks are identical to the server verifier
/// above. There is no `expected_peer_id` because the server does not know in
/// advance which peer will connect — any well-formed Tentacle identity is
/// accepted and the resulting `PeerId` is surfaced to `InnerService` via
/// `SessionContext.remote_pubkey`.
///
/// Client authentication is **mandatory** — a plain TLS client cannot connect.
pub struct TentacleQuicClientCertVerifier<K: KeyProvider> {
    /// Local `KeyProvider`, used only to dispatch `verify_ecdsa`.
    local_key: K,

    /// Crypto provider used for TLS signature verification and to populate
    /// `supported_verify_schemes`.
    crypto_provider: Arc<CryptoProvider>,
}

impl<K: KeyProvider> TentacleQuicClientCertVerifier<K> {
    /// Build a new verifier with the default `aws_lc_rs` crypto provider.
    pub fn new(local_key: K) -> Self {
        Self {
            local_key,
            crypto_provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }
}

impl<K: KeyProvider> std::fmt::Debug for TentacleQuicClientCertVerifier<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TentacleQuicClientCertVerifier")
            .finish_non_exhaustive()
    }
}

impl<K: KeyProvider> ClientCertVerifier for TentacleQuicClientCertVerifier<K> {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        verify_tentacle_cert(&self.local_key, end_entity, intermediates, now, None)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ─────────────────────────────────────── shared check ───────────────────────────────────────

/// Run the tentacle identity checks shared by both verifiers (steps 1–10 of
/// plan.md §4.4). The returned `rustls::Error` is what propagates into the
/// QUIC handshake failure visible to the application as a connection abort.
fn verify_tentacle_cert<K: KeyProvider>(
    local_key: &K,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
    expected_peer_id: Option<&secio::PeerId>,
) -> Result<(), RustlsError> {
    // Step 1: non-empty chain. `end_entity` is non-optional in the rustls API,
    //         so presence is already guaranteed.

    // Step 2: no intermediates — the Tentacle identity must live on a
    //         single self-signed leaf.
    if !intermediates.is_empty() {
        return Err(RustlsError::General(
            "tentacle quic cert chain must contain exactly one leaf certificate".to_string(),
        ));
    }

    // Steps 3 & 4: parse and check validity window.
    let leaf_der = end_entity.as_ref();
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf_der)
        .map_err(|e| RustlsError::General(format!("failed to parse leaf certificate: {}", e)))?;

    let now_secs = now.as_secs() as i64;
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    if now_secs < not_before || now_secs > not_after {
        return Err(RustlsError::General(
            "tentacle quic cert is outside its validity period".to_string(),
        ));
    }

    // Steps 5–7: locate the private extension, molecule-decode it, validate
    //            version. All handled inside `extract_identity`.
    let identity = extract_identity(leaf_der)
        .map_err(|e| RustlsError::General(format!("identity extension: {}", e)))?;

    // Reconstruct the secio public key and derive PeerId from the extension.
    // Note: we intentionally skip checking the `peer_id` field in the extension
    // against `secio_pubkey` — it is a redundant deterministic derivation with
    // no security value. The verifier always derives PeerId from `secio_pubkey`.
    let secio_pubkey = secio::PublicKey::from_raw_key(identity.secio_pubkey);
    let derived_peer_id = secio_pubkey.peer_id();

    // Step 8: pull SPKI DER from the parsed cert for the binding check.
    let spki_der = parsed.public_key().raw;

    // Step 9: verify the secio binding signature over the SPKI DER.
    verify_binding(local_key, &secio_pubkey, spki_der, &identity.binding_sig)
        .map_err(|e| RustlsError::General(format!("binding signature invalid: {}", e)))?;

    // Step 10: client-only pinned peer_id check. Server-side verifier passes
    //          `None` here.
    if let Some(expected) = expected_peer_id {
        if *expected != derived_peer_id {
            return Err(RustlsError::General(format!(
                "tentacle identity: expected peer_id {}, got {}",
                expected, derived_peer_id
            )));
        }
    }

    // SAN and hostname checks are intentionally omitted — the identity model
    // above is sufficient to bind the TLS key to the tentacle PeerId.
    Ok(())
}

// ──────────────────────────────────────────── tests ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use molecule::prelude::{Builder, Entity};
    use secio::SecioKeyPair;
    use std::time::Duration;

    use crate::quic::identity::{IDENTITY_VERSION, TENTACLE_QUIC_IDENT_OID, build_self_signed};
    use crate::quic::identity_mol::{Bytes as MolBytes, TentacleQuicIdentityV1, Uint8};

    fn now() -> UnixTime {
        UnixTime::now()
    }

    fn valid_server_name() -> ServerName<'static> {
        ServerName::try_from("tentacle.invalid").unwrap()
    }

    /// Build a cert whose tentacle extension carries an arbitrary payload.
    fn build_cert_with_payload(payload: Vec<u8>) -> Vec<u8> {
        let tls_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["tentacle.invalid".to_string()]).unwrap();
        let ext = rcgen::CustomExtension::from_oid_content(TENTACLE_QUIC_IDENT_OID, payload);
        params.custom_extensions.push(ext);
        params.self_signed(&tls_keypair).unwrap().der().to_vec()
    }

    /// Build a self-signed cert that does NOT carry the tentacle extension.
    fn build_cert_without_extension() -> Vec<u8> {
        let tls_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["tentacle.invalid".to_string()]).unwrap();
        params.self_signed(&tls_keypair).unwrap().der().to_vec()
    }

    /// Molecule-encode an identity payload with arbitrary field values.
    fn encode_identity(version: u8, secio_pubkey: &[u8], binding_sig: &[u8]) -> Vec<u8> {
        let v = Uint8::new_builder().nth0(version).build();
        let sp = MolBytes::new_builder()
            .extend(secio_pubkey.iter().copied().map(Into::into))
            .build();
        let sig = MolBytes::new_builder()
            .extend(binding_sig.iter().copied().map(Into::into))
            .build();

        TentacleQuicIdentityV1::new_builder()
            .version(v)
            .secio_pubkey(sp)
            .binding_sig(sig)
            .build()
            .as_bytes()
            .to_vec()
    }

    // ──────────────────────── server-side verifier ────────────────────────

    #[test]
    fn test_server_verify_ok() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).unwrap();
        let verifier = TentacleQuicServerCertVerifier::new(key, None);
        let cert_der = CertificateDer::from(cert.cert_der);

        verifier
            .verify_server_cert(&cert_der, &[], &valid_server_name(), &[], now())
            .expect("valid cert should pass");
    }

    #[test]
    fn test_server_verify_expired_cert() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).unwrap();
        let verifier = TentacleQuicServerCertVerifier::new(key, None);
        let cert_der = CertificateDer::from(cert.cert_der);

        // rcgen defaults not_after = year 4096. 1<<56 seconds ≈ year 2_283_970.
        let far_future = UnixTime::since_unix_epoch(Duration::from_secs(1u64 << 56));
        let result =
            verifier.verify_server_cert(&cert_der, &[], &valid_server_name(), &[], far_future);
        assert!(
            result.is_err(),
            "cert valid past its not_after should be rejected"
        );
    }

    #[test]
    fn test_server_verify_future_cert() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).unwrap();
        let verifier = TentacleQuicServerCertVerifier::new(key, None);
        let cert_der = CertificateDer::from(cert.cert_der);

        // rcgen defaults not_before = 1975. Epoch (1970) is before that.
        let too_early = UnixTime::since_unix_epoch(Duration::from_secs(0));
        let result =
            verifier.verify_server_cert(&cert_der, &[], &valid_server_name(), &[], too_early);
        assert!(
            result.is_err(),
            "cert valid before its not_before should be rejected"
        );
    }

    #[test]
    fn test_server_verify_with_intermediate() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).unwrap();
        let verifier = TentacleQuicServerCertVerifier::new(key, None);
        let leaf = CertificateDer::from(cert.cert_der.clone());
        let intermediates = [CertificateDer::from(cert.cert_der)];

        let result =
            verifier.verify_server_cert(&leaf, &intermediates, &valid_server_name(), &[], now());
        assert!(
            result.is_err(),
            "any non-empty intermediate list must be rejected"
        );
    }

    #[test]
    fn test_server_verify_missing_extension() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert_bytes = build_cert_without_extension();
        let verifier = TentacleQuicServerCertVerifier::new(key, None);
        let cert_der = CertificateDer::from(cert_bytes);

        let result = verifier.verify_server_cert(&cert_der, &[], &valid_server_name(), &[], now());
        assert!(
            result.is_err(),
            "cert without tentacle extension must be rejected"
        );
    }

    #[test]
    fn test_server_verify_wrong_version() {
        let key = SecioKeyPair::secp256k1_generated();
        let pubkey = key.public_key().inner_ref().to_vec();

        let payload = encode_identity(2, &pubkey, &[0u8; 64]);
        let cert_bytes = build_cert_with_payload(payload);

        let verifier = TentacleQuicServerCertVerifier::new(key, None);
        let cert_der = CertificateDer::from(cert_bytes);

        let result = verifier.verify_server_cert(&cert_der, &[], &valid_server_name(), &[], now());
        assert!(result.is_err(), "version != 1 must be rejected");
    }

    #[test]
    fn test_server_verify_binding_sig_invalid() {
        let key = SecioKeyPair::secp256k1_generated();
        let pubkey = key.public_key().inner_ref().to_vec();

        // A syntactically reasonable but semantically wrong signature.
        let bogus_sig = vec![0xab; 64];
        let payload = encode_identity(IDENTITY_VERSION, &pubkey, &bogus_sig);
        let cert_bytes = build_cert_with_payload(payload);

        let verifier = TentacleQuicServerCertVerifier::new(key, None);
        let cert_der = CertificateDer::from(cert_bytes);

        let result = verifier.verify_server_cert(&cert_der, &[], &valid_server_name(), &[], now());
        assert!(result.is_err(), "invalid binding_sig must be rejected");
    }

    #[test]
    fn test_server_verify_expected_peer_id_mismatch() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).unwrap();

        // Expect a different peer than the one the cert actually binds to.
        let wrong_expected = SecioKeyPair::secp256k1_generated().public_key().peer_id();
        let verifier = TentacleQuicServerCertVerifier::new(key, Some(wrong_expected));
        let cert_der = CertificateDer::from(cert.cert_der);

        let result = verifier.verify_server_cert(&cert_der, &[], &valid_server_name(), &[], now());
        assert!(
            result.is_err(),
            "dial target peer_id mismatch must be rejected"
        );
    }

    #[test]
    fn test_server_verify_expected_peer_id_match() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).unwrap();
        let correct_peer_id = key.public_key().peer_id();

        let verifier = TentacleQuicServerCertVerifier::new(key, Some(correct_peer_id));
        let cert_der = CertificateDer::from(cert.cert_der);

        verifier
            .verify_server_cert(&cert_der, &[], &valid_server_name(), &[], now())
            .expect("correct expected peer_id should pass");
    }

    // ──────────────────────── client-side verifier ────────────────────────

    #[test]
    fn test_client_verify_ok() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).unwrap();
        let verifier = TentacleQuicClientCertVerifier::new(key);
        let cert_der = CertificateDer::from(cert.cert_der);

        verifier
            .verify_client_cert(&cert_der, &[], now())
            .expect("valid client cert should pass");
    }

    #[test]
    fn test_client_verify_rejects_intermediate() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).unwrap();
        let verifier = TentacleQuicClientCertVerifier::new(key);
        let leaf = CertificateDer::from(cert.cert_der.clone());
        let intermediates = [CertificateDer::from(cert.cert_der)];

        let result = verifier.verify_client_cert(&leaf, &intermediates, now());
        assert!(result.is_err());
    }

    #[test]
    fn test_client_verify_mandatory() {
        let key = SecioKeyPair::secp256k1_generated();
        let verifier = TentacleQuicClientCertVerifier::new(key);

        assert!(
            verifier.client_auth_mandatory(),
            "client auth must be mandatory"
        );
        assert!(verifier.offer_client_auth());
        assert!(
            verifier.root_hint_subjects().is_empty(),
            "tentacle does not surface CA hints"
        );
    }
}
