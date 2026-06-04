use molecule::prelude::{Builder, Entity, Reader};
use secio::KeyProvider;

use crate::quic::error::QuicErrorKind;
use crate::quic::identity_mol::{
    Bytes as MolBytes, TentacleQuicIdentityV1, TentacleQuicIdentityV1Reader, Uint8,
};

/// OID for tentacle QUIC identity X.509 extension.
pub const TENTACLE_QUIC_IDENT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1, 1];
/// Domain separation tag for the secio → TLS binding signature.
pub const BINDING_DOMAIN: &[u8] = b"tentacle-quic-binding/v1";
/// Payload version in the identity extension.
pub const IDENTITY_VERSION: u8 = 1;

/// A freshly-generated self-signed TLS certificate carrying the
/// tentacle identity extension, ready to be plugged into a
/// `rustls::ServerConfig` / `rustls::ClientConfig`.
///
/// Both fields are DER-encoded. `cert_der` is the X.509 leaf with the
/// tentacle private extension attached; `key_der` is the matching
/// PKCS#8 private key for the embedded TLS keypair (K_tls). The secio
/// private key is **not** stored here.
pub struct TentacleQuicCert {
    /// DER-encoded X.509 leaf certificate.
    pub cert_der: Vec<u8>,
    /// PKCS#8 DER-encoded private key for the embedded TLS keypair.
    pub key_der: Vec<u8>,
}

/// Derive a self-signed QUIC TLS certificate from a secio `KeyProvider`.
///
/// Steps:
///   1. Generate a fresh Ed25519 TLS keypair (K_tls).
///   2. Extract the DER-encoded SubjectPublicKeyInfo of K_tls.
///   3. Compute `binding_sig = secp256k1_sign(K_secio, sha256(BINDING_DOMAIN || spki))`.
///   4. Encode `(version, secio_pubkey, binding_sig)` as a molecule
///      `TentacleQuicIdentityV1` payload and attach it as a private X.509
///      extension with OID `TENTACLE_QUIC_IDENT_OID`. The `PeerId` is **not**
///      stored in the payload — it is deterministically derived from
///      `secio_pubkey` by both sides.
///   5. Self-sign the certificate.
pub fn build_self_signed<K: KeyProvider>(key: &K) -> Result<TentacleQuicCert, QuicErrorKind> {
    // 1. Generate TLS keypair (K_tls)
    let tls_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| QuicErrorKind::CertificateError(e.to_string()))?;

    // 2. Extract SPKI DER of K_tls
    let spki_der = tls_keypair.public_key_der();

    // 3. binding_sig = secp256k1_sign(K_secio, sha256(BINDING_DOMAIN || spki_der))
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(BINDING_DOMAIN);
    ctx.update(&spki_der);
    let digest = ctx.finish();

    let binding_sig = key
        .sign_ecdsa(digest.as_ref())
        .map_err(|e| QuicErrorKind::SigningError(e.into().to_string()))?;

    // 4. Build molecule payload and wrap as a custom X.509 extension
    let secio_pubkey = key.pubkey();
    let payload = encode_identity_payload(&secio_pubkey, &binding_sig);
    let ext = rcgen::CustomExtension::from_oid_content(TENTACLE_QUIC_IDENT_OID, payload);

    // 5. Build CertificateParams and self-sign
    let mut params = rcgen::CertificateParams::new(vec!["tentacle.invalid".to_string()])
        .map_err(|e| QuicErrorKind::CertificateError(e.to_string()))?;

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "tentacle.invalid");
    params.distinguished_name = dn;

    // rcgen defaults not_before/not_after to 1975 → 4096, which is fine for our use
    params.custom_extensions.push(ext);

    let cert = params
        .self_signed(&tls_keypair)
        .map_err(|e| QuicErrorKind::CertificateError(e.to_string()))?;

    Ok(TentacleQuicCert {
        cert_der: cert.der().to_vec(),
        key_der: tls_keypair.serialize_der(),
    })
}

/// Encode the identity fields as a molecule `TentacleQuicIdentityV1` payload.
fn encode_identity_payload(secio_pubkey: &[u8], binding_sig: &[u8]) -> Vec<u8> {
    let version = Uint8::new_builder().nth0(IDENTITY_VERSION).build();
    let secio_pubkey = MolBytes::new_builder()
        .extend(secio_pubkey.iter().copied().map(Into::into))
        .build();
    let binding_sig = MolBytes::new_builder()
        .extend(binding_sig.iter().copied().map(Into::into))
        .build();

    TentacleQuicIdentityV1::new_builder()
        .version(version)
        .secio_pubkey(secio_pubkey)
        .binding_sig(binding_sig)
        .build()
        .as_bytes()
        .to_vec()
}

/// Decoded contents of the tentacle QUIC identity X.509 extension.
///
/// Returned by [`extract_identity`]. Wrapping the molecule type in a
/// plain struct keeps the auto-generated `identity_mol` codec out of
/// the public API surface, so consumers don't have to reach through
/// molecule's reader / entity types to inspect the fields.
#[derive(Debug, Clone)]
pub struct TentacleQuicIdentity {
    /// Identity payload version. Always equal to [`IDENTITY_VERSION`]
    /// for a successfully-extracted v1 payload.
    pub version: u8,
    /// Raw bytes of the peer's secio public key (`K_secio`). The
    /// `PeerId` is derived from this with
    /// [`secio::PublicKey::from_raw_key`] + [`secio::PublicKey::peer_id`].
    pub secio_pubkey: Vec<u8>,
    /// Raw bytes of the secp256k1 binding signature, which proves the
    /// holder of `K_secio` also controls the leaf certificate's TLS
    /// keypair (`K_tls`). Verified by
    /// [`verify_binding`].
    pub binding_sig: Vec<u8>,
}

/// Pull the tentacle identity payload out of a peer-presented leaf
/// certificate.
///
/// Walks the X.509 extensions, locates the unique extension with OID
/// [`TENTACLE_QUIC_IDENT_OID`], molecule-decodes its payload, and
/// validates that the version field equals [`IDENTITY_VERSION`].
///
/// Returns:
/// - [`QuicErrorKind::CertificateError`] if the cert can't be parsed
///   or the molecule payload is malformed.
/// - [`QuicErrorKind::ExtensionNotFound`] if no extension with the
///   tentacle OID is present.
/// - [`QuicErrorKind::MultipleIdentityFound`] if more than one such
///   extension is present (a tampered or malformed cert).
/// - [`QuicErrorKind::IdentityVersionUnsupported`] if the payload
///   version is not 1.
pub fn extract_identity(leaf_der: &[u8]) -> Result<TentacleQuicIdentity, QuicErrorKind> {
    let (_, parsed_cert) = x509_parser::parse_x509_certificate(leaf_der)
        .map_err(|e| QuicErrorKind::CertificateError(e.to_string()))?;
    let mut identity = None;
    for ext in parsed_cert.extensions() {
        if let Some(iter) = ext.oid.iter() {
            if iter.collect::<Vec<_>>() == TENTACLE_QUIC_IDENT_OID {
                if identity.is_some() {
                    return Err(QuicErrorKind::MultipleIdentityFound);
                }
                identity = Some(
                    TentacleQuicIdentityV1Reader::from_compatible_slice(ext.value)
                        .map_err(|e| {
                            QuicErrorKind::CertificateError(format!(
                                "Unable to parse cert extension: {}",
                                e
                            ))
                        })?
                        .to_entity(),
                );
            }
        }
    }
    if let Some(identity) = identity {
        let version = identity.version().nth0().into();

        if version != IDENTITY_VERSION {
            return Err(QuicErrorKind::IdentityVersionUnsupported(version));
        }
        return Ok(TentacleQuicIdentity {
            version,
            secio_pubkey: identity.secio_pubkey().raw_data().to_vec(),
            binding_sig: identity.binding_sig().raw_data().to_vec(),
        });
    } else {
        Err(QuicErrorKind::ExtensionNotFound)
    }
}
/// Verify that `sig` is a valid secp256k1 signature by `secio_pubkey` over
/// `sha256(BINDING_DOMAIN || leaf_spki_der)`.
///
/// `local_key` is any local `KeyProvider` — it is only used to dispatch the
/// `verify_ecdsa` call; its private key material is never touched. In practice
/// pass the local service's own `KeyProvider`.
pub fn verify_binding<K: KeyProvider>(
    local_key: &K,
    secio_pubkey: &secio::PublicKey,
    leaf_spki_der: &[u8],
    sig: &[u8],
) -> Result<(), QuicErrorKind> {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(BINDING_DOMAIN);
    ctx.update(leaf_spki_der);
    let digest = ctx.finish();

    if local_key.verify_ecdsa(secio_pubkey.inner_ref(), digest.as_ref(), sig) {
        Ok(())
    } else {
        Err(QuicErrorKind::SigningError(
            "binding signature verification failed".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secio::SecioKeyPair;
    use x509_parser::parse_x509_certificate;

    /// Helper: extract the DER-encoded SubjectPublicKeyInfo from a cert DER.
    fn spki_der_of(cert_der: &[u8]) -> Vec<u8> {
        let (_, parsed) = parse_x509_certificate(cert_der).expect("parse cert");
        parsed.public_key().raw.to_vec()
    }

    #[test]
    fn test_build_and_extract() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).expect("build cert");

        let identity = extract_identity(&cert.cert_der).expect("extract identity");

        // version must be 1
        assert_eq!(identity.version, IDENTITY_VERSION);

        // secio_pubkey must round-trip exactly
        assert_eq!(
            identity.secio_pubkey.as_slice(),
            key.public_key().inner_ref()
        );

        // PeerId can be derived from secio_pubkey (no separate field stored)
        let derived = secio::PublicKey::from_raw_key(identity.secio_pubkey.clone()).peer_id();
        assert_eq!(derived, key.public_key().peer_id());

        // binding_sig must be non-empty
        assert!(!identity.binding_sig.is_empty());
    }

    #[test]
    fn test_verify_binding_ok() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).expect("build cert");

        let spki_der = spki_der_of(&cert.cert_der);
        let identity = extract_identity(&cert.cert_der).expect("extract identity");

        verify_binding(&key, &key.public_key(), &spki_der, &identity.binding_sig)
            .expect("binding verification should pass");
    }

    #[test]
    fn test_verify_binding_tampered_sig() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).expect("build cert");

        let spki_der = spki_der_of(&cert.cert_der);
        let identity = extract_identity(&cert.cert_der).expect("extract identity");
        let mut sig = identity.binding_sig.clone();

        // Flip the last byte
        let last = sig.len() - 1;
        sig[last] ^= 0xff;

        let result = verify_binding(&key, &key.public_key(), &spki_der, &sig);
        assert!(
            matches!(result, Err(QuicErrorKind::SigningError(_))),
            "expected SigningError, got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_binding_wrong_pubkey() {
        let key_a = SecioKeyPair::secp256k1_generated();
        let key_b = SecioKeyPair::secp256k1_generated();
        let cert_a = build_self_signed(&key_a).expect("build cert");

        let spki_der = spki_der_of(&cert_a.cert_der);
        let identity = extract_identity(&cert_a.cert_der).expect("extract identity");

        // Signature was made by key_a, but we try to verify with key_b's public key
        let result = verify_binding(
            &key_a,
            &key_b.public_key(),
            &spki_der,
            &identity.binding_sig,
        );
        assert!(
            matches!(result, Err(QuicErrorKind::SigningError(_))),
            "expected SigningError, got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_binding_wrong_spki() {
        let key = SecioKeyPair::secp256k1_generated();
        let cert = build_self_signed(&key).expect("build cert");
        let identity = extract_identity(&cert.cert_der).expect("extract identity");
        let sig = identity.binding_sig.clone();

        // Use an unrelated byte string as SPKI
        let fake_spki = b"not the real SPKI der".to_vec();

        let result = verify_binding(&key, &key.public_key(), &fake_spki, &sig);
        assert!(
            matches!(result, Err(QuicErrorKind::SigningError(_))),
            "expected SigningError, got {:?}",
            result
        );
    }

    #[test]
    fn test_extract_missing_extension() {
        // Build a cert via rcgen directly, without the tentacle custom extension
        let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("gen keypair");
        let params =
            rcgen::CertificateParams::new(vec!["tentacle.invalid".to_string()]).expect("params");
        let cert = params.self_signed(&keypair).expect("self sign");

        let result = extract_identity(cert.der());
        assert!(
            matches!(result, Err(QuicErrorKind::ExtensionNotFound)),
            "expected ExtensionNotFound, got {:?}",
            result
        );
    }

    #[test]
    fn test_extract_malformed_payload() {
        // Cert with the correct OID but random bytes as the extension payload
        let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("gen keypair");
        let mut params =
            rcgen::CertificateParams::new(vec!["tentacle.invalid".to_string()]).expect("params");
        let bogus = vec![0xde, 0xad, 0xbe, 0xef];
        let ext = rcgen::CustomExtension::from_oid_content(TENTACLE_QUIC_IDENT_OID, bogus);
        params.custom_extensions.push(ext);
        let cert = params.self_signed(&keypair).expect("self sign");

        let result = extract_identity(cert.der());
        assert!(
            matches!(result, Err(QuicErrorKind::CertificateError(_))),
            "expected CertificateError, got {:?}",
            result
        );
    }

    #[test]
    fn test_extract_unsupported_version() {
        // Build a properly-formatted molecule payload but with version = 2
        let key = SecioKeyPair::secp256k1_generated();
        let secio_pubkey = key.public_key().inner_ref().to_vec();
        let binding_sig = vec![0u8; 64];

        let version = Uint8::new_builder().nth0(2u8).build();
        let secio_pubkey_mol = MolBytes::new_builder()
            .extend(secio_pubkey.iter().copied().map(Into::into))
            .build();
        let sig_mol = MolBytes::new_builder()
            .extend(binding_sig.iter().copied().map(Into::into))
            .build();
        let payload = TentacleQuicIdentityV1::new_builder()
            .version(version)
            .secio_pubkey(secio_pubkey_mol)
            .binding_sig(sig_mol)
            .build()
            .as_bytes()
            .to_vec();

        let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("gen keypair");
        let mut params =
            rcgen::CertificateParams::new(vec!["tentacle.invalid".to_string()]).expect("params");
        let ext = rcgen::CustomExtension::from_oid_content(TENTACLE_QUIC_IDENT_OID, payload);
        params.custom_extensions.push(ext);
        let cert = params.self_signed(&keypair).expect("self sign");

        let result = extract_identity(cert.der());
        assert!(
            matches!(result, Err(QuicErrorKind::IdentityVersionUnsupported(2))),
            "expected IdentityVersionUnsupported(2), got {:?}",
            result
        );
    }

    #[test]
    fn test_extract_multiple_identity() {
        // Two extensions with the same OID — should be rejected
        let key = SecioKeyPair::secp256k1_generated();
        let secio_pubkey = key.public_key().inner_ref().to_vec();

        let build_payload = || {
            let version = Uint8::new_builder().nth0(IDENTITY_VERSION).build();
            let p_mol = MolBytes::new_builder()
                .extend(secio_pubkey.iter().copied().map(Into::into))
                .build();
            let sig_mol = MolBytes::new_builder()
                .extend(vec![0u8; 64].into_iter().map(Into::into))
                .build();
            TentacleQuicIdentityV1::new_builder()
                .version(version)
                .secio_pubkey(p_mol)
                .binding_sig(sig_mol)
                .build()
                .as_bytes()
                .to_vec()
        };

        let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("gen keypair");
        let mut params =
            rcgen::CertificateParams::new(vec!["tentacle.invalid".to_string()]).expect("params");

        let ext1 =
            rcgen::CustomExtension::from_oid_content(TENTACLE_QUIC_IDENT_OID, build_payload());
        let ext2 =
            rcgen::CustomExtension::from_oid_content(TENTACLE_QUIC_IDENT_OID, build_payload());
        params.custom_extensions.push(ext1);
        params.custom_extensions.push(ext2);

        let cert = params.self_signed(&keypair).expect("self sign");
        let result = extract_identity(cert.der());

        assert!(
            matches!(result, Err(QuicErrorKind::MultipleIdentityFound)),
            "expected MultipleIdentityFound, got {:?}",
            result
        );
    }
}
