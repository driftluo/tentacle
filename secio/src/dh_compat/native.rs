/// Most of the code for this module comes from `rust-libp2p`.
/// Change return type to Result
use log::debug;
use ring::agreement;
use ring::rand as ring_rand;

use super::KeyAgreement;
use crate::error::SecioError;
pub use ring::agreement::EphemeralPrivateKey;

impl From<KeyAgreement> for &'static agreement::Algorithm {
    #[inline]
    fn from(a: KeyAgreement) -> &'static agreement::Algorithm {
        match a {
            KeyAgreement::EcdhP256 => &agreement::ECDH_P256,
            KeyAgreement::EcdhP384 => &agreement::ECDH_P384,
            KeyAgreement::X25519 => &agreement::X25519,
        }
    }
}

/// Generates a new key pair as part of the exchange.
///
/// Returns the opaque private key and the corresponding public key.
pub fn generate_agreement(
    algorithm: KeyAgreement,
) -> Result<(agreement::EphemeralPrivateKey, Vec<u8>), SecioError> {
    let rng = ring_rand::SystemRandom::new();

    match agreement::EphemeralPrivateKey::generate(algorithm.into(), &rng) {
        Ok(tmp_priv_key) => {
            let tmp_pub_key = tmp_priv_key
                .compute_public_key()
                .map_err(|_| SecioError::EphemeralKeyGenerationFailed)?;
            Ok((tmp_priv_key, tmp_pub_key.as_ref().to_vec()))
        }
        Err(_) => {
            debug!("failed to generate ECDH key");
            Err(SecioError::EphemeralKeyGenerationFailed)
        }
    }
}

/// Finish the agreement. On success, returns the shared key that both remote agreed upon.
pub fn agree(
    algorithm: KeyAgreement,
    my_private_key: agreement::EphemeralPrivateKey,
    other_public_key: &[u8],
) -> Result<Vec<u8>, SecioError> {
    agreement::agree_ephemeral(
        my_private_key,
        &agreement::UnparsedPublicKey::new(algorithm.into(), other_public_key),
        SecioError::SecretGenerationFailed,
        |key_material| Ok(key_material.to_vec()),
    )
}
