use super::KeyAgreement;
use crate::error::SecioError;
use rand_core::OsRng;
pub use x25519_dalek::EphemeralSecret as EphemeralPrivateKey;
use x25519_dalek::PublicKey;

/// Generates a new key pair as part of the exchange.
///
/// Returns the opaque private key and the corresponding public key.
pub fn generate_agreement(
    algorithm: KeyAgreement,
) -> Result<(EphemeralPrivateKey, Vec<u8>), SecioError> {
    match algorithm {
        KeyAgreement::X25519 => {
            let key = EphemeralPrivateKey::new(OsRng);
            let pubkey = PublicKey::from(&key);
            Ok((key, pubkey.to_bytes().to_vec()))
        }
        KeyAgreement::EcdhP256 => Err(SecioError::EphemeralKeyGenerationFailed),
        KeyAgreement::EcdhP384 => Err(SecioError::EphemeralKeyGenerationFailed),
    }
}

/// Finish the agreement. On success, returns the shared key that both remote agreed upon.
pub fn agree(
    algorithm: KeyAgreement,
    my_private_key: EphemeralPrivateKey,
    other_public_key: &[u8],
) -> Result<Vec<u8>, SecioError> {
    if !matches!(algorithm, KeyAgreement::X25519) || other_public_key.len() < 32 {
        return Err(SecioError::SecretGenerationFailed);
    }
    let mut bytes = [0; 32];

    bytes.copy_from_slice(other_public_key);

    let pubkey = PublicKey::from(bytes);

    Ok(my_private_key.diffie_hellman(&pubkey).to_bytes().to_vec())
}
