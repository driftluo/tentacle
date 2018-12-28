use log::debug;
use ring::agreement;
use ring::rand as ring_rand;
use untrusted::Input;

use crate::error::SecioError;

/// Possible key agreement algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyAgreement {
    EcdhP256,
    EcdhP384,
}

impl Into<&'static agreement::Algorithm> for KeyAgreement {
    #[inline]
    fn into(self) -> &'static agreement::Algorithm {
        match self {
            KeyAgreement::EcdhP256 => &agreement::ECDH_P256,
            KeyAgreement::EcdhP384 => &agreement::ECDH_P384,
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
            let mut tmp_pub_key: Vec<u8> = (0..tmp_priv_key.public_key_len()).map(|_| 0).collect();
            tmp_priv_key.compute_public_key(&mut tmp_pub_key).unwrap();
            Ok((tmp_priv_key, tmp_pub_key))
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
    _out_size: usize,
) -> Result<Vec<u8>, SecioError> {
    agreement::agree_ephemeral(
        my_private_key,
        algorithm.into(),
        Input::from(other_public_key),
        SecioError::SecretGenerationFailed,
        |key_material| Ok(key_material.to_vec()),
    )
}
