#[cfg(unix)]
mod openssl_impl;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(any(test, not(unix), not(ossl110)))]
mod ring_impl;
#[cfg(any(target_arch = "wasm32", test))]
mod wasm_compat;

#[cfg(target_arch = "wasm32")]
pub use wasm_compat::*;

/// Possible key agreement algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyAgreement {
    EcdhP256,
    EcdhP384,
    X25519,
}

#[cfg(all(ossl110, unix))]
pub use openssl_impl::*;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(unix))]
pub use ring_impl::*;
#[cfg(all(not(ossl110), unix))]
pub use ring_openssl_unix::*;

#[cfg(all(not(ossl110), unix))]
mod ring_openssl_unix {
    use super::KeyAgreement;
    use super::{openssl_impl, ring_impl};
    use crate::error::SecioError;

    pub enum EphemeralPrivateKey {
        Openssl(openssl_impl::EphemeralPrivateKey),
        Ring(ring_impl::EphemeralPrivateKey),
    }

    pub fn generate_agreement(
        algorithm: KeyAgreement,
    ) -> Result<(EphemeralPrivateKey, Vec<u8>), SecioError> {
        match algorithm {
            KeyAgreement::EcdhP256 | KeyAgreement::EcdhP384 => {
                openssl_impl::generate_agreement(algorithm)
                    .map(|(private, pubkey)| (EphemeralPrivateKey::Openssl(private), pubkey))
            }
            KeyAgreement::X25519 => ring_impl::generate_agreement(algorithm)
                .map(|(private, pubkey)| (EphemeralPrivateKey::Ring(private), pubkey)),
        }
    }

    pub fn agree(
        algorithm: KeyAgreement,
        my_private_key: EphemeralPrivateKey,
        other_public_key: &[u8],
    ) -> Result<Vec<u8>, SecioError> {
        match my_private_key {
            EphemeralPrivateKey::Openssl(private_key) => {
                openssl_impl::agree(algorithm, private_key, other_public_key)
            }
            EphemeralPrivateKey::Ring(private_key) => {
                ring_impl::agree(algorithm, private_key, other_public_key)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hd() {
        let (pk_native, sk_native) = generate_agreement(KeyAgreement::X25519).unwrap();
        let (pk_wasm, sk_wasm) = wasm_compat::generate_agreement(KeyAgreement::X25519).unwrap();

        let secret_native = agree(KeyAgreement::X25519, pk_native, &sk_wasm).unwrap();
        let secret_wasm = wasm_compat::agree(KeyAgreement::X25519, pk_wasm, &sk_native).unwrap();

        assert_eq!(secret_native, secret_wasm)
    }
}
