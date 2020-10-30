#![allow(dead_code, unused_imports)]

use super::KeyAgreement;
use crate::error::SecioError;
use core::slice;
use rand::{CryptoRng, Error, RngCore};
use std::io;
pub use x25519_dalek::EphemeralSecret as EphemeralPrivateKey;
use x25519_dalek::PublicKey;

/// wasm doesn't support rand, use `getrandom` instead
#[cfg(test)]
use rand::rngs::OsRng;

#[cfg(not(test))]
struct OsRng;

#[cfg(not(test))]
impl CryptoRng for OsRng {}

#[cfg(not(test))]
impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut int = 0;
        unsafe {
            let ptr = &mut int as *mut u32 as *mut u8;
            let slice = slice::from_raw_parts_mut(ptr, 4);
            self.fill_bytes(slice);
        }
        int
    }
    fn next_u64(&mut self) -> u64 {
        let mut int = 0;
        unsafe {
            let ptr = &mut int as *mut u64 as *mut u8;
            let slice = slice::from_raw_parts_mut(ptr, 8);
            self.fill_bytes(slice);
        }
        int
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(e) = self.try_fill_bytes(dest) {
            panic!("Error: {}", e);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom::getrandom(dest)
            .map_err(|e| Error::new(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
        Ok(())
    }
}

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
