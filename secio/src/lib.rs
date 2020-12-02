//! Aes Encrypted communication and handshake process implementation

#![deny(missing_docs)]
use rand::RngCore;

pub use crate::{handshake::handshake_struct::PublicKey, peer_id::PeerId};

/// Encrypted and decrypted codec implementation, and stream handle
pub mod codec;
/// Symmetric ciphers algorithms
pub mod crypto;
mod dh_compat;
/// Error type
pub mod error;
/// Implementation of the handshake process
pub mod handshake;
/// Peer id
pub mod peer_id;
/// A little encapsulation of secp256k1
mod secp256k1_compat;
mod sha256_compat;
/// Supported algorithms
mod support;

/// Public key generated temporarily during the handshake
pub type EphemeralPublicKey = Vec<u8>;

/// Key pair of asymmetric encryption algorithm
#[derive(Clone, Debug)]
pub struct SecioKeyPair {
    inner: KeyPairInner,
}

impl SecioKeyPair {
    /// Generates a new random sec256k1 key pair.
    pub fn secp256k1_generated() -> SecioKeyPair {
        loop {
            let mut key = [0; crate::secp256k1_compat::SECRET_KEY_SIZE];
            rand::thread_rng().fill_bytes(&mut key);
            if let Ok(private) = crate::secp256k1_compat::secret_key_from_slice(&key) {
                return SecioKeyPair {
                    inner: KeyPairInner::Secp256k1 { private },
                };
            }
        }
    }

    /// Builds a `SecioKeyPair` from a raw secp256k1 32 bytes private key.
    pub fn secp256k1_raw_key<K>(key: K) -> Result<SecioKeyPair, error::SecioError>
    where
        K: AsRef<[u8]>,
    {
        let private = crate::secp256k1_compat::secret_key_from_slice(key.as_ref())
            .map_err(|_| error::SecioError::SecretGenerationFailed)?;

        Ok(SecioKeyPair {
            inner: KeyPairInner::Secp256k1 { private },
        })
    }

    /// Returns the public key corresponding to this key pair.
    pub fn public_key(&self) -> PublicKey {
        match self.inner {
            KeyPairInner::Secp256k1 { ref private } => {
                let pubkey = crate::secp256k1_compat::from_secret_key(private);
                PublicKey::Secp256k1(crate::secp256k1_compat::serialize_pubkey(&pubkey))
            }
        }
    }

    /// Generate Peer id
    pub fn peer_id(&self) -> PeerId {
        self.public_key().peer_id()
    }
}

#[derive(Clone, Debug)]
enum KeyPairInner {
    Secp256k1 {
        private: crate::secp256k1_compat::SecretKey,
    },
}

/// Possible digest algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Digest {
    /// Sha256 digest
    Sha256,
    /// Sha512 digest
    Sha512,
}

impl Digest {
    /// Returns the size in bytes of a digest of this kind.
    #[inline]
    pub fn num_bytes(self) -> usize {
        match self {
            Digest::Sha256 => 256 / 8,
            Digest::Sha512 => 512 / 8,
        }
    }
}
