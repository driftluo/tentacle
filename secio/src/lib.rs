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
                PublicKey {
                    key: crate::secp256k1_compat::serialize_pubkey(&pubkey),
                }
            }
        }
    }

    /// Generate Peer id
    pub fn peer_id(&self) -> PeerId {
        self.public_key().peer_id()
    }
}

#[derive(Clone)]
enum KeyPairInner {
    Secp256k1 {
        private: crate::secp256k1_compat::SecretKey,
    },
}

impl std::fmt::Debug for KeyPairInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair").finish()
    }
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

/// KeyProvider on ecdh procedure
#[cfg_attr(all(target_arch = "wasm32", feature = "async-trait"), async_trait::async_trait(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), feature = "async-trait"),
    async_trait::async_trait
)]
pub trait KeyProvider: std::clone::Clone + Send + Sync + 'static {
    /// Error
    type Error: Into<crate::error::SecioError>;

    /// Constructs a signature for `msg` using the secret key `sk`
    #[cfg(feature = "async-trait")]
    async fn sign_ecdsa_async<T: AsRef<[u8]> + Send>(
        &self,
        message: T,
    ) -> Result<Vec<u8>, Self::Error> {
        self.sign_ecdsa(message)
    }

    /// Constructs a signature for `msg` using the secret key `sk`
    fn sign_ecdsa<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, Self::Error>;

    /// Creates a new public key from the [`KeyProvider`].
    fn pubkey(&self) -> Vec<u8>;

    /// Checks that `sig` is a valid ECDSA signature for `msg` using the pubkey.
    fn verify_ecdsa<P, T, F>(pubkey: P, message: T, signature: F) -> bool
    where
        P: AsRef<[u8]>,
        T: AsRef<[u8]>,
        F: AsRef<[u8]>;
}

impl KeyProvider for SecioKeyPair {
    type Error = error::SecioError;

    fn sign_ecdsa<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, Self::Error> {
        let msg = match crate::secp256k1_compat::message_from_slice(message.as_ref()) {
            Ok(m) => m,
            Err(_) => {
                log::debug!("message has wrong format");
                return Err(error::SecioError::InvalidMessage);
            }
        };
        let signature = match self.inner {
            KeyPairInner::Secp256k1 { ref private } => crate::secp256k1_compat::sign(&msg, private),
        };

        Ok(crate::secp256k1_compat::signature_to_vec(signature))
    }

    fn pubkey(&self) -> Vec<u8> {
        match self.inner {
            KeyPairInner::Secp256k1 { ref private } => crate::secp256k1_compat::serialize_pubkey(
                &crate::secp256k1_compat::from_secret_key(private),
            ),
        }
    }

    fn verify_ecdsa<P, T, F>(pubkey: P, message: T, signature: F) -> bool
    where
        P: AsRef<[u8]>,
        T: AsRef<[u8]>,
        F: AsRef<[u8]>,
    {
        let signature = crate::secp256k1_compat::signature_from_der(signature.as_ref());
        let msg = crate::secp256k1_compat::message_from_slice(message.as_ref());
        let pubkey = crate::secp256k1_compat::pubkey_from_slice(pubkey.as_ref());

        if let (Ok(signature), Ok(message), Ok(pubkey)) = (signature, msg, pubkey) {
            if !crate::secp256k1_compat::verify(&message, &signature, &pubkey) {
                log::debug!("failed to verify the remote's signature");
                return false;
            }
        } else {
            log::debug!("remote's secp256k1 signature has wrong format");
            return false;
        }
        true
    }
}
/// Empty key provider
#[derive(Debug, Clone)]
pub struct NoopKeyProvider;

impl KeyProvider for NoopKeyProvider {
    type Error = error::SecioError;

    fn sign_ecdsa<T: AsRef<[u8]>>(&self, _message: T) -> Result<Vec<u8>, Self::Error> {
        Err(error::SecioError::NotSupportKeyProvider)
    }

    fn pubkey(&self) -> Vec<u8> {
        Vec::new()
    }

    fn verify_ecdsa<P, T, F>(_pubkey: P, _message: T, _signature: F) -> bool
    where
        P: AsRef<[u8]>,
        T: AsRef<[u8]>,
        F: AsRef<[u8]>,
    {
        false
    }
}
