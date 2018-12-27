use secp256k1::key::SecretKey;

pub mod codec;
pub mod error;
pub mod exchange;
pub mod handshake;
pub mod stream_cipher;
pub mod support;

#[derive(Clone)]
pub struct SecioKeyPair {
    inner: SecretKey,
}

impl SecioKeyPair {
    /// Generates a new random sec256k1 key pair.
    pub fn secp256k1_generated() -> SecioKeyPair {
        use rand::Rng;
        let mut random_slice = [0u8; secp256k1::constants::SECRET_KEY_SIZE];
        rand::thread_rng().fill(&mut random_slice[..]);
        let private = SecretKey::from_slice(&random_slice).expect("slice has the right size");
        SecioKeyPair { inner: private }
    }

    /// Builds a `SecioKeyPair` from a raw secp256k1 32 bytes private key.
    pub fn secp256k1_raw_key<K>(key: K) -> SecioKeyPair
    where
        K: AsRef<[u8]>,
    {
        let private =
            secp256k1::key::SecretKey::from_slice(key.as_ref()).expect("slice has the right size");

        SecioKeyPair { inner: private }
    }

    /// Returns the public key corresponding to this key pair.
    pub fn to_public_key(&self) -> Vec<u8> {
        let secp = secp256k1::Secp256k1::signing_only();
        let pubkey = secp256k1::key::PublicKey::from_secret_key(&secp, &self.inner);
        pubkey.serialize().to_vec()
    }
}

/// Possible digest algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Digest {
    Sha256,
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
