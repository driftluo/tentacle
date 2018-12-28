pub mod secure_stream;
pub mod stream_handle;

use aes_ctr::stream_cipher::StreamCipher as AES_StreamCipher;
use hmac::{self, Mac};
use sha2::{Sha256, Sha512};

use crate::Digest;

pub type StreamCipher = Box<dyn AES_StreamCipher + Send>;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Hmac {
    Sha256(hmac::Hmac<Sha256>),
    Sha512(hmac::Hmac<Sha512>),
}

impl Hmac {
    /// Returns the size of the hash in bytes.
    #[inline]
    pub fn num_bytes(&self) -> usize {
        match *self {
            Hmac::Sha256(_) => 32,
            Hmac::Sha512(_) => 64,
        }
    }

    /// Builds a `Hmac` from an algorithm and key.
    pub fn from_key(algorithm: Digest, key: &[u8]) -> Self {
        match algorithm {
            Digest::Sha256 => {
                Hmac::Sha256(Mac::new_varkey(key).expect("Hmac::new_varkey accepts any key length"))
            }
            Digest::Sha512 => {
                Hmac::Sha512(Mac::new_varkey(key).expect("Hmac::new_varkey accepts any key length"))
            }
        }
    }

    /// Signs the data.
    pub fn sign(&mut self, crypted_data: &[u8]) -> Vec<u8> {
        match *self {
            Hmac::Sha256(ref hmac) => {
                let mut mac = hmac.clone();
                mac.input(crypted_data);
                mac.result().code().to_vec()
            }
            Hmac::Sha512(ref hmac) => {
                let mut mac = hmac.clone();
                mac.input(crypted_data);
                mac.result().code().to_vec()
            }
        }
    }

    /// Verifies that the data matches the expected hash.
    pub fn verify(&mut self, crypted_data: &[u8], expected_hash: &[u8]) -> bool {
        match *self {
            Hmac::Sha256(ref hmac) => {
                let mut mac = hmac.clone();
                mac.input(crypted_data);
                mac.verify(expected_hash).is_ok()
            }
            Hmac::Sha512(ref hmac) => {
                let mut mac = hmac.clone();
                mac.input(crypted_data);
                mac.verify(expected_hash).is_ok()
            }
        }
    }
}
