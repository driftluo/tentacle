#![allow(dead_code)]

use crate::Digest;
use hmac::{self, Mac};
use sha2::{Sha256, Sha512};

/// Hash-based Message Authentication Code (HMAC).
#[derive(Debug, Clone)]
pub enum Hmac {
    /// sha256
    Sha256(Box<hmac::Hmac<Sha256>>),
    /// sha512
    Sha512(Box<hmac::Hmac<Sha512>>),
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
            Digest::Sha256 => Hmac::Sha256(Box::new(
                hmac::Hmac::new_from_slice(key).expect("Hmac::new_varkey accepts any key length"),
            )),
            Digest::Sha512 => Hmac::Sha512(Box::new(
                hmac::Hmac::new_from_slice(key).expect("Hmac::new_varkey accepts any key length"),
            )),
        }
    }

    /// Signs the data.
    pub fn sign(&self, crypted_data: &[u8]) -> Vec<u8> {
        match *self {
            Hmac::Sha256(ref hmac) => {
                let mut hmac = hmac.clone();
                hmac.update(crypted_data);
                hmac.finalize().into_bytes().to_vec()
            }
            Hmac::Sha512(ref hmac) => {
                let mut hmac = hmac.clone();
                hmac.update(crypted_data);
                hmac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// Verifies that the data matches the expected hash.
    pub fn verify(&self, crypted_data: &[u8], expected_hash: &[u8]) -> bool {
        match *self {
            Hmac::Sha256(ref hmac) => {
                let mut hmac = hmac.clone();
                hmac.update(crypted_data);
                hmac.verify_slice(expected_hash).is_ok()
            }
            Hmac::Sha512(ref hmac) => {
                let mut hmac = hmac.clone();
                hmac.update(crypted_data);
                hmac.verify_slice(expected_hash).is_ok()
            }
        }
    }

    /// Return a multi-step hmac context
    pub fn context(&self) -> Context {
        match self {
            Hmac::Sha256(ref hmac) => Context::Sha256(hmac.clone()),
            Hmac::Sha512(ref hmac) => Context::Sha512(hmac.clone()),
        }
    }
}

pub enum Context {
    Sha256(Box<hmac::Hmac<Sha256>>),
    Sha512(Box<hmac::Hmac<Sha512>>),
}

impl Context {
    pub fn update(&mut self, data: &[u8]) {
        match *self {
            Context::Sha256(ref mut hmac) => {
                hmac.update(data);
            }
            Context::Sha512(ref mut hmac) => {
                hmac.update(data);
            }
        }
    }

    pub fn sign(self) -> Vec<u8> {
        match self {
            Context::Sha256(hmac) => hmac.finalize().into_bytes().to_vec(),
            Context::Sha512(hmac) => hmac.finalize().into_bytes().to_vec(),
        }
    }
}
