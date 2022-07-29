use openssl::{
    hash::MessageDigest,
    memcmp,
    pkey::{PKey, Private},
    sign::Signer,
};

use crate::Digest;

/// Hash-based Message Authentication Code (HMAC).
pub struct Hmac {
    digest: MessageDigest,
    key: PKey<Private>,
}

impl Hmac {
    /// Returns the size of the hash in bytes.
    #[inline]
    pub fn num_bytes(&self) -> usize {
        self.digest.size()
    }

    /// Builds a `Hmac` from an algorithm and key.
    pub fn from_key(algorithm: Digest, key: &[u8]) -> Self {
        let digest = match algorithm {
            Digest::Sha256 => MessageDigest::sha256(),
            Digest::Sha512 => MessageDigest::sha512(),
        };

        let key = PKey::hmac(key).expect("init openssl hmac ctx fail");
        Hmac { digest, key }
    }

    /// Signs the data.
    pub fn sign(&mut self, crypted_data: &[u8]) -> Vec<u8> {
        let mut sign = Signer::new(self.digest, &self.key).expect("init openssl signer ctx fail");
        sign.update(crypted_data).expect("openssl hmac update fail");
        sign.sign_to_vec().expect("hmac sign oneshot fail")
    }

    /// Verifies that the data matches the expected hash.
    pub fn verify(&mut self, crypted_data: &[u8], expected_hash: &[u8]) -> bool {
        let n = self.sign(crypted_data);
        if n.len() != expected_hash.len() {
            return false;
        }
        memcmp::eq(&n, expected_hash)
    }

    /// Return a multi-step hmac context
    pub fn context(&self) -> Context<'_> {
        Context(Signer::new(self.digest, &self.key).expect("init openssl signer ctx fail"))
    }
}

pub struct Context<'a>(Signer<'a>);

impl<'a> Context<'a> {
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("openssl hmac update fail")
    }

    pub fn sign(self) -> Vec<u8> {
        self.0.sign_to_vec().expect("hmac sign oneshot fail")
    }
}
