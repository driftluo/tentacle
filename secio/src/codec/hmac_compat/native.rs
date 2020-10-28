use crate::Digest;

/// Hash-based Message Authentication Code (HMAC).
#[derive(Debug, Clone)]
pub struct Hmac(ring::hmac::Key);

impl Hmac {
    /// Returns the size of the hash in bytes.
    #[inline]
    pub fn num_bytes(&self) -> usize {
        self.0.algorithm().digest_algorithm().output_len
    }

    /// Builds a `Hmac` from an algorithm and key.
    pub fn from_key(algorithm: Digest, key: &[u8]) -> Self {
        match algorithm {
            Digest::Sha256 => Hmac(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key)),
            Digest::Sha512 => Hmac(ring::hmac::Key::new(ring::hmac::HMAC_SHA512, key)),
        }
    }

    /// Signs the data.
    pub fn sign(&mut self, crypted_data: &[u8]) -> ring::hmac::Tag {
        ring::hmac::sign(&self.0, crypted_data)
    }

    /// Verifies that the data matches the expected hash.
    pub fn verify(&mut self, crypted_data: &[u8], expected_hash: &[u8]) -> bool {
        ring::hmac::verify(&self.0, crypted_data, expected_hash).is_ok()
    }

    /// Return a multi-step hmac context
    pub fn context(&self) -> ring::hmac::Context {
        ring::hmac::Context::with_key(&self.0)
    }
}
