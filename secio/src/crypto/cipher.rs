use ring::aead;

/// Possible encryption ciphers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherType {
    /// Aes128Gcm
    Aes128Gcm,
    /// Aes256Gcm
    Aes256Gcm,
    /// ChaCha20Poly1305
    ChaCha20Poly1305,
}

impl CipherType {
    /// Returns the size of in bytes of the key expected by the cipher.
    pub fn key_size(self) -> usize {
        match self {
            CipherType::Aes128Gcm => aead::AES_128_GCM.key_len(),
            CipherType::Aes256Gcm => aead::AES_256_GCM.key_len(),
            CipherType::ChaCha20Poly1305 => aead::CHACHA20_POLY1305.key_len(),
        }
    }

    /// Returns the size of in bytes of the IV expected by the cipher.
    #[inline]
    pub fn iv_size(self) -> usize {
        match self {
            CipherType::Aes128Gcm => aead::AES_128_GCM.nonce_len(),
            CipherType::Aes256Gcm => aead::AES_256_GCM.nonce_len(),
            CipherType::ChaCha20Poly1305 => aead::CHACHA20_POLY1305.nonce_len(),
        }
    }

    /// Returns the size of in bytes of the tag expected by the cipher.
    #[inline]
    pub fn tag_size(self) -> usize {
        match self {
            CipherType::Aes128Gcm => aead::AES_128_GCM.tag_len(),
            CipherType::Aes256Gcm => aead::AES_256_GCM.tag_len(),
            CipherType::ChaCha20Poly1305 => aead::CHACHA20_POLY1305.tag_len(),
        }
    }
}
