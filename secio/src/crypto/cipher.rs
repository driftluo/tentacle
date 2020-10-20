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
    pub const fn key_size(self) -> usize {
        match self {
            CipherType::Aes128Gcm => 16,
            CipherType::Aes256Gcm => 32,
            CipherType::ChaCha20Poly1305 => 2 * 16,
        }
    }

    /// Returns the size of in bytes of the IV expected by the cipher.
    #[inline]
    pub const fn iv_size(self) -> usize {
        match self {
            CipherType::Aes128Gcm => 96 / 8,
            CipherType::Aes256Gcm => 96 / 8,
            CipherType::ChaCha20Poly1305 => 96 / 8,
        }
    }

    /// Returns the size of in bytes of the tag expected by the cipher.
    #[inline]
    pub const fn tag_size(self) -> usize {
        match self {
            CipherType::Aes128Gcm => 16,
            CipherType::Aes256Gcm => 16,
            CipherType::ChaCha20Poly1305 => 16,
        }
    }
}
