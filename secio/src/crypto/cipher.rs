use openssl::symm::Cipher as OpensslCipher;
use ring::aead;

/// Possible encryption ciphers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherType {
    /// Aes128Ctr
    Aes128Ctr,
    /// Aes256Ctr
    Aes256Ctr,
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
            CipherType::Aes128Ctr => OpensslCipher::aes_128_ctr().key_len(),
            CipherType::Aes256Ctr => OpensslCipher::aes_256_ctr().key_len(),
            CipherType::Aes128Gcm => OpensslCipher::aes_128_gcm().key_len(),
            CipherType::Aes256Gcm => OpensslCipher::aes_256_gcm().key_len(),
            CipherType::ChaCha20Poly1305 => aead::CHACHA20_POLY1305.key_len(),
        }
    }

    /// Returns the size of in bytes of the IV expected by the cipher.
    #[inline]
    pub fn iv_size(self) -> usize {
        match self {
            CipherType::Aes128Ctr => OpensslCipher::aes_128_ctr().iv_len().unwrap_or_default(),
            CipherType::Aes256Ctr => OpensslCipher::aes_256_ctr().iv_len().unwrap_or_default(),
            CipherType::Aes128Gcm => OpensslCipher::aes_128_gcm().iv_len().unwrap_or_default(),
            CipherType::Aes256Gcm => OpensslCipher::aes_256_gcm().iv_len().unwrap_or_default(),
            CipherType::ChaCha20Poly1305 => aead::CHACHA20_POLY1305.nonce_len(),
        }
    }
}
