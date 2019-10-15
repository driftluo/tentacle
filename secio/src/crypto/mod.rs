use bytes::BytesMut;
use openssl::symm;

use crate::error::SecioError;

/// Define cipher
pub mod cipher;
mod openssl_impl;
mod ring_impl;

/// Variant cipher which contains all possible stream ciphers
pub type BoxStreamCipher = Box<dyn StreamCipher + Send>;

/// Basic operation of Cipher, which is a Symmetric Cipher.
///
/// The `update` method could be called multiple times, and the `finalize` method will
/// encrypt the last block
pub trait StreamCipher {
    /// Feeds data from input through the cipher, writing encrypted/decrypted bytes into output.
    ///
    /// The number of bytes written to output is returned. Note that this may not be equal to the length of input.
    fn update(&mut self, data: &[u8], out: &mut BytesMut) -> Result<(), SecioError>;
    /// Finishes the encryption/decryption process, writing any remaining data to output.
    ///
    /// The number of bytes written to output is returned.
    ///
    /// update should not be called after this method.
    fn finalize(&mut self, out: &mut BytesMut) -> Result<(), SecioError>;
    /// Gets output buffer size based on data
    fn buffer_size(&self, data: &[u8]) -> usize;
}

/// Crypto mode, encrypt or decrypt
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum CryptoMode {
    /// Encrypt
    Encrypt,
    /// Decrypt
    Decrypt,
}

impl std::convert::From<CryptoMode> for symm::Mode {
    fn from(m: CryptoMode) -> symm::Mode {
        match m {
            CryptoMode::Encrypt => symm::Mode::Encrypt,
            CryptoMode::Decrypt => symm::Mode::Decrypt,
        }
    }
}

/// Generate a specific Cipher with key and initialize vector
pub fn new_stream(
    t: cipher::CipherType,
    key: &[u8],
    iv: &[u8],
    mode: CryptoMode,
) -> BoxStreamCipher {
    use cipher::CipherType::*;

    match t {
        Aes128Ctr | Aes256Ctr | Aes128Gcm | Aes256Gcm => {
            Box::new(openssl_impl::OpenSSLCrypt::new(t, key, iv, mode))
        }
        ChaCha20Poly1305 => Box::new(ring_impl::RingAeadCipher::new(t, key, mode)),
    }
}
