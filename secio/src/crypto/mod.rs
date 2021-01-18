use crate::error::SecioError;

/// Define cipher
pub mod cipher;
#[cfg(unix)]
mod openssl_impl;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(any(not(ossl110), test, not(unix)))]
mod ring_impl;
#[cfg(any(target_arch = "wasm32", test))]
mod wasm_compat;

/// Variant cipher which contains all possible stream ciphers
#[doc(hidden)]
pub type BoxStreamCipher = Box<dyn StreamCipher + Send>;

/// Basic operation of Cipher, which is a Symmetric Cipher.
#[doc(hidden)]
pub trait StreamCipher {
    /// Feeds data from input through the cipher, return encrypted bytes.
    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError>;
    /// Feeds data from input through the cipher, return decrypted bytes.
    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError>;
    /// Whether support in place decrypt
    #[inline]
    fn is_in_place(&self) -> bool {
        false
    }
    /// Feeds data from input through the cipher, in place decrypted.
    fn decrypt_in_place(&mut self, _input: &mut bytes::BytesMut) -> Result<(), SecioError> {
        Err(SecioError::InvalidProposition(
            "don't support in place decrypted",
        ))
    }
}

/// Crypto mode, encrypt or decrypt
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[doc(hidden)]
pub enum CryptoMode {
    /// Encrypt
    Encrypt,
    /// Decrypt
    Decrypt,
}

/// Generate a specific Cipher with key and initialize vector
#[doc(hidden)]
#[cfg(all(ossl110, unix))]
pub fn new_stream(t: cipher::CipherType, key: &[u8], _mode: CryptoMode) -> BoxStreamCipher {
    Box::new(openssl_impl::OpenSSLCrypt::new(t, key))
}

/// Generate a specific Cipher with key and initialize vector
#[doc(hidden)]
#[cfg(all(not(ossl110), unix))]
pub fn new_stream(t: cipher::CipherType, key: &[u8], mode: CryptoMode) -> BoxStreamCipher {
    use cipher::CipherType::*;

    match t {
        Aes128Gcm | Aes256Gcm => Box::new(openssl_impl::OpenSSLCrypt::new(t, key)),
        ChaCha20Poly1305 => Box::new(ring_impl::RingAeadCipher::new(t, key, mode)),
    }
}

/// Generate a specific Cipher with key and initialize vector
#[doc(hidden)]
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(unix))]
pub fn new_stream(t: cipher::CipherType, key: &[u8], mode: CryptoMode) -> BoxStreamCipher {
    Box::new(ring_impl::RingAeadCipher::new(t, key, mode))
}

/// Generate a specific Cipher with key and initialize vector
#[doc(hidden)]
#[cfg(target_arch = "wasm32")]
pub fn new_stream(t: cipher::CipherType, key: &[u8], _mode: CryptoMode) -> BoxStreamCipher {
    Box::new(wasm_compat::WasmCrypt::new(t, key))
}

/// [0, 0, 0, 0]
/// [1, 0, 0, 0]
/// ...
/// [255, 0, 0, 0]
/// [0, 1, 0, 0]
/// [1, 1, 0, 0]
/// ...
fn nonce_advance(nonce: &mut [u8]) {
    for i in nonce {
        if std::u8::MAX == *i {
            *i = 0;
        } else {
            *i += 1;
            return;
        }
    }
}

#[cfg(all(test, unix))]
mod test {
    use super::{
        cipher::CipherType, openssl_impl::OpenSSLCrypt, ring_impl::RingAeadCipher,
        wasm_compat::WasmCrypt, CryptoMode,
    };

    fn test_openssl_encrypt_ring_decrypt(cipher: CipherType) {
        let key = (0..cipher.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let mut openssl_encrypt = OpenSSLCrypt::new(cipher, &key);
        let mut ring_decrypt = RingAeadCipher::new(cipher, &key, CryptoMode::Decrypt);

        // first time
        let message = b"HELLO WORLD";

        let encrypted_msg = openssl_encrypt.encrypt(message).unwrap();
        let decrypted_msg = ring_decrypt.decrypt(&encrypted_msg).unwrap();

        assert_eq!(message, &decrypted_msg[..]);

        // second time
        let message = b"hello, world";

        let encrypted_msg = openssl_encrypt.encrypt(message).unwrap();
        let decrypted_msg = ring_decrypt.decrypt(&encrypted_msg).unwrap();

        assert_eq!(message, &decrypted_msg[..]);
    }

    fn test_ring_encrypt_openssl_decrypt(cipher: CipherType) {
        let key = (0..cipher.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let mut ring_encrypt = RingAeadCipher::new(cipher, &key, CryptoMode::Encrypt);
        let mut openssl_decrypt = OpenSSLCrypt::new(cipher, &key);

        // first time
        let message = b"HELLO WORLD";

        let encrypted_msg = ring_encrypt.encrypt(message).unwrap();
        let decrypted_msg = openssl_decrypt.decrypt(&encrypted_msg).unwrap();

        assert_eq!(message, &decrypted_msg[..]);

        // second time
        let message = b"hello, world";

        let encrypted_msg = ring_encrypt.encrypt(message).unwrap();
        let decrypted_msg = openssl_decrypt.decrypt(&encrypted_msg).unwrap();

        assert_eq!(message, &decrypted_msg[..]);
    }

    fn test_ring_encrypt_wasm_decrypt(cipher: CipherType) {
        let key = (0..cipher.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let mut ring_encrypt = RingAeadCipher::new(cipher, &key, CryptoMode::Encrypt);
        let mut wasm_decrypt = WasmCrypt::new(cipher, &key);

        // first time
        let message = b"HELLO WORLD";

        let encrypted_msg = ring_encrypt.encrypt(message).unwrap();
        let decrypted_msg = wasm_decrypt.decrypt(&encrypted_msg).unwrap();

        assert_eq!(message, &decrypted_msg[..]);

        // second time
        let message = b"hello, world";

        let encrypted_msg = ring_encrypt.encrypt(message).unwrap();
        let decrypted_msg = wasm_decrypt.decrypt(&encrypted_msg).unwrap();

        assert_eq!(message, &decrypted_msg[..]);
    }

    fn test_wasm_encrypt_openssl_decrypt(cipher: CipherType) {
        let key = (0..cipher.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let mut wasm_encrypt = WasmCrypt::new(cipher, &key);
        let mut openssl_decrypt = OpenSSLCrypt::new(cipher, &key);

        // first time
        let message = b"HELLO WORLD";

        let encrypted_msg = wasm_encrypt.encrypt(message).unwrap();
        let decrypted_msg = openssl_decrypt.decrypt(&encrypted_msg).unwrap();

        assert_eq!(message, &decrypted_msg[..]);

        // second time
        let message = b"hello, world";

        let encrypted_msg = wasm_encrypt.encrypt(message).unwrap();
        let decrypted_msg = openssl_decrypt.decrypt(&encrypted_msg).unwrap();

        assert_eq!(message, &decrypted_msg[..]);
    }

    #[test]
    fn test_aes_128_gcm() {
        test_ring_encrypt_openssl_decrypt(CipherType::Aes128Gcm);
        test_openssl_encrypt_ring_decrypt(CipherType::Aes128Gcm)
    }

    #[test]
    fn test_aes_256_gcm() {
        test_ring_encrypt_openssl_decrypt(CipherType::Aes256Gcm);
        test_openssl_encrypt_ring_decrypt(CipherType::Aes256Gcm)
    }

    #[cfg(any(ossl110))]
    #[test]
    fn test_chacha20_poly1305() {
        test_ring_encrypt_openssl_decrypt(CipherType::ChaCha20Poly1305);
        test_openssl_encrypt_ring_decrypt(CipherType::ChaCha20Poly1305);
        test_ring_encrypt_wasm_decrypt(CipherType::ChaCha20Poly1305);
        test_wasm_encrypt_openssl_decrypt(CipherType::ChaCha20Poly1305)
    }
}
