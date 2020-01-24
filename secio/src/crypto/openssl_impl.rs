use bytes::{Bytes, BytesMut};
use openssl::symm;

use crate::{
    crypto::{cipher::CipherType, nonce_advance, StreamCipher},
    error::SecioError,
};

pub(crate) struct OpenSSLCrypt {
    cipher: symm::Cipher,
    cipher_type: CipherType,
    key: Bytes,
    iv: BytesMut,
    aead: bool,
}

impl OpenSSLCrypt {
    pub fn new(cipher_type: CipherType, key: &[u8], iv: &[u8]) -> Self {
        let (cipher, aead) = match cipher_type {
            CipherType::Aes128Ctr => (symm::Cipher::aes_128_ctr(), false),
            CipherType::Aes256Ctr => (symm::Cipher::aes_256_ctr(), false),
            CipherType::Aes128Gcm => (symm::Cipher::aes_128_gcm(), true),
            CipherType::Aes256Gcm => (symm::Cipher::aes_256_gcm(), true),
            #[cfg(any(ossl110))]
            CipherType::ChaCha20Poly1305 => (symm::Cipher::chacha20_poly1305(), true),
            #[cfg(not(ossl110))]
            _ => panic!(
                "Cipher type {:?} does not supported by OpenSSLCrypt yet",
                cipher_type
            ),
        };

        // aead use self-increase iv, ctr use fixed iv
        let iv = if aead {
            let nonce_size = cipher_type.iv_size();
            let mut nonce = BytesMut::with_capacity(nonce_size);
            unsafe {
                nonce.set_len(nonce_size);
                ::std::ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_size);
            }
            nonce
        } else {
            BytesMut::from(iv)
        };

        OpenSSLCrypt {
            cipher,
            cipher_type,
            key: Bytes::from(key.to_owned()),
            iv,
            aead,
        }
    }

    /// Encrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len() + tag.len()`.
    /// ```plain
    /// +----------------------------------------+-----------------------+
    /// | ENCRYPTED TEXT (length = input.len())  | TAG                   |
    /// +----------------------------------------+-----------------------+
    /// ```
    pub fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        if self.aead {
            nonce_advance(self.iv.as_mut());
            let tag_size = self.cipher_type.tag_size();
            let mut tag = Vec::with_capacity(tag_size);
            unsafe {
                tag.set_len(tag_size);
            }
            let mut output =
                symm::encrypt_aead(self.cipher, &self.key, Some(&self.iv), &[], input, &mut tag)?;
            output.append(&mut tag);
            Ok(output)
        } else {
            symm::encrypt(self.cipher, &self.key, Some(&self.iv), input).map_err(Into::into)
        }
    }

    /// Decrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len() - tag.len()`.
    /// ```plain
    /// +----------------------------------------+-----------------------+
    /// | ENCRYPTED TEXT (length = output.len()) | TAG                   |
    /// +----------------------------------------+-----------------------+
    /// ```
    pub fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        if self.aead {
            nonce_advance(self.iv.as_mut());
            let crypt_data_len = input.len() - self.cipher_type.tag_size();
            openssl::symm::decrypt_aead(
                self.cipher,
                &self.key,
                Some(&self.iv),
                &[],
                &input[..crypt_data_len],
                &input[crypt_data_len..],
            )
            .map_err(Into::into)
        } else {
            symm::decrypt(self.cipher, &self.key, Some(&self.iv), input).map_err(Into::into)
        }
    }
}

impl StreamCipher for OpenSSLCrypt {
    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        self.encrypt(input)
    }

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        self.decrypt(input)
    }
}

#[cfg(test)]
mod test {
    use super::{CipherType, OpenSSLCrypt};
    use rand;

    fn test_openssl(mode: CipherType) {
        let key = (0..mode.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();
        let iv = (0..mode.iv_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let mut encryptor = OpenSSLCrypt::new(mode, &key[0..], &iv[0..]);
        let mut decryptor = OpenSSLCrypt::new(mode, &key[0..], &iv[0..]);

        // first time
        let message = b"HELLO WORLD";

        let encrypted_msg = encryptor.encrypt(message).unwrap();
        let decrypted_msg = decryptor.decrypt(&encrypted_msg[..]).unwrap();

        assert_eq!(message, &decrypted_msg[..]);

        // second time
        let message = b"hello, world";

        let encrypted_msg = encryptor.encrypt(message).unwrap();
        let decrypted_msg = decryptor.decrypt(&encrypted_msg[..]).unwrap();

        assert_eq!(message, &decrypted_msg[..]);
    }

    #[test]
    fn test_aes_128_ctr() {
        test_openssl(CipherType::Aes128Ctr)
    }

    #[test]
    fn test_aes_256_ctr() {
        test_openssl(CipherType::Aes256Ctr)
    }

    #[test]
    fn test_aes_128_gcm() {
        test_openssl(CipherType::Aes128Gcm)
    }

    #[test]
    fn test_aes_256_gcm() {
        test_openssl(CipherType::Aes256Gcm)
    }

    #[cfg(any(ossl110))]
    #[test]
    fn test_chacha20_poly1305() {
        test_openssl(CipherType::ChaCha20Poly1305)
    }
}
