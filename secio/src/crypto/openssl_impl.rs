use bytes::{Bytes, BytesMut};
use openssl::symm;

use crate::{
    crypto::{cipher::CipherType, nonce_advance, StreamCipher},
    error::SecioError,
};

pub(crate) struct OpenSsLCrypt {
    cipher: symm::Cipher,
    cipher_type: CipherType,
    key: Bytes,
    iv: BytesMut,
}

impl OpenSsLCrypt {
    pub fn new(cipher_type: CipherType, key: &[u8]) -> Self {
        let cipher = match cipher_type {
            CipherType::Aes128Gcm => symm::Cipher::aes_128_gcm(),
            CipherType::Aes256Gcm => symm::Cipher::aes_256_gcm(),
            #[cfg(any(ossl110))]
            CipherType::ChaCha20Poly1305 => symm::Cipher::chacha20_poly1305(),
            #[cfg(not(ossl110))]
            _ => panic!(
                "Cipher type {:?} does not supported by OpenSsLCrypt yet",
                cipher_type
            ),
        };

        // aead use self-increase iv
        let nonce_size = cipher_type.iv_size();
        let nonce = BytesMut::from(vec![0u8; nonce_size].as_slice());

        OpenSsLCrypt {
            cipher,
            cipher_type,
            key: Bytes::from(key.to_owned()),
            iv: nonce,
        }
    }

    /// Encrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len() + tag.len()`.
    /// ```plain
    /// +----------------------------------------+-----------------------+
    /// | ENCRYPTED TEXT (length = input.len())  | TAG                   |
    /// +----------------------------------------+-----------------------+
    /// ```
    pub fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        nonce_advance(self.iv.as_mut());
        let tag_size = self.cipher_type.tag_size();
        let mut tag = vec![0; tag_size];
        let mut output =
            symm::encrypt_aead(self.cipher, &self.key, Some(&self.iv), &[], input, &mut tag)?;
        output.append(&mut tag);
        Ok(output)
    }

    /// Decrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len() - tag.len()`.
    /// ```plain
    /// +----------------------------------------+-----------------------+
    /// | ENCRYPTED TEXT (length = output.len()) | TAG                   |
    /// +----------------------------------------+-----------------------+
    /// ```
    pub fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        nonce_advance(self.iv.as_mut());
        let crypt_data_len = input
            .len()
            .checked_sub(self.cipher_type.tag_size())
            .ok_or(SecioError::FrameTooShort)?;
        openssl::symm::decrypt_aead(
            self.cipher,
            &self.key,
            Some(&self.iv),
            &[],
            &input[..crypt_data_len],
            &input[crypt_data_len..],
        )
        .map_err(Into::into)
    }
}

impl StreamCipher for OpenSsLCrypt {
    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        self.encrypt(input)
    }

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        self.decrypt(input)
    }
}

#[cfg(test)]
mod test {
    use super::{CipherType, OpenSsLCrypt};
    use proptest::prelude::*;

    fn test_openssl(mode: CipherType, message: &[u8]) {
        let key = (0..mode.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let mut encryptor = OpenSsLCrypt::new(mode, &key[0..]);
        let mut decryptor = OpenSsLCrypt::new(mode, &key[0..]);

        let encrypted_msg = encryptor.encrypt(message).unwrap();
        let decrypted_msg = decryptor.decrypt(&encrypted_msg[..]).unwrap();

        assert_eq!(message, &decrypted_msg[..]);

        let encrypted_msg = encryptor.encrypt(message).unwrap();
        let decrypted_msg = decryptor.decrypt(&encrypted_msg[..]).unwrap();

        assert_eq!(message, &decrypted_msg[..]);
    }

    proptest! {
        #[test]
        fn test_aes_128_gcm(message: Vec<u8>) {
            test_openssl(CipherType::Aes128Gcm, &message)
        }

        #[test]
        fn test_aes_256_gcm(message: Vec<u8>) {
            test_openssl(CipherType::Aes256Gcm, &message)
        }

        #[cfg(any(ossl110))]
        #[test]
        fn test_chacha20_poly1305(message: Vec<u8>) {
            test_openssl(CipherType::ChaCha20Poly1305, &message)
        }
    }
}
