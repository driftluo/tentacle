use bytes::BytesMut;
use openssl::symm;

use crate::{
    crypto::{cipher::CipherType, CryptoMode, StreamCipher},
    error::SecioError,
};

pub(crate) struct OpenSSLCrypt {
    cipher: symm::Cipher,
    inner: symm::Crypter,
}

impl OpenSSLCrypt {
    pub fn new(cipher_type: CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> Self {
        let cipher = match cipher_type {
            CipherType::Aes128Ctr => symm::Cipher::aes_128_ctr(),
            CipherType::Aes256Ctr => symm::Cipher::aes_256_ctr(),
            CipherType::Aes128Gcm => symm::Cipher::aes_128_gcm(),
            CipherType::Aes256Gcm => symm::Cipher::aes_256_gcm(),
            _ => panic!(
                "Cipher type {:?} does not supported by OpenSSLCrypt yet",
                cipher_type
            ),
        };
        // Panic if error occurs
        let cypter = symm::Crypter::new(cipher, From::from(mode), key, Some(iv)).unwrap();
        OpenSSLCrypt {
            cipher,
            inner: cypter,
        }
    }

    pub fn update(&mut self, data: &[u8], out: &mut BytesMut) -> Result<(), SecioError> {
        let least_reserved = data.len() + self.cipher.block_size();
        let mut buf = BytesMut::with_capacity(least_reserved); // NOTE: len() is 0 now!
        unsafe {
            buf.set_len(least_reserved);
        }
        let length = self.inner.update(data, &mut *buf)?;
        buf.truncate(length);
        out.unsplit(buf);
        Ok(())
    }

    /// Generate the final block
    pub fn finalize(&mut self, out: &mut BytesMut) -> Result<(), SecioError> {
        let least_reserved = self.cipher.block_size();
        let mut buf = BytesMut::with_capacity(least_reserved); // NOTE: len() is 0 now!
        unsafe {
            buf.set_len(least_reserved);
        }

        let length = self.inner.finalize(&mut *buf)?;
        buf.truncate(length);
        out.unsplit(buf);
        Ok(())
    }

    /// Gets output buffer size based on data
    pub fn buffer_size(&self, data: &[u8]) -> usize {
        self.cipher.block_size() + data.len()
    }
}

impl StreamCipher for OpenSSLCrypt {
    fn update(&mut self, data: &[u8], out: &mut BytesMut) -> Result<(), SecioError> {
        self.update(data, out)
    }

    fn finalize(&mut self, out: &mut BytesMut) -> Result<(), SecioError> {
        self.finalize(out)
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        self.buffer_size(data)
    }
}

#[cfg(test)]
mod test {
    use super::{BytesMut, CipherType, CryptoMode, OpenSSLCrypt};
    use rand;

    fn test_openssl(mode: CipherType) {
        let key = (0..mode.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();
        let iv = (0..mode.iv_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let mut encryptor = OpenSSLCrypt::new(mode, &key[0..], &iv[0..], CryptoMode::Encrypt);
        let mut decryptor = OpenSSLCrypt::new(mode, &key[0..], &iv[0..], CryptoMode::Decrypt);

        // first time
        let message = b"HELLO WORLD";

        let mut encrypted_msg = BytesMut::new();
        encryptor.update(message, &mut encrypted_msg).unwrap();
        let mut decrypted_msg = BytesMut::new();
        decryptor
            .update(&encrypted_msg[..], &mut decrypted_msg)
            .unwrap();

        assert_eq!(message, &decrypted_msg[..]);

        // second time
        let message = b"hello, world";

        let mut encrypted_msg = BytesMut::new();
        encryptor.update(message, &mut encrypted_msg).unwrap();
        let mut decrypted_msg = BytesMut::new();
        decryptor
            .update(&encrypted_msg[..], &mut decrypted_msg)
            .unwrap();

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
}
