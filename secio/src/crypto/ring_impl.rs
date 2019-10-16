use bytes::{BufMut, BytesMut};
use ring::{
    aead::{
        Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_128_GCM,
        AES_256_GCM, CHACHA20_POLY1305,
    },
    error::Unspecified,
};

use std::ptr;

use crate::{
    crypto::{cipher::CipherType, nonce_advance, CryptoMode, StreamCipher},
    error::SecioError,
};

struct RingNonce(BytesMut);

impl NonceSequence for RingNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        nonce_advance(self.0.as_mut());
        Nonce::try_assume_unique_for_key(&self.0)
    }
}

enum RingAeadCryptoVariant {
    Seal(SealingKey<RingNonce>),
    Open(OpeningKey<RingNonce>),
}

pub(crate) struct RingAeadCipher {
    cipher: RingAeadCryptoVariant,
    cipher_type: CipherType,
}

impl RingAeadCipher {
    pub fn new(cipher_type: CipherType, key: &[u8], mode: CryptoMode) -> Self {
        let nonce_size = cipher_type.iv_size();
        let mut nonce = BytesMut::with_capacity(nonce_size);
        unsafe {
            nonce.set_len(nonce_size);
            ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_size);
        }

        let algorithm = match cipher_type {
            CipherType::Aes128Gcm => &AES_128_GCM,
            CipherType::Aes256Gcm => &AES_256_GCM,
            CipherType::ChaCha20Poly1305 => &CHACHA20_POLY1305,
            _ => panic!(
                "Cipher type {:?} does not supported by RingAead yet",
                cipher_type
            ),
        };

        let cipher = match mode {
            CryptoMode::Encrypt => RingAeadCryptoVariant::Seal(SealingKey::new(
                UnboundKey::new(algorithm, key).unwrap(),
                RingNonce(nonce),
            )),
            CryptoMode::Decrypt => RingAeadCryptoVariant::Open(OpeningKey::new(
                UnboundKey::new(algorithm, key).unwrap(),
                RingNonce(nonce),
            )),
        };
        RingAeadCipher {
            cipher,
            cipher_type,
        }
    }

    /// Encrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len() + tag.len()`.
    /// ```plain
    /// +----------------------------------------+-----------------------+
    /// | ENCRYPTED TEXT (length = input.len())  | TAG                   |
    /// +----------------------------------------+-----------------------+
    /// ```
    pub fn encrypt(&mut self, input: &[u8], output: &mut BytesMut) {
        output.reserve(input.len() + self.cipher_type.tag_size());
        unsafe {
            output.set_len(input.len() + self.cipher_type.tag_size());
        }
        let mut buf = BytesMut::with_capacity(output.len());
        buf.put_slice(input);
        if let RingAeadCryptoVariant::Seal(ref mut key) = self.cipher {
            key.seal_in_place_append_tag(Aad::empty(), &mut buf)
                .unwrap();
            output.copy_from_slice(&buf);
        } else {
            unreachable!("encrypt is called on a non-seal cipher")
        }
    }

    /// Decrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len() - tag.len()`.
    /// ```plain
    /// +----------------------------------------+-----------------------+
    /// | ENCRYPTED TEXT (length = output.len()) | TAG                   |
    /// +----------------------------------------+-----------------------+
    /// ```
    pub fn decrypt(&mut self, input: &[u8], output: &mut BytesMut) -> Result<(), SecioError> {
        output.reserve(input.len() - self.cipher_type.tag_size());
        unsafe {
            output.set_len(input.len() - self.cipher_type.tag_size());
        }

        let mut buf = BytesMut::with_capacity(self.cipher_type.tag_size() + input.len());
        buf.put_slice(input);

        if let RingAeadCryptoVariant::Open(ref mut key) = self.cipher {
            match key.open_in_place(Aad::empty(), &mut buf) {
                Ok(out_buf) => output.copy_from_slice(out_buf),
                Err(e) => return Err(e.into()),
            }
        } else {
            unreachable!("encrypt is called on a non-seal cipher")
        }
        Ok(())
    }
}

impl StreamCipher for RingAeadCipher {
    fn encrypt(&mut self, input: &[u8], output: &mut BytesMut) -> Result<(), SecioError> {
        self.encrypt(input, output);
        Ok(())
    }

    fn decrypt(&mut self, input: &[u8], output: &mut BytesMut) -> Result<(), SecioError> {
        self.decrypt(input, output)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{BytesMut, CipherType, CryptoMode, RingAeadCipher};

    fn test_ring_aead(cipher: CipherType) {
        let key = (0..cipher.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        // first time
        let message = b"HELLO WORLD";

        let mut enc = RingAeadCipher::new(cipher, &key[..], CryptoMode::Encrypt);

        let mut encrypted_msg = BytesMut::new();
        enc.encrypt(message, &mut encrypted_msg);

        assert_ne!(message, &encrypted_msg[..]);

        let mut dec = RingAeadCipher::new(cipher, &key[..], CryptoMode::Decrypt);
        let mut decrypted_msg = BytesMut::new();

        dec.decrypt(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);

        // second time
        let message = b"hello, world";

        let mut encrypted_msg = BytesMut::new();
        enc.encrypt(message, &mut encrypted_msg);

        assert_ne!(message, &encrypted_msg[..]);

        let mut decrypted_msg = BytesMut::new();

        dec.decrypt(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }

    #[test]
    fn test_aes_128_gcm() {
        test_ring_aead(CipherType::Aes128Gcm)
    }

    #[test]
    fn test_aes_256_gcm() {
        test_ring_aead(CipherType::Aes256Gcm)
    }

    #[test]
    fn test_aes_chacha20_poly1305() {
        test_ring_aead(CipherType::ChaCha20Poly1305)
    }
}
