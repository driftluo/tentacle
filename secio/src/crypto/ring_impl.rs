use bytes::BytesMut;
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
    pub fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        let mut output = vec![0; input.len()];
        output.copy_from_slice(input);
        if let RingAeadCryptoVariant::Seal(ref mut key) = self.cipher {
            key.seal_in_place_append_tag(Aad::empty(), &mut output)
                .map_err::<SecioError, _>(Into::into)?;
            Ok(output)
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
    pub fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        let output_len = input
            .len()
            .checked_sub(self.cipher_type.tag_size())
            .ok_or(SecioError::FrameTooShort)?;
        let mut buf = vec![0; input.len()];

        buf.copy_from_slice(input);

        if let RingAeadCryptoVariant::Open(ref mut key) = self.cipher {
            key.open_in_place(Aad::empty(), &mut buf)?;
        } else {
            unreachable!("encrypt is called on a non-open cipher")
        }
        buf.truncate(output_len);
        Ok(buf)
    }

    pub fn decrypt_in_place(&mut self, input: &mut BytesMut) -> Result<(), SecioError> {
        let output_len = input
            .len()
            .checked_sub(self.cipher_type.tag_size())
            .ok_or(SecioError::FrameTooShort)?;

        if let RingAeadCryptoVariant::Open(ref mut key) = self.cipher {
            key.open_in_place(Aad::empty(), input)?;
        } else {
            unreachable!("encrypt is called on a non-open cipher")
        }
        input.truncate(output_len);
        Ok(())
    }
}

impl StreamCipher for RingAeadCipher {
    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        self.encrypt(input)
    }

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        self.decrypt(input)
    }

    #[inline]
    fn is_in_place(&self) -> bool {
        true
    }

    fn decrypt_in_place(&mut self, input: &mut BytesMut) -> Result<(), SecioError> {
        self.decrypt_in_place(input)
    }
}

#[cfg(test)]
mod test {
    use super::{CipherType, CryptoMode, RingAeadCipher};
    use proptest::prelude::*;

    fn test_ring_aead(cipher: CipherType, message: &[u8]) {
        let key = (0..cipher.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let mut enc = RingAeadCipher::new(cipher, &key[..], CryptoMode::Encrypt);

        let encrypted_msg = enc.encrypt(message).unwrap();

        assert_ne!(message, &encrypted_msg[..]);

        let mut dec = RingAeadCipher::new(cipher, &key[..], CryptoMode::Decrypt);
        let decrypted_msg = dec.decrypt(&encrypted_msg[..]).unwrap();

        assert_eq!(&decrypted_msg[..], message);

        let encrypted_msg = enc.encrypt(message).unwrap();

        assert_ne!(message, &encrypted_msg[..]);

        let decrypted_msg = dec.decrypt(&encrypted_msg[..]).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }

    proptest! {
        #[test]
        fn test_aes_128_gcm(message: Vec<u8>) {
            test_ring_aead(CipherType::Aes128Gcm, &message)
        }

        #[test]
        fn test_aes_256_gcm(message: Vec<u8>) {
            test_ring_aead(CipherType::Aes256Gcm, &message)
        }

        #[test]
        fn test_chacha20_poly1305(message: Vec<u8>) {
            test_ring_aead(CipherType::ChaCha20Poly1305, &message)
        }
    }
}
