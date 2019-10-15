use bytes::{BufMut, BytesMut};
use ring::{
    aead::{
        Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, CHACHA20_POLY1305,
    },
    error::Unspecified,
};

use std::ptr;

use crate::{
    crypto::{cipher::CipherType, CryptoMode, StreamCipher},
    error::SecioError,
};

struct RingNonce(BytesMut);

impl NonceSequence for RingNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut prev: u16 = 1;
        for i in self.0.as_mut() {
            prev += u16::from(*i);
            *i = prev as u8;
            prev >>= 8;
        }
        Nonce::try_assume_unique_for_key(&self.0)
    }
}

enum RingAeadCryptoVariant {
    Seal(SealingKey<RingNonce>),
    Open(OpeningKey<RingNonce>),
}

pub(crate) struct RingAeadCipher {
    cipher: RingAeadCryptoVariant,
    seal: bool,
}

impl RingAeadCipher {
    pub fn new(cipher_type: CipherType, key: &[u8], mode: CryptoMode) -> Self {
        let nonce_size = cipher_type.iv_size();
        let mut nonce = BytesMut::with_capacity(nonce_size);
        unsafe {
            nonce.set_len(nonce_size);
            ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_size);
        }

        let (cipher, seal) = match mode {
            CryptoMode::Encrypt => (
                RingAeadCryptoVariant::Seal(SealingKey::new(
                    UnboundKey::new(&CHACHA20_POLY1305, key).unwrap(),
                    RingNonce(nonce),
                )),
                true,
            ),
            CryptoMode::Decrypt => (
                RingAeadCryptoVariant::Open(OpeningKey::new(
                    UnboundKey::new(&CHACHA20_POLY1305, key).unwrap(),
                    RingNonce(nonce),
                )),
                false,
            ),
        };
        RingAeadCipher { cipher, seal }
    }

    fn encrypt(&mut self, input: &[u8], output: &mut BytesMut) {
        output.reserve(input.len() + CHACHA20_POLY1305.tag_len());
        unsafe {
            output.set_len(input.len() + CHACHA20_POLY1305.tag_len());
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

    fn decrypt(&mut self, input: &[u8], output: &mut BytesMut) -> Result<(), SecioError> {
        output.reserve(input.len() - CHACHA20_POLY1305.tag_len());
        unsafe {
            output.set_len(input.len() - CHACHA20_POLY1305.tag_len());
        }

        let mut buf = BytesMut::with_capacity(CHACHA20_POLY1305.tag_len() + input.len());
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
    fn update(&mut self, data: &[u8], out: &mut BytesMut) -> Result<(), SecioError> {
        if self.seal {
            self.encrypt(data, out);
        } else {
            self.decrypt(data, out)?;
        }
        Ok(())
    }

    fn finalize(&mut self, _out: &mut BytesMut) -> Result<(), SecioError> {
        Ok(())
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        data.len()
    }
}

#[cfg(test)]
mod test {
    use super::{BytesMut, CipherType, CryptoMode, RingAeadCipher};

    #[test]
    fn test_ring_aead() {
        let key = (0..CipherType::ChaCha20Poly1305.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        // first time
        let message = b"HELLO WORLD";

        let mut enc =
            RingAeadCipher::new(CipherType::ChaCha20Poly1305, &key[..], CryptoMode::Encrypt);

        let mut encrypted_msg = BytesMut::new();
        enc.encrypt(message, &mut encrypted_msg);

        assert_ne!(message, &encrypted_msg[..]);

        let mut dec =
            RingAeadCipher::new(CipherType::ChaCha20Poly1305, &key[..], CryptoMode::Decrypt);
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
}
