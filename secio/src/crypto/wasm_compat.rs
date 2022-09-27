#![allow(dead_code)]

use chacha20poly1305::{
    aead::{Aead, AeadInPlace, Buffer, Error, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::{
    crypto::{cipher::CipherType, nonce_advance, StreamCipher},
    error::SecioError,
};

use bytes::BytesMut;

pub(crate) struct WasmCrypt {
    cipher: ChaCha20Poly1305,
    _cipher_type: CipherType,
    iv: BytesMut,
}

impl WasmCrypt {
    pub fn new(cipher_type: CipherType, key: &[u8]) -> Self {
        let cipher = match cipher_type {
            CipherType::ChaCha20Poly1305 => ChaCha20Poly1305::new(Key::from_slice(key)),
            _ => panic!(
                "Cipher type {:?} does not supported by WasmCrypt yet",
                cipher_type
            ),
        };

        // aead use self-increase iv
        let nonce_size = cipher_type.iv_size();
        let mut nonce = BytesMut::with_capacity(nonce_size);
        unsafe {
            nonce.set_len(nonce_size);
            ::std::ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_size);
        }

        WasmCrypt {
            cipher,
            _cipher_type: cipher_type,
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
        self.cipher
            .encrypt(Nonce::from_slice(self.iv.as_ref()), input)
            .map_err(|_| SecioError::CryptoError)
    }

    /// Decrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len() - tag.len()`.
    /// ```plain
    /// +----------------------------------------+-----------------------+
    /// | ENCRYPTED TEXT (length = output.len()) | TAG                   |
    /// +----------------------------------------+-----------------------+
    /// ```
    pub fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecioError> {
        nonce_advance(self.iv.as_mut());
        self.cipher
            .decrypt(Nonce::from_slice(self.iv.as_ref()), input)
            .map_err(|_| SecioError::CryptoError)
    }

    pub fn decrypt_in_place(&mut self, input: &mut BytesMut) -> Result<(), SecioError> {
        nonce_advance(self.iv.as_mut());
        self.cipher
            .decrypt_in_place(
                Nonce::from_slice(self.iv.as_ref()),
                b"",
                &mut BufferWrap(input),
            )
            .map_err(|_| SecioError::CryptoError)
    }
}

impl StreamCipher for WasmCrypt {
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

struct BufferWrap<'a>(&'a mut BytesMut);

impl<'a> AsRef<[u8]> for BufferWrap<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> AsMut<[u8]> for BufferWrap<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<'a> Buffer for BufferWrap<'a> {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

#[cfg(test)]
mod test {
    use super::{BytesMut, CipherType, WasmCrypt};
    use proptest::prelude::*;

    fn test_wasm(mode: CipherType, message: &[u8]) {
        let key = (0..mode.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let mut encryptor = WasmCrypt::new(mode, &key[0..]);
        let mut decryptor = WasmCrypt::new(mode, &key[0..]);

        let encrypted_msg = encryptor.encrypt(message).unwrap();
        let decrypted_msg = decryptor.decrypt(&encrypted_msg[..]).unwrap();

        assert_eq!(message, &decrypted_msg[..]);

        let encrypted_msg = encryptor.encrypt(message).unwrap();
        let decrypted_msg = decryptor.decrypt(&encrypted_msg[..]).unwrap();

        assert_eq!(message, &decrypted_msg[..]);
    }

    fn test_wasm_in_place(mode: CipherType, message: &[u8]) {
        let key = (0..mode.key_size())
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let mut encryptor = WasmCrypt::new(mode, &key[0..]);
        let mut decryptor = WasmCrypt::new(mode, &key[0..]);

        let mut encrypted_msg = BytesMut::from(encryptor.encrypt(message).unwrap().as_slice());
        decryptor.decrypt_in_place(&mut encrypted_msg).unwrap();

        assert_eq!(message, &encrypted_msg[..]);

        let mut encrypted_msg = BytesMut::from(encryptor.encrypt(message).unwrap().as_slice());
        decryptor.decrypt_in_place(&mut encrypted_msg).unwrap();

        assert_eq!(message, &encrypted_msg[..]);
    }

    proptest! {
        #[test]
        fn test_chacha20_poly1305(message: Vec<u8>) {
            test_wasm(CipherType::ChaCha20Poly1305, &message);
            test_wasm_in_place(CipherType::ChaCha20Poly1305, &message);
        }
    }
}
