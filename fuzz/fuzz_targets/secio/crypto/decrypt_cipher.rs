#![no_main]
use libfuzzer_sys::fuzz_target;
use rand;
use tentacle_secio::crypto::{new_stream, cipher::CipherType, CryptoMode, BoxStreamCipher};

fn new_decrypt_cipher(cipher_type: CipherType) -> BoxStreamCipher {
    let key = (0..cipher_type.key_size())
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();
    new_stream(cipher_type, &key, CryptoMode::Decrypt)
}

fuzz_target!(|data: &[u8]| {
    let mut cipher = new_decrypt_cipher(CipherType::Aes128Gcm);
    let _ = cipher.decrypt(data);

    let mut cipher = new_decrypt_cipher(CipherType::Aes256Gcm);
    let _ = cipher.decrypt(data);

    let mut cipher = new_decrypt_cipher(CipherType::ChaCha20Poly1305);
    let _ = cipher.decrypt(data);
});
