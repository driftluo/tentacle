#![allow(dead_code)]

pub use secpwasm::{verify, Message, PublicKey, SecretKey, Signature};

pub const SECRET_KEY_SIZE: usize = 32;

pub fn from_secret_key(secret: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(secret)
}

// compressed serialize, len = 33
pub fn serialize_pubkey(pubkey: &PublicKey) -> Vec<u8> {
    pubkey.serialize_compressed().to_vec()
}

pub fn sign(message: &Message, secret: &SecretKey) -> Signature {
    secpwasm::sign(message, secret).0
}

pub fn signature_to_vec(signature: Signature) -> Vec<u8> {
    signature.serialize_der().as_ref().to_vec()
}

pub fn secret_key_from_slice(key: &[u8]) -> Result<SecretKey, secpwasm::Error> {
    SecretKey::parse_slice(key)
}

pub fn pubkey_from_slice(key: &[u8]) -> Result<PublicKey, secpwasm::Error> {
    PublicKey::parse_slice(key, None)
}

pub fn message_from_slice(msg: &[u8]) -> Result<Message, secpwasm::Error> {
    Message::parse_slice(msg)
}

pub fn signature_from_der(data: &[u8]) -> Result<Signature, secpwasm::Error> {
    Signature::parse_der(data)
}
