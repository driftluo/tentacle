pub use secp256k1::{constants::SECRET_KEY_SIZE, ecdsa::Signature, Message, PublicKey, SecretKey};

pub fn from_secret_key(secret: &SecretKey) -> PublicKey {
    let secp = secp256k1::Secp256k1::signing_only();
    secp256k1::PublicKey::from_secret_key(&secp, secret)
}

// compressed serialize, len = 33
pub fn serialize_pubkey(pubkey: &PublicKey) -> Vec<u8> {
    pubkey.serialize().to_vec()
}

pub fn signature_to_vec(signature: Signature) -> Vec<u8> {
    signature.serialize_der().to_vec()
}

pub fn sign(message: &Message, secret: &SecretKey) -> Signature {
    let secp256k1_key = secp256k1::Secp256k1::signing_only();
    secp256k1_key.sign_ecdsa(message, secret)
}

pub fn verify(message: &Message, signature: &Signature, pubkey: &PublicKey) -> bool {
    let secp256k1 = secp256k1::Secp256k1::verification_only();
    secp256k1.verify_ecdsa(message, signature, pubkey).is_ok()
}

pub fn secret_key_from_slice(key: &[u8]) -> Result<SecretKey, secp256k1::Error> {
    SecretKey::from_slice(key)
}

pub fn pubkey_from_slice(key: &[u8]) -> Result<PublicKey, secp256k1::Error> {
    PublicKey::from_slice(key)
}

pub fn message_from_slice(msg: &[u8]) -> Result<Message, secp256k1::Error> {
    Message::from_slice(msg)
}

pub fn signature_from_der(data: &[u8]) -> Result<Signature, secp256k1::Error> {
    Signature::from_der(data)
}
