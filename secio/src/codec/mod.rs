/// Hmac struct on this module comes from `rust-libp2p`, but use high version of hamc

/// Encryption and decryption stream
pub mod secure_stream;
// hmac compatible
mod hmac_compat;

pub use hmac_compat::Hmac;
