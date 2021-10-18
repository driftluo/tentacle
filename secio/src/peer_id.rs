/// Most of the code for this module comes from `rust-libp2p`.
use std::fmt;

use rand::{thread_rng, Rng};
use unsigned_varint::{decode, encode};

use crate::handshake::handshake_struct::PublicKey;

const SHA256_CODE: u16 = 0x12;
const SHA256_SIZE: u8 = 32;

/// Identifier of a peer of the network
///
/// The data is a hash of the public key of the peer
#[derive(Clone, PartialOrd, PartialEq, Eq, Hash)]
pub struct PeerId {
    inner: Vec<u8>,
}

impl PeerId {
    /// Builds a `PeerId` from a public key.
    #[inline]
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let key_inner = public_key.inner_ref();
        Self::from_seed(key_inner)
    }

    /// If data is a valid `PeerId`, return `PeerId`, else return error
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::Empty);
        }

        let (code, bytes) = decode::u16(&data).map_err(|_| Error::InvalidData)?;

        if code != SHA256_CODE {
            return Err(Error::NotSupportHashCode);
        }

        if bytes.len() != SHA256_SIZE as usize + 1 {
            return Err(Error::WrongLength);
        }

        if bytes[0] != SHA256_SIZE {
            return Err(Error::InvalidData);
        }

        Ok(PeerId { inner: data })
    }

    /// Return a random `PeerId`
    pub fn random() -> Self {
        let mut seed = [0u8; 20];
        thread_rng().fill(&mut seed[..]);
        Self::from_seed(&seed)
    }

    /// Return `PeerId` which used hashed seed as inner.
    fn from_seed(seed: &[u8]) -> Self {
        let mut buf = encode::u16_buffer();
        let code = encode::u16(SHA256_CODE, &mut buf);

        let header_len = code.len() + 1;

        let mut inner = Vec::new();
        inner.resize(header_len + SHA256_SIZE as usize, 0);
        inner[..code.len()].copy_from_slice(code);
        inner[code.len()] = SHA256_SIZE;

        let mut ctx = crate::sha256_compat::Context::new();
        ctx.update(seed);
        inner[header_len..].copy_from_slice(ctx.finish().as_ref());
        PeerId { inner }
    }

    /// Return raw bytes representation of this peer id
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Consume self, return raw bytes representation of this peer id
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.inner
    }

    /// Returns a base-58 encoded string of this `PeerId`.
    #[inline]
    pub fn to_base58(&self) -> String {
        bs58::encode(self.inner.clone()).into_string()
    }

    /// Returns the raw bytes of the hash of this `PeerId`.
    #[inline]
    pub fn digest(&self) -> &[u8] {
        let (_, bytes) = decode::u16(&self.inner).expect("a invalid digest");
        &bytes[1..]
    }

    /// Checks whether the public key passed as parameter matches the public key of this `PeerId`.
    pub fn is_public_key(&self, public_key: &PublicKey) -> bool {
        let peer_id = Self::from_public_key(public_key);
        &peer_id == self
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PeerId({})", self.to_base58())
    }
}

impl From<PublicKey> for PeerId {
    #[inline]
    fn from(key: PublicKey) -> PeerId {
        PeerId::from_public_key(&key)
    }
}

impl ::std::str::FromStr for PeerId {
    type Err = Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec().map_err(|_| Error::InvalidData)?;
        PeerId::from_bytes(bytes)
    }
}

/// Error code from generate peer id
#[derive(Debug)]
pub enum Error {
    /// invalid data
    InvalidData,
    /// data has wrong length
    WrongLength,
    /// not support hash code
    NotSupportHashCode,
    /// empty data
    Empty,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Empty => write!(f, "data is empty"),
            Error::InvalidData => write!(f, "invalid data"),
            Error::WrongLength => write!(f, "wrong length"),
            Error::NotSupportHashCode => write!(f, "not support hash code"),
        }
    }
}

impl ::std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use crate::{peer_id::PeerId, SecioKeyPair};

    #[test]
    fn peer_id_is_public_key() {
        let pub_key = SecioKeyPair::secp256k1_generated().public_key();
        let peer_id = PeerId::from_public_key(&pub_key);
        assert!(peer_id.is_public_key(&pub_key));
    }

    #[test]
    fn peer_id_into_bytes_then_from_bytes() {
        let peer_id = SecioKeyPair::secp256k1_generated().peer_id();
        let second = PeerId::from_bytes(peer_id.as_bytes().to_vec()).unwrap();
        assert_eq!(peer_id, second);
    }

    #[test]
    fn peer_id_to_base58_then_back() {
        let peer_id = SecioKeyPair::secp256k1_generated().peer_id();
        let second: PeerId = peer_id.to_base58().parse().unwrap();
        assert_eq!(peer_id, second);
    }

    #[test]
    fn peer_id_randomness() {
        let peer_id = PeerId::random();
        let second: PeerId = PeerId::random();
        assert_ne!(peer_id, second);
    }
}
