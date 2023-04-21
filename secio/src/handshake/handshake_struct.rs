use crate::handshake::handshake_mol;
use molecule::prelude::{Builder, Entity, Reader};

use crate::peer_id::PeerId;

use bytes::Bytes;
use std::fmt;

#[derive(Clone, Default, PartialEq, Ord, PartialOrd, Eq, Debug)]
pub struct Propose {
    pub(crate) rand: Vec<u8>,
    /// flatbuffer public key bytes
    pub(crate) pubkey: Bytes,
    pub(crate) exchange: String,
    pub(crate) ciphers: String,
    pub(crate) hashes: String,
}

impl Propose {
    pub fn new() -> Self {
        Default::default()
    }

    /// Encode with molecule
    pub fn encode(self) -> Bytes {
        let rand = handshake_mol::Bytes::new_builder()
            .set(self.rand.into_iter().map(Into::into).collect())
            .build();
        let pubkey = handshake_mol::Bytes::new_builder()
            .set(self.pubkey.iter().copied().map(Into::into).collect())
            .build();
        let exchange = handshake_mol::String::new_builder()
            .set(
                self.exchange
                    .into_bytes()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
            .build();
        let ciphers = handshake_mol::String::new_builder()
            .set(
                self.ciphers
                    .into_bytes()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
            .build();
        let hashes = handshake_mol::String::new_builder()
            .set(
                self.hashes
                    .into_bytes()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
            .build();

        handshake_mol::Propose::new_builder()
            .rand(rand)
            .pubkey(pubkey)
            .exchanges(exchange)
            .ciphers(ciphers)
            .hashes(hashes)
            .build()
            .as_bytes()
    }

    /// Decode with molecule
    pub fn decode(data: &[u8]) -> Option<Self> {
        let reader = handshake_mol::ProposeReader::from_compatible_slice(data).ok()?;
        Some(Propose {
            rand: reader.rand().raw_data().to_owned(),
            pubkey: Bytes::from(reader.pubkey().raw_data().to_owned()),
            exchange: String::from_utf8(reader.exchanges().raw_data().to_owned()).ok()?,
            ciphers: String::from_utf8(reader.ciphers().raw_data().to_owned()).ok()?,
            hashes: String::from_utf8(reader.hashes().raw_data().to_owned()).ok()?,
        })
    }
}

#[derive(Clone, Default, PartialEq, Ord, PartialOrd, Eq, Debug)]
pub struct Exchange {
    pub(crate) epubkey: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

impl Exchange {
    pub fn new() -> Self {
        Default::default()
    }

    /// Encode with molecule
    pub fn encode(self) -> Bytes {
        let epubkey = handshake_mol::Bytes::new_builder()
            .set(self.epubkey.into_iter().map(Into::into).collect())
            .build();
        let signature = handshake_mol::Bytes::new_builder()
            .set(self.signature.into_iter().map(Into::into).collect())
            .build();

        handshake_mol::Exchange::new_builder()
            .epubkey(epubkey)
            .signature(signature)
            .build()
            .as_bytes()
    }

    /// Decode with molecule
    pub fn decode(data: &[u8]) -> Option<Self> {
        let reader = handshake_mol::ExchangeReader::from_compatible_slice(data).ok()?;
        Some(Exchange {
            epubkey: reader.epubkey().raw_data().to_owned(),
            signature: reader.signature().raw_data().to_owned(),
        })
    }
}

/// Public Key
#[derive(Clone, PartialEq, Ord, PartialOrd, Eq, Hash)]
pub struct PublicKey {
    pub(crate) key: Vec<u8>,
}

impl PublicKey {
    /// Get inner data
    pub fn inner_ref(&self) -> &[u8] {
        &self.key
    }

    /// Get inner data
    pub fn inner(self) -> Vec<u8> {
        self.key
    }

    /// Encode with molecule
    pub fn encode(self) -> Bytes {
        let secp256k1 = handshake_mol::Secp256k1::new_builder()
            .set(self.inner().into_iter().map(Into::into).collect())
            .build();
        let pubkey = handshake_mol::PublicKey::new_builder()
            .set(secp256k1)
            .build();
        pubkey.as_bytes()
    }

    /// Decode with molecule
    pub fn decode(data: &[u8]) -> Option<Self> {
        let reader = handshake_mol::PublicKeyReader::from_compatible_slice(data).ok()?;
        let union = reader.to_enum();

        match union {
            handshake_mol::PublicKeyUnionReader::Secp256k1(reader) => Some(PublicKey {
                key: reader.raw_data().to_owned(),
            }),
        }
    }

    /// Generate Peer id
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public_key(self)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x")?;
        for byte in self.inner_ref() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Exchange, Propose, PublicKey};
    use crate::{SecioKeyPair, Signer};
    use bytes::Bytes;

    #[test]
    fn decode_encode_pubkey() {
        let raw = SecioKeyPair::secp256k1_generated().public_key();
        let byte = raw.clone();

        assert_eq!(raw, PublicKey::decode(&byte.encode()).unwrap())
    }

    #[test]
    fn decode_encode_propose() {
        let nonce: [u8; 16] = rand::random();
        let mut raw = Propose::new();
        raw.rand = nonce.to_vec();
        raw.pubkey = Bytes::from(vec![25u8; 256]);

        let byte = raw.clone();

        assert_eq!(raw, Propose::decode(&byte.encode()).unwrap())
    }

    #[test]
    fn decode_encode_exchange() {
        let mut raw = Exchange::new();
        raw.signature = vec![1u8; 256];
        raw.epubkey = vec![9u8; 256];

        let byte = raw.clone();

        assert_eq!(raw, Exchange::decode(&byte.encode()).unwrap())
    }

    #[test]
    fn test_pubkey_from_slice() {
        let privkey = SecioKeyPair::secp256k1_generated();
        let raw = privkey.public_key();
        let inner = raw.inner_ref();

        let other = SecioKeyPair::pubkey_from_slice(inner).unwrap();
        assert_eq!(raw.inner_ref(), other.serialize());
        let uncompressed = crate::secp256k1_compat::pubkey_from_slice(inner)
            .map(|key| key.serialize_uncompressed().to_vec())
            .unwrap();

        let other_1 = SecioKeyPair::pubkey_from_slice(&uncompressed).unwrap();
        assert_eq!(raw.inner_ref(), other_1.serialize());
    }
}
