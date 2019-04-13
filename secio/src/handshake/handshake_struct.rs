use crate::handshake::handshake_generated::p2p::handshake::{
    Exchange as FBSExchange, ExchangeBuilder, Propose as FBSPropose, ProposeBuilder,
    PublicKey as FBSPublicKey, PublicKeyBuilder, Type,
};
use crate::peer_id::PeerId;

use flatbuffers::FlatBufferBuilder;
use flatbuffers_verifier::get_root;

use std::fmt;

#[derive(Clone, Default, PartialEq, Ord, PartialOrd, Eq, Debug)]
pub struct Propose {
    pub(crate) rand: Vec<u8>,
    /// flatbuffer public key bytes
    pub(crate) pubkey: Vec<u8>,
    pub(crate) exchange: String,
    pub(crate) ciphers: String,
    pub(crate) hashes: String,
}

impl Propose {
    pub fn new() -> Self {
        Default::default()
    }

    /// Encode with flatbuffer
    pub fn encode(&self) -> Vec<u8> {
        let mut fbb = FlatBufferBuilder::new();
        let rand = fbb.create_vector(&self.rand);
        let pub_key = fbb.create_vector(&self.pubkey);
        let exchange = fbb.create_string(&self.exchange);
        let ciphers = fbb.create_string(&self.ciphers);
        let hashes = fbb.create_string(&self.hashes);

        let mut builder = ProposeBuilder::new(&mut fbb);
        builder.add_rand(rand);
        builder.add_pubkey(pub_key);
        builder.add_exchanges(exchange);
        builder.add_ciphers(ciphers);
        builder.add_hashes(hashes);
        let data = builder.finish();

        fbb.finish(data, None);
        fbb.finished_data().to_vec()
    }

    /// Decode with Flatbuffer
    pub fn decode(data: &[u8]) -> Option<Self> {
        let fbs_propose = get_root::<FBSPropose>(data).ok()?;
        match (
            fbs_propose.rand(),
            fbs_propose.pubkey(),
            fbs_propose.exchanges(),
            fbs_propose.ciphers(),
            fbs_propose.hashes(),
        ) {
            (Some(rand), Some(pubkey), Some(exchange), Some(ciphers), Some(hashes)) => {
                Some(Propose {
                    rand: rand.to_owned(),
                    pubkey: pubkey.to_owned(),
                    exchange: exchange.to_owned(),
                    ciphers: ciphers.to_owned(),
                    hashes: hashes.to_owned(),
                })
            }
            _ => None,
        }
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

    /// Encode with flatbuffer
    pub fn encode(&self) -> Vec<u8> {
        let mut fbb = FlatBufferBuilder::new();
        let epubkey = fbb.create_vector(&self.epubkey);
        let signature = fbb.create_vector(&self.signature);

        let mut builder = ExchangeBuilder::new(&mut fbb);
        builder.add_epubkey(epubkey);
        builder.add_signature(signature);
        let data = builder.finish();

        fbb.finish(data, None);
        fbb.finished_data().to_vec()
    }

    /// Decode with Flatbuffer
    pub fn decode(data: &[u8]) -> Option<Self> {
        let fbs_exchange = get_root::<FBSExchange>(data).ok()?;
        match (fbs_exchange.epubkey(), fbs_exchange.signature()) {
            (Some(epubkey), Some(signature)) => Some(Exchange {
                epubkey: epubkey.to_owned(),
                signature: signature.to_owned(),
            }),
            _ => None,
        }
    }
}

/// Public Key
#[derive(Clone, PartialEq, Ord, PartialOrd, Eq, Hash)]
pub enum PublicKey {
    /// Secp256k1
    Secp256k1(Vec<u8>),
}

impl PublicKey {
    /// Get inner data
    pub fn inner_ref(&self) -> &Vec<u8> {
        match self {
            PublicKey::Secp256k1(ref key) => key,
        }
    }

    /// Encode with flatbuffer
    pub fn encode(&self) -> Vec<u8> {
        let mut fbb = FlatBufferBuilder::new();
        let pubkey = fbb.create_vector(self.inner_ref());

        let mut builder = PublicKeyBuilder::new(&mut fbb);
        builder.add_key_type(Type::Secp256k1);
        builder.add_pubkey(pubkey);

        let data = builder.finish();

        fbb.finish(data, None);
        fbb.finished_data().to_vec()
    }

    /// Decode with Flatbuffer
    pub fn decode(data: &[u8]) -> Option<Self> {
        let pubkey = get_root::<FBSPublicKey>(data).ok()?;
        match pubkey.pubkey() {
            Some(pub_key) => match pubkey.key_type() {
                Type::Secp256k1 => Some(PublicKey::Secp256k1(pub_key.to_owned())),
            },
            None => None,
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
    use crate::SecioKeyPair;
    use rand;

    #[test]
    fn decode_encode_pubkey() {
        let raw = SecioKeyPair::secp256k1_generated().to_public_key();
        let byte = raw.encode();

        assert_eq!(raw, PublicKey::decode(&byte).unwrap())
    }

    #[test]
    fn decode_encode_propose() {
        let nonce: [u8; 16] = rand::random();
        let mut raw = Propose::new();
        raw.rand = nonce.to_vec();
        raw.pubkey = vec![25u8; 256];

        let byte = raw.encode();

        assert_eq!(raw, Propose::decode(&byte).unwrap())
    }

    #[test]
    fn decode_encode_exchange() {
        let mut raw = Exchange::new();
        raw.signature = vec![1u8; 256];
        raw.epubkey = vec![9u8; 256];

        let byte = raw.encode();

        assert_eq!(raw, Exchange::decode(&byte).unwrap())
    }
}
