use crate::handshake::handshake_generated::p2p::handshake::{
    Exchange as FBSExchange, ExchangeBuilder, Propose as FBSPropose, ProposeBuilder,
    PublicKey as FBSPublicKey, PublicKeyBuilder, Type,
};

use flatbuffers::{get_root, FlatBufferBuilder};

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
    pub fn decode(data: &[u8]) -> Result<Self, ()> {
        let fbs_propose = get_root::<FBSPropose>(data);
        if fbs_propose.rand().is_none()
            || fbs_propose.pubkey().is_none()
            || fbs_propose.exchanges().is_none()
            || fbs_propose.ciphers().is_none()
            || fbs_propose.hashes().is_none()
        {
            Err(())
        } else {
            Ok(Propose {
                rand: fbs_propose.rand().unwrap().to_owned(),
                pubkey: fbs_propose.pubkey().unwrap().to_owned(),
                exchange: fbs_propose.exchanges().unwrap().to_owned(),
                ciphers: fbs_propose.ciphers().unwrap().to_owned(),
                hashes: fbs_propose.hashes().unwrap().to_owned(),
            })
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
    pub fn decode(data: &[u8]) -> Result<Self, ()> {
        let fbs_exchange = get_root::<FBSExchange>(data);
        if fbs_exchange.epubkey().is_none() || fbs_exchange.signature().is_none() {
            Err(())
        } else {
            Ok(Exchange {
                epubkey: fbs_exchange.epubkey().unwrap().to_owned(),
                signature: fbs_exchange.signature().unwrap().to_owned(),
            })
        }
    }
}

/// Public Key
#[derive(Clone, Debug, PartialEq, Ord, PartialOrd, Eq)]
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
    pub fn decode(data: &[u8]) -> Result<Self, ()> {
        let pubkey = get_root::<FBSPublicKey>(data);
        if pubkey.pubkey().is_none() {
            Err(())
        } else {
            match pubkey.key_type() {
                Type::Secp256k1 => Ok(PublicKey::Secp256k1(pubkey.pubkey().unwrap().to_owned())),
            }
        }
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
