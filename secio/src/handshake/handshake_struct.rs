use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Propose {
    pub(crate) rand: Vec<u8>,
    pub(crate) pubkey: Vec<u8>,
    pub(crate) exchange: String,
    pub(crate) ciphers: String,
    pub(crate) hashes: String,
}

impl Propose {
    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Exchange {
    pub(crate) epubkey: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

impl Exchange {
    pub fn new() -> Self {
        Default::default()
    }
}
