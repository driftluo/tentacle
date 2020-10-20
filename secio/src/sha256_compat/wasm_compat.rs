#![allow(dead_code)]

use sha2::digest::Output;
use sha2::{Digest, Sha256};

/// Sha256 Context
pub struct Context(sha2::Sha256);

impl Context {
    pub fn new() -> Self {
        Context(sha2::Sha256::new())
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
    pub fn finish(self) -> Output<Sha256> {
        self.0.finalize()
    }
}

pub fn sha256(data: &[u8]) -> Output<Sha256> {
    let mut s = sha2::Sha256::new();
    s.update(data);
    s.finalize()
}
