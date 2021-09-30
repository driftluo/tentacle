/// Sha256 Context
pub struct Context(ring::digest::Context);

impl Context {
    pub fn new() -> Self {
        Context(ring::digest::Context::new(&ring::digest::SHA256))
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
    pub fn finish(self) -> ring::digest::Digest {
        self.0.finish()
    }
}

pub fn sha256(data: &[u8]) -> ring::digest::Digest {
    ring::digest::digest(&ring::digest::SHA256, data)
}
