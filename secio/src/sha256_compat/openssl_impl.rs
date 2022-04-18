pub struct Context(openssl::sha::Sha256);

impl Context {
    pub fn new() -> Self {
        Context(openssl::sha::Sha256::new())
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
    pub fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    openssl::sha::sha256(data)
}
