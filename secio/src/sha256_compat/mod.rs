#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(any(target_arch = "wasm32", test))]
mod wasm_compat;

#[cfg(not(target_arch = "wasm32"))]
pub use native::*;

#[cfg(target_arch = "wasm32")]
pub use wasm_compat::*;

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_sha256() {
        let mut key = [0; 64];
        rand::thread_rng().fill(&mut key[..]);

        let hash = sha256(&key);
        let hash_wasm = wasm_compat::sha256(&key);

        assert_eq!(hash.as_ref(), hash_wasm.as_slice());

        let mut context = Context::new();
        context.update(&key);
        let hash_context = context.finish();

        let mut context_wasm = wasm_compat::Context::new();
        context_wasm.update(&key);
        let hash_context_wasm = context_wasm.finish();

        assert_eq!(hash.as_ref(), hash_context.as_ref());
        assert_eq!(hash.as_ref(), hash_context_wasm.as_slice());
    }
}
