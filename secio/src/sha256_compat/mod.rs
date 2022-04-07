#[cfg(unix)]
mod openssl_impl;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(any(test, not(unix)))]
mod ring_impl;
#[cfg(any(target_arch = "wasm32", test))]
mod wasm_compat;

#[cfg(unix)]
pub use openssl_impl::*;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(unix))]
pub use ring_impl::*;

#[cfg(target_arch = "wasm32")]
pub use wasm_compat::*;

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    proptest! {
            #[test]
        fn test_sha256(key: Vec<u8>) {
            let hash = sha256(&key);
            let hash_wasm = wasm_compat::sha256(&key);
            let hash_ring = ring_impl::sha256(&key);

            assert_eq!(hash.as_ref(), hash_wasm.as_slice());
            assert_eq!(hash.as_ref(), hash_ring.as_ref());

            let mut context = Context::new();
            context.update(&key);
            let hash_context = context.finish();

            let mut context_wasm = wasm_compat::Context::new();
            context_wasm.update(&key);
            let hash_context_wasm = context_wasm.finish();

            let mut context_ring = ring_impl::Context::new();
            context_ring.update(&key);
            let hash_context_ring = context_ring.finish();

            assert_eq!(hash.as_ref(), hash_context.as_ref());
            assert_eq!(hash.as_ref(), hash_context_ring.as_ref());
            assert_eq!(hash.as_ref(), hash_context_wasm.as_slice());
        }
    }
}
