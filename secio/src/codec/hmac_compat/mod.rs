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
    use crate::Digest;
    use proptest::prelude::*;
    use rand::Rng;

    proptest! {
        #[test]
        fn test_mac_oneshot(data: Vec<u8>) {
            let key = rand::random::<[u8; 32]>();
            let mut hmac = Hmac::from_key(Digest::Sha256, &key);

            let output = hmac.sign(&data);

            let hmac_wasm = wasm_compat::Hmac::from_key(Digest::Sha256, &key);

            let output_wasm = hmac_wasm.sign(&data);

            let mut hmac_ring = ring_impl::Hmac::from_key(Digest::Sha256, &key);

            let output_ring = hmac_ring.sign(&data);

            assert_eq!(AsRef::<[u8]>::as_ref(&output), output_wasm.as_slice());
            assert_eq!(AsRef::<[u8]>::as_ref(&output_ring), output_wasm.as_slice());
            assert_eq!(hmac.num_bytes(), hmac_ring.num_bytes());
            assert_eq!(hmac.num_bytes(), hmac_wasm.num_bytes());
            assert!(hmac.verify(&data, output_ring.as_ref()));
            assert!(hmac_ring.verify(&data, &output_wasm));
            assert!(hmac_wasm.verify(&data, AsRef::<[u8]>::as_ref(&output)));

            let mut key = [0; 64];
            rand::thread_rng().fill(&mut key[..]);
            let mut hmac = Hmac::from_key(Digest::Sha512, &key);

            let output = hmac.sign(&data);

            let hmac_wasm = wasm_compat::Hmac::from_key(Digest::Sha512, &key);

            let output_wasm = hmac_wasm.sign(&data);

            let mut hmac_ring = ring_impl::Hmac::from_key(Digest::Sha512, &key);

            let output_ring = hmac_ring.sign(&data);

            assert_eq!(AsRef::<[u8]>::as_ref(&output), output_wasm.as_slice());
            assert_eq!(AsRef::<[u8]>::as_ref(&output_ring), output_wasm.as_slice());
            assert_eq!(hmac.num_bytes(), hmac_ring.num_bytes());
            assert_eq!(hmac.num_bytes(), hmac_wasm.num_bytes());
        }

        #[test]
        fn test_mac_multi_step(data: Vec<u8>) {
            let key = rand::random::<[u8; 32]>();

            let hmac = Hmac::from_key(Digest::Sha256, &key);
            let mut context = hmac.context();
            context.update(&data);
            context.update(&data);
            let output = context.sign();

            let hmac_ring = ring_impl::Hmac::from_key(Digest::Sha256, &key);
            let mut context_ring = hmac_ring.context();
            context_ring.update(&data);
            context_ring.update(&data);
            let output_ring = context_ring.sign();

            let hmac_wasm = wasm_compat::Hmac::from_key(Digest::Sha256, &key);
            let mut context_wasm = hmac_wasm.context();
            context_wasm.update(&data);
            context_wasm.update(&data);
            let output_wasm = context_wasm.sign();

            assert_eq!(AsRef::<[u8]>::as_ref(&output), output_wasm.as_slice());
            assert_eq!(AsRef::<[u8]>::as_ref(&output_ring), output_wasm.as_slice());

            let mut key = [0; 64];
            rand::thread_rng().fill(&mut key[..]);

            let hmac = Hmac::from_key(Digest::Sha512, &key);
            let mut context = hmac.context();
            context.update(&data);
            context.update(&data);
            let output = context.sign();

            let hmac_ring = ring_impl::Hmac::from_key(Digest::Sha512, &key);
            let mut context_ring = hmac_ring.context();
            context_ring.update(&data);
            context_ring.update(&data);
            let output_ring = context_ring.sign();

            let hmac_wasm = wasm_compat::Hmac::from_key(Digest::Sha512, &key);
            let mut context_wasm = hmac_wasm.context();
            context_wasm.update(&data);
            context_wasm.update(&data);
            let output_wasm = context_wasm.sign();

            assert_eq!(AsRef::<[u8]>::as_ref(&output), output_wasm.as_slice());
            assert_eq!(AsRef::<[u8]>::as_ref(&output_ring), output_wasm.as_slice())
        }
    }
}
