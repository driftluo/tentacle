#[cfg(all(ossl110, unix))]
mod openssl_impl;
#[cfg(any(test, not(unix), not(ossl110)))]
mod ring_impl;
#[cfg(any(target_arch = "wasm32", test))]
mod wasm_compat;

#[cfg(unix)]
pub use openssl_impl::*;
#[cfg(not(unix))]
pub use ring_impl::*;
#[cfg(target_arch = "wasm32")]
pub use wasm_compat::*;

/// Possible key agreement algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyAgreement {
    EcdhP256,
    EcdhP384,
    X25519,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hd() {
        let (pk_native, sk_native) = generate_agreement(KeyAgreement::X25519).unwrap();
        let (pk_wasm, sk_wasm) = wasm_compat::generate_agreement(KeyAgreement::X25519).unwrap();

        let secret_native = agree(KeyAgreement::X25519, pk_native, &sk_wasm).unwrap();
        let secret_wasm = wasm_compat::agree(KeyAgreement::X25519, pk_wasm, &sk_native).unwrap();

        assert_eq!(secret_native, secret_wasm)
    }
}
