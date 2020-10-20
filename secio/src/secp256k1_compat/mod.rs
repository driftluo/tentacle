#[cfg(not(target_os = "unknown"))]
mod native;
#[cfg(any(target_arch = "wasm32", test))]
mod wasm_compat;

#[cfg(not(target_os = "unknown"))]
pub use native::*;

#[cfg(target_arch = "wasm32")]
pub use wasm_compat::*;

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_pk_to_sk() {
        let mut message = [0; 64];
        rand::thread_rng().fill(&mut message[..]);
        let pk_native = loop {
            if let Ok(private) = secret_key_from_slice(&rand::random::<[u8; SECRET_KEY_SIZE]>()) {
                break private;
            }
        };

        let sk_native = from_secret_key(&pk_native);

        let sk_wasm = wasm_compat::pubkey_from_slice(&serialize_pubkey(&sk_native)).unwrap();

        let raw_msg = crate::sha256_compat::sha256(&message);
        let msg = message_from_slice(raw_msg.as_ref()).unwrap();

        let signature = sign(&msg, &pk_native);

        assert!(verify(&msg, &signature, &sk_native));

        let msg_wasm = wasm_compat::message_from_slice(raw_msg.as_ref()).unwrap();

        let signature_wasm = wasm_compat::signature_from_der(&signature_to_vec(signature)).unwrap();

        assert!(wasm_compat::verify(&msg_wasm, &signature_wasm, &sk_wasm));
    }
}
