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
    fn test_pk_to_sk() {
        let mut data = [0; 64];
        rand::thread_rng().fill(&mut data[..]);
        let (pk_native, pk_wasm) = loop {
            let rand_p = rand::random::<[u8; SECRET_KEY_SIZE]>();
            if let (Ok(p1), Ok(p2)) = (
                secret_key_from_slice(&rand_p),
                wasm_compat::secret_key_from_slice(&rand_p),
            ) {
                break (p1, p2);
            }
        };

        let sk_native = from_secret_key(&pk_native);
        let sk_wasm = wasm_compat::from_secret_key(&pk_wasm);

        assert_eq!(
            serialize_pubkey(&sk_native),
            wasm_compat::serialize_pubkey(&sk_wasm)
        );

        let raw_msg = crate::sha256_compat::sha256(&data);
        let msg_native = message_from_slice(raw_msg.as_ref()).unwrap();
        let signature_native = sign(&msg_native, &pk_native);

        assert!(verify(&msg_native, &signature_native, &sk_native));

        let msg_wasm = wasm_compat::message_from_slice(raw_msg.as_ref()).unwrap();
        let signature_wasm = wasm_compat::sign(&msg_wasm, &pk_wasm);

        assert!(wasm_compat::verify(&msg_wasm, &signature_wasm, &sk_wasm));

        assert_eq!(
            signature_to_vec(signature_native),
            wasm_compat::signature_to_vec(signature_wasm)
        )
    }
}
