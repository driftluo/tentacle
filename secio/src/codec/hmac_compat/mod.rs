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
    use crate::Digest;
    use rand::Rng;

    #[test]
    fn test_mac() {
        let data = "hello";
        let key = rand::random::<[u8; 32]>();
        let mut hmac = Hmac::from_key(Digest::Sha256, &key);

        let output = hmac.sign(data.as_bytes());

        let hmac_wasm = wasm_compat::Hmac::from_key(Digest::Sha256, &key);

        let output_wasm = hmac_wasm.sign(data.as_bytes());

        assert_eq!(output.as_ref(), output_wasm.as_slice());

        let mut key = [0; 64];
        rand::thread_rng().fill(&mut key[..]);
        let mut hmac = Hmac::from_key(Digest::Sha512, &key);

        let output = hmac.sign(data.as_bytes());

        let hmac_wasm = wasm_compat::Hmac::from_key(Digest::Sha512, &key);

        let output_wasm = hmac_wasm.sign(data.as_bytes());

        assert_eq!(output.as_ref(), output_wasm.as_slice())
    }
}
