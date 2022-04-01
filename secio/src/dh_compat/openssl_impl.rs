use log::debug;
use openssl_sys::{
    point_conversion_form_t, EC_KEY_free, EC_KEY_generate_key, EC_KEY_get0_group,
    EC_KEY_get0_public_key, EC_KEY_new, EC_KEY_new_by_curve_name, EC_KEY_set_group,
    EC_KEY_set_public_key, EC_POINT_free, EC_POINT_new, EC_POINT_oct2point, EC_POINT_point2oct,
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id, EVP_PKEY_derive,
    EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer, EVP_PKEY_free, EVP_PKEY_get_raw_public_key,
    EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_PKEY_new, EVP_PKEY_new_raw_public_key,
    NID_X9_62_prime256v1, NID_secp384r1, EC_KEY, EVP_PKEY, EVP_PKEY_X25519,
};

use std::{
    ops::{Deref, DerefMut},
    ptr::null_mut,
};

use crate::{dh_compat::KeyAgreement, error::SecioError};

// P256 and P384:
// private key use `BN_bn2bin` and `BN_bin2bn` to serialize and deserialize
// pubkey use `EC_POINT_point2oct` and `EC_POINT_oct2point` to serialize and deserialize

// X25519:
// can't use `EC_KEY_new_by_curve_name` and `EVP_PKEY_get1_EC_KEY`
// private key use `EVP_PKEY_get_raw_private_key` and `EVP_PKEY_new_raw_private_key` to serialize and deserialize
// pubkey use `EVP_PKEY_get_raw_public_key` and `EVP_PKEY_new_raw_public_key` to serialize and deserialize

// ref: https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
//      https://www.openssl.org/docs/

static ECDH_P256: Algorithm = Algorithm {
    _private_len: 256 / 8,
    pubkey_len: 1 + (2 * ((256 + 7) / 8)),
    pairs_generate: p256_generate,
    from_pubkey: p256_from_pubkey,
};

static ECDH_P384: Algorithm = Algorithm {
    _private_len: 384 / 8,
    pubkey_len: 1 + (2 * ((384 + 7) / 8)),
    pairs_generate: p384_generate,
    from_pubkey: p384_from_pubkey,
};

static X25519: Algorithm = Algorithm {
    _private_len: 32,
    pubkey_len: 32,
    pairs_generate: x25519_generate,
    from_pubkey: x25519_from_pubkey,
};

/// pairs generater for ANSI X9.62 Prime 256v1 and secp384r1
unsafe fn generater_secpvx(
    nid: libc::c_int,
    pubkey: &mut [u8],
) -> Result<SmartPointer<EVP_PKEY>, SecioError> {
    let ec_key = SmartPointer::new_unchecked(EC_KEY_new_by_curve_name(nid), EC_KEY_free);

    if ec_key.as_ptr().is_null() {
        debug!("Failed to create key curve");
        return Err(SecioError::EphemeralKeyGenerationFailed);
    }

    if 1 != EC_KEY_generate_key(ec_key.as_ptr()) {
        debug!("Failed to generate key");
        return Err(SecioError::EphemeralKeyGenerationFailed);
    }

    let group = EC_KEY_get0_group(ec_key.as_ptr());
    let point = EC_KEY_get0_public_key(ec_key.as_ptr());

    let len = EC_POINT_point2oct(
        group,
        point,
        point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
        pubkey.as_mut_ptr(),
        pubkey.len(),
        null_mut(),
    );

    if len != pubkey.len() {
        debug!("Ecdh P256 public key get error");

        return Err(SecioError::EphemeralKeyGenerationFailed);
    }

    let my_evp_key = SmartPointer::new_unchecked(EVP_PKEY_new(), EVP_PKEY_free);

    if 1 != EVP_PKEY_set1_EC_KEY(my_evp_key.as_ptr(), ec_key.as_ptr()) {
        debug!("fail to recover evp key");

        return Err(SecioError::EphemeralKeyGenerationFailed);
    }

    Ok(my_evp_key)
}

/// recover evp key for ANSI X9.62 Prime 256v1 and secp384r1
unsafe fn secpvx_from_pubkey(
    nid: libc::c_int,
    other_public_key: &[u8],
) -> Result<SmartPointer<EVP_PKEY>, SecioError> {
    let peer_ec_key = EC_KEY_new_by_curve_name(nid);

    let group = EC_KEY_get0_group(peer_ec_key);

    let p_ecdh_public = SmartPointer::new_unchecked(EC_POINT_new(group), EC_POINT_free);

    if 1 != EC_POINT_oct2point(
        group,
        p_ecdh_public.as_ptr(),
        other_public_key.as_ptr(),
        other_public_key.len(),
        null_mut(),
    ) {
        debug!("EC_POINT oct2point error");

        return Err(SecioError::SecretGenerationFailed);
    }

    let peer_ec_key = SmartPointer::new_unchecked(EC_KEY_new(), EC_KEY_free);

    if 1 != EC_KEY_set_group(peer_ec_key.as_ptr(), group) {
        debug!("Ecdh set group error");

        return Err(SecioError::SecretGenerationFailed);
    }

    if 1 != EC_KEY_set_public_key(peer_ec_key.as_ptr(), p_ecdh_public.as_ptr()) {
        debug!("Ecdh set public key error");

        return Err(SecioError::SecretGenerationFailed);
    }

    let peer_evp_key = SmartPointer::new_unchecked(EVP_PKEY_new(), EVP_PKEY_free);

    if 1 != EVP_PKEY_set1_EC_KEY(peer_evp_key.as_ptr(), peer_ec_key.as_ptr()) {
        debug!("fail to recover peer evp key");

        return Err(SecioError::SecretGenerationFailed);
    }

    Ok(peer_evp_key)
}

fn p256_generate(pubkey_len: usize) -> Result<(SmartPointer<EVP_PKEY>, Vec<u8>), SecioError> {
    let mut ecdh_public_key = Vec::with_capacity(pubkey_len);

    unsafe {
        ecdh_public_key.set_len(pubkey_len);
        let evp_key = generater_secpvx(NID_X9_62_prime256v1, &mut ecdh_public_key)?;

        Ok((evp_key, ecdh_public_key))
    }
}

fn p256_from_pubkey(other_public_key: &[u8]) -> Result<SmartPointer<EVP_PKEY>, SecioError> {
    unsafe { secpvx_from_pubkey(NID_X9_62_prime256v1, other_public_key) }
}

fn p384_generate(pubkey_len: usize) -> Result<(SmartPointer<EVP_PKEY>, Vec<u8>), SecioError> {
    let mut ecdh_public_key = Vec::with_capacity(pubkey_len);
    unsafe {
        ecdh_public_key.set_len(pubkey_len);
        let evp_key = generater_secpvx(NID_secp384r1, &mut ecdh_public_key)?;

        Ok((evp_key, ecdh_public_key))
    }
}

fn p384_from_pubkey(other_public_key: &[u8]) -> Result<SmartPointer<EVP_PKEY>, SecioError> {
    unsafe { secpvx_from_pubkey(NID_secp384r1, other_public_key) }
}

fn x25519_generate(mut pubkey_len: usize) -> Result<(SmartPointer<EVP_PKEY>, Vec<u8>), SecioError> {
    unsafe {
        let evp_key = SmartPointer::new_unchecked(EVP_PKEY_new(), EVP_PKEY_free);

        let ctx = SmartPointer::new_unchecked(
            EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, null_mut()),
            EVP_PKEY_CTX_free,
        );

        if 1 != EVP_PKEY_keygen_init(ctx.as_ptr()) {
            debug!("init evp ctx fail");

            return Err(SecioError::EphemeralKeyGenerationFailed);
        }

        if 1 != EVP_PKEY_keygen(ctx.as_ptr(), &mut evp_key.as_ptr()) {
            debug!("evp keygen fail");

            return Err(SecioError::EphemeralKeyGenerationFailed);
        }

        let mut pubkey = Vec::with_capacity(pubkey_len);

        pubkey.set_len(pubkey_len);

        if 1 != EVP_PKEY_get_raw_public_key(
            evp_key.as_ptr(),
            pubkey.as_mut_ptr(),
            &mut pubkey_len as _,
        ) {
            debug!("evp key get pubkey fail");

            return Err(SecioError::EphemeralKeyGenerationFailed);
        }

        Ok((evp_key, pubkey))
    }
}

fn x25519_from_pubkey(pubkey: &[u8]) -> Result<SmartPointer<EVP_PKEY>, SecioError> {
    unsafe {
        let evp_key =
            EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, null_mut(), pubkey.as_ptr(), pubkey.len());

        if evp_key.is_null() {
            debug!("fail to recover peer evp key");
            return Err(SecioError::SecretGenerationFailed);
        }

        Ok(SmartPointer::new_unchecked(evp_key, EVP_PKEY_free))
    }
}

struct Algorithm {
    _private_len: usize,
    pubkey_len: usize,
    pairs_generate: fn(usize) -> Result<(SmartPointer<EVP_PKEY>, Vec<u8>), SecioError>,
    from_pubkey: fn(&[u8]) -> Result<SmartPointer<EVP_PKEY>, SecioError>,
}

impl From<KeyAgreement> for &'static Algorithm {
    fn from(src: KeyAgreement) -> &'static Algorithm {
        match src {
            KeyAgreement::EcdhP256 => &ECDH_P256,
            KeyAgreement::EcdhP384 => &ECDH_P384,
            KeyAgreement::X25519 => &X25519,
        }
    }
}

pub struct EphemeralPrivateKey {
    evp_key: SmartPointer<EVP_PKEY>,
    al: &'static Algorithm,
}

/// RAII pointer
struct SmartPointer<T: ?Sized> {
    pointer: *mut T,
    drop: unsafe extern "C" fn(*mut T),
}

impl<T> SmartPointer<T> {
    unsafe fn new_unchecked(ptr: *mut T, drop: unsafe extern "C" fn(*mut T)) -> Self {
        SmartPointer { pointer: ptr, drop }
    }

    pub unsafe fn as_mut<'a>(&mut self) -> &'a mut T {
        &mut *self.pointer
    }

    pub const fn as_ptr(&self) -> *mut T {
        self.pointer as *mut T
    }
}

impl<T> Deref for SmartPointer<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.pointer }
    }
}

impl<T> DerefMut for SmartPointer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.pointer }
    }
}

impl<T: ?Sized> Drop for SmartPointer<T> {
    fn drop(&mut self) {
        unsafe {
            if !self.pointer.is_null() {
                (self.drop)(self.pointer)
            }
        }
    }
}

unsafe impl<T> Send for SmartPointer<T> {}

pub fn generate_agreement(
    algorithm: KeyAgreement,
) -> Result<(EphemeralPrivateKey, Vec<u8>), SecioError> {
    let al: &'static Algorithm = algorithm.into();

    let (evp_key, ecdh_public_key) = (al.pairs_generate)(al.pubkey_len)?;

    Ok((EphemeralPrivateKey { evp_key, al }, ecdh_public_key))
}

pub fn agree(
    _algorithm: KeyAgreement,
    mut my_private_key: EphemeralPrivateKey,
    other_public_key: &[u8],
) -> Result<Vec<u8>, SecioError> {
    if other_public_key.len() != my_private_key.al.pubkey_len {
        return Err(SecioError::SecretGenerationFailed);
    }

    let mut secret: Vec<u8>;
    unsafe {
        let mut peer_evp_key = (my_private_key.al.from_pubkey)(other_public_key)?;

        let ctx = SmartPointer::new_unchecked(
            EVP_PKEY_CTX_new(my_private_key.evp_key.as_mut(), null_mut()),
            EVP_PKEY_CTX_free,
        );

        if ctx.as_ptr().is_null() {
            debug!("EVP_PKEY_CTX create fail");

            return Err(SecioError::SecretGenerationFailed);
        }

        if 1 != EVP_PKEY_derive_init(ctx.as_ptr()) {
            debug!("EVP_PKEY derive init fail");

            return Err(SecioError::SecretGenerationFailed);
        }

        if 1 != EVP_PKEY_derive_set_peer(ctx.as_ptr(), peer_evp_key.as_mut()) {
            debug!("EVP_PKEY derive set peer key fail");

            return Err(SecioError::SecretGenerationFailed);
        }

        let mut secret_len: usize = 0;

        if 1 != EVP_PKEY_derive(ctx.as_ptr(), null_mut(), &mut secret_len as _) {
            debug!("EVP_PKEY derive set secret len fail");

            return Err(SecioError::SecretGenerationFailed);
        }

        secret = Vec::with_capacity(secret_len);
        secret.set_len(secret_len);

        if 1 != EVP_PKEY_derive(ctx.as_ptr(), secret.as_mut_ptr(), &mut secret_len as _) {
            debug!("EVP_PKEY derive secret key fail");

            return Err(SecioError::SecretGenerationFailed);
        }
    }

    Ok(secret)
}

extern "C" {
    // deprecated function, Applications should instead use EVP_PKEY_fromdata(3).
    // but EVP_PKEY_fromdata need EVP_PKEY_CTX_new_from_name can't find on my local libssl-dev with "undefined symbol: EVP_PKEY_CTX_new_from_name"
    pub fn EVP_PKEY_set1_EC_KEY(evp_key: *mut EVP_PKEY, ec_key: *mut EC_KEY) -> libc::c_int;
}

#[cfg(test)]
mod test {
    use super::{agree, generate_agreement};
    use crate::dh_compat::{
        ring_impl::{agree as agree_ring, generate_agreement as generate_agreement_ring},
        KeyAgreement,
    };

    fn test_ecdh(ty: KeyAgreement) {
        let (private_key, pub_key) = generate_agreement(ty).unwrap();

        let (peer_private_key, peer_pub_key) = generate_agreement_ring(ty).unwrap();

        let a = agree(ty, private_key, &peer_pub_key).unwrap();
        let b = agree_ring(ty, peer_private_key, &pub_key).unwrap();

        assert_eq!(a, b, "{:?} fail", ty)
    }

    #[test]
    fn test_all_ecdh() {
        test_ecdh(KeyAgreement::EcdhP256);
        test_ecdh(KeyAgreement::EcdhP384);
        test_ecdh(KeyAgreement::X25519);
    }
}
