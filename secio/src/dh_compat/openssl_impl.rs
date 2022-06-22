use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
};

use crate::{dh_compat::KeyAgreement, error::SecioError};

type PairsGenarate = fn() -> Result<(PKey<Private>, Vec<u8>), SecioError>;

struct Algorithm {
    _private_len: usize,
    pubkey_len: usize,
    pairs_generate: PairsGenarate,
    from_pubkey: fn(&[u8]) -> Result<PKey<Public>, SecioError>,
}

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

#[cfg(ossl110)]
static X25519: Algorithm = Algorithm {
    _private_len: 32,
    pubkey_len: 32,
    pairs_generate: x25519_generate,
    from_pubkey: x25519_from_pubkey,
};

impl From<KeyAgreement> for &'static Algorithm {
    fn from(src: KeyAgreement) -> &'static Algorithm {
        match src {
            KeyAgreement::EcdhP256 => &ECDH_P256,
            KeyAgreement::EcdhP384 => &ECDH_P384,
            #[cfg(ossl110)]
            KeyAgreement::X25519 => &X25519,
            #[cfg(not(ossl110))]
            _ => panic!("ECDH {:?} does not supported by openssl yet", src),
        }
    }
}

pub struct EphemeralPrivateKey {
    evp_key: PKey<Private>,
    al: &'static Algorithm,
}

fn ec_generate(nid: Nid) -> Result<(PKey<Private>, Vec<u8>), SecioError> {
    let group = EcGroup::from_curve_name(nid)?;

    let mut ctx = BigNumContext::new()?;

    let ec_key = EcKey::generate(&group)?;

    let pubkey =
        ec_key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

    let evp_key = PKey::from_ec_key(ec_key)?;
    Ok((evp_key, pubkey))
}

fn ec_from_pubkey(nid: Nid, other_public_key: &[u8]) -> Result<PKey<Public>, SecioError> {
    let group = EcGroup::from_curve_name(nid)?;
    let mut ctx = BigNumContext::new()?;

    let point = EcPoint::from_bytes(&group, other_public_key, &mut ctx)?;

    let ec_key = EcKey::from_public_key(&group, &point)?;
    PKey::from_ec_key(ec_key).map_err(Into::into)
}

fn p256_generate() -> Result<(PKey<Private>, Vec<u8>), SecioError> {
    ec_generate(Nid::X9_62_PRIME256V1)
}

fn p256_from_pubkey(other_public_key: &[u8]) -> Result<PKey<Public>, SecioError> {
    ec_from_pubkey(Nid::X9_62_PRIME256V1, other_public_key)
}

fn p384_generate() -> Result<(PKey<Private>, Vec<u8>), SecioError> {
    ec_generate(Nid::SECP384R1)
}

fn p384_from_pubkey(other_public_key: &[u8]) -> Result<PKey<Public>, SecioError> {
    ec_from_pubkey(Nid::SECP384R1, other_public_key)
}

#[cfg(ossl110)]
fn x25519_generate() -> Result<(PKey<Private>, Vec<u8>), SecioError> {
    let evp_key = PKey::generate_x25519()?;

    let pubkey = evp_key.as_ref().raw_public_key()?;

    Ok((evp_key, pubkey))
}

#[cfg(ossl110)]
fn x25519_from_pubkey(pubkey: &[u8]) -> Result<PKey<Public>, SecioError> {
    PKey::public_key_from_raw_bytes(pubkey, Id::X25519).map_err(Into::into)
}

pub fn generate_agreement(
    algorithm: KeyAgreement,
) -> Result<(EphemeralPrivateKey, Vec<u8>), SecioError> {
    let al: &'static Algorithm = algorithm.into();

    let (evp_key, ecdh_public_key) = (al.pairs_generate)()?;

    Ok((EphemeralPrivateKey { evp_key, al }, ecdh_public_key))
}

pub fn agree(
    _algorithm: KeyAgreement,
    my_private_key: EphemeralPrivateKey,
    other_public_key: &[u8],
) -> Result<Vec<u8>, SecioError> {
    if other_public_key.len() != my_private_key.al.pubkey_len {
        return Err(SecioError::SecretGenerationFailed);
    }

    let peer_evp_key = (my_private_key.al.from_pubkey)(other_public_key)?;

    let mut deriver = Deriver::new(&my_private_key.evp_key)?;

    deriver.set_peer(&peer_evp_key)?;

    deriver.derive_to_vec().map_err(Into::into)
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
        #[cfg(ossl110)]
        test_ecdh(KeyAgreement::X25519);
    }
}
