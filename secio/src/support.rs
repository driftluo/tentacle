use crate::error::SecioError;
use crate::exchange::KeyAgreement;
use crate::{stream_cipher::Cipher, Digest};

use std::cmp::Ordering;

const ECDH_P256: &str = "P-256";
const ECDH_P384: &str = "P-384";

const AES_128: &str = "AES-128";
const AES_256: &str = "AES-256";
const TWOFISH_CTR: &str = "TwofishCTR";
//const NULL: &str = "NULL";

const SHA_256: &str = "SHA256";
const SHA_512: &str = "SHA512";

pub(crate) const DEFAULT_AGREEMENTS_PROPOSITION: &str = "P-256,P-384";
pub(crate) const DEFAULT_CIPHERS_PROPOSITION: &str = "AES-128,AES-256,TwofishCTR";
pub(crate) const DEFAULT_DIGESTS_PROPOSITION: &str = "SHA256,SHA512";

/// Return a proposition string from the given sequence of `KeyAgreement` values.
pub fn key_agreements_proposition<'a, I>(exchanges: I) -> String
where
    I: IntoIterator<Item = &'a KeyAgreement>,
{
    let mut s = String::new();
    for x in exchanges {
        match x {
            KeyAgreement::EcdhP256 => {
                s.push_str(ECDH_P256);
                s.push(',')
            }
            KeyAgreement::EcdhP384 => {
                s.push_str(ECDH_P384);
                s.push(',')
            }
        }
    }
    s.pop(); // remove trailing comma if any
    s
}

/// Given two key agreement proposition strings try to figure out a match.
///
/// The `Ordering` parameter determines which argument is preferred. If `Less` or `Equal` we
/// try for each of `theirs` every one of `ours`, for `Greater` it's the other way around.
pub fn select_agreement(r: Ordering, ours: &str, theirs: &str) -> Result<KeyAgreement, SecioError> {
    let (a, b) = match r {
        Ordering::Less | Ordering::Equal => (theirs, ours),
        Ordering::Greater => (ours, theirs),
    };
    for x in a.split(',') {
        if b.split(',').any(|y| x == y) {
            match x {
                ECDH_P256 => return Ok(KeyAgreement::EcdhP256),
                ECDH_P384 => return Ok(KeyAgreement::EcdhP384),
                _ => continue,
            }
        }
    }
    Err(SecioError::NoSupportIntersection)
}

/// Return a proposition string from the given sequence of `Cipher` values.
pub fn ciphers_proposition<'a, I>(ciphers: I) -> String
where
    I: IntoIterator<Item = &'a Cipher>,
{
    let mut s = String::new();
    for c in ciphers {
        match c {
            Cipher::Aes128 => {
                s.push_str(AES_128);
                s.push(',')
            }
            Cipher::Aes256 => {
                s.push_str(AES_256);
                s.push(',')
            }
            Cipher::TwofishCtr => {
                s.push_str(TWOFISH_CTR);
                s.push(',')
            } //            Cipher::Null => {
              //                s.push_str(NULL);
              //                s.push(',')
              //            }
        }
    }
    s.pop(); // remove trailing comma if any
    s
}

/// Return a proposition string from the given sequence of `Digest` values.
pub fn digests_proposition<'a, I>(digests: I) -> String
where
    I: IntoIterator<Item = &'a Digest>,
{
    let mut s = String::new();
    for d in digests {
        match d {
            Digest::Sha256 => {
                s.push_str(SHA_256);
                s.push(',')
            }
            Digest::Sha512 => {
                s.push_str(SHA_512);
                s.push(',')
            }
        }
    }
    s.pop(); // remove trailing comma if any
    s
}

/// Given two digest proposition strings try to figure out a match.
///
/// The `Ordering` parameter determines which argument is preferred. If `Less` or `Equal` we
/// try for each of `theirs` every one of `ours`, for `Greater` it's the other way around.
pub fn select_digest(r: Ordering, ours: &str, theirs: &str) -> Result<Digest, SecioError> {
    let (a, b) = match r {
        Ordering::Less | Ordering::Equal => (theirs, ours),
        Ordering::Greater => (ours, theirs),
    };
    for x in a.split(',') {
        if b.split(',').any(|y| x == y) {
            match x {
                SHA_256 => return Ok(Digest::Sha256),
                SHA_512 => return Ok(Digest::Sha512),
                _ => continue,
            }
        }
    }
    Err(SecioError::NoSupportIntersection)
}

/// Given two cipher proposition strings try to figure out a match.
///
/// The `Ordering` parameter determines which argument is preferred. If `Less` or `Equal` we
/// try for each of `theirs` every one of `ours`, for `Greater` it's the other way around.
pub fn select_cipher(r: Ordering, ours: &str, theirs: &str) -> Result<Cipher, SecioError> {
    let (a, b) = match r {
        Ordering::Less | Ordering::Equal => (theirs, ours),
        Ordering::Greater => (ours, theirs),
    };
    for x in a.split(',') {
        if b.split(',').any(|y| x == y) {
            match x {
                AES_128 => return Ok(Cipher::Aes128),
                AES_256 => return Ok(Cipher::Aes256),
                TWOFISH_CTR => return Ok(Cipher::TwofishCtr),
                //                NULL => return Ok(Cipher::Null),
                _ => continue,
            }
        }
    }
    Err(SecioError::NoSupportIntersection)
}
