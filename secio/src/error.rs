/// I borrowed the error type of `rust-libp2p`, deleted some error types, and added an error type.
use std::{error, fmt, io};

/// Error at the SECIO layer communication.
#[derive(Debug)]
pub enum SecioError {
    /// I/O error.
    IoError(io::Error),

    /// Openssl stack error
    #[cfg(unix)]
    Openssl(openssl::error::ErrorStack),

    /// Crypto error
    CryptoError,

    /// Failed to generate ephemeral key.
    EphemeralKeyGenerationFailed,

    /// Failed to generate the secret shared key from the ephemeral key.
    SecretGenerationFailed,

    /// There is no protocol supported by both the local and remote hosts.
    NoSupportIntersection,

    /// The final check of the handshake failed.
    NonceVerificationFailed,

    /// The received frame was of invalid length.
    FrameTooShort,

    /// The hashes of the message didn't match.
    HmacNotMatching,

    /// Connect yourself
    ConnectSelf,

    /// Failed to parse one of the handshake bincode messages.
    HandshakeParsingFailure,

    /// The signature of the exchange packet doesn't verify the remote public key.
    SignatureVerificationFailed,

    /// Invalid message message found during handshake
    InvalidMessage,

    /// We received an invalid proposition from remote.
    InvalidProposition(&'static str),
}

impl PartialEq for SecioError {
    fn eq(&self, other: &SecioError) -> bool {
        use self::SecioError::*;
        match (self, other) {
            (InvalidProposition(i), InvalidProposition(j)) => i == j,
            (EphemeralKeyGenerationFailed, EphemeralKeyGenerationFailed)
            | (SecretGenerationFailed, SecretGenerationFailed)
            | (NoSupportIntersection, NoSupportIntersection)
            | (NonceVerificationFailed, NonceVerificationFailed)
            | (FrameTooShort, FrameTooShort)
            | (HmacNotMatching, HmacNotMatching)
            | (ConnectSelf, ConnectSelf)
            | (HandshakeParsingFailure, HandshakeParsingFailure)
            | (SignatureVerificationFailed, SignatureVerificationFailed)
            | (InvalidMessage, InvalidMessage) => true,
            _ => false,
        }
    }
}

impl From<io::Error> for SecioError {
    #[inline]
    fn from(err: io::Error) -> SecioError {
        SecioError::IoError(err)
    }
}

impl From<SecioError> for io::Error {
    #[inline]
    fn from(err: SecioError) -> io::Error {
        match err {
            SecioError::IoError(e) => e,
            e => io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()),
        }
    }
}

#[cfg(unix)]
impl From<openssl::error::ErrorStack> for SecioError {
    fn from(err: openssl::error::ErrorStack) -> SecioError {
        SecioError::Openssl(err)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<ring::error::Unspecified> for SecioError {
    fn from(_err: ring::error::Unspecified) -> SecioError {
        SecioError::CryptoError
    }
}

impl error::Error for SecioError {}

impl fmt::Display for SecioError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SecioError::IoError(e) => fmt::Display::fmt(&e, f),
            #[cfg(unix)]
            SecioError::Openssl(e) => fmt::Display::fmt(&e, f),
            SecioError::CryptoError => write!(f, "Crypto Error"),
            SecioError::EphemeralKeyGenerationFailed => write!(f, "EphemeralKey Generation Failed"),
            SecioError::SecretGenerationFailed => write!(f, "Secret Generation Failed"),
            SecioError::NoSupportIntersection => write!(f, "No Support Intersection"),
            SecioError::NonceVerificationFailed => write!(f, "Nonce Verification Failed"),
            SecioError::FrameTooShort => write!(f, "Frame Too Short"),
            SecioError::HmacNotMatching => write!(f, "Hmac Not Matching"),
            SecioError::ConnectSelf => write!(f, "Connect Self"),
            SecioError::HandshakeParsingFailure => write!(f, "Handshake Parsing Failure"),
            SecioError::InvalidMessage => write!(f, "Invalid Message"),
            SecioError::SignatureVerificationFailed => write!(f, "Signature Verification Failed"),
            SecioError::InvalidProposition(e) => write!(f, "Invalid Proposition: {}", e),
        }
    }
}
