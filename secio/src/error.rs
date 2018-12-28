use std::io;

/// Error at the SECIO layer communication.
#[derive(Debug)]
pub enum SecioError {
    /// I/O error.
    IoError(io::Error),

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

    /// We received an invalid proposition from remote.
    InvalidProposition(&'static str),
}

impl From<io::Error> for SecioError {
    #[inline]
    fn from(err: io::Error) -> SecioError {
        SecioError::IoError(err)
    }
}
