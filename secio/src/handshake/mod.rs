/// Most of the code for this module comes from `rust-libp2p`, but modified some logic(struct).
use crate::{
    codec::stream_handle::StreamHandle, crypto::cipher::CipherType, error::SecioError,
    exchange::KeyAgreement, handshake::procedure::handshake, support, Digest, EphemeralPublicKey,
    PublicKey, SecioKeyPair,
};

use tokio::prelude::{AsyncRead, AsyncWrite};

#[cfg(all(feature = "flatc", feature = "molc"))]
compile_error!("features `flatc` and `molc` are mutually exclusive");
#[cfg(all(not(feature = "flatc"), not(feature = "molc")))]
compile_error!("Please choose a serialization format via feature. Possible choices: flatc, molc");

#[cfg(feature = "flatc")]
#[rustfmt::skip]
#[allow(clippy::all)]
mod handshake_generated;
#[cfg(feature = "flatc")]
#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod handshake_generated_verifier;
#[cfg(feature = "molc")]
#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod handshake_mol;

mod handshake_context;
pub(crate) mod handshake_struct;
mod procedure;

const MAX_FRAME_SIZE: usize = 1024 * 1024 * 8;

/// Config for Secio
#[derive(Debug, Clone)]
pub struct Config {
    pub(crate) key: SecioKeyPair,
    pub(crate) agreements_proposal: Option<String>,
    pub(crate) ciphers_proposal: Option<String>,
    pub(crate) digests_proposal: Option<String>,
    pub(crate) max_frame_length: usize,
}

impl Config {
    /// Create config
    pub fn new(key_pair: SecioKeyPair) -> Self {
        Config {
            key: key_pair,
            agreements_proposal: None,
            ciphers_proposal: None,
            digests_proposal: None,
            max_frame_length: MAX_FRAME_SIZE,
        }
    }

    /// Max frame length
    pub fn max_frame_length(mut self, size: usize) -> Self {
        self.max_frame_length = size;
        self
    }

    /// Override the default set of supported key agreement algorithms.
    pub fn key_agreements<'a, I>(mut self, xs: I) -> Self
    where
        I: IntoIterator<Item = &'a KeyAgreement>,
    {
        self.agreements_proposal = Some(support::key_agreements_proposition(xs));
        self
    }

    /// Override the default set of supported ciphers.
    pub fn ciphers<'a, I>(mut self, xs: I) -> Self
    where
        I: IntoIterator<Item = &'a CipherType>,
    {
        self.ciphers_proposal = Some(support::ciphers_proposition(xs));
        self
    }

    /// Override the default set of supported digest algorithms.
    pub fn digests<'a, I>(mut self, xs: I) -> Self
    where
        I: IntoIterator<Item = &'a Digest>,
    {
        self.digests_proposal = Some(support::digests_proposition(xs));
        self
    }

    /// Attempts to perform a handshake on the given socket.
    ///
    /// On success, produces a `SecureStream` that can then be used to encode/decode
    /// communications, plus the public key of the remote, plus the ephemeral public key.
    pub async fn handshake<T>(
        self,
        socket: T,
    ) -> Result<(StreamHandle, PublicKey, EphemeralPublicKey), SecioError>
    where
        T: AsyncRead + AsyncWrite + Send + 'static + Unpin,
    {
        handshake(socket, self).await
    }
}
