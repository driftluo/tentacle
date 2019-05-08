/// Most of the code for this module comes from `rust-libp2p`, but modified some logic(struct).
use crate::{
    codec::{secure_stream::StreamConfig, stream_handle::StreamHandle},
    error::SecioError,
    exchange::KeyAgreement,
    handshake::procedure::handshake,
    stream_cipher::Cipher,
    support, Digest, EphemeralPublicKey, PublicKey, SecioKeyPair,
};

use futures::Future;
use tokio::prelude::{AsyncRead, AsyncWrite};

mod handshake_context;
#[rustfmt::skip]
#[allow(clippy::all)]
mod handshake_generated;
#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod handshake_generated_verifier;
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
    pub(crate) stream_config: StreamConfig,
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
            stream_config: StreamConfig::new(),
        }
    }

    /// Max frame length
    pub fn max_frame_length(mut self, size: usize) -> Self {
        // if max > default, change all size limit to max
        if size > MAX_FRAME_SIZE {
            self.stream_config.frame_size = size;
            self.stream_config.send_buffer_size = size;
            self.stream_config.recv_buffer_size = size;
        }
        self.max_frame_length = size;
        self
    }

    /// Set secure stream config
    pub fn stream_config(mut self, config: StreamConfig) -> Self {
        self.stream_config = config;
        if self.stream_config.frame_size == 0 {
            panic!("frame_size can't be zero")
        }
        if self.stream_config.frame_size > MAX_FRAME_SIZE {
            self.max_frame_length = self.stream_config.frame_size;
        }
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
        I: IntoIterator<Item = &'a Cipher>,
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
    pub fn handshake<T>(
        self,
        socket: T,
    ) -> impl Future<Item = (StreamHandle, PublicKey, EphemeralPublicKey), Error = SecioError>
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        handshake(socket, self)
    }
}
