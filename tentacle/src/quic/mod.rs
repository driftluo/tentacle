//! QUIC transport for tentacle.
//!
//! Implements an alternative transport stack that replaces the classic
//! TCP + secio + yamux pipeline with QUIC + a tentacle-specific TLS
//! identity binding. The two stacks coexist inside the same `Service`
//! and are dispatched by multiaddr shape (`/ip{4,6}/.../udp/.../quic-v1`
//! routes here, everything else continues through the classic pipeline).
//!
//! Sub-module breakdown:
//! - [`config`]: user-facing transport configuration (idle timeouts,
//!   keep-alive, stream limits).
//! - [`error`]: QUIC-specific error variants surfaced to the rest of
//!   the crate via [`crate::error::TransportErrorKind::QuicError`].
//! - [`identity`]: build / parse the self-signed TLS certificate that
//!   carries the tentacle identity X.509 extension.
//! - [`identity_mol`]: molecule-generated codec for the identity
//!   payload (auto-generated from `identity.mol`; not edited by hand).
//! - [`verifier`]: custom rustls certificate verifiers that swap the
//!   conventional CA / hostname model for the tentacle identity binding.
//! - [`endpoint`]: factory for QUIC listeners and outgoing dials,
//!   wrapping `quinn::Endpoint`.
//! - [`stream`]: adapter that exposes a `quinn` bidirectional stream as
//!   tokio `AsyncRead + AsyncWrite`.
//! - [`session`]: per-connection main loop, mirroring
//!   [`crate::session::Session`] for the QUIC backend.

/// Molecule-generated codec for the tentacle QUIC identity payload.
///
/// Auto-generated from `identity.mol` by `moleculec`; kept
/// `pub(crate)` so its undocumented generated types do not leak into
/// the public API. The hand-written wrapper
/// [`identity::TentacleQuicIdentity`] is what consumers see.
pub(crate) mod identity_mol;

/// User-facing transport configuration for the QUIC stack.
pub mod config;

/// Self-signed TLS certificate construction and identity-extension
/// parsing for the tentacle QUIC binding.
pub mod identity;

/// Error variants for the QUIC transport.
pub mod error;

/// Custom rustls certificate verifiers implementing the tentacle
/// identity binding (replaces conventional CA / hostname checks).
pub mod verifier;

/// Adapter exposing a `quinn` bidirectional stream as
/// `AsyncRead + AsyncWrite` so it can carry tentacle protocols.
pub mod stream;

/// Factory for QUIC listeners and outgoing dials, plus address
/// parsing helpers.
pub mod endpoint;

/// QUIC-backed tentacle session main loop.
pub mod session;
