/// Errors that can occur in the QUIC transport.
#[derive(Debug, thiserror::Error)]
pub enum QuicErrorKind {
    /// Failed to build or parse the X.509 certificate.
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// Failed to sign the binding payload with the secio key.
    #[error("Secio signing error: {0}")]
    SigningError(String),

    /// Unable to find tentacle OID extension
    #[error("Certificate extension not found")]
    ExtensionNotFound,

    /// Unsupported identity version
    #[error("Unsupported identity version: {0}")]
    IdentityVersionUnsupported(u8),

    /// Multiple identity found
    #[error("Multiple identity found")]
    MultipleIdentityFound,

    /// Multiaddr is not a valid QUIC address (must be `/ip{4,6}/.../udp/.../quic-v1`).
    #[error("Invalid QUIC multiaddr: {0}")]
    InvalidAddress(String),

    /// Configured TLS settings are not acceptable for QUIC (e.g. wrong cipher suite).
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    /// Underlying UDP socket bind / endpoint construction failed.
    #[error("Endpoint bind failed: {0}")]
    EndpointBind(#[from] std::io::Error),

    /// Failed to start dialing — invalid configuration / server name etc.
    #[error("Connect failed: {0}")]
    Connect(#[from] quinn::ConnectError),

    /// QUIC connection ended in failure (handshake timeout, transport error, …).
    #[error("Connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// Peer did not present a TLS certificate during the QUIC handshake.
    #[error("Peer did not present a certificate")]
    NoPeerCert,

    /// `ServiceBuilder::quic_config(...)` was not called, so the QUIC
    /// transport is unavailable. Distinct from
    /// [`crate::error::TransportErrorKind::NotSupported`]: the address
    /// shape is fine, the service just hasn't opted into QUIC.
    #[error("QUIC transport is not configured; call ServiceBuilder::quic_config(...) to enable")]
    NotConfigured,

    /// QUIC was requested via `ServiceBuilder::quic_config(...)` but the
    /// service is internally inconsistent — e.g. `HandshakeType::Noop`
    /// (QUIC's TLS identity binding requires a secio key), or
    /// `QuicEndpoint::new` failed at build time.
    #[error("QUIC misconfigured: {0}")]
    Misconfigured(String),
}
