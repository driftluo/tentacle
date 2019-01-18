//! A multiplexed p2p network based on yamux that supports mounting custom protocols
//!
//!

#![deny(missing_docs)]

/// Re-pub multiaddr crate
pub use multiaddr;
/// Re-pub some useful structures in secio
pub use secio::{PublicKey, SecioKeyPair};
/// Re-pub some useful structures in yamux
pub use yamux::{session::SessionType, Session};

/// Some gadgets that help create a service
pub mod builder;
/// Context for Session and Service
pub mod context;
/// Error
pub mod error;
/// Protocol select
pub mod protocol_select;
/// An abstraction of p2p service
pub mod service;
/// Wrapper for real data streams
pub mod session;
/// Each custom protocol in a session corresponds to a sub stream
pub mod substream;
/// Useful traits
pub mod traits;
/// Some useful functions
pub mod utils;

/// Index of sub/protocol stream
pub type StreamId = usize;
/// Protocol id
pub type ProtocolId = usize;
/// Index of session
pub type SessionId = usize;
