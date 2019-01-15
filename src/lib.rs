//! A multiplexed p2p network based on yamux that supports mounting custom protocols
//!
//!

#![deny(missing_docs)]

/// Some gadgets that help create a service
pub mod builder;
/// An abstraction of p2p service
pub mod service;
/// Wrapper for real data streams
pub mod session;
/// Each custom protocol in a session corresponds to a sub stream
pub mod substream;
/// Re-pub some useful structures in secio
pub use secio::{PublicKey, SecioKeyPair};
/// Re-pub some useful structures in yamux
pub use yamux::{session::SessionType, Session};
/// Protocol select
pub mod protocol_select;
/// Re-pub multiaddr crate
pub use multiaddr;
