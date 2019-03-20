//! ## Summary
//!
//! A multiplexed p2p network framework based on yamux that supports mounting custom protocols.
//!
//! The crate is aimed at implementing a framework that light weight, simple, reliable, high performance, and friendly to users.
//!
//! ### Concept
//!
//! #### Multiaddr
//!
//! [Multiaddr](https://github.com/multiformats/multiaddr) aims to make network addresses future-proof, composable, and efficient.
//!
//! It can express almost all network protocols, such as:
//! - TCP/IP: `/ip4/127.0.0.1/tcp/1337`
//! - DNS/IP: `/dns4/localhost/tcp/1337`
//! - UDP: `/ip4/127.0.0.1/udp/1234`
//!

#![deny(missing_docs)]

/// Re-pub multiaddr crate
pub use multiaddr;
/// Re-pub secio crate
pub use secio;
/// Re-pub yamux crate
pub use yamux;

/// Some gadgets that help create a service
pub mod builder;
/// Context for Session and Service
pub mod context;
/// Error
pub mod error;
/// Protocol handle callback stream
pub(crate) mod protocol_handle_stream;
/// Protocol select
pub mod protocol_select;
/// An abstraction of p2p service
pub mod service;
/// Wrapper for real data streams
pub(crate) mod session;
/// Each custom protocol in a session corresponds to a sub stream
pub(crate) mod substream;
/// Useful traits
pub mod traits;
/// Underlying transport protocols wrapper
pub(crate) mod transports;
/// Some useful functions
pub mod utils;

/// Index of sub/protocol stream
pub type StreamId = usize;
/// Protocol id
pub type ProtocolId = usize;
/// Index of session
pub type SessionId = usize;
