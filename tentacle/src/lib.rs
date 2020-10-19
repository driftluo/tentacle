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

/// Re-pub bytes crate
pub use bytes;
/// Re-pub multiaddr crate
pub use multiaddr;
/// Re-pub secio crate
pub use secio;
/// Re-pub yamux crate
pub use yamux;

/// Buffer management in distribution mode
pub(crate) mod buffer;
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

mod channel;
mod runtime;

pub(crate) mod upnp;

use std::{fmt, ops::AddAssign};

/// Index of sub/protocol stream
type StreamId = usize;
/// Protocol id
#[derive(Debug, Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct ProtocolId(usize);

impl ProtocolId {
    /// New a protocol id
    pub const fn new(id: usize) -> Self {
        ProtocolId(id)
    }

    /// Get inner value
    pub const fn value(self) -> usize {
        self.0
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ProtocolId({})", self.0)
    }
}

impl From<usize> for ProtocolId {
    fn from(id: usize) -> Self {
        ProtocolId::new(id)
    }
}

/// Index of session
#[derive(Debug, Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct SessionId(usize);

impl SessionId {
    /// New a session id
    pub const fn new(id: usize) -> Self {
        SessionId(id)
    }

    /// Get inner value
    pub const fn value(self) -> usize {
        self.0
    }

    pub(crate) const fn wrapping_add(self, rhs: usize) -> SessionId {
        SessionId(self.0.wrapping_add(rhs))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SessionId({})", self.0)
    }
}

impl AddAssign<usize> for SessionId {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs
    }
}

impl From<usize> for SessionId {
    fn from(id: usize) -> Self {
        SessionId(id)
    }
}
