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
//! - Websocket: `/ip4/127.0.0.1/tcp/1337/ws`
//! - Tls: `/ip4/127.0.0.1/tcp/1337/tls/domain_name.com`
//!
//! #### Protocol
//!
//! In this library, the most important concept is protocol, so we need to clarify what is the protocol defined by tentacle.
//!
//! If you use the simplest way to understand, then it can be compared to the http protocol on the TCP protocol,
//! that is, each protocol can have its own behavior standards, analysis methods, etc.
//!
//! As a framework, a builder is provided to describe the standard protocol, and three traits
//! are provided to define the behavior of the protocol. Unfortunately, users also need an event trait to
//! perceive other events that occur in the service, such as session establishment, protocol exceptions, etc.
//!
//! builder: [`MetaBuilder`]
//!
//! traits: [`ServiceProtocol`]/[`SessionProtocol`]/[`ProtocolSpawn`]
//!
//! event trait: [`ServiceHandle`]
//!
//! The biggest question users may have is why there are three different traits defining protocol behavior.
//!
//! These three traits can be divided into two groups, representing two different design ideas:
//!
//! ##### Callback
//!
//! user can only do what it defines, tentacle has stronger constraints on it
//!
//! [`ServiceProtocol`] defines a globally unique single-protocol processing capability, and
//! all the protocol data and behaviors opened by the session will be summarized here for processing.
//! Its lifetime is from the start of the service to the end.
//!
//! [`SessionProtocol`] its lifetime is only in the phase when the corresponding session is opened,
//! the session is disconnected, and the handle drop, session open, handle open. That's all.
//!
//! Obviously, there is an abstraction of data interception
//!
//! ##### Stream
//!
//! user can combine stream with any existing future ecology, tentacle restricts it weaker
//!
//! [`ProtocolSpawn`] Users can get a perfect asynchronous environment to make complex control flow,
//! and even use this trait to implement data summary processing in callback mode again
//!
//! Compared with callback mode, it reduces a layer of abstraction
//!
//! ### Use tentacle
//!
//! 1. Define protocol behavior with [Callback](#callback) or [Stream](#stream) trait
//! 2. Define [`ServiceHandle`] to process other event output on tentacle service
//! 3. Build all need [`ProtocolMeta`] from [`MetaBuilder`]
//! 4. Register all [`ProtocolMeta`] into [`ServiceBuilder`], then build [`Service`]
//! 5. Setup an async runtime such as tokio
//! 6. Run [`Service`] just like other stream, maybe keep a [`Control`] on some place which want to
//!    communicate with background [`Service`]
//!
//! ### Feature flags
//! Tentacle uses the Feature flag to enable some optional functions and split the smallest dependencies
//! for use as much as possible. Users can choose the dependencies they want according to their needs.
//!
//! Related to runtime :
//! - `tokio-runtime`: Enable by default, use tokio runtime
//! - `tokio-timer`: Enable by default, use tokio inner timer
//!
//! - `async-timer`: use async-io timer
//! - `async-runtime`: use async-std runtime
//!
//! - `generic-timer`: use futures-timer
//! - `wasm-timer`: only use on Browser WebAssembly platform
//!
//! Function related:
//! - `ws`: Enable websocket protocol support
//! - `upnp`: Enable upnp protocol, automatically try to register the port to the gateway
//! - `unstable`: Enable the feature that has not yet decided to stabilize the API
//! - `parking_lot`: Enable priority channel use `parking_lot`
//!
//! [`MetaBuilder`]: crate::builder::MetaBuilder
//! [`ServiceBuilder`]: crate::builder::ServiceBuilder
//! [`ServiceProtocol`]: crate::traits::ServiceProtocol
//! [`SessionProtocol`]: crate::traits::SessionProtocol
//! [`ProtocolSpawn`]: crate::traits::ProtocolSpawn
//! [`ServiceHandle`]: crate::traits::ServiceHandle
//! [`ProtocolMeta`]: crate::service::config::ProtocolMeta
//! [`Control`]: crate::service::ServiceControl
//! [`Service`]: crate::service::Service
//!

#![deny(missing_docs)]
#![cfg_attr(
    target_arch = "wasm32",
    allow(dead_code, unused_variables, unused_imports)
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// Re-pub async trait
pub use async_trait::async_trait;
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
pub(crate) mod lock;
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
#[cfg_attr(not(feature = "unstable"), doc(hidden))]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
#[allow(missing_docs)]
pub mod runtime;

#[cfg(all(not(target_arch = "wasm32"), feature = "upnp"))]
pub(crate) mod upnp;

use std::{fmt, ops::AddAssign};

pub use substream::SubstreamReadPart;

/// Index of sub/protocol stream
type StreamId = usize;
/// Protocol id
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, Default)]
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

impl std::hash::Hash for ProtocolId {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        hasher.write_usize(self.0)
    }
}

impl PartialEq for ProtocolId {
    fn eq(&self, other: &ProtocolId) -> bool {
        self.0.eq(&other.0)
    }
}

impl nohash_hasher::IsEnabled for ProtocolId {}

/// Index of session
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, Default)]
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

impl std::hash::Hash for SessionId {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        hasher.write_usize(self.0)
    }
}

impl PartialEq for SessionId {
    fn eq(&self, other: &SessionId) -> bool {
        self.0.eq(&other.0)
    }
}

impl nohash_hasher::IsEnabled for SessionId {}
