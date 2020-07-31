//! A Rust implementation of yamux
//!
//! Spec: https://github.com/hashicorp/yamux/blob/master/spec.md

#![deny(missing_docs)]

// Config module
pub mod config;
// Error module
pub mod error;
// Frame module
pub mod frame;
// Session module
pub mod session;
// Stream module
mod control;
pub mod stream;

// Stream ID type
pub(crate) type StreamId = u32;

pub use crate::{
    config::Config, control::Control, error::Error, session::Session, stream::StreamHandle,
};

// Latest Protocol Version
pub(crate) const PROTOCOL_VERSION: u8 = 0;
// The 0 ID is reserved to represent the session.
pub(crate) const RESERVED_STREAM_ID: StreamId = 0;
// The header is 12 bytes
pub(crate) const HEADER_SIZE: usize = 12;
