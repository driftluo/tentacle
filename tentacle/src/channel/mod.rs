//! This module forks a channel code for future-rs,
//! but it is slightly modified to make the channel support priority operation
//!

#![allow(dead_code)]

mod bound;
mod queue;
mod sink_impl;
#[cfg(test)]
mod tests;
mod unbound;

pub(crate) mod mpsc {
    pub use super::bound::{channel, Receiver, Sender};
    pub use super::unbound::{unbounded, UnboundedReceiver, UnboundedSender};
    pub use super::{Priority, SendError, TrySendError};
}
pub use sink_impl::QuickSinkExt;

use std::fmt;

// The `is_open` flag is stored in the left-most bit of `Inner::state`
const OPEN_MASK: usize = usize::max_value() - (usize::max_value() >> 1);

// When a new channel is created, it is created in the open state with no
// pending messages.
const INIT_STATE: usize = OPEN_MASK;

// The maximum number of messages that a channel can track is `usize::max_value() >> 1`
const MAX_CAPACITY: usize = !(OPEN_MASK);

// The maximum requested buffer size must be less than the maximum capacity of
// a channel. This is because each sender gets a guaranteed slot.
const MAX_BUFFER: usize = MAX_CAPACITY >> 1;

// Struct representation of `Inner::state`.
#[derive(Debug, Clone, Copy)]
struct State {
    // `true` when the channel is open
    is_open: bool,

    // Number of messages in the channel
    num_messages: usize,
}

impl State {
    fn is_closed(&self) -> bool {
        !self.is_open && self.num_messages == 0
    }
}

fn decode_state(num: usize) -> State {
    State {
        is_open: num & OPEN_MASK == OPEN_MASK,
        num_messages: num & MAX_CAPACITY,
    }
}

fn encode_state(state: &State) -> usize {
    let mut num = state.num_messages;

    if state.is_open {
        num |= OPEN_MASK;
    }

    num
}

/// The error type for [`Sender`s](Sender) used as `Sink`s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendError {
    kind: SendErrorKind,
}

/// The error type returned from [`try_send`](Sender::try_send).
#[derive(Clone, PartialEq, Eq)]
pub struct TrySendError<T> {
    err: SendError,
    val: T,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SendErrorKind {
    Full,
    Disconnected,
}

/// The error type returned from [`try_next`](Receiver::try_next).
pub struct TryRecvError {
    _priv: (),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_full() {
            write!(f, "send failed because channel is full")
        } else {
            write!(f, "send failed because receiver is gone")
        }
    }
}

impl std::error::Error for SendError {}

impl SendError {
    /// Returns `true` if this error is a result of the channel being full.
    pub fn is_full(&self) -> bool {
        matches!(self.kind, SendErrorKind::Full)
    }

    /// Returns `true` if this error is a result of the receiver being dropped.
    pub fn is_disconnected(&self) -> bool {
        matches!(self.kind, SendErrorKind::Disconnected)
    }
}

impl<T> fmt::Debug for TrySendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrySendError")
            .field("kind", &self.err.kind)
            .finish()
    }
}

impl<T> fmt::Display for TrySendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_full() {
            write!(f, "send failed because channel is full")
        } else {
            write!(f, "send failed because receiver is gone")
        }
    }
}

impl<T: core::any::Any> std::error::Error for TrySendError<T> {}

impl<T> TrySendError<T> {
    /// Returns `true` if this error is a result of the channel being full.
    pub fn is_full(&self) -> bool {
        self.err.is_full()
    }

    /// Returns `true` if this error is a result of the receiver being dropped.
    pub fn is_disconnected(&self) -> bool {
        self.err.is_disconnected()
    }

    /// Returns the message that was attempted to be sent but failed.
    pub fn into_inner(self) -> T {
        self.val
    }

    /// Drops the message and converts into a `SendError`.
    pub fn into_send_error(self) -> SendError {
        self.err
    }
}

impl fmt::Debug for TryRecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TryRecvError").finish()
    }
}

impl fmt::Display for TryRecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "receiver channel is empty")
    }
}

/// Priority for send
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Priority {
    High,
    Normal,
}

impl Priority {
    #[inline]
    pub fn is_high(self) -> bool {
        match self {
            Priority::High => true,
            Priority::Normal => false,
        }
    }
}
