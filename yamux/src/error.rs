//! The error types

use std::{error, fmt};

/// The error types
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// InvalidVersion means we received a frame with an
    /// invalid version
    InvalidVersion,

    /// InvalidMsgType means we received a frame with an
    /// invalid message type
    InvalidMsgType,

    /// SessionShutdown is used if there is a shutdown during
    /// an operation
    SessionShutdown,

    /// StreamsExhausted is returned if we have no more
    /// stream ids to issue
    StreamsExhausted,

    /// DuplicateStream is used if a duplicate stream is
    /// opened inbound
    DuplicateStream,

    /// ReceiveWindowExceeded indicates the window was exceeded
    RecvWindowExceeded,

    /// Timeout is used when we reach an IO deadline
    Timeout,

    /// StreamClosed is returned when using a closed stream
    StreamClosed,

    /// UnexpectedFlag is set when we get an unexpected flag
    UnexpectedFlag,

    /// RemoteGoAway is used when we get a go away from the other side
    RemoteGoAway,

    /// ConnectionReset is sent if a stream is reset. This can happen
    /// if the backlog is exceeded, or if there was a remote GoAway.
    ConnectionReset,

    /// ConnectionWriteTimeout indicates that we hit the "safety valve"
    /// timeout writing to the underlying stream connection.
    ConnectionWriteTimeout,

    /// KeepAliveTimeout is sent if a missed keepalive caused the stream close
    KeepAliveTimeout,

    /// Remote sub stream is closed, but local can still send data to remote
    SubStreamRemoteClosing,

    /// Sub stream send event channel full, block to complete
    WouldBlock,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidVersion => write!(f, "Received a frame with an invalid version"),
            Error::InvalidMsgType => write!(f, "Received a frame with an invalid message type"),
            Error::SessionShutdown => write!(f, "Session shutdown"),
            Error::StreamsExhausted => write!(f, "No more stream ids to issue"),
            Error::DuplicateStream => write!(f, "Duplicate stream is opened inbound"),
            Error::RecvWindowExceeded => write!(f, "Received window was exceeded"),
            Error::Timeout => write!(f, "Reach an IO deadline"),
            Error::StreamClosed => write!(f, "Using a closed stream"),
            Error::UnexpectedFlag => write!(f, "Get an unexpected flag"),
            Error::RemoteGoAway => write!(f, "Go away message from the other side"),
            Error::ConnectionReset => write!(f, "Stream is reset"),
            Error::ConnectionWriteTimeout => {
                write!(f, "Timeout on write to the underlying stream connection")
            }
            Error::KeepAliveTimeout => write!(f, "Keepalive timeout"),
            Error::SubStreamRemoteClosing => write!(f, "Remote sub stream is closed"),
            Error::WouldBlock => write!(f, "Sub stream send channel full"),
        }
    }
}
