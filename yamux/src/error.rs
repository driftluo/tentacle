//! The error types

/// The error types
#[derive(Debug)]
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
}
