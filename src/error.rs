use crate::SessionId;
use futures::sync::mpsc;
use secio::error::SecioError;
use std::{error, fmt, io};

/// Error from p2p framework
#[derive(Debug)]
pub enum Error {
    /// IO error
    IoError(io::Error),
    /// Service Task channel full
    TaskFull,
    /// Service Task channel has been dropped
    TaskDisconnect,
    /// Connect self
    ConnectSelf,
    /// Connected to the connected peer
    RepeatedConnection(SessionId),
    /// Handshake error
    HandshakeError(SecioError),
}

impl PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        use self::Error::*;
        match (self, other) {
            (TaskFull, TaskFull) => true,
            (TaskDisconnect, TaskDisconnect) => true,
            (ConnectSelf, ConnectSelf) => true,
            (RepeatedConnection(i), RepeatedConnection(j)) => i == j,
            (HandshakeError(i), HandshakeError(j)) => i == j,
            _ => false,
        }
    }
}

impl From<io::Error> for Error {
    #[inline]
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl<T> From<mpsc::TrySendError<T>> for Error {
    #[inline]
    fn from(err: mpsc::TrySendError<T>) -> Error {
        if err.is_full() {
            Error::TaskFull
        } else {
            Error::TaskDisconnect
        }
    }
}

impl From<SecioError> for Error {
    #[inline]
    fn from(err: SecioError) -> Error {
        match err {
            SecioError::ConnectSelf => Error::ConnectSelf,
            error => Error::HandshakeError(error),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::IoError(e) => error::Error::description(e),
            Error::TaskFull => "Service Task channel is full",
            Error::TaskDisconnect => "Service Task channel has been dropped",
            Error::ConnectSelf => "Connect self",
            Error::RepeatedConnection(_) => "Connected to the connected peer",
            Error::HandshakeError(e) => error::Error::description(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(e) => fmt::Display::fmt(e, f),
            Error::TaskFull => write!(f, "Service Task channel is full"),
            Error::TaskDisconnect => write!(f, "Service Task channel has been dropped"),
            Error::ConnectSelf => write!(f, "Connect self"),
            Error::RepeatedConnection(id) => {
                write!(f, "Connected to the connected peer, session id: [{}]", id)
            }
            Error::HandshakeError(e) => fmt::Display::fmt(e, f),
        }
    }
}
