use crate::{secio::error::SecioError, SessionId};
use futures::sync::mpsc;
use std::{error, fmt, io};

/// Error from p2p framework
#[derive(Debug)]
pub enum Error {
    /// IO error
    IoError(io::Error),
    /// Service Task channel has been dropped
    TaskDisconnect,
    /// Connect self
    ConnectSelf,
    /// When dial remote, peer id does not match
    PeerIdNotMatch,
    /// Connected to the connected peer
    RepeatedConnection(SessionId),
    /// Handshake error
    HandshakeError(SecioError),
    /// DNS resolver error
    DNSResolverError(io::Error),
}

impl PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        use self::Error::*;
        match (self, other) {
            (TaskDisconnect, TaskDisconnect)
            | (ConnectSelf, ConnectSelf)
            | (PeerIdNotMatch, PeerIdNotMatch) => true,
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

impl<T> From<mpsc::SendError<T>> for Error {
    #[inline]
    fn from(_err: mpsc::SendError<T>) -> Error {
        Error::TaskDisconnect
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
            Error::TaskDisconnect => "Service Task channel has been dropped",
            Error::ConnectSelf => "Connect self",
            Error::RepeatedConnection(_) => "Connected to the connected peer",
            Error::PeerIdNotMatch => "When dial remote, peer id does not match",
            Error::HandshakeError(e) => error::Error::description(e),
            Error::DNSResolverError(_) => "DNS resolver error",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(e) => fmt::Display::fmt(e, f),
            Error::TaskDisconnect => write!(f, "Service Task channel has been dropped"),
            Error::ConnectSelf => write!(f, "Connect self"),
            Error::RepeatedConnection(id) => {
                write!(f, "Connected to the connected peer, session id: [{}]", id)
            }
            Error::PeerIdNotMatch => write!(f, "When dial remote, peer id does not match"),
            Error::HandshakeError(e) => fmt::Display::fmt(e, f),
            Error::DNSResolverError(e) => write!(f, "DNs resolver error: {:?}", e),
        }
    }
}
