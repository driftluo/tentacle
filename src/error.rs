use crate::{secio::error::SecioError, SessionId};
use futures::channel::mpsc;
use std::{error, fmt, io};

/// Error from p2p framework
#[derive(Debug)]
pub enum Error {
    /// IO error
    IoError(io::Error),
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
    /// Service protocol handle block, may be user's protocol handle implementation problem
    ServiceProtoHandleBlock,
    /// protocol handle abnormally closed, may be user's protocol handle implementation problem
    ServiceProtoHandleAbnormallyClosed,
    /// Session protocol handle block, may be user's protocol handle implementation problem
    SessionProtoHandleBlock(SessionId),
    /// protocol handle abnormally closed, may be user's protocol handle implementation problem
    SessionProtoHandleAbnormallyClosed(SessionId),
}

impl PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        use self::Error::*;
        match (self, other) {
            (ConnectSelf, ConnectSelf) | (PeerIdNotMatch, PeerIdNotMatch) => true,
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

impl From<mpsc::SendError> for Error {
    #[inline]
    fn from(_err: mpsc::SendError) -> Error {
        Error::IoError(io::ErrorKind::BrokenPipe.into())
    }
}

impl<T> From<mpsc::TrySendError<T>> for Error {
    #[inline]
    fn from(_err: mpsc::TrySendError<T>) -> Error {
        Error::IoError(io::ErrorKind::BrokenPipe.into())
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
            Error::ConnectSelf => "Connect self",
            Error::RepeatedConnection(_) => "Connected to the connected peer",
            Error::PeerIdNotMatch => "When dial remote, peer id does not match",
            Error::HandshakeError(e) => error::Error::description(e),
            Error::DNSResolverError(_) => "DNS resolver error",
            Error::ServiceProtoHandleBlock => "Service protocol handle block",
            Error::ServiceProtoHandleAbnormallyClosed => {
                "Service protocol handle abnormally closed"
            }
            Error::SessionProtoHandleBlock(_) => "Session protocol handle block",
            Error::SessionProtoHandleAbnormallyClosed(_) => {
                "Session protocol handle abnormally closed"
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(e) => fmt::Display::fmt(e, f),
            Error::ConnectSelf => write!(f, "Connect self"),
            Error::RepeatedConnection(id) => {
                write!(f, "Connected to the connected peer, session id: [{}]", id)
            }
            Error::PeerIdNotMatch => write!(f, "When dial remote, peer id does not match"),
            Error::HandshakeError(e) => fmt::Display::fmt(e, f),
            Error::DNSResolverError(e) => write!(f, "DNs resolver error: {:?}", e),
            Error::ServiceProtoHandleBlock => write!(f, "Service protocol handle block"),
            Error::ServiceProtoHandleAbnormallyClosed => {
                write!(f, "Service protocol handle abnormally closed")
            }
            Error::SessionProtoHandleBlock(id) => {
                write!(f, "Session [{}] protocol handle block", id)
            }
            Error::SessionProtoHandleAbnormallyClosed(id) => {
                write!(f, "Session [{}] protocol handle abnormally closed", id)
            }
        }
    }
}
