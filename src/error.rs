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
    /// protocol handle block, may be user's protocol handle implementation problem
    ProtoHandleBlock(Option<SessionId>),
    /// protocol handle abnormally closed, may be user's protocol handle implementation problem
    ProtoHandleAbnormallyClosed(Option<SessionId>),
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

impl error::Error for Error {}

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
            Error::ProtoHandleBlock(id) => write!(
                f,
                "Protocol handle block{}",
                match id {
                    Some(id) => format!(", caused by session [{}]", id),
                    None => "".to_string(),
                }
            ),
            Error::ProtoHandleAbnormallyClosed(id) => write!(
                f,
                "Protocol handle abnormally closed{}",
                match id {
                    Some(id) => format!(", caused by session [{}]", id),
                    None => "".to_string(),
                }
            ),
        }
    }
}
