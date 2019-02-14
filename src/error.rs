use crate::SessionId;
use futures::sync::mpsc;
use secio::error::SecioError;
use std::{error, fmt, io};

/// Error from p2p framework
#[derive(Debug)]
pub enum Error<T: fmt::Debug> {
    /// IO error
    IoError(io::Error),
    /// Service Task channel full
    TaskFull(T),
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
}

impl<T> PartialEq for Error<T>
where
    T: fmt::Debug,
{
    fn eq(&self, other: &Error<T>) -> bool {
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

impl<T> From<io::Error> for Error<T>
where
    T: fmt::Debug,
{
    #[inline]
    fn from(err: io::Error) -> Error<T> {
        Error::IoError(err)
    }
}

impl<T> From<mpsc::TrySendError<T>> for Error<T>
where
    T: fmt::Debug,
{
    #[inline]
    fn from(err: mpsc::TrySendError<T>) -> Error<T> {
        if err.is_full() {
            Error::TaskFull(err.into_inner())
        } else {
            Error::TaskDisconnect
        }
    }
}

impl<T> From<SecioError> for Error<T>
where
    T: fmt::Debug,
{
    #[inline]
    fn from(err: SecioError) -> Error<T> {
        match err {
            SecioError::ConnectSelf => Error::ConnectSelf,
            error => Error::HandshakeError(error),
        }
    }
}

impl<T> error::Error for Error<T>
where
    T: fmt::Debug,
{
    fn description(&self) -> &str {
        match self {
            Error::IoError(e) => error::Error::description(e),
            Error::TaskFull(_) => "Service Task channel is full",
            Error::TaskDisconnect => "Service Task channel has been dropped",
            Error::ConnectSelf => "Connect self",
            Error::RepeatedConnection(_) => "Connected to the connected peer",
            Error::PeerIdNotMatch => "When dial remote, peer id does not match",
            Error::HandshakeError(e) => error::Error::description(e),
        }
    }
}

impl<T> fmt::Display for Error<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(e) => fmt::Display::fmt(e, f),
            Error::TaskFull(_) => write!(f, "Service Task channel is full"),
            Error::TaskDisconnect => write!(f, "Service Task channel has been dropped"),
            Error::ConnectSelf => write!(f, "Connect self"),
            Error::RepeatedConnection(id) => {
                write!(f, "Connected to the connected peer, session id: [{}]", id)
            }
            Error::PeerIdNotMatch => write!(f, "When dial remote, peer id does not match"),
            Error::HandshakeError(e) => fmt::Display::fmt(e, f),
        }
    }
}
