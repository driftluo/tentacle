use crate::{secio::error::SecioError, SessionId};
use multiaddr::Multiaddr;

#[derive(Debug)]
/// Transport Error
pub enum TransportErrorKind {
    /// IO error
    Io(std::io::Error),
    /// Protocol not support
    NotSupport(Multiaddr),
    /// Dns resolver error
    DNSResolverError((Multiaddr, std::io::Error)),
}

#[derive(Debug)]
/// Protocol handle error
pub enum ProtocolHandleErrorKind {
    /// protocol handle block, may be user's protocol handle implementation problem
    Block(Option<SessionId>),
    /// protocol handle abnormally closed, may be user's protocol handle implementation problem
    AbnormallyClosed(Option<SessionId>),
}

#[derive(Debug)]
/// Detail error kind when dial remote error
pub enum DialerErrorKind {
    /// IO error
    IoError(std::io::Error),
    /// When dial remote, peer id does not match
    PeerIdNotMatch,
    /// Connected to the connected peer
    RepeatedConnection(SessionId),
    /// Handshake error
    HandshakeError(HandshakeErrorKind),
    /// Transport error
    TransportError(TransportErrorKind),
}

#[derive(Debug)]
/// Handshake error
pub enum HandshakeErrorKind {
    /// Handshake timeout error
    Timeout(String),
    /// Secio error
    SecioError(SecioError),
}

#[derive(Debug)]
/// Listener error kind when dial remote error
pub enum ListenErrorKind {
    /// IO error
    IoError(std::io::Error),
    /// Connected to the connected peer
    RepeatedConnection(SessionId),
    /// Transport error
    TransportError(TransportErrorKind),
}

#[derive(Debug)]
/// Send error kind when send service task
pub enum SendErrorKind {
    /// Sending failed because a pipe was closed.
    BrokenPipe,
    /// The operation needs to block to complete, but the blocking operation was requested to not occur.
    WouldBlock,
}
