use std::{error, fmt};
use unsigned_varint::decode;

#[derive(Debug)]
pub enum Error {
    DataLessThanLen,
    InvalidMultiaddr,
    InvalidProtocolString,
    InvalidUvar(decode::Error),
    ParsingError(Box<dyn error::Error + Send + Sync>),
    UnknownHash,
    UnknownProtocolId(u32),
    UnknownProtocolString,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DataLessThanLen => f.write_str("we have less data than indicated by length"),
            Error::InvalidMultiaddr => f.write_str("invalid multiaddr"),
            Error::InvalidProtocolString => f.write_str("invalid protocol string"),
            Error::InvalidUvar(e) => write!(f, "failed to decode unsigned varint: {}", e),
            Error::ParsingError(e) => write!(f, "failed to parse: {}", e),
            Error::UnknownHash => write!(f, "unknown hash"),
            Error::UnknownProtocolId(id) => write!(f, "unknown protocol id: {}", id),
            Error::UnknownProtocolString => f.write_str("unknown protocol string"),
        }
    }
}

impl error::Error for Error {
    #[inline]
    fn cause(&self) -> Option<&dyn error::Error> {
        if let Error::ParsingError(e) = self {
            Some(&**e)
        } else {
            None
        }
    }
}

impl From<::std::io::Error> for Error {
    fn from(err: ::std::io::Error) -> Error {
        Error::ParsingError(err.into())
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(err: bs58::decode::Error) -> Error {
        Error::ParsingError(err.into())
    }
}

impl From<::std::net::AddrParseError> for Error {
    fn from(err: ::std::net::AddrParseError) -> Error {
        Error::ParsingError(err.into())
    }
}

impl From<::std::num::ParseIntError> for Error {
    fn from(err: ::std::num::ParseIntError) -> Error {
        Error::ParsingError(err.into())
    }
}

impl From<::std::string::FromUtf8Error> for Error {
    fn from(err: ::std::string::FromUtf8Error) -> Error {
        Error::ParsingError(err.into())
    }
}

impl From<::std::str::Utf8Error> for Error {
    fn from(err: ::std::str::Utf8Error) -> Error {
        Error::ParsingError(err.into())
    }
}

impl From<unsigned_varint::decode::Error> for Error {
    fn from(e: unsigned_varint::decode::Error) -> Error {
        Error::InvalidUvar(e)
    }
}
