use bytes::{Buf, BufMut};
use std::{
    borrow::Cow,
    fmt,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::{self, FromStr},
};

use crate::error::Error;

const DNS4: u32 = 0x36;
const DNS6: u32 = 0x37;
const IP4: u32 = 0x04;
const IP6: u32 = 0x29;
const P2P: u32 = 0x01a5;
const TCP: u32 = 0x06;
const TLS: u32 = 0x01c0;
const WS: u32 = 0x01dd;
const WSS: u32 = 0x01de;
const MEMORY: u32 = 0x0309;

const SHA256_CODE: u16 = 0x12;
const SHA256_SIZE: u8 = 32;

/// `Protocol` describes all possible multiaddress protocols.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Protocol<'a> {
    Dns4(Cow<'a, str>),
    Dns6(Cow<'a, str>),
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
    P2P(Cow<'a, [u8]>),
    Tcp(u16),
    Tls(Cow<'a, str>),
    Ws,
    Wss,
    /// Contains the "port" to contact. Similar to TCP or UDP, 0 means "assign me a port".
    Memory(u64),
}

impl<'a> Protocol<'a> {
    /// Parse a protocol value from the given iterator of string slices.
    ///
    /// The parsing only consumes the minimum amount of string slices necessary to
    /// produce a well-formed protocol. The same iterator can thus be used to parse
    /// a sequence of protocols in succession. It is up to client code to check
    /// that iteration has finished whenever appropriate.
    pub fn from_str_peek<T>(mut iter: T) -> Result<Self, Error>
    where
        T: Iterator<Item = &'a str>,
    {
        match iter.next().ok_or(Error::InvalidProtocolString)? {
            "dns4" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Dns4(Cow::Borrowed(s)))
            }
            "dns6" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Dns6(Cow::Borrowed(s)))
            }
            "ip4" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Ip4(Ipv4Addr::from_str(s)?))
            }
            "ip6" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Ip6(Ipv6Addr::from_str(s)?))
            }
            "tls" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Tls(Cow::Borrowed(s)))
            }
            "p2p" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                let decoded = bs58::decode(s).into_vec()?;
                check_p2p(decoded.as_slice())?;
                Ok(Protocol::P2P(Cow::Owned(decoded)))
            }
            "tcp" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Tcp(s.parse()?))
            }
            "ws" => Ok(Protocol::Ws),
            "wss" => Ok(Protocol::Wss),
            "memory" => {
                let s = iter.next().ok_or(Error::InvalidProtocolString)?;
                Ok(Protocol::Memory(s.parse()?))
            }
            _ => Err(Error::UnknownProtocolString),
        }
    }

    /// Parse a single `Protocol` value from its byte slice representation,
    /// returning the protocol as well as the remaining byte slice.
    pub fn from_bytes(input: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        use unsigned_varint::decode;
        fn split_header(n: usize, input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
            if input.len() < n {
                return Err(Error::DataLessThanLen);
            }
            Ok(input.split_at(n))
        }
        let (id, input) = decode::u32(input)?;
        match id {
            DNS4 => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_header(n, input)?;
                Ok((Protocol::Dns4(Cow::Borrowed(str::from_utf8(data)?)), rest))
            }
            DNS6 => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_header(n, input)?;
                Ok((Protocol::Dns6(Cow::Borrowed(str::from_utf8(data)?)), rest))
            }
            IP4 => {
                let (data, rest) = split_header(4, input)?;
                Ok((
                    Protocol::Ip4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                    rest,
                ))
            }
            IP6 => {
                let (data, rest) = split_header(16, input)?;
                let mut rdr = Cursor::new(data);
                let mut seg = [0_u16; 8];

                for x in seg.iter_mut() {
                    *x = rdr.get_u16();
                }

                let addr = Ipv6Addr::new(
                    seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
                );

                Ok((Protocol::Ip6(addr), rest))
            }
            TLS => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_header(n, input)?;
                Ok((Protocol::Tls(Cow::Borrowed(str::from_utf8(data)?)), rest))
            }
            P2P => {
                let (n, input) = decode::usize(input)?;
                let (data, rest) = split_header(n, input)?;
                check_p2p(data)?;
                Ok((Protocol::P2P(Cow::Borrowed(data)), rest))
            }
            TCP => {
                let (data, rest) = split_header(2, input)?;
                let mut rdr = Cursor::new(data);
                let num = rdr.get_u16();
                Ok((Protocol::Tcp(num), rest))
            }
            WS => Ok((Protocol::Ws, input)),
            WSS => Ok((Protocol::Wss, input)),
            MEMORY => {
                let (data, rest) = split_header(8, input)?;
                let mut rdr = Cursor::new(data);
                let num = rdr.get_u64();
                Ok((Protocol::Memory(num), rest))
            }
            _ => Err(Error::UnknownProtocolId(id)),
        }
    }

    /// Encode this protocol by writing its binary representation into
    /// the given `BufMut` impl.
    pub fn write_to_bytes<W: BufMut>(&self, w: &mut W) {
        use unsigned_varint::encode;
        let mut buf = encode::u32_buffer();
        match self {
            Protocol::Dns4(s) => {
                w.put(encode::u32(DNS4, &mut buf));
                let bytes = s.as_bytes();
                w.put(encode::usize(bytes.len(), &mut encode::usize_buffer()));
                w.put(bytes)
            }
            Protocol::Dns6(s) => {
                w.put(encode::u32(DNS6, &mut buf));
                let bytes = s.as_bytes();
                w.put(encode::usize(bytes.len(), &mut encode::usize_buffer()));
                w.put(bytes)
            }
            Protocol::Ip4(addr) => {
                w.put(encode::u32(IP4, &mut buf));
                w.put(&addr.octets()[..])
            }
            Protocol::Ip6(addr) => {
                w.put(encode::u32(IP6, &mut buf));
                for &segment in &addr.segments() {
                    w.put_u16(segment)
                }
            }
            Protocol::Tcp(port) => {
                w.put(encode::u32(TCP, &mut buf));
                w.put_u16(*port)
            }
            Protocol::Tls(s) => {
                w.put(encode::u32(TLS, &mut buf));
                let bytes = s.as_bytes();
                w.put(encode::usize(bytes.len(), &mut encode::usize_buffer()));
                w.put(bytes)
            }
            Protocol::P2P(b) => {
                w.put(encode::u32(P2P, &mut buf));
                w.put(encode::usize(b.len(), &mut encode::usize_buffer()));
                w.put(&b[..])
            }
            Protocol::Ws => w.put(encode::u32(WS, &mut buf)),
            Protocol::Wss => w.put(encode::u32(WSS, &mut buf)),
            Protocol::Memory(port) => {
                w.put(encode::u32(MEMORY, &mut buf));
                w.put_u64(*port)
            }
        }
    }

    /// Turn this `Protocol` into one that owns its data, thus being valid for any lifetime.
    pub fn acquire<'b>(self) -> Protocol<'b> {
        match self {
            Protocol::Dns4(s) => Protocol::Dns4(Cow::Owned(s.into_owned())),
            Protocol::Dns6(s) => Protocol::Dns6(Cow::Owned(s.into_owned())),
            Protocol::Ip4(addr) => Protocol::Ip4(addr),
            Protocol::Ip6(addr) => Protocol::Ip6(addr),
            Protocol::Tcp(port) => Protocol::Tcp(port),
            Protocol::Tls(s) => Protocol::Tls(Cow::Owned(s.into_owned())),
            Protocol::P2P(s) => Protocol::P2P(Cow::Owned(s.into_owned())),
            Protocol::Ws => Protocol::Ws,
            Protocol::Wss => Protocol::Wss,
            Protocol::Memory(a) => Protocol::Memory(a),
        }
    }
}

impl<'a> fmt::Display for Protocol<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Protocol::*;
        match self {
            Dns4(s) => write!(f, "/dns4/{}", s),
            Dns6(s) => write!(f, "/dns6/{}", s),
            Ip4(addr) => write!(f, "/ip4/{}", addr),
            Ip6(addr) => write!(f, "/ip6/{}", addr),
            P2P(c) => write!(f, "/p2p/{}", bs58::encode(c).into_string()),
            Tcp(port) => write!(f, "/tcp/{}", port),
            Tls(s) => write!(f, "/tls/{}", s),
            Ws => write!(f, "/ws"),
            Wss => write!(f, "/wss"),
            Memory(port) => write!(f, "/memory/{}", port),
        }
    }
}

impl<'a> From<IpAddr> for Protocol<'a> {
    #[inline]
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => Protocol::Ip4(addr),
            IpAddr::V6(addr) => Protocol::Ip6(addr),
        }
    }
}

impl<'a> From<Ipv4Addr> for Protocol<'a> {
    #[inline]
    fn from(addr: Ipv4Addr) -> Self {
        Protocol::Ip4(addr)
    }
}

impl<'a> From<Ipv6Addr> for Protocol<'a> {
    #[inline]
    fn from(addr: Ipv6Addr) -> Self {
        Protocol::Ip6(addr)
    }
}

fn check_p2p(data: &[u8]) -> Result<(), Error> {
    let (code, bytes) = unsigned_varint::decode::u16(data)?;

    if code != SHA256_CODE {
        return Err(Error::UnknownHash);
    }

    if bytes.len() != SHA256_SIZE as usize + 1 {
        return Err(Error::UnknownHash);
    }

    if bytes[0] != SHA256_SIZE {
        return Err(Error::UnknownHash);
    }
    Ok(())
}
