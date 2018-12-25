//! Process the frame

use std::io;

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use log::trace;
use tokio::codec::{Decoder, Encoder};

use crate::{StreamId, HEADER_SIZE, PROTOCOL_VERSION, RESERVED_STREAM_ID};

// TODO remove Clone later
/// The base message type is frame
#[derive(Debug)]
pub struct Frame {
    header: Header,
    body: Option<Bytes>,
}

impl Frame {
    /// Create a data frame
    pub fn new_data(flags: Flags, stream_id: StreamId, body: Bytes) -> Frame {
        Frame {
            header: Header {
                version: PROTOCOL_VERSION,
                ty: Type::Data,
                flags,
                stream_id,
                length: body.len() as u32,
            },
            body: Some(body),
        }
    }

    /// Create a window update frame
    pub fn new_window_update(flags: Flags, stream_id: StreamId, delta: u32) -> Frame {
        Frame {
            header: Header {
                version: PROTOCOL_VERSION,
                ty: Type::WindowUpdate,
                flags,
                stream_id,
                length: delta,
            },
            body: None,
        }
    }

    /// Create a ping frame
    pub fn new_ping(flags: Flags, ping_id: u32) -> Frame {
        Frame {
            header: Header {
                version: PROTOCOL_VERSION,
                ty: Type::Ping,
                flags,
                stream_id: RESERVED_STREAM_ID,
                length: ping_id,
            },
            body: None,
        }
    }

    /// Create a go away frame
    pub fn new_go_away(reason: GoAwayCode) -> Frame {
        Frame {
            header: Header {
                version: PROTOCOL_VERSION,
                ty: Type::GoAway,
                flags: Flags::default(),
                stream_id: RESERVED_STREAM_ID,
                length: reason as u32,
            },
            body: None,
        }
    }

    /// The type of current frame
    pub fn ty(&self) -> Type {
        self.header.ty
    }

    /// The stream id of current frame
    pub fn stream_id(&self) -> StreamId {
        self.header.stream_id
    }

    /// The flags of current frame
    pub fn flags(&self) -> Flags {
        self.header.flags
    }

    /// The length field of current body or some other things such as ping_id/go away code/delta
    pub fn length(&self) -> u32 {
        self.header.length
    }

    /// Consume current frame split into header and body
    pub fn into_parts(self) -> (Header, Option<Bytes>) {
        (self.header, self.body)
    }

    /// The length field of current frame
    pub fn size(&self) -> usize {
        if self.body.is_some() {
            self.header.length as usize + HEADER_SIZE
        } else {
            HEADER_SIZE
        }
    }
}

/// The frame header
#[derive(Clone, Debug)]
pub struct Header {
    version: u8,
    ty: Type,
    flags: Flags,
    stream_id: StreamId,
    length: u32,
}

/// The type field is used to switch the frame message type.
/// The following message types are supported:
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Type {
    /// Used to transmit data.
    /// May transmit zero length payloads depending on the flags.
    Data = 0x0,

    /// Used to updated the senders receive window size.
    /// This is used to implement per-session flow control.
    WindowUpdate = 0x1,

    /// Used to measure RTT.
    /// It can also be used to heart-beat and do keep-alives over TCP.
    Ping = 0x2,

    /// Used to close a session.
    GoAway = 0x3,
}

impl Type {
    pub(crate) fn try_from(value: u8) -> Option<Type> {
        match value {
            0x0 => Some(Type::Data),
            0x1 => Some(Type::WindowUpdate),
            0x2 => Some(Type::Ping),
            0x3 => Some(Type::GoAway),
            _ => None,
        }
    }
}

/// The frame flag
#[derive(Copy, Clone, Debug)]
#[repr(u16)]
pub enum Flag {
    /// SYN - Signals the start of a new stream.
    ///   May be sent with a data or window update message.
    ///   Also sent with a ping to indicate outbound.
    Syn = 0x1,

    /// ACK - Acknowledges the start of a new stream.
    ///   May be sent with a data or window update message.
    ///   Also sent with a ping to indicate response.
    Ack = 0x2,

    /// FIN (finish) - Performs a half-close of a stream.
    ///   May be sent with a data message or window update.
    Fin = 0x4,

    /// RST - Reset a stream immediately.
    ///   May be sent with a data or window update message.
    Rst = 0x8,
}

impl From<Flag> for Flags {
    fn from(value: Flag) -> Flags {
        Flags(value as u16)
    }
}

/// Represent all flags of a frame
#[derive(Copy, Clone, Debug, Default)]
pub struct Flags(u16);

impl Flags {
    /// Add a flag
    pub fn add(&mut self, flag: Flag) {
        self.0 |= flag as u16;
    }

    /// Remove a flag
    pub fn remove(&mut self, flag: Flag) {
        self.0 ^= flag as u16;
    }

    /// Check if contains a target flag
    pub fn contains(self, flag: Flag) -> bool {
        let flag_value = flag as u16;
        (self.0 & flag_value) == flag_value
    }

    /// The value of all flags
    pub fn value(self) -> u16 {
        self.0
    }
}

/// When a session is being terminated, the Go Away message should
/// be sent. The Length should be set to one of the following to
/// provide an error code:
#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum GoAwayCode {
    /// Normal termination
    Normal = 0x0,
    /// Protocol error
    ProtocolError = 0x1,
    /// Internal error
    InternalError = 0x2,
}

impl From<u32> for GoAwayCode {
    fn from(value: u32) -> GoAwayCode {
        match value {
            0x0 => GoAwayCode::Normal,
            0x1 => GoAwayCode::ProtocolError,
            0x2 => GoAwayCode::InternalError,
            _ => GoAwayCode::ProtocolError,
        }
    }
}

/// The frame decoder/encoder
#[derive(Default)]
pub(crate) struct FrameCodec {
    unused_data_header: Option<Header>,
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        let header = match self.unused_data_header.take() {
            Some(header) => header,
            None if src.len() >= HEADER_SIZE => {
                let header_data = src.split_to(HEADER_SIZE);

                let version = header_data[0];
                if version != PROTOCOL_VERSION {
                    let err = io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("yamux.version={}", version),
                    );
                    return Err(err);
                }
                let ty_value = header_data[1];
                let ty = match Type::try_from(ty_value) {
                    Some(ty) => ty,
                    None => {
                        let err = io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("yamux.type={}", ty_value),
                        );
                        return Err(err);
                    }
                };

                let flags = Flags(BigEndian::read_u16(&header_data[2..4]));
                let stream_id = BigEndian::read_u32(&header_data[4..8]);
                let length = BigEndian::read_u32(&header_data[8..12]);
                Header {
                    version,
                    ty,
                    flags,
                    stream_id,
                    length,
                }
            }
            None => {
                trace!("not enough data for decode header");
                return Ok(None);
            }
        };

        let body = if header.ty == Type::Data {
            if src.len() < header.length as usize {
                trace!("not enough data for decode body");
                self.unused_data_header = Some(header);
                return Ok(None);
            } else {
                Some(Bytes::from(src.split_to(header.length as usize)))
            }
        } else {
            // Not data frame
            None
        };

        Ok(Some(Frame { header, body }))
    }
}

impl Encoder for FrameCodec {
    type Item = Frame;
    type Error = io::Error;
    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Must ensure that there is enough space in the buf
        dst.reserve(item.size());
        let (header, body) = item.into_parts();
        dst.put(header.version);
        dst.put(header.ty as u8);
        dst.put_u16_be(header.flags.value());
        dst.put_u32_be(header.stream_id);
        dst.put_u32_be(header.length);
        if let Some(data) = body {
            dst.put(data);
        }
        trace!("encode item: length={}", dst.len());
        Ok(())
    }
}
