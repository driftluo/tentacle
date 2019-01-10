use std::io;

use bytes::{Bytes, BytesMut};
use log::debug;
use serde_derive::{Deserialize, Serialize};
use tokio::codec::length_delimited::LengthDelimitedCodec;
use tokio::codec::{Decoder, Encoder};

use crate::addr::RawAddr;

pub(crate) struct DiscoveryCodec {
    inner: LengthDelimitedCodec,
}

impl Default for DiscoveryCodec {
    fn default() -> DiscoveryCodec {
        DiscoveryCodec {
            inner: LengthDelimitedCodec::new(),
        }
    }
}

impl Decoder for DiscoveryCodec {
    type Item = DiscoveryMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src) {
            Ok(Some(frame)) => {
                // TODO: more error information
                bincode::deserialize(&frame).map(Some).map_err(|err| {
                    debug!("deserialize error: {:?}", err);
                    io::ErrorKind::InvalidData.into()
                })
            }
            Ok(None) => Ok(None),
            // TODO: more error information
            Err(err) => {
                debug!("decode error: {:?}", err);
                Err(io::ErrorKind::InvalidData.into())
            }
        }
    }
}

impl Encoder for DiscoveryCodec {
    type Item = DiscoveryMessage;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // TODO: more error information
        bincode::serialize(&item)
            .map_err(|err| {
                debug!("serialize error: {:?}", err);
                io::ErrorKind::InvalidData.into()
            })
            .and_then(|frame| self.inner.encode(Bytes::from(frame), dst))
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum DiscoveryMessage {
    GetNodes {
        version: u32,
        count: u32,
        listen_port: Option<u16>,
    },
    Nodes(Nodes),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Nodes {
    pub(crate) announce: bool,
    pub(crate) items: Vec<Node>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Node {
    pub(crate) addresses: Vec<RawAddr>,
}

impl std::fmt::Display for DiscoveryMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            DiscoveryMessage::GetNodes { version, count, .. } => {
                write!(
                    f,
                    "DiscoveryMessage::GetNodes(version:{}, count:{})",
                    version, count
                )?;
            }
            DiscoveryMessage::Nodes(Nodes { announce, items }) => {
                write!(
                    f,
                    "DiscoveryMessage::Nodes(announce:{}, items.length:{})",
                    announce,
                    items.len()
                )?;
            }
        }
        Ok(())
    }
}
