use std::io;

use bytes::{Bytes, BytesMut};
use flatbuffers::FlatBufferBuilder;
use log::debug;
use p2p::multiaddr::Multiaddr;
use tokio::codec::length_delimited::LengthDelimitedCodec;
use tokio::codec::{Decoder, Encoder};

use crate::{
    protocol_generated::p2p::discovery::{
        BytesBuilder, DiscoveryMessage as FbsDiscoveryMessage, DiscoveryMessageBuilder,
        DiscoveryPayload as FbsDiscoveryPayload, GetNodes as FbsGetNodes, GetNodesBuilder,
        NodeBuilder, Nodes as FbsNodes, NodesBuilder,
    },
    protocol_generated_verifier::get_root,
};

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
                DiscoveryMessage::decode(&frame).map(Some).ok_or_else(|| {
                    debug!("deserialize error");
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
        let data = DiscoveryMessage::encode(&item);
        self.inner.encode(Bytes::from(data), dst)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DiscoveryMessage {
    GetNodes {
        version: u32,
        count: u32,
        listen_port: Option<u16>,
    },
    Nodes(Nodes),
}

impl DiscoveryMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut fbb = FlatBufferBuilder::new();
        let offset = match self {
            DiscoveryMessage::GetNodes {
                version,
                count,
                listen_port,
            } => {
                let mut get_nodes_builder = GetNodesBuilder::new(&mut fbb);
                get_nodes_builder.add_version(*version);
                get_nodes_builder.add_count(*count);
                get_nodes_builder.add_listen_port(listen_port.unwrap_or(0));

                let get_nodes = get_nodes_builder.finish();

                let mut builder = DiscoveryMessageBuilder::new(&mut fbb);
                builder.add_payload_type(FbsDiscoveryPayload::GetNodes);
                builder.add_payload(get_nodes.as_union_value());
                builder.finish()
            }
            DiscoveryMessage::Nodes(Nodes { announce, items }) => {
                let mut vec_items = Vec::new();
                for item in items {
                    let mut vec_addrs = Vec::new();
                    for address in &item.addresses {
                        let seq = fbb.create_vector(&address.to_bytes());
                        let mut bytes_builder = BytesBuilder::new(&mut fbb);
                        bytes_builder.add_seq(seq);
                        vec_addrs.push(bytes_builder.finish());
                    }
                    let fbs_addrs = fbb.create_vector(&vec_addrs);
                    let mut node_builder = NodeBuilder::new(&mut fbb);
                    node_builder.add_addresses(fbs_addrs);
                    vec_items.push(node_builder.finish());
                }
                let fbs_items = fbb.create_vector(&vec_items);
                let mut nodes_builder = NodesBuilder::new(&mut fbb);
                nodes_builder.add_announce(*announce);
                nodes_builder.add_items(fbs_items);
                let nodes = nodes_builder.finish();

                let mut builder = DiscoveryMessageBuilder::new(&mut fbb);
                builder.add_payload_type(FbsDiscoveryPayload::Nodes);
                builder.add_payload(nodes.as_union_value());
                builder.finish()
            }
        };
        fbb.finish(offset, None);
        fbb.finished_data().to_vec()
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let fbs_message = get_root::<FbsDiscoveryMessage>(data).ok()?;
        let payload = fbs_message.payload()?;
        match fbs_message.payload_type() {
            FbsDiscoveryPayload::GetNodes => {
                let fbs_get_nodes = FbsGetNodes::init_from_table(payload);
                let listen_port = if fbs_get_nodes.listen_port() == 0 {
                    None
                } else {
                    Some(fbs_get_nodes.listen_port())
                };
                Some(DiscoveryMessage::GetNodes {
                    version: fbs_get_nodes.version(),
                    count: fbs_get_nodes.count(),
                    listen_port,
                })
            }
            FbsDiscoveryPayload::Nodes => {
                let fbs_nodes = FbsNodes::init_from_table(payload);
                let fbs_items = fbs_nodes.items()?;
                let mut items = Vec::new();
                for i in 0..fbs_items.len() {
                    let fbs_node = fbs_items.get(i);
                    let fbs_addresses = fbs_node.addresses()?;
                    let mut addresses = Vec::new();
                    for j in 0..fbs_addresses.len() {
                        let address = fbs_addresses.get(j);
                        let multiaddr = Multiaddr::from_bytes(address.seq()?.to_vec()).ok()?;
                        addresses.push(multiaddr);
                    }
                    items.push(Node { addresses });
                }
                Some(DiscoveryMessage::Nodes(Nodes {
                    announce: fbs_nodes.announce(),
                    items,
                }))
            }
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Nodes {
    pub(crate) announce: bool,
    pub(crate) items: Vec<Node>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Node {
    pub(crate) addresses: Vec<Multiaddr>,
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
