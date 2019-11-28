#[cfg(all(feature = "flatc", feature = "molc"))]
compile_error!("features `flatc` and `molc` are mutually exclusive");
#[cfg(all(not(feature = "flatc"), not(feature = "molc")))]
compile_error!("Please choose a serialization format via feature. Possible choices: flatc, molc");

use std::{convert::TryFrom, io};

use bytes::{Bytes, BytesMut};
use log::debug;
use p2p::multiaddr::Multiaddr;
use tokio_util::codec::length_delimited::LengthDelimitedCodec;
use tokio_util::codec::{Decoder, Encoder};

#[cfg(feature = "flatc")]
use crate::protocol_generated::p2p::discovery::{
    BytesBuilder, DiscoveryMessage as FbsDiscoveryMessage, DiscoveryMessageBuilder,
    DiscoveryPayload as FbsDiscoveryPayload, GetNodes as FbsGetNodes, GetNodesBuilder, NodeBuilder,
    Nodes as FbsNodes, NodesBuilder,
};
#[cfg(feature = "molc")]
use crate::protocol_mol;
#[cfg(feature = "molc")]
use molecule::prelude::{Builder, Entity, Reader};

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
        self.inner.encode(item.encode(), dst)
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
    #[cfg(feature = "flatc")]
    pub fn encode(&self) -> Bytes {
        let mut fbb = flatbuffers::FlatBufferBuilder::new();
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
                        let seq = fbb.create_vector(address.as_ref());
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
        Bytes::from(fbb.finished_data().to_owned())
    }

    #[cfg(feature = "flatc")]
    pub fn decode(data: &[u8]) -> Option<Self> {
        let fbs_message = flatbuffers_verifier::get_root::<FbsDiscoveryMessage>(data).ok()?;
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
                        let multiaddr = Multiaddr::try_from(address.seq()?.to_vec()).ok()?;
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

    #[cfg(feature = "molc")]
    pub fn encode(self) -> Bytes {
        let playload = match self {
            DiscoveryMessage::GetNodes {
                version,
                count,
                listen_port,
            } => {
                let version_le = version.to_le_bytes();
                let count_le = count.to_le_bytes();
                let version = protocol_mol::Uint32::new_builder()
                    .nth0(version_le[0].into())
                    .nth1(version_le[1].into())
                    .nth2(version_le[2].into())
                    .nth3(version_le[3].into())
                    .build();
                let count = protocol_mol::Uint32::new_builder()
                    .nth0(count_le[0].into())
                    .nth1(count_le[1].into())
                    .nth2(count_le[2].into())
                    .nth3(count_le[3].into())
                    .build();
                let listen_port = protocol_mol::PortOpt::new_builder()
                    .set(listen_port.map(|port| {
                        let port_le = port.to_le_bytes();
                        protocol_mol::Uint16::new_builder()
                            .nth0(port_le[0].into())
                            .nth1(port_le[1].into())
                            .build()
                    }))
                    .build();
                let get_node = protocol_mol::GetNodes::new_builder()
                    .listen_port(listen_port)
                    .count(count)
                    .version(version)
                    .build();
                protocol_mol::DiscoveryPayload::new_builder()
                    .set(get_node)
                    .build()
            }
            DiscoveryMessage::Nodes(Nodes { announce, items }) => {
                let bool_ = if announce { 1u8 } else { 0 };
                let announce = protocol_mol::Bool::new_builder()
                    .set([bool_.into()])
                    .build();
                let mut item_vec = Vec::with_capacity(items.len());
                for item in items {
                    let mut vec_addrs = Vec::with_capacity(item.addresses.len());
                    for addr in item.addresses {
                        vec_addrs.push(
                            protocol_mol::Bytes::new_builder()
                                .set(addr.to_vec().into_iter().map(Into::into).collect())
                                .build(),
                        )
                    }
                    let bytes_vec = protocol_mol::BytesVec::new_builder().set(vec_addrs).build();
                    let node = protocol_mol::Node::new_builder()
                        .addresses(bytes_vec)
                        .build();
                    item_vec.push(node)
                }
                let items = protocol_mol::NodeVec::new_builder().set(item_vec).build();
                let nodes = protocol_mol::Nodes::new_builder()
                    .announce(announce)
                    .items(items)
                    .build();
                protocol_mol::DiscoveryPayload::new_builder()
                    .set(nodes)
                    .build()
            }
        };
        Bytes::from(
            protocol_mol::DiscoveryMessage::new_builder()
                .payload(playload)
                .build()
                .as_slice()
                .to_owned(),
        )
    }

    #[cfg(feature = "molc")]
    #[allow(clippy::cast_ptr_alignment)]
    pub fn decode(data: &[u8]) -> Option<Self> {
        let reader = protocol_mol::DiscoveryMessageReader::from_compatible_slice(data).ok()?;
        match reader.payload().to_enum() {
            protocol_mol::DiscoveryPayloadUnionReader::GetNodes(reader) => {
                let le = reader.version().raw_data().as_ptr() as *const u32;
                let version = u32::from_le(unsafe { *le });
                let le = reader.count().raw_data().as_ptr() as *const u32;
                let count = u32::from_le(unsafe { *le });
                let listen_port = reader.listen_port().to_opt().map(|port_reader| {
                    let le = port_reader.raw_data().as_ptr() as *const u16;
                    u16::from_le(unsafe { *le })
                });
                Some(DiscoveryMessage::GetNodes {
                    version,
                    count,
                    listen_port,
                })
            }
            protocol_mol::DiscoveryPayloadUnionReader::Nodes(reader) => {
                let announce = match reader.announce().as_slice()[0] {
                    0 => false,
                    1 => true,
                    _ => return None,
                };
                let mut items = Vec::with_capacity(reader.items().len());
                for node_reader in reader.items().iter() {
                    let mut addresses = Vec::with_capacity(node_reader.addresses().len());
                    for address_reader in node_reader.addresses().iter() {
                        addresses
                            .push(Multiaddr::try_from(address_reader.raw_data().to_vec()).ok()?)
                    }
                    items.push(Node { addresses })
                }
                Some(DiscoveryMessage::Nodes(Nodes { announce, items }))
            }
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
