use flatbuffers::{FlatBufferBuilder, WIPOffset};
use flatbuffers_verifier::get_root;

use crate::protocol_generated::p2p::identify::{
    Address as FbsAddress, AddressBuilder, IdentifyMessage as FbsIdentifyMessage,
    IdentifyMessageBuilder, IdentifyPayload as FbsIdentifyPayload, ListenAddrs as FbsListenAddrs,
    ListenAddrsBuilder, ObservedAddr as FbsObservedAddr, ObservedAddrBuilder,
};
use bytes::Bytes;
use p2p::multiaddr::Multiaddr;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum IdentifyMessage {
    ListenAddrs(Vec<Multiaddr>),
    ObservedAddr(Multiaddr),
}

impl IdentifyMessage {
    pub(crate) fn encode(&self) -> Bytes {
        let mut fbb = FlatBufferBuilder::new();
        let offset = match self {
            IdentifyMessage::ListenAddrs(addrs) => {
                let mut vec_addrs = Vec::new();
                for addr in addrs {
                    vec_addrs.push(addr_to_offset(&mut fbb, addr));
                }
                let fbs_addrs = fbb.create_vector(&vec_addrs);
                let mut listen_addrs_builder = ListenAddrsBuilder::new(&mut fbb);
                listen_addrs_builder.add_addrs(fbs_addrs);
                let listen_addrs = listen_addrs_builder.finish();

                let mut builder = IdentifyMessageBuilder::new(&mut fbb);
                builder.add_payload_type(FbsIdentifyPayload::ListenAddrs);
                builder.add_payload(listen_addrs.as_union_value());
                builder.finish()
            }
            IdentifyMessage::ObservedAddr(addr) => {
                let addr_offset = addr_to_offset(&mut fbb, &addr);
                let mut observed_addr_builder = ObservedAddrBuilder::new(&mut fbb);
                observed_addr_builder.add_addr(addr_offset);
                let observed_addr = observed_addr_builder.finish();

                let mut builder = IdentifyMessageBuilder::new(&mut fbb);
                builder.add_payload_type(FbsIdentifyPayload::ObservedAddr);
                builder.add_payload(observed_addr.as_union_value());
                builder.finish()
            }
        };
        fbb.finish(offset, None);
        Bytes::from(fbb.finished_data())
    }

    pub(crate) fn decode(data: &[u8]) -> Option<Self> {
        let fbs_message = get_root::<FbsIdentifyMessage>(data).ok()?;
        let payload = fbs_message.payload()?;
        match fbs_message.payload_type() {
            FbsIdentifyPayload::ListenAddrs => {
                let fbs_listen_addrs = FbsListenAddrs::init_from_table(payload);
                let fbs_addrs = fbs_listen_addrs.addrs()?;
                let mut addrs = Vec::new();
                for i in 0..fbs_addrs.len() {
                    let addr = fbs_addrs.get(i);
                    addrs.push(fbs_to_addr(&addr)?);
                }
                Some(IdentifyMessage::ListenAddrs(addrs))
            }
            FbsIdentifyPayload::ObservedAddr => {
                let fbs_observed_addr = FbsObservedAddr::init_from_table(payload);
                let fbs_addr = fbs_observed_addr.addr()?;
                let addr = fbs_to_addr(&fbs_addr)?;
                Some(IdentifyMessage::ObservedAddr(addr))
            }
            _ => None,
        }
    }
}

fn addr_to_offset<'b>(
    fbb: &mut FlatBufferBuilder<'b>,
    addr: &Multiaddr,
) -> WIPOffset<FbsAddress<'b>> {
    let bytes = fbb.create_vector(&addr.to_bytes());
    let mut addr_builder = AddressBuilder::new(fbb);
    addr_builder.add_bytes(bytes);
    addr_builder.finish()
}

fn fbs_to_addr(addr: &FbsAddress) -> Option<Multiaddr> {
    Multiaddr::from_bytes(addr.bytes()?.to_vec()).ok()
}
