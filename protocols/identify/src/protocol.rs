use flatbuffers::{FlatBufferBuilder, WIPOffset};
use flatbuffers_verifier::get_root;

use crate::protocol_generated::p2p::identify::{
    Address as FbsAddress, AddressBuilder, IdentifyMessage as FbsIdentifyMessage,
    IdentifyMessageBuilder,
};
use bytes::Bytes;
use p2p::multiaddr::Multiaddr;

use std::convert::TryFrom;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentifyMessage {
    pub(crate) listen_addrs: Vec<Multiaddr>,
    pub(crate) observed_addr: Multiaddr,
    pub(crate) identify: Vec<u8>,
}

impl IdentifyMessage {
    pub(crate) fn new(
        listen_addrs: Vec<Multiaddr>,
        observed_addr: Multiaddr,
        identify: Vec<u8>,
    ) -> Self {
        IdentifyMessage {
            listen_addrs,
            observed_addr,
            identify,
        }
    }

    pub(crate) fn encode(&self) -> Bytes {
        let mut fbb = FlatBufferBuilder::new();

        let mut listens = Vec::new();
        for addr in self.listen_addrs.as_slice() {
            listens.push(addr_to_offset(&mut fbb, &addr));
        }
        let listens_vec = fbb.create_vector(&listens);

        let observed = addr_to_offset(&mut fbb, &self.observed_addr);

        let identify = fbb.create_vector(self.identify.as_slice());

        let mut builder = IdentifyMessageBuilder::new(&mut fbb);

        builder.add_listen_addrs(listens_vec);
        builder.add_observed_addr(observed);
        builder.add_identify(identify);

        let data = builder.finish();

        fbb.finish(data, None);
        Bytes::from(fbb.finished_data())
    }

    pub(crate) fn decode(data: &[u8]) -> Option<Self> {
        let fbs_message = get_root::<FbsIdentifyMessage>(data).ok()?;

        match (
            fbs_message.listen_addrs(),
            fbs_message.observed_addr(),
            fbs_message.identify(),
        ) {
            (Some(raw_listens), Some(raw_observed), Some(raw_identify)) => {
                let mut listen_addrs = Vec::with_capacity(raw_listens.len());
                for i in 0..raw_listens.len() {
                    listen_addrs.push(fbs_to_addr(&raw_listens.get(i))?);
                }

                let observed_addr = fbs_to_addr(&raw_observed)?;

                let identify = raw_identify.to_owned();

                Some(IdentifyMessage {
                    listen_addrs,
                    observed_addr,
                    identify,
                })
            }
            _ => None,
        }
    }
}

fn addr_to_offset<'b>(
    fbb: &mut FlatBufferBuilder<'b>,
    addr: &Multiaddr,
) -> WIPOffset<FbsAddress<'b>> {
    let bytes = fbb.create_vector(addr.as_ref());
    let mut addr_builder = AddressBuilder::new(fbb);
    addr_builder.add_bytes(bytes);
    addr_builder.finish()
}

fn fbs_to_addr(addr: &FbsAddress) -> Option<Multiaddr> {
    Multiaddr::try_from(addr.bytes()?.to_vec()).ok()
}
