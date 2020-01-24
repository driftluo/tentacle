#[cfg(all(feature = "flatc", feature = "molc"))]
compile_error!("features `flatc` and `molc` are mutually exclusive");
#[cfg(all(not(feature = "flatc"), not(feature = "molc")))]
compile_error!("Please choose a serialization format via feature. Possible choices: flatc, molc");

#[cfg(feature = "flatc")]
use crate::protocol_generated::p2p::identify::{
    Address as FbsAddress, AddressBuilder, IdentifyMessage as FbsIdentifyMessage,
    IdentifyMessageBuilder,
};
#[cfg(feature = "molc")]
use crate::protocol_mol;
#[cfg(feature = "molc")]
use molecule::prelude::{Builder, Entity, Reader};

use bytes::Bytes;
use p2p::multiaddr::Multiaddr;

use std::convert::TryFrom;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentifyMessage<'a> {
    pub(crate) listen_addrs: Vec<Multiaddr>,
    pub(crate) observed_addr: Multiaddr,
    pub(crate) identify: &'a [u8],
}

impl<'a> IdentifyMessage<'a> {
    pub(crate) fn new(
        listen_addrs: Vec<Multiaddr>,
        observed_addr: Multiaddr,
        identify: &'a [u8],
    ) -> Self {
        IdentifyMessage {
            listen_addrs,
            observed_addr,
            identify,
        }
    }

    #[cfg(feature = "flatc")]
    pub(crate) fn encode(&self) -> Bytes {
        let mut fbb = flatbuffers::FlatBufferBuilder::new();

        let mut listens = Vec::new();
        for addr in self.listen_addrs.as_slice() {
            listens.push(addr_to_offset(&mut fbb, &addr));
        }
        let listens_vec = fbb.create_vector(&listens);

        let observed = addr_to_offset(&mut fbb, &self.observed_addr);

        let identify = fbb.create_vector(self.identify);

        let mut builder = IdentifyMessageBuilder::new(&mut fbb);

        builder.add_listen_addrs(listens_vec);
        builder.add_observed_addr(observed);
        builder.add_identify(identify);

        let data = builder.finish();

        fbb.finish(data, None);
        Bytes::from(fbb.finished_data().to_owned())
    }

    #[cfg(feature = "flatc")]
    pub(crate) fn decode(data: &'a [u8]) -> Option<Self> {
        let fbs_message = flatbuffers_verifier::get_root::<FbsIdentifyMessage>(data).ok()?;

        match (
            fbs_message.listen_addrs(),
            fbs_message.observed_addr(),
            fbs_message.identify(),
        ) {
            (Some(raw_listens), Some(raw_observed), Some(identify)) => {
                let mut listen_addrs = Vec::with_capacity(raw_listens.len());
                for i in 0..raw_listens.len() {
                    listen_addrs.push(fbs_to_addr(&raw_listens.get(i))?);
                }

                let observed_addr = fbs_to_addr(&raw_observed)?;

                Some(IdentifyMessage {
                    listen_addrs,
                    observed_addr,
                    identify,
                })
            }
            _ => None,
        }
    }

    #[cfg(feature = "molc")]
    pub(crate) fn encode(self) -> Bytes {
        let identify = protocol_mol::Bytes::new_builder()
            .set(self.identify.to_vec().into_iter().map(Into::into).collect())
            .build();
        let observed_addr = protocol_mol::Address::new_builder()
            .bytes(
                protocol_mol::Bytes::new_builder()
                    .set(
                        self.observed_addr
                            .to_vec()
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                    )
                    .build(),
            )
            .build();
        let mut listen_addrs = Vec::with_capacity(self.listen_addrs.len());
        for addr in self.listen_addrs {
            listen_addrs.push(
                protocol_mol::Address::new_builder()
                    .bytes(
                        protocol_mol::Bytes::new_builder()
                            .set(addr.to_vec().into_iter().map(Into::into).collect())
                            .build(),
                    )
                    .build(),
            )
        }
        let listen_addrs = protocol_mol::AddressVec::new_builder()
            .set(listen_addrs)
            .build();

        Bytes::from(
            protocol_mol::IdentifyMessage::new_builder()
                .listen_addrs(listen_addrs)
                .observed_addr(observed_addr)
                .identify(identify)
                .build()
                .as_slice()
                .to_owned(),
        )
    }

    #[cfg(feature = "molc")]
    pub(crate) fn decode(data: &'a [u8]) -> Option<Self> {
        let reader = protocol_mol::IdentifyMessageReader::from_compatible_slice(data).ok()?;

        let identify = reader.identify().raw_data();
        let observed_addr =
            Multiaddr::try_from(reader.observed_addr().bytes().raw_data().to_vec()).ok()?;
        let mut listen_addrs = Vec::with_capacity(reader.listen_addrs().len());
        for addr in reader.listen_addrs().iter() {
            listen_addrs.push(Multiaddr::try_from(addr.bytes().raw_data().to_vec()).ok()?)
        }

        Some(IdentifyMessage {
            identify,
            observed_addr,
            listen_addrs,
        })
    }
}

#[cfg(feature = "flatc")]
fn addr_to_offset<'b>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'b>,
    addr: &Multiaddr,
) -> flatbuffers::WIPOffset<FbsAddress<'b>> {
    let bytes = fbb.create_vector(addr.as_ref());
    let mut addr_builder = AddressBuilder::new(fbb);
    addr_builder.add_bytes(bytes);
    addr_builder.finish()
}

#[cfg(feature = "flatc")]
fn fbs_to_addr(addr: &FbsAddress) -> Option<Multiaddr> {
    Multiaddr::try_from(addr.bytes()?.to_vec()).ok()
}
