#[rustfmt::skip]
#[allow(clippy::all)]
mod protocol_generated;

mod protocol;

use log::{debug, error};
use p2p::{
    context::{ServiceContext, SessionContext},
    secio::PeerId,
    traits::{ProtocolHandle, ProtocolMeta, ServiceProtocol},
    utils::multiaddr_to_socketaddr,
    ProtocolId, SessionId,
};
use std::net::SocketAddr;
use tokio::codec::length_delimited::LengthDelimitedCodec;

use protocol::IdentifyMessage;

pub trait AddrManager {}

pub struct IdentifyProtocol {
    id: ProtocolId,
    listen_addrs: Vec<SocketAddr>,
}

impl ProtocolMeta<LengthDelimitedCodec> for IdentifyProtocol {
    fn id(&self) -> ProtocolId {
        self.id
    }

    fn codec(&self) -> LengthDelimitedCodec {
        LengthDelimitedCodec::new()
    }

    fn service_handle(&self) -> ProtocolHandle<Box<dyn ServiceProtocol + Send + 'static>> {
        ProtocolHandle::Empty
    }
}

impl ServiceProtocol for IdentifyProtocol {
    fn init(&mut self, service: &mut ServiceContext) {
        self.listen_addrs = service
            .listens()
            .iter()
            .map(|addr| multiaddr_to_socketaddr(addr).unwrap())
            .collect();
    }

    fn connected(
        &mut self,
        service: &mut ServiceContext,
        session: &SessionContext,
        _version: &str,
    ) {
        let data = IdentifyMessage::ListenAddrs(self.listen_addrs.clone()).encode();
        service.send_message(session.id, self.id, data);
        let remote_addr =
            multiaddr_to_socketaddr(&session.address).expect("Can not get remote address");
        let data = IdentifyMessage::ObservedAddr(remote_addr).encode();
        service.send_message(session.id, self.id, data);
    }

    fn disconnected(&mut self, _service: &mut ServiceContext, _session: &SessionContext) {}

    fn received(
        &mut self,
        _service: &mut ServiceContext,
        _session: &SessionContext,
        _data: bytes::Bytes,
    ) {
    }

    fn notify(&mut self, _service: &mut ServiceContext, _token: u64) {}
}
