use crate::protocol_generated::p2p::ping::*;
use flatbuffers::{FlatBufferBuilder, WIPOffset};

impl<'a> PingMessage<'a> {
    pub fn build_ping<'b>(
        fbb: &mut FlatBufferBuilder<'b>,
        nonce: u32,
    ) -> WIPOffset<PingMessage<'b>> {
        let ping = {
            let mut ping = PingBuilder::new(fbb);
            ping.add_nonce(nonce);
            ping.finish()
        };
        let mut builder = PingMessageBuilder::new(fbb);
        builder.add_payload_type(PingPayload::Ping);
        builder.add_payload(ping.as_union_value());
        builder.finish()
    }

    pub fn build_pong<'b>(
        fbb: &mut FlatBufferBuilder<'b>,
        nonce: u32,
    ) -> WIPOffset<PingMessage<'b>> {
        let pong = {
            let mut pong = PongBuilder::new(fbb);
            pong.add_nonce(nonce);
            pong.finish()
        };
        let mut builder = PingMessageBuilder::new(fbb);
        builder.add_payload_type(PingPayload::Pong);
        builder.add_payload(pong.as_union_value());
        builder.finish()
    }
}
