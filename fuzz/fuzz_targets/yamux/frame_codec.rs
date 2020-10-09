#![no_main]
use libfuzzer_sys::fuzz_target;
use bytes::BytesMut;
use tokio_yamux::frame::FrameCodec;
use tokio_util::codec::Decoder;

fn decode(data: &[u8]) {
    let mut codec = FrameCodec::default();
    let mut data = BytesMut::from(data);
    let _ = codec.decode(&mut data);
}

fuzz_target!(|data: &[u8]| {
    decode(data);
});
