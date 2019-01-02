use env_logger;
use bincode::{deserialize, serialize};
use bytes::{BufMut, Bytes, BytesMut};
use fnv::{FnvHashMap, FnvHashSet};
use futures::{
    sync::mpsc::{channel, Receiver, Sender},
    try_ready, Async, AsyncSink, Poll, Sink, Stream,
};
use log::{debug, info, warn, error};
use serde_derive::{Deserialize, Serialize};
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::{self, Interval};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use discovery::{
    RawAddr,
    Discovery,
    DiscoveryHandle,
    DemoAddressManager,
};

fn main() {
    env_logger::init();
    info!("Starting ......");
    let addrs: FnvHashMap<RawAddr, i32>  = (1..3333)
        .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))
        .map(|addr| (RawAddr::from(addr), 100))
        .collect();
    start_discovery(&addrs);
}

fn start_discovery(addrs: &FnvHashMap<RawAddr, i32>) {
    let addr_mgr = DemoAddressManager { addrs: addrs.clone() };
    let discovery = Discovery::new(addr_mgr);
    let handle = discovery.handle();
    let fut = discovery
        .map_err(|err| {
            warn!("Receive nodes error: {:?}", err);
            ()
        })
        .for_each(|nodes| {
            info!("Got nodes: {:?}", nodes);
            Ok(())
        });
    tokio::run(fut);
}
