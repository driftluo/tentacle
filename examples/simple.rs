use p2p::{service::Service, sessions::{ProtocolUpgrade, ProtocolId}};
use tokio::prelude::{AsyncRead, AsyncWrite};
use tokio::codec::{Framed, BytesCodec};
use std::sync::Arc;
use std::collections::HashMap;
use yamux::StreamHandle;
use futures::prelude::*;
use std::thread;
use log::{info};
use env_logger;

pub struct Protocol {
    id: ProtocolId,
    name: String
}

impl Protocol {
    fn new<T: Into<String>>(id: ProtocolId, name: T) -> Self {
        Protocol {
            id,
            name: name.into()
        }
    }
}

impl ProtocolUpgrade<StreamHandle, BytesCodec> for Protocol
{
    fn name(&self) -> &str {
        &self.name
    }
    fn id(&self) -> ProtocolId {
        self.id
    }
    fn framed(&self, stream: StreamHandle) -> Framed<StreamHandle, BytesCodec> {
        Framed::new(stream, BytesCodec::new())
    }
}

fn main() {
    env_logger::init();

    if std::env::args().nth(1) == Some("server".to_string()) {
        info!("Starting server ......");
        server();
    } else {
        info!("Starting client ......");
        client();
    }
}

fn server() {
    let proto = Protocol::new(0, "/proto/");
    let name = proto.name().to_string();
    let mut config: HashMap<String, Box<dyn ProtocolUpgrade<StreamHandle, BytesCodec> + Send + Sync>> = HashMap::new();
    config.insert(name, Box::new(proto));
    let mut service = Service::new(Arc::new(config));
    let _ = service.listen("127.0.0.1:1337".parse().unwrap());

    tokio::run(service.for_each(|event| {
        info!("{:?}", event);
        Ok(())
    }).map_err(|err| {
        info!("{:?}", err);
        ()
    }))
}

fn client() {
    let proto = Protocol::new(0, "/proto/");
    let name = proto.name().to_string();
    let mut config: HashMap<String, Box<dyn ProtocolUpgrade<StreamHandle, BytesCodec> + Send + Sync>> = HashMap::new();
    config.insert(name, Box::new(proto));
    let mut service = Service::new(Arc::new(config))
        .dialer("127.0.0.1:1337".parse().unwrap());
    let _ = service.listen("127.0.0.1:1337".parse().unwrap());

    tokio::run(service.for_each(|event| {
        info!("{:?}", event);
        Ok(())
    }).map_err(|err| {
        info!("{:?}", err);
        ()
    }))
}
