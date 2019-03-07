use env_logger;
use log::{debug, info};

use std::time::Duration;

use futures::{future::lazy, prelude::*, sync::mpsc::channel};
use identify::IdentifyProtocol;
use tentacle::{
    builder::ServiceBuilder,
    context::ServiceContext,
    secio::SecioKeyPair,
    service::{ServiceError, ServiceEvent},
    traits::ServiceHandle,
};

fn main() {
    env_logger::init();
    let protocol = IdentifyProtocol::new(1);
    if std::env::args().nth(1) == Some("server".to_string()) {
        debug!("Starting server ......");
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .key_pair(SecioKeyPair::secp256k1_generated())
            .forever(true)
            .build(SimpleHandler {});
        let _ = service.dial("/ip4/127.0.0.1/tcp/1338".parse().unwrap());
        let _ = service.listen("/ip4/127.0.0.1/tcp/1337".parse().unwrap());
        tokio::run(lazy(|| service.for_each(|_| Ok(()))))
    } else {
        debug!("Starting client ......");
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .key_pair(SecioKeyPair::secp256k1_generated())
            .forever(true)
            .build(SimpleHandler {});
        let _ = service.dial("/ip4/127.0.0.1/tcp/1337".parse().unwrap());
        let _ = service.listen("/ip4/127.0.0.1/tcp/1338".parse().unwrap());
        tokio::run(lazy(|| service.for_each(|_| Ok(()))))
    }
}

struct SimpleHandler {}

impl ServiceHandle for SimpleHandler {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        debug!("service error: {:?}", error);
    }

    fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        debug!("service event: {:?}", event);
    }
}
