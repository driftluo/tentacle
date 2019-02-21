use env_logger;
use log::{debug, info};

use std::time::Duration;

use futures::{future::lazy, prelude::*, sync::mpsc::channel};
use p2p::{
    builder::ServiceBuilder,
    context::ServiceContext,
    service::{ServiceError, ServiceEvent},
    traits::ServiceHandle,
};
use ping::{Event, PingProtocol};

fn main() {
    env_logger::init();
    if std::env::args().nth(1) == Some("server".to_string()) {
        debug!("Starting server ......");
        let (sender, receiver) = channel(256);
        let protocol =
            PingProtocol::new(1, Duration::from_secs(5), Duration::from_secs(15), sender);
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .forever(true)
            .build(SimpleHandler {});
        let _ = service.listen(&"/ip4/127.0.0.1/tcp/1337".parse().unwrap());
        tokio::run(lazy(|| {
            tokio::spawn(receiver.for_each(|event: Event| {
                info!("server receive event: {:?}", event);
                Ok(())
            }));
            service.for_each(|_| Ok(()))
        }))
    } else {
        debug!("Starting client ......");
        let (sender, receiver) = channel(256);
        let protocol =
            PingProtocol::new(1, Duration::from_secs(5), Duration::from_secs(15), sender);
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .forever(true)
            .build(SimpleHandler {});
        let _ = service.dial("/ip4/127.0.0.1/tcp/1337".parse().unwrap());
        let _ = service.listen(&"/ip4/127.0.0.1/tcp/1338".parse().unwrap());
        tokio::run(lazy(|| {
            tokio::spawn(receiver.for_each(|event| {
                info!("client receive event: {:?}", event);
                Ok(())
            }));
            service.for_each(|_| Ok(()))
        }))
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
