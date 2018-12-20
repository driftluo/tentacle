use env_logger;
use futures::prelude::*;
use log::info;
use p2p::{
    service::{
        Message, ProtocolHandle, Service, ServiceContext, ServiceEvent, ServiceHandle, ServiceTask,
    },
    sessions::{ProtocolId, ProtocolMeta},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::{
    str,
    time::{Duration, Instant},
};
use tokio::codec::{BytesCodec, Framed};
use tokio::timer::{Delay, Interval};
use yamux::StreamHandle;

pub struct Protocol {
    id: ProtocolId,
}

impl Protocol {
    fn new(id: ProtocolId) -> Self {
        Protocol { id }
    }
}

impl ProtocolMeta<BytesCodec> for Protocol {
    fn id(&self) -> ProtocolId {
        self.id
    }
    fn framed(&self, stream: StreamHandle) -> Framed<StreamHandle, BytesCodec> {
        Framed::new(stream, BytesCodec::new())
    }
    fn handle(&self) -> Box<dyn ProtocolHandle + Send + 'static> {
        Box::new(PHandle::default())
    }
}

#[derive(Default)]
struct PHandle {
    count: usize,
}

impl ProtocolHandle for PHandle {
    fn received(&mut self, _env: &mut ServiceContext, data: Message) {
        self.count += 1;
        info!(
            "received from [{}]: proto [{}] data {:?}, message count: {}",
            data.id,
            data.proto_id,
            str::from_utf8(&data.data).unwrap(),
            self.count
        );
    }
}

struct SHandle;

impl ServiceHandle for SHandle {
    fn error_handle(&mut self, _env: &mut ServiceContext, error: ServiceEvent) {
        info!("service error: {:?}", error);
    }
    fn session_handle(&mut self, env: &mut ServiceContext, event: ServiceEvent) {
        info!("service event: {:?}", event);
        if let ServiceEvent::SessionOpen { id, .. } = event {
            let mut delay_sender = env.sender().clone();
            let mut interval_sender = env.sender().clone();
            let delay_task = Delay::new(Instant::now() + Duration::from_secs(3))
                .and_then(move |_| {
                    let _ = delay_sender.try_send(ServiceTask::ProtocolMessage {
                        ids: None,
                        message: Message {
                            id,
                            proto_id: 0,
                            data: b"I am a delayed message".to_vec(),
                        },
                    });
                    Ok(())
                })
                .map_err(|err| info!("{}", err));
            let interval_task = Interval::new(Instant::now(), Duration::from_secs(5))
                .for_each(move |_| {
                    let _ = interval_sender.try_send(ServiceTask::ProtocolMessage {
                        ids: None,
                        message: Message {
                            id,
                            proto_id: 1,
                            data: b"I am a interval message".to_vec(),
                        },
                    });
                    Ok(())
                })
                .map_err(|err| info!("{}", err));
            env.future_task(Box::new(delay_task));
            env.future_task(Box::new(interval_task));
        }
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

fn create_service() -> Service<SHandle, BytesCodec> {
    let proto_0 = Protocol::new(0);
    let name_0 = proto_0.name();
    let proto_1 = Protocol::new(1);
    let name_1 = proto_1.name();
    let mut config = HashMap::new();
    config.insert(
        name_0,
        Box::new(proto_0) as Box<dyn ProtocolMeta<_> + Send + Sync>,
    );
    config.insert(
        name_1,
        Box::new(proto_1) as Box<dyn ProtocolMeta<_> + Send + Sync>,
    );
    Service::new(Arc::new(config), SHandle)
}

fn server() {
    let mut service = create_service();
    let _ = service.listen("127.0.0.1:1337".parse().unwrap());

    tokio::run(service.for_each(|_| Ok(())))
}

fn client() {
    let mut service = create_service().dial("127.0.0.1:1337".parse().unwrap());
    let _ = service.listen("127.0.0.1:1337".parse().unwrap());

    tokio::run(service.for_each(|_| Ok(())))
}
