use env_logger;
use futures::prelude::*;
use log::info;
use p2p::{
    service::{
        Message, ProtocolHandle, Service, ServiceContext, ServiceEvent, ServiceHandle, ServiceTask,
    },
    sessions::{ProtocolId, ProtocolMeta, SessionId},
    StreamHandle,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::{
    str,
    time::{Duration, Instant},
};
use tokio::codec::{length_delimited::LengthDelimitedCodec, Framed};
use tokio::timer::{Delay, Interval};

pub struct Protocol {
    id: ProtocolId,
}

impl Protocol {
    fn new(id: ProtocolId) -> Self {
        Protocol { id }
    }
}

impl ProtocolMeta<LengthDelimitedCodec> for Protocol {
    fn id(&self) -> ProtocolId {
        self.id
    }
    fn framed(&self, stream: StreamHandle) -> Framed<StreamHandle, LengthDelimitedCodec> {
        Framed::new(stream, LengthDelimitedCodec::new())
    }
    fn handle(&self) -> Box<dyn ProtocolHandle + Send + 'static> {
        Box::new(PHandle {
            proto_id: self.id,
            count: 0,
            connected_session_ids: Vec::new(),
        })
    }
}

#[derive(Default)]
struct PHandle {
    proto_id: ProtocolId,
    count: usize,
    connected_session_ids: Vec<SessionId>,
}

impl ProtocolHandle for PHandle {
    fn init(&mut self, control: &mut ServiceContext) {
        if self.proto_id == 0 {
            let mut interval_sender = control.sender().clone();
            let proto_id = self.proto_id;
            let interval_task = Interval::new(Instant::now(), Duration::from_secs(5))
                .for_each(move |_| {
                    let _ = interval_sender
                        .try_send(ServiceTask::ProtocolNotify { proto_id, token: 3 });
                    Ok(())
                })
                .map_err(|err| info!("{}", err));
            control.future_task(Box::new(interval_task));
        } else {
            let mut interval_sender = control.sender().clone();
            let interval_task = Interval::new(Instant::now(), Duration::from_secs(5))
                .for_each(move |_| {
                    let _ = interval_sender.try_send(ServiceTask::ProtocolMessage {
                        ids: None,
                        message: Message {
                            id: 0,
                            proto_id: 1,
                            data: b"I am a interval message".to_vec(),
                        },
                    });
                    Ok(())
                })
                .map_err(|err| info!("{}", err));
            control.future_task(Box::new(interval_task));
        }
    }

    fn connected(&mut self, _control: &mut ServiceContext, session_id: SessionId) {
        self.connected_session_ids.push(session_id);
        info!("connected sessions are: {:?}", self.connected_session_ids);
    }
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

    fn notify(&mut self, _control: &mut ServiceContext, token: u64) {
        info!("proto [{}] received notify token: {}", self.proto_id, token);
    }
}

struct SHandle;

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceEvent) {
        info!("service error: {:?}", error);
    }
    fn handle_event(&mut self, env: &mut ServiceContext, event: ServiceEvent) {
        info!("service event: {:?}", event);
        if let ServiceEvent::SessionOpen { id, .. } = event {
            let mut delay_sender = env.sender().clone();

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

            env.future_task(Box::new(delay_task));
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

fn create_service() -> Service<SHandle, LengthDelimitedCodec> {
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
