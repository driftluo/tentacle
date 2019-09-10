use futures::{future::pending, StreamExt};
use std::time::Duration;
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::ProtocolContext,
    service::{ProtocolHandle, ProtocolMeta, Service},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

pub fn create<F>(meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
{
    ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true)
        .build(shandle)
}

#[derive(Default)]
struct PHandle {
    count: u8,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, context: &mut ProtocolContext) {
        let proto_id = context.proto_id;

        let _ = context.set_service_notify(proto_id, Duration::from_secs(1), 1);

        for _ in 0..4096 {
            let _ = context.future_task(pending());
        }
    }

    fn notify(&mut self, context: &mut ProtocolContext, _token: u64) {
        self.count += 1;
        if self.count > 3 {
            let _ = context.shutdown();
        }
    }
}

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            let handle = Box::new(PHandle::default());
            ProtocolHandle::Callback(handle)
        })
        .build()
}

#[test]
fn test_block_future_task() {
    let mut service = create(create_meta(1.into()), ());

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.spawn(async move {
        loop {
            if service.next().await.is_none() {
                break;
            }
        }
    });
    rt.shutdown_on_idle();
}
