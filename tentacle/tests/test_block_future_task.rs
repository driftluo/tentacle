use futures::future::pending;
use std::time::Duration;
use tentacle::{
    async_trait,
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

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, context: &mut ProtocolContext) {
        let proto_id = context.proto_id;

        let _rse = context
            .set_service_notify(proto_id, Duration::from_millis(100), 1)
            .await;

        for _ in 0..4096 {
            let _res = context.future_task(pending()).await;
        }
    }

    async fn notify(&mut self, context: &mut ProtocolContext, _token: u64) {
        self.count += 1;
        if self.count > 3 {
            let _res = context.shutdown().await;
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
    rt.block_on(async move { service.run().await });
}
