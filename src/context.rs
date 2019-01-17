use futures::{
    prelude::*,
    sync::{mpsc, oneshot},
};
use log::{debug, warn};
use multiaddr::Multiaddr;
use secio::PublicKey;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::timer::{self, Interval};
use yamux::session::SessionType;

use crate::protocol_select::ProtocolInfo;
use crate::{
    service::{Message, ServiceTask},
    session::SessionEvent,
    ProtocolId, SessionId,
};

/// Session context
#[derive(Clone)]
pub struct SessionContext {
    pub(crate) event_sender: mpsc::Sender<SessionEvent>,
    /// Session's ID
    pub id: SessionId,
    /// Remote socket address
    pub address: Multiaddr,
    /// Session type (server or client)
    pub ty: SessionType,
    // TODO: use reference?
    /// Remote public key
    pub remote_pubkey: Option<PublicKey>,
}

/// The Service runtime can send some instructions to the inside of the handle.
/// This is the sending channel.
// TODO: Need to maintain the network topology map here?
pub struct ServiceContext {
    // For tell notify finished
    session_notify_senders: HashMap<(SessionId, ProtocolId), Vec<oneshot::Sender<()>>>,
    listens: Vec<Multiaddr>,
    inner: ServiceControl,
}

impl ServiceContext {
    /// New
    pub(crate) fn new(
        service_task_sender: mpsc::Sender<ServiceTask>,
        proto_infos: HashMap<ProtocolId, ProtocolInfo>,
    ) -> Self {
        ServiceContext {
            inner: ServiceControl::new(service_task_sender, proto_infos),
            session_notify_senders: HashMap::default(),
            listens: Vec::new(),
        }
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&mut self, address: Multiaddr) -> Result<(), mpsc::TrySendError<ServiceTask>> {
        self.inner.dial(address)
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(
        &mut self,
        session_id: SessionId,
    ) -> Result<(), mpsc::TrySendError<ServiceTask>> {
        self.inner.disconnect(session_id)
    }

    /// Send message
    #[inline]
    pub fn send_message(
        &mut self,
        session_ids: Option<Vec<SessionId>>,
        message: Message,
    ) -> Result<(), mpsc::TrySendError<ServiceTask>> {
        self.inner.send_message(session_ids, message)
    }

    /// Send a future task
    #[inline]
    pub fn future_task<T>(&mut self, task: T) -> Result<(), mpsc::TrySendError<ServiceTask>>
    where
        T: Future<Item = (), Error = ()> + 'static + Send,
    {
        self.inner.future_task(task)
    }

    /// Set a service notify token
    pub fn set_service_notify(&mut self, proto_id: ProtocolId, interval: Duration, token: u64) {
        let mut interval_sender = self.control().clone();
        let fut = Interval::new(Instant::now(), interval)
            .for_each(move |_| {
                interval_sender
                    .send(ServiceTask::ProtocolNotify { proto_id, token })
                    .map_err(|err| {
                        debug!("interval error: {:?}", err);
                        timer::Error::shutdown()
                    })
            })
            .map_err(|err| warn!("{}", err));
        let _ = self.future_task(fut);
    }

    /// Set as session notify token
    pub fn set_session_notify(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) {
        let (sender, mut receiver) = oneshot::channel::<()>();
        self.session_notify_senders
            .entry((session_id, proto_id))
            .or_default()
            .push(sender);
        let mut interval_sender = self.control().clone();
        let fut = Interval::new(Instant::now(), interval)
            .for_each(move |_| {
                if receiver.poll() == Ok(Async::NotReady) {
                    interval_sender
                        .send(ServiceTask::ProtocolSessionNotify {
                            session_id,
                            proto_id,
                            token,
                        })
                        .map_err(|err| {
                            debug!("interval error: {:?}", err);
                            timer::Error::shutdown()
                        })
                } else {
                    Err(timer::Error::shutdown())
                }
            })
            .map_err(|err| warn!("{}", err));
        let _ = self.future_task(fut);
    }

    /// Get the internal channel sender side handle
    #[inline]
    pub fn control(&mut self) -> &mut ServiceControl {
        &mut self.inner
    }

    /// Get service protocol message, Map(ID, Name), but can't modify
    #[inline]
    pub fn protocols(&self) -> &Arc<HashMap<ProtocolId, ProtocolInfo>> {
        &self.inner.proto_infos
    }

    /// Get service listen address list
    #[inline]
    pub fn listens(&self) -> &Vec<Multiaddr> {
        &self.listens
    }

    /// Update listen list
    #[inline]
    pub(crate) fn update_listens(&mut self, address_list: Vec<Multiaddr>) {
        self.listens = address_list;
    }

    pub(crate) fn remove_session_notify_senders(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
    ) {
        if let Some(senders) = self.session_notify_senders.remove(&(session_id, proto_id)) {
            for sender in senders {
                let _ = sender.send(());
            }
        }
    }
}

/// Service control
#[derive(Clone)]
pub struct ServiceControl {
    service_task_sender: mpsc::Sender<ServiceTask>,
    proto_infos: Arc<HashMap<ProtocolId, ProtocolInfo>>,
}

impl ServiceControl {
    /// New
    pub(crate) fn new(
        service_task_sender: mpsc::Sender<ServiceTask>,
        proto_infos: HashMap<ProtocolId, ProtocolInfo>,
    ) -> Self {
        ServiceControl {
            service_task_sender,
            proto_infos: Arc::new(proto_infos),
        }
    }

    /// Real send function
    #[inline]
    fn send(&mut self, event: ServiceTask) -> Result<(), mpsc::TrySendError<ServiceTask>> {
        self.service_task_sender.try_send(event)
    }

    /// Get service protocol message, Map(ID, Name), but can't modify
    #[inline]
    pub fn protocols(&self) -> &Arc<HashMap<ProtocolId, ProtocolInfo>> {
        &self.proto_infos
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&mut self, address: Multiaddr) -> Result<(), mpsc::TrySendError<ServiceTask>> {
        self.send(ServiceTask::Dial { address })
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(
        &mut self,
        session_id: SessionId,
    ) -> Result<(), mpsc::TrySendError<ServiceTask>> {
        self.send(ServiceTask::Disconnect { session_id })
    }

    /// Send message
    #[inline]
    pub fn send_message(
        &mut self,
        session_ids: Option<Vec<SessionId>>,
        message: Message,
    ) -> Result<(), mpsc::TrySendError<ServiceTask>> {
        self.send(ServiceTask::ProtocolMessage {
            session_ids,
            message,
        })
    }

    /// Send a future task
    #[inline]
    pub fn future_task<T>(&mut self, task: T) -> Result<(), mpsc::TrySendError<ServiceTask>>
    where
        T: Future<Item = (), Error = ()> + 'static + Send,
    {
        self.send(ServiceTask::FutureTask {
            task: Box::new(task),
        })
    }
}
