use futures::{
    prelude::*,
    sync::{mpsc, oneshot},
};

use log::{debug, warn};
use std::time::{Duration, Instant};
use std::{collections::HashMap, sync::Arc};
use tokio::timer::{self, Interval};

use crate::{
    error::Error,
    multiaddr::Multiaddr,
    protocol_select::ProtocolInfo,
    service::{DialProtocol, ServiceTask},
    ProtocolId, SessionId,
};

/// Service control, used to send commands externally at runtime
#[derive(Clone)]
pub struct ServiceControl {
    pub(crate) service_task_sender: mpsc::Sender<ServiceTask>,
    pub(crate) proto_infos: Arc<HashMap<ProtocolId, ProtocolInfo>>,
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

    /// Send raw event
    #[inline]
    pub fn send(&mut self, event: ServiceTask) -> Result<(), Error<ServiceTask>> {
        self.service_task_sender
            .try_send(event)
            .map_err(|e| e.into())
    }

    /// Get service protocol message, Map(ID, Name), but can't modify
    #[inline]
    pub fn protocols(&self) -> &Arc<HashMap<ProtocolId, ProtocolInfo>> {
        &self.proto_infos
    }

    /// Create a new listener
    #[inline]
    pub fn listen(&mut self, address: Multiaddr) -> Result<(), Error<ServiceTask>> {
        self.send(ServiceTask::Listen { address })
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(
        &mut self,
        address: Multiaddr,
        target: DialProtocol,
    ) -> Result<(), Error<ServiceTask>> {
        self.send(ServiceTask::Dial { address, target })
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(&mut self, session_id: SessionId) -> Result<(), Error<ServiceTask>> {
        self.send(ServiceTask::Disconnect { session_id })
    }

    /// Send message
    #[inline]
    pub fn send_message(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Vec<u8>,
    ) -> Result<(), Error<ServiceTask>> {
        self.filter_broadcast(Some(vec![session_id]), proto_id, data)
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub fn filter_broadcast(
        &mut self,
        session_ids: Option<Vec<SessionId>>,
        proto_id: ProtocolId,
        data: Vec<u8>,
    ) -> Result<(), Error<ServiceTask>> {
        self.send(ServiceTask::ProtocolMessage {
            session_ids,
            proto_id,
            data,
        })
    }

    /// Send a future task
    #[inline]
    pub fn future_task<T>(&mut self, task: T) -> Result<(), Error<ServiceTask>>
    where
        T: Future<Item = (), Error = ()> + 'static + Send,
    {
        self.send(ServiceTask::FutureTask {
            task: Box::new(task),
        })
    }

    /// Try open a protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub fn open_protocol(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
    ) -> Result<(), Error<ServiceTask>> {
        self.send(ServiceTask::ProtocolOpen {
            session_id,
            proto_id,
        })
    }

    /// Try close a protocol
    ///
    /// If the protocol has been closed, do nothing
    #[inline]
    pub fn close_protocol(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
    ) -> Result<(), Error<ServiceTask>> {
        self.send(ServiceTask::ProtocolClose {
            session_id,
            proto_id,
        })
    }

    /// Set a service notify token
    pub fn set_service_notify(
        &mut self,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result<oneshot::Sender<()>, Error<ServiceTask>> {
        let (signal_sender, mut signal_receiver) = oneshot::channel::<()>();
        let mut interval_sender = self.service_task_sender.clone();
        let fut = Interval::new(Instant::now(), interval)
            .for_each(move |_| {
                if signal_receiver.poll() == Ok(Async::NotReady) {
                    interval_sender
                        .try_send(ServiceTask::ProtocolNotify { proto_id, token })
                        .map_err(|err| {
                            debug!("interval error: {:?}", err);
                            timer::Error::shutdown()
                        })
                } else {
                    Err(timer::Error::shutdown())
                }
            })
            .map_err(|err| warn!("{}", err));
        self.future_task(fut).map(|()| signal_sender)
    }

    /// Set a session notify token
    pub fn set_session_notify(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result<oneshot::Sender<()>, Error<ServiceTask>> {
        let (signal_sender, mut signal_receiver) = oneshot::channel::<()>();
        let mut interval_sender = self.service_task_sender.clone();
        let fut = Interval::new(Instant::now(), interval)
            .for_each(move |_| {
                if signal_receiver.poll() == Ok(Async::NotReady) {
                    interval_sender
                        .try_send(ServiceTask::ProtocolSessionNotify {
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
        self.future_task(fut).map(|()| signal_sender)
    }
}
