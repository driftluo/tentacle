use futures::{prelude::*, sync::mpsc};

use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use crate::{
    error::Error,
    multiaddr::Multiaddr,
    protocol_select::ProtocolInfo,
    service::{event::Priority, DialProtocol, ServiceTask, TargetSession},
    ProtocolId, SessionId,
};
use bytes::Bytes;

/// Service control, used to send commands externally at runtime
#[derive(Clone)]
pub struct ServiceControl {
    pub(crate) service_task_sender: mpsc::Sender<ServiceTask>,
    pub(crate) quick_task_sender: mpsc::Sender<ServiceTask>,
    pub(crate) proto_infos: Arc<HashMap<ProtocolId, ProtocolInfo>>,
}

impl ServiceControl {
    /// New
    pub(crate) fn new(
        service_task_sender: mpsc::Sender<ServiceTask>,
        quick_task_sender: mpsc::Sender<ServiceTask>,
        proto_infos: HashMap<ProtocolId, ProtocolInfo>,
    ) -> Self {
        ServiceControl {
            service_task_sender,
            quick_task_sender,
            proto_infos: Arc::new(proto_infos),
        }
    }

    /// Send raw event
    #[inline]
    fn send(&mut self, event: ServiceTask) -> Result<(), Error> {
        self.service_task_sender.start_send(event)?;
        loop {
            // Wait until the message has been sent
            if self.service_task_sender.poll_complete()?.is_ready() {
                return Ok(());
            }
        }
    }

    /// Send raw event on quick channel
    #[inline]
    fn quick_send(&mut self, event: ServiceTask) -> Result<(), Error> {
        self.quick_task_sender.start_send(event)?;
        loop {
            // Wait until the message has been sent
            if self.quick_task_sender.poll_complete()?.is_ready() {
                return Ok(());
            }
        }
    }

    /// Get service protocol message, Map(ID, Name), but can't modify
    #[inline]
    pub fn protocols(&self) -> &Arc<HashMap<ProtocolId, ProtocolInfo>> {
        &self.proto_infos
    }

    /// Create a new listener
    #[inline]
    pub fn listen(&mut self, address: Multiaddr) -> Result<(), Error> {
        self.send(ServiceTask::Listen { address })
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&mut self, address: Multiaddr, target: DialProtocol) -> Result<(), Error> {
        self.send(ServiceTask::Dial { address, target })
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(&mut self, session_id: SessionId) -> Result<(), Error> {
        self.send(ServiceTask::Disconnect { session_id })
    }

    /// Send message
    #[inline]
    pub fn send_message_to(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result<(), Error> {
        self.filter_broadcast(TargetSession::Single(session_id), proto_id, data)
    }

    /// Send message on quick channel
    #[inline]
    pub fn quick_send_message_to(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result<(), Error> {
        self.quick_filter_broadcast(TargetSession::Single(session_id), proto_id, data)
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub fn filter_broadcast(
        &mut self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result<(), Error> {
        self.send(ServiceTask::ProtocolMessage {
            target,
            proto_id,
            priority: Priority::Normal,
            data,
        })
    }

    /// Send data to the specified protocol for the specified sessions on quick channel.
    #[inline]
    pub fn quick_filter_broadcast(
        &mut self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result<(), Error> {
        self.quick_send(ServiceTask::ProtocolMessage {
            target,
            proto_id,
            priority: Priority::High,
            data,
        })
    }

    /// Send a future task
    #[inline]
    pub fn future_task<T>(&mut self, task: T) -> Result<(), Error>
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
        self.send(ServiceTask::SetProtocolNotify {
            proto_id,
            interval,
            token,
        })
    }

    /// remove a service notify token
    pub fn remove_service_notify(&mut self, proto_id: ProtocolId, token: u64) -> Result<(), Error> {
        self.send(ServiceTask::RemoveProtocolNotify { proto_id, token })
    }

    /// Set a session notify token
    pub fn set_session_notify(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result<(), Error> {
        self.send(ServiceTask::SetProtocolSessionNotify {
            session_id,
            proto_id,
            interval,
            token,
        })
    }

    /// Remove a session notify token
    pub fn remove_session_notify(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        token: u64,
    ) -> Result<(), Error> {
        self.send(ServiceTask::RemoveProtocolSessionNotify {
            session_id,
            proto_id,
            token,
        })
    }

    /// Close service
    ///
    /// Order:
    /// 1. close all listens
    /// 2. try close all session's protocol stream
    /// 3. try close all session
    /// 4. close service
    pub fn close(&mut self) -> Result<(), Error> {
        self.quick_send(ServiceTask::Shutdown(false))
    }

    /// Shutdown service, don't care anything, may cause partial message loss
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.quick_send(ServiceTask::Shutdown(true))
    }
}
