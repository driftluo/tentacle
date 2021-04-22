use futures::prelude::*;

use std::time::Duration;
use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc},
};

use crate::{
    channel::mpsc,
    error::SendErrorKind,
    multiaddr::Multiaddr,
    protocol_select::ProtocolInfo,
    service::{event::ServiceTask, TargetProtocol, TargetSession},
    ProtocolId, SessionId,
};
use bytes::Bytes;
use std::sync::atomic::AtomicBool;

type Result = std::result::Result<(), SendErrorKind>;

/// Service control, used to send commands externally at runtime
#[derive(Clone)]
pub struct ServiceControl {
    pub(crate) task_sender: mpsc::Sender<ServiceTask>,
    pub(crate) proto_infos: Arc<HashMap<ProtocolId, ProtocolInfo>>,
    closed: Arc<AtomicBool>,
}

impl ServiceControl {
    /// New
    pub(crate) fn new(
        task_sender: mpsc::Sender<ServiceTask>,
        proto_infos: HashMap<ProtocolId, ProtocolInfo>,
        closed: Arc<AtomicBool>,
    ) -> Self {
        ServiceControl {
            task_sender,
            proto_infos: Arc::new(proto_infos),
            closed,
        }
    }

    /// Send raw event
    pub(crate) fn send(&self, event: ServiceTask) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        self.task_sender.try_send(event).map_err(|err| {
            if err.is_full() {
                SendErrorKind::WouldBlock
            } else {
                SendErrorKind::BrokenPipe
            }
        })
    }

    /// Send raw event on quick channel
    #[inline]
    fn quick_send(&self, event: ServiceTask) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        self.task_sender.try_quick_send(event).map_err(|err| {
            if err.is_full() {
                SendErrorKind::WouldBlock
            } else {
                SendErrorKind::BrokenPipe
            }
        })
    }

    /// Get service protocol message, Map(ID, Name), but can't modify
    #[inline]
    pub fn protocols(&self) -> &Arc<HashMap<ProtocolId, ProtocolInfo>> {
        &self.proto_infos
    }

    /// Create a new listener
    #[inline]
    pub fn listen(&self, address: Multiaddr) -> Result {
        self.quick_send(ServiceTask::Listen { address })
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&self, address: Multiaddr, target: TargetProtocol) -> Result {
        self.quick_send(ServiceTask::Dial { address, target })
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(&self, session_id: SessionId) -> Result {
        self.quick_send(ServiceTask::Disconnect { session_id })
    }

    /// Send message
    #[inline]
    pub fn send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.filter_broadcast(TargetSession::Single(session_id), proto_id, data)
    }

    /// Send message on quick channel
    #[inline]
    pub fn quick_send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.quick_filter_broadcast(TargetSession::Single(session_id), proto_id, data)
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub fn filter_broadcast(
        &self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.send(ServiceTask::ProtocolMessage {
            target,
            proto_id,
            data,
        })
    }

    /// Send data to the specified protocol for the specified sessions on quick channel.
    #[inline]
    pub fn quick_filter_broadcast(
        &self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.quick_send(ServiceTask::ProtocolMessage {
            target,
            proto_id,
            data,
        })
    }

    /// Send a future task
    #[inline]
    pub fn future_task<T>(&self, task: T) -> Result
    where
        T: Future<Output = ()> + 'static + Send,
    {
        self.send(ServiceTask::FutureTask {
            task: Box::pin(task),
        })
    }

    /// Try open a protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub fn open_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result {
        self.quick_send(ServiceTask::ProtocolOpen {
            session_id,
            target: proto_id.into(),
        })
    }

    /// Try open protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub fn open_protocols(&self, session_id: SessionId, target: TargetProtocol) -> Result {
        self.quick_send(ServiceTask::ProtocolOpen { session_id, target })
    }

    /// Try close a protocol
    ///
    /// If the protocol has been closed, do nothing
    #[inline]
    pub fn close_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result {
        self.quick_send(ServiceTask::ProtocolClose {
            session_id,
            proto_id,
        })
    }

    /// Set a service notify token
    pub fn set_service_notify(
        &self,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result {
        self.send(ServiceTask::SetProtocolNotify {
            proto_id,
            interval,
            token,
        })
    }

    /// remove a service notify token
    pub fn remove_service_notify(&self, proto_id: ProtocolId, token: u64) -> Result {
        self.send(ServiceTask::RemoveProtocolNotify { proto_id, token })
    }

    /// Set a session notify token
    pub fn set_session_notify(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result {
        self.send(ServiceTask::SetProtocolSessionNotify {
            session_id,
            proto_id,
            interval,
            token,
        })
    }

    /// Remove a session notify token
    pub fn remove_session_notify(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        token: u64,
    ) -> Result {
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
    pub fn close(&self) -> Result {
        self.quick_send(ServiceTask::Shutdown(false))
    }

    /// Shutdown service, don't care anything, may cause partial message loss
    pub fn shutdown(&self) -> Result {
        self.quick_send(ServiceTask::Shutdown(true))
    }
}

impl From<ServiceControl> for ServiceAsyncControl {
    fn from(control: ServiceControl) -> Self {
        ServiceAsyncControl {
            task_sender: control.task_sender,
            proto_infos: control.proto_infos,
            closed: control.closed,
        }
    }
}

impl From<ServiceAsyncControl> for ServiceControl {
    fn from(control: ServiceAsyncControl) -> Self {
        ServiceControl {
            task_sender: control.task_sender,
            proto_infos: control.proto_infos,
            closed: control.closed,
        }
    }
}

/// Service control, used to send commands externally at runtime, All interfaces are async methods
#[derive(Clone)]
pub struct ServiceAsyncControl {
    task_sender: mpsc::Sender<ServiceTask>,
    proto_infos: Arc<HashMap<ProtocolId, ProtocolInfo>>,
    closed: Arc<AtomicBool>,
}

impl ServiceAsyncControl {
    /// Send raw event
    async fn send(&self, event: ServiceTask) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        self.task_sender.async_send(event).await.map_err(|_err| {
            // await only return err when channel close
            SendErrorKind::BrokenPipe
        })
    }

    /// Send raw event on quick channel
    #[inline]
    async fn quick_send(&self, event: ServiceTask) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        self.task_sender
            .async_quick_send(event)
            .await
            .map_err(|_err| {
                // await only return err when channel close
                SendErrorKind::BrokenPipe
            })
    }

    /// Get service protocol message, Map(ID, Name), but can't modify
    #[inline]
    pub fn protocols(&self) -> &Arc<HashMap<ProtocolId, ProtocolInfo>> {
        &self.proto_infos
    }

    /// Create a new listener
    #[inline]
    pub async fn listen(&self, address: Multiaddr) -> Result {
        self.quick_send(ServiceTask::Listen { address }).await
    }

    /// Initiate a connection request to address
    #[inline]
    pub async fn dial(&self, address: Multiaddr, target: TargetProtocol) -> Result {
        self.quick_send(ServiceTask::Dial { address, target }).await
    }

    /// Disconnect a connection
    #[inline]
    pub async fn disconnect(&self, session_id: SessionId) -> Result {
        self.quick_send(ServiceTask::Disconnect { session_id })
            .await
    }

    /// Send message
    #[inline]
    pub async fn send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.filter_broadcast(TargetSession::Single(session_id), proto_id, data)
            .await
    }

    /// Send message on quick channel
    #[inline]
    pub async fn quick_send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.quick_filter_broadcast(TargetSession::Single(session_id), proto_id, data)
            .await
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub async fn filter_broadcast(
        &self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.send(ServiceTask::ProtocolMessage {
            target,
            proto_id,
            data,
        })
        .await
    }

    /// Send data to the specified protocol for the specified sessions on quick channel.
    #[inline]
    pub async fn quick_filter_broadcast(
        &self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.quick_send(ServiceTask::ProtocolMessage {
            target,
            proto_id,
            data,
        })
        .await
    }

    /// Send a future task
    #[inline]
    pub async fn future_task<T>(&self, task: T) -> Result
    where
        T: Future<Output = ()> + 'static + Send,
    {
        self.send(ServiceTask::FutureTask {
            task: Box::pin(task),
        })
        .await
    }

    /// Try open a protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub async fn open_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result {
        self.quick_send(ServiceTask::ProtocolOpen {
            session_id,
            target: proto_id.into(),
        })
        .await
    }

    /// Try open protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub async fn open_protocols(&self, session_id: SessionId, target: TargetProtocol) -> Result {
        self.quick_send(ServiceTask::ProtocolOpen { session_id, target })
            .await
    }

    /// Try close a protocol
    ///
    /// If the protocol has been closed, do nothing
    #[inline]
    pub async fn close_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result {
        self.quick_send(ServiceTask::ProtocolClose {
            session_id,
            proto_id,
        })
        .await
    }

    /// Set a service notify token
    pub async fn set_service_notify(
        &self,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result {
        self.send(ServiceTask::SetProtocolNotify {
            proto_id,
            interval,
            token,
        })
        .await
    }

    /// remove a service notify token
    pub async fn remove_service_notify(&self, proto_id: ProtocolId, token: u64) -> Result {
        self.send(ServiceTask::RemoveProtocolNotify { proto_id, token })
            .await
    }

    /// Set a session notify token
    pub async fn set_session_notify(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result {
        self.send(ServiceTask::SetProtocolSessionNotify {
            session_id,
            proto_id,
            interval,
            token,
        })
        .await
    }

    /// Remove a session notify token
    pub async fn remove_session_notify(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        token: u64,
    ) -> Result {
        self.send(ServiceTask::RemoveProtocolSessionNotify {
            session_id,
            proto_id,
            token,
        })
        .await
    }

    /// Close service
    ///
    /// Order:
    /// 1. close all listens
    /// 2. try close all session's protocol stream
    /// 3. try close all session
    /// 4. close service
    pub async fn close(&self) -> Result {
        self.quick_send(ServiceTask::Shutdown(false)).await
    }

    /// Shutdown service, don't care anything, may cause partial message loss
    pub async fn shutdown(&self) -> Result {
        self.quick_send(ServiceTask::Shutdown(true)).await
    }
}
