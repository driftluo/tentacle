use futures::{channel::mpsc, prelude::*};

use std::time::Duration;
use std::{
    collections::HashMap,
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use crate::{
    error::Error,
    multiaddr::Multiaddr,
    protocol_select::ProtocolInfo,
    service::{
        event::Priority, DialProtocol, ServiceTask, TargetProtocol, TargetSession,
        RECEIVED_BUFFER_SIZE,
    },
    ProtocolId, SessionId,
};
use bytes::Bytes;
use std::sync::atomic::AtomicBool;

/// Service control, used to send commands externally at runtime
#[derive(Clone)]
pub struct ServiceControl {
    pub(crate) service_task_sender: mpsc::UnboundedSender<ServiceTask>,
    pub(crate) quick_task_sender: mpsc::UnboundedSender<ServiceTask>,
    pub(crate) proto_infos: Arc<HashMap<ProtocolId, ProtocolInfo>>,
    pub(crate) normal_count: Arc<AtomicUsize>,
    pub(crate) quick_count: Arc<AtomicUsize>,
    timeout: Duration,
    closed: Arc<AtomicBool>,
}

impl ServiceControl {
    /// New
    pub(crate) fn new(
        service_task_sender: mpsc::UnboundedSender<ServiceTask>,
        quick_task_sender: mpsc::UnboundedSender<ServiceTask>,
        proto_infos: HashMap<ProtocolId, ProtocolInfo>,
        timeout: Duration,
        closed: Arc<AtomicBool>,
    ) -> Self {
        ServiceControl {
            service_task_sender,
            quick_task_sender,
            proto_infos: Arc::new(proto_infos),
            normal_count: Arc::new(AtomicUsize::new(0)),
            quick_count: Arc::new(AtomicUsize::new(0)),
            timeout,
            closed,
        }
    }

    pub(crate) fn normal_count_sub(&self) {
        self.normal_count.fetch_sub(1, Ordering::SeqCst);
    }

    pub(crate) fn quick_count_sub(&self) {
        self.quick_count.fetch_sub(1, Ordering::SeqCst);
    }

    fn block_send(
        &self,
        sender: &mpsc::UnboundedSender<ServiceTask>,
        event: ServiceTask,
        counter: &Arc<AtomicUsize>,
        limit: usize,
    ) -> Result<(), Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::IoError(io::ErrorKind::BrokenPipe.into()));
        }
        if counter.load(Ordering::SeqCst) < limit {
            counter.fetch_add(1, Ordering::SeqCst);
            sender.unbounded_send(event).map_err(Into::into)
        } else {
            Err(Error::IoError(io::ErrorKind::WouldBlock.into()))
        }
    }

    /// Send raw event
    pub(crate) fn send(&self, event: ServiceTask) -> Result<(), Error> {
        self.block_send(
            &self.service_task_sender,
            event,
            &self.normal_count,
            RECEIVED_BUFFER_SIZE,
        )
    }

    /// Send raw event on quick channel
    #[inline]
    fn quick_send(&self, event: ServiceTask) -> Result<(), Error> {
        self.block_send(
            &self.quick_task_sender,
            event,
            &self.quick_count,
            RECEIVED_BUFFER_SIZE / 2,
        )
    }

    /// Get service protocol message, Map(ID, Name), but can't modify
    #[inline]
    pub fn protocols(&self) -> &Arc<HashMap<ProtocolId, ProtocolInfo>> {
        &self.proto_infos
    }

    /// Create a new listener
    #[inline]
    pub fn listen(&self, address: Multiaddr) -> Result<(), Error> {
        self.quick_send(ServiceTask::Listen { address })
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&self, address: Multiaddr, target: DialProtocol) -> Result<(), Error> {
        self.quick_send(ServiceTask::Dial {
            address,
            target: target.into(),
        })
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(&self, session_id: SessionId) -> Result<(), Error> {
        self.quick_send(ServiceTask::Disconnect { session_id })
    }

    /// Send message
    #[inline]
    pub fn send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result<(), Error> {
        self.filter_broadcast(TargetSession::Single(session_id), proto_id, data)
    }

    /// Send message on quick channel
    #[inline]
    pub fn quick_send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result<(), Error> {
        self.quick_filter_broadcast(TargetSession::Single(session_id), proto_id, data)
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub fn filter_broadcast(
        &self,
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
        &self,
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
    pub fn future_task<T>(&self, task: T) -> Result<(), Error>
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
    pub fn open_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result<(), Error> {
        self.quick_send(ServiceTask::ProtocolOpen {
            session_id,
            target: proto_id.into(),
        })
    }

    /// Try open protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub fn open_protocols(
        &self,
        session_id: SessionId,
        target: TargetProtocol,
    ) -> Result<(), Error> {
        self.quick_send(ServiceTask::ProtocolOpen { session_id, target })
    }

    /// Try close a protocol
    ///
    /// If the protocol has been closed, do nothing
    #[inline]
    pub fn close_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
        self.send(ServiceTask::SetProtocolNotify {
            proto_id,
            interval,
            token,
        })
    }

    /// remove a service notify token
    pub fn remove_service_notify(&self, proto_id: ProtocolId, token: u64) -> Result<(), Error> {
        self.send(ServiceTask::RemoveProtocolNotify { proto_id, token })
    }

    /// Set a session notify token
    pub fn set_session_notify(
        &self,
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
        &self,
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
    pub fn close(&self) -> Result<(), Error> {
        self.quick_send(ServiceTask::Shutdown(false))
    }

    /// Shutdown service, don't care anything, may cause partial message loss
    pub fn shutdown(&self) -> Result<(), Error> {
        self.quick_send(ServiceTask::Shutdown(true))
    }
}
