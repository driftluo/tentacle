use futures::{
    prelude::*,
    sync::{mpsc, oneshot},
};
use std::{
    collections::{HashMap, VecDeque},
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use crate::{
    error::Error,
    multiaddr::Multiaddr,
    protocol_select::ProtocolInfo,
    secio::{PublicKey, SecioKeyPair},
    service::{DialProtocol, ServiceControl, ServiceTask},
    session::SessionEvent,
    yamux::session::SessionType,
    ProtocolId, SessionId,
};

pub(crate) struct SessionControl {
    pub(crate) inner: SessionContext,
    pub(crate) notify_signals: HashMap<ProtocolId, HashMap<u64, oneshot::Sender<()>>>,
    pub(crate) event_sender: mpsc::Sender<SessionEvent>,
}

/// Session context, contains basic information about the current connection
#[derive(Clone, Debug)]
pub struct SessionContext {
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
    pub(crate) pending_tasks: VecDeque<ServiceTask>,
    listens: Vec<Multiaddr>,
    key_pair: Option<SecioKeyPair>,
    inner: ServiceControl,
}

impl ServiceContext {
    /// New
    pub(crate) fn new(
        service_task_sender: mpsc::Sender<ServiceTask>,
        proto_infos: HashMap<ProtocolId, ProtocolInfo>,
        key_pair: Option<SecioKeyPair>,
    ) -> Self {
        ServiceContext {
            inner: ServiceControl::new(service_task_sender, proto_infos),
            pending_tasks: VecDeque::default(),
            key_pair,
            listens: Vec::new(),
        }
    }

    /// Create a new listener
    #[inline]
    pub fn listen(&mut self, address: Multiaddr) {
        if let Err(Error::TaskFull(task)) = self.inner.listen(address) {
            self.pending_tasks.push_back(task);
        }
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&mut self, address: Multiaddr, target: DialProtocol) {
        if let Err(Error::TaskFull(task)) = self.inner.dial(address, target) {
            self.pending_tasks.push_back(task);
        }
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(&mut self, session_id: SessionId) {
        if let Err(Error::TaskFull(task)) = self.inner.disconnect(session_id) {
            self.pending_tasks.push_back(task);
        }
    }

    /// Send message
    #[inline]
    pub fn send_message(&mut self, session_id: SessionId, proto_id: ProtocolId, data: Vec<u8>) {
        if let Err(Error::TaskFull(task)) = self.inner.send_message(session_id, proto_id, data) {
            self.pending_tasks.push_back(task);
        }
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub fn filter_broadcast(
        &mut self,
        session_ids: Option<Vec<SessionId>>,
        proto_id: ProtocolId,
        data: Vec<u8>,
    ) {
        if let Err(Error::TaskFull(task)) = self.inner.filter_broadcast(session_ids, proto_id, data)
        {
            self.pending_tasks.push_back(task);
        }
    }

    /// Send a future task
    #[inline]
    pub fn future_task<T>(&mut self, task: T)
    where
        T: Future<Item = (), Error = ()> + 'static + Send,
    {
        if let Err(Error::TaskFull(task)) = self.inner.future_task(task) {
            self.pending_tasks.push_back(task);
        }
    }

    /// Try open a protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub fn open_protocol(&mut self, session_id: SessionId, proto_id: ProtocolId) {
        if let Err(Error::TaskFull(task)) = self.inner.open_protocol(session_id, proto_id) {
            self.pending_tasks.push_back(task);
        }
    }

    /// Try close a protocol
    ///
    /// If the protocol has been closed, do nothing
    #[inline]
    pub fn close_protocol(&mut self, session_id: SessionId, proto_id: ProtocolId) {
        if let Err(Error::TaskFull(task)) = self.inner.close_protocol(session_id, proto_id) {
            self.pending_tasks.push_back(task);
        }
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

    /// Get the key pair of self
    #[inline]
    pub fn key_pair(&self) -> Option<&SecioKeyPair> {
        self.key_pair.as_ref()
    }

    /// Get service listen address list
    #[inline]
    pub fn listens(&self) -> &Vec<Multiaddr> {
        &self.listens
    }

    /// Send raw event
    #[inline]
    pub fn send(&mut self, event: ServiceTask) {
        if let Err(Error::TaskFull(task)) = self.inner.send(event) {
            self.pending_tasks.push_back(task);
        }
    }

    /// Update listen list
    #[inline]
    pub(crate) fn update_listens(&mut self, address_list: Vec<Multiaddr>) {
        self.listens = address_list;
    }

    /// Set a service notify token
    pub fn set_service_notify(&mut self, proto_id: ProtocolId, interval: Duration, token: u64) {
        if let Err(Error::TaskFull(task)) = self.inner.set_service_notify(proto_id, interval, token)
        {
            self.pending_tasks.push_back(task);
        }
    }

    /// Set a session notify token
    pub fn set_session_notify(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) {
        if let Err(Error::TaskFull(task)) = self
            .inner
            .set_session_notify(session_id, proto_id, interval, token)
        {
            self.pending_tasks.push_back(task);
        }
    }

    /// Remove a service timer by a token
    pub fn remove_service_notify(&mut self, proto_id: ProtocolId, token: u64) {
        if let Err(Error::TaskFull(task)) = self.inner.remove_service_notify(proto_id, token) {
            self.pending_tasks.push_back(task);
        }
    }

    /// Remove a session timer by a token
    pub fn remove_session_notify(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        token: u64,
    ) {
        if let Err(Error::TaskFull(task)) = self
            .inner
            .remove_session_notify(session_id, proto_id, token)
        {
            self.pending_tasks.push_back(task);
        }
    }

    pub(crate) fn clone_self(&self) -> Self {
        ServiceContext {
            inner: self.inner.clone(),
            pending_tasks: VecDeque::default(),
            key_pair: self.key_pair.clone(),
            listens: self.listens.clone(),
        }
    }
}

/// Protocol handle context
pub struct ProtocolContext {
    inner: ServiceContext,
    /// Protocol id
    pub proto_id: ProtocolId,
}

impl ProtocolContext {
    pub(crate) fn new(service_context: ServiceContext, proto_id: ProtocolId) -> Self {
        ProtocolContext {
            inner: service_context,
            proto_id,
        }
    }

    #[inline]
    pub(crate) fn as_mut<'a, 'b: 'a>(
        &'b mut self,
        session: &'a SessionContext,
    ) -> ProtocolContextMutRef<'a> {
        ProtocolContextMutRef {
            inner: &mut self.inner,
            proto_id: self.proto_id,
            session,
        }
    }
}

/// Protocol handle context contain session context
pub struct ProtocolContextMutRef<'a> {
    inner: &'a mut ServiceContext,
    /// Protocol id
    pub proto_id: ProtocolId,
    /// Session context
    pub session: &'a SessionContext,
}

impl<'a> ProtocolContextMutRef<'a> {
    /// Send message to current protocol current session
    #[inline]
    pub fn send_message(&mut self, data: Vec<u8>) {
        self.inner
            .send_message(self.session.id, self.proto_id, data)
    }
}

impl Deref for ProtocolContext {
    type Target = ServiceContext;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ProtocolContext {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a> Deref for ProtocolContextMutRef<'a> {
    type Target = ServiceContext;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a> DerefMut for ProtocolContextMutRef<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
