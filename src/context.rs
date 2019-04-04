use futures::{
    prelude::*,
    sync::{mpsc, oneshot},
};
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use crate::{
    multiaddr::Multiaddr,
    protocol_select::ProtocolInfo,
    secio::{PublicKey, SecioKeyPair},
    service::{event::ServiceTask, DialProtocol, ServiceControl, SessionType, TargetSession},
    session::SessionEvent,
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
    listens: Vec<Multiaddr>,
    key_pair: Option<SecioKeyPair>,
    inner: ServiceControl,
}

impl ServiceContext {
    /// New
    pub(crate) fn new(
        service_task_sender: mpsc::UnboundedSender<ServiceTask>,
        proto_infos: HashMap<ProtocolId, ProtocolInfo>,
        key_pair: Option<SecioKeyPair>,
    ) -> Self {
        ServiceContext {
            inner: ServiceControl::new(service_task_sender, proto_infos),
            key_pair,
            listens: Vec::new(),
        }
    }

    /// Create a new listener
    #[inline]
    pub fn listen(&mut self, address: Multiaddr) {
        self.inner
            .listen(address)
            .expect("Service is abnormally closed")
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&mut self, address: Multiaddr, target: DialProtocol) {
        self.inner
            .dial(address, target)
            .expect("Service is abnormally closed")
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(&mut self, session_id: SessionId) {
        self.inner
            .disconnect(session_id)
            .expect("Service is abnormally closed")
    }

    /// Send message
    #[inline]
    pub fn send_message(&mut self, session_id: SessionId, proto_id: ProtocolId, data: Vec<u8>) {
        self.inner
            .send_message(session_id, proto_id, data)
            .expect("Service is abnormally closed")
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub fn filter_broadcast(
        &mut self,
        session_ids: TargetSession,
        proto_id: ProtocolId,
        data: Vec<u8>,
    ) {
        self.inner
            .filter_broadcast(session_ids, proto_id, data)
            .expect("Service is abnormally closed")
    }

    /// Send a future task
    #[inline]
    pub fn future_task<T>(&mut self, task: T)
    where
        T: Future<Item = (), Error = ()> + 'static + Send,
    {
        self.inner
            .future_task(task)
            .expect("Service is abnormally closed")
    }

    /// Try open a protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub fn open_protocol(&mut self, session_id: SessionId, proto_id: ProtocolId) {
        self.inner
            .open_protocol(session_id, proto_id)
            .expect("Service is abnormally closed")
    }

    /// Try close a protocol
    ///
    /// If the protocol has been closed, do nothing
    #[inline]
    pub fn close_protocol(&mut self, session_id: SessionId, proto_id: ProtocolId) {
        self.inner
            .close_protocol(session_id, proto_id)
            .expect("Service is abnormally closed")
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
    pub fn listens(&self) -> &[Multiaddr] {
        self.listens.as_ref()
    }

    /// Update listen list
    #[inline]
    pub(crate) fn update_listens(&mut self, address_list: Vec<Multiaddr>) {
        self.listens = address_list;
    }

    /// Set a service notify token
    pub fn set_service_notify(&mut self, proto_id: ProtocolId, interval: Duration, token: u64) {
        self.inner
            .set_service_notify(proto_id, interval, token)
            .expect("Service is abnormally closed")
    }

    /// Set a session notify token
    pub fn set_session_notify(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) {
        self.inner
            .set_session_notify(session_id, proto_id, interval, token)
            .expect("Service is abnormally closed")
    }

    /// Remove a service timer by a token
    pub fn remove_service_notify(&mut self, proto_id: ProtocolId, token: u64) {
        self.inner
            .remove_service_notify(proto_id, token)
            .expect("Service is abnormally closed")
    }

    /// Remove a session timer by a token
    pub fn remove_session_notify(
        &mut self,
        session_id: SessionId,
        proto_id: ProtocolId,
        token: u64,
    ) {
        self.inner
            .remove_session_notify(session_id, proto_id, token)
            .expect("Service is abnormally closed")
    }

    pub(crate) fn clone_self(&self) -> Self {
        ServiceContext {
            inner: self.inner.clone(),
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
