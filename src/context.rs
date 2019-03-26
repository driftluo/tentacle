use futures::{
    prelude::*,
    sync::{mpsc, oneshot},
};
use log::{debug, warn};
use std::{
    collections::{HashMap, VecDeque},
    ops::{Deref, DerefMut},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::timer::{self, Interval};

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
    // For tell notify finished
    session_notify_senders: HashMap<(SessionId, ProtocolId), Vec<oneshot::Sender<()>>>,
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
            session_notify_senders: HashMap::default(),
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
        self.future_task(fut);
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
        self.future_task(fut);
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

    pub(crate) fn clone_self(&self) -> Self {
        ServiceContext {
            inner: self.inner.clone(),
            session_notify_senders: HashMap::default(),
            pending_tasks: VecDeque::default(),
            key_pair: self.key_pair.clone(),
            listens: self.listens.clone(),
        }
    }
}

/// Protocol handle context
pub struct HandleContext {
    inner: ServiceContext,
    /// Protocol id
    pub proto_id: ProtocolId,
}

impl HandleContext {
    pub(crate) fn new(service_context: ServiceContext, proto_id: ProtocolId) -> Self {
        HandleContext {
            inner: service_context,
            proto_id,
        }
    }

    #[inline]
    pub(crate) fn as_mut<'a, 'b: 'a>(
        &'b mut self,
        session_context: &'a SessionContext,
    ) -> HandleContextMutRef<'a> {
        HandleContextMutRef {
            inner: &mut self.inner,
            proto_id: self.proto_id,
            session_context,
        }
    }

    /// Get ServiceContext
    #[inline]
    pub fn service_mut(&mut self) -> &mut ServiceContext {
        &mut self.inner
    }

    #[inline]
    pub(crate) fn remove_session_notify_senders(&mut self, session_id: SessionId) {
        self.inner
            .remove_session_notify_senders(session_id, self.proto_id)
    }
}

/// Protocol handle context contain session context
pub struct HandleContextMutRef<'a> {
    inner: &'a mut ServiceContext,
    /// Protocol id
    pub proto_id: ProtocolId,
    /// Session context
    pub session_context: &'a SessionContext,
}

impl<'a> HandleContextMutRef<'a> {
    /// Get service context
    #[inline]
    pub fn service_mut(&mut self) -> &mut ServiceContext {
        &mut self.inner
    }

    /// Send message to current protocol current session
    #[inline]
    pub fn send_message(&mut self, data: Vec<u8>) {
        self.inner
            .send_message(self.session_context.id, self.proto_id, data)
    }
}

impl Deref for HandleContext {
    type Target = ServiceContext;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for HandleContext {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a> Deref for HandleContextMutRef<'a> {
    type Target = ServiceContext;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a> DerefMut for HandleContextMutRef<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
