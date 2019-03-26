use futures::{prelude::*, sync::mpsc, task};
use log::warn;
use std::collections::HashMap;

use crate::{
    context::{ProtocolContext, ServiceContext, SessionContext},
    multiaddr::Multiaddr,
    traits::{ServiceProtocol, SessionProtocol},
    ProtocolId, SessionId,
};

pub enum ServiceProtocolEvent {
    Init,
    Connected {
        session: SessionContext,
        version: String,
    },
    Disconnected {
        id: SessionId,
    },
    /// Protocol data
    Received {
        /// Session id
        id: SessionId,
        /// Data
        data: bytes::Bytes,
    },
    Notify {
        /// Notify token
        token: u64,
    },
    Update {
        listen_addrs: Vec<Multiaddr>,
    },
}

pub struct ServiceProtocolStream {
    handle: Box<dyn ServiceProtocol + Send + 'static>,
    /// External event is passed in from this
    handle_context: ProtocolContext,
    sessions: HashMap<SessionId, SessionContext>,
    receiver: mpsc::Receiver<ServiceProtocolEvent>,
}

impl ServiceProtocolStream {
    pub fn new(
        handle: Box<dyn ServiceProtocol + Send + 'static>,
        service_context: ServiceContext,
        receiver: mpsc::Receiver<ServiceProtocolEvent>,
        proto_id: ProtocolId,
    ) -> Self {
        ServiceProtocolStream {
            handle,
            handle_context: ProtocolContext::new(service_context, proto_id),
            sessions: HashMap::default(),
            receiver,
        }
    }

    #[inline]
    fn handle_event(&mut self, event: ServiceProtocolEvent) {
        use self::ServiceProtocolEvent::*;
        match event {
            Init => self.handle.init(&mut self.handle_context),
            Connected { session, version } => {
                self.handle
                    .connected(self.handle_context.as_mut(&session), &version);
                self.sessions.insert(session.id, session);
            }
            Disconnected { id } => {
                if let Some(session) = self.sessions.remove(&id) {
                    self.handle
                        .disconnected(self.handle_context.as_mut(&session));
                }
                self.handle_context.remove_session_notify_senders(id);
            }
            Received { id, data } => {
                if let Some(session) = self.sessions.get(&id) {
                    self.handle
                        .received(self.handle_context.as_mut(&session), data);
                }
            }
            Notify { token } => {
                self.handle.notify(&mut self.handle_context, token);
            }
            Update { listen_addrs } => {
                self.handle_context.update_listens(listen_addrs);
            }
        }
    }
}

impl Stream for ServiceProtocolStream {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match self.receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_event(event),
                Ok(Async::Ready(None)) => {
                    for id in self.sessions.keys() {
                        self.handle_context.remove_session_notify_senders(*id);
                    }
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!(
                        "service proto [{}] handle receive message error: {:?}",
                        self.handle_context.proto_id, err
                    );
                    return Err(());
                }
            }
        }

        self.handle.poll(&mut self.handle_context);

        for task in self.handle_context.pending_tasks.split_off(0) {
            self.handle_context.send(task);
        }

        if !self.handle_context.pending_tasks.is_empty() {
            task::current().notify();
        }

        Ok(Async::NotReady)
    }
}

pub enum SessionProtocolEvent {
    Connected {
        version: String,
    },
    Disconnected,
    /// Protocol data
    Received {
        /// Data
        data: bytes::Bytes,
    },
    Notify {
        /// Notify token
        token: u64,
    },
    Update {
        listen_addrs: Vec<Multiaddr>,
    },
}

pub struct SessionProtocolStream {
    handle: Box<dyn SessionProtocol + Send + 'static>,
    /// External event is passed in from this
    handle_context: ProtocolContext,
    context: SessionContext,
    receiver: mpsc::Receiver<SessionProtocolEvent>,
}

impl SessionProtocolStream {
    pub fn new(
        handle: Box<dyn SessionProtocol + Send + 'static>,
        service_context: ServiceContext,
        context: SessionContext,
        receiver: mpsc::Receiver<SessionProtocolEvent>,
        proto_id: ProtocolId,
    ) -> Self {
        SessionProtocolStream {
            handle,
            handle_context: ProtocolContext::new(service_context, proto_id),
            receiver,
            context,
        }
    }

    #[inline]
    fn handle_event(&mut self, event: SessionProtocolEvent) {
        use self::SessionProtocolEvent::*;
        match event {
            Connected { version } => {
                self.handle
                    .connected(self.handle_context.as_mut(&self.context), &version);
            }
            Disconnected => {
                self.handle
                    .disconnected(self.handle_context.as_mut(&self.context));
                self.close();
            }
            Received { data } => {
                self.handle
                    .received(self.handle_context.as_mut(&self.context), data);
            }
            Notify { token } => {
                self.handle
                    .notify(self.handle_context.as_mut(&self.context), token);
            }
            Update { listen_addrs } => {
                self.handle_context.update_listens(listen_addrs);
            }
        }
    }

    #[inline(always)]
    fn close(&mut self) {
        self.handle_context
            .remove_session_notify_senders(self.context.id);
        self.receiver.close();
    }
}

impl Stream for SessionProtocolStream {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match self.receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_event(event),
                Ok(Async::Ready(None)) => {
                    self.close();
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!(
                        "session proto [{}] handle receive message error: {:?}",
                        self.handle_context.proto_id, err
                    );
                    return Err(());
                }
            }
        }

        self.handle.poll(self.handle_context.as_mut(&self.context));

        for task in self.handle_context.pending_tasks.split_off(0) {
            self.handle_context.send(task);
        }

        if !self.handle_context.pending_tasks.is_empty() {
            task::current().notify();
        }

        Ok(Async::NotReady)
    }
}
