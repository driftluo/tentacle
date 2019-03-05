use futures::{prelude::*, sync::mpsc, task};
use log::warn;
use std::collections::HashMap;

use crate::{
    context::{ServiceContext, SessionContext},
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
    proto_id: ProtocolId,
    /// External event is passed in from this
    service_context: ServiceContext,
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
            proto_id,
            service_context,
            sessions: HashMap::default(),
            receiver,
        }
    }

    #[inline]
    fn handle_event(&mut self, event: ServiceProtocolEvent) {
        use self::ServiceProtocolEvent::*;
        match event {
            Init => self.handle.init(&mut self.service_context),
            Connected { session, version } => {
                self.handle
                    .connected(&mut self.service_context, &session, &version);
                self.sessions.insert(session.id, session);
            }
            Disconnected { id } => {
                if let Some(session) = self.sessions.remove(&id) {
                    self.handle
                        .disconnected(&mut self.service_context, &session);
                }
                self.service_context
                    .remove_session_notify_senders(id, self.proto_id);
            }
            Received { id, data } => {
                if let Some(session) = self.sessions.get_mut(&id) {
                    self.handle
                        .received(&mut self.service_context, session, data);
                }
            }
            Notify { token } => {
                self.handle.notify(&mut self.service_context, token);
            }
            Update { listen_addrs } => {
                self.service_context.update_listens(listen_addrs);
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
                        self.service_context
                            .remove_session_notify_senders(*id, self.proto_id);
                    }
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    warn!(
                        "service proto [{}] handle receive message error: {:?}",
                        self.proto_id, err
                    );
                    return Err(());
                }
            }
        }

        for task in self.service_context.pending_tasks.split_off(0) {
            self.service_context.send(task);
        }

        if !self.service_context.pending_tasks.is_empty() {
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
    service_context: ServiceContext,
    context: SessionContext,
    proto_id: ProtocolId,
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
            proto_id,
            service_context,
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
                    .connected(&mut self.service_context, &self.context, &version);
            }
            Disconnected => {
                self.handle.disconnected(&mut self.service_context);
                self.close();
            }
            Received { data } => {
                self.handle.received(&mut self.service_context, data);
            }
            Notify { token } => {
                self.handle.notify(&mut self.service_context, token);
            }
            Update { listen_addrs } => {
                self.service_context.update_listens(listen_addrs);
            }
        }
    }

    #[inline(always)]
    fn close(&mut self) {
        self.service_context
            .remove_session_notify_senders(self.context.id, self.proto_id);
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
                        self.proto_id, err
                    );
                    return Err(());
                }
            }
        }

        for task in self.service_context.pending_tasks.split_off(0) {
            self.service_context.send(task);
        }

        if !self.service_context.pending_tasks.is_empty() {
            task::current().notify();
        }

        Ok(Async::NotReady)
    }
}
