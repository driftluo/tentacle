use futures::{prelude::*, sync::mpsc};
use log::warn;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::{
    context::{ProtocolContext, ServiceContext, SessionContext},
    multiaddr::Multiaddr,
    traits::{ServiceProtocol, SessionProtocol},
    ProtocolId, SessionId,
};

pub enum ServiceProtocolEvent {
    Init,
    Connected {
        session: Arc<SessionContext>,
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

pub struct ServiceProtocolStream<T> {
    handle: T,
    /// External event is passed in from this
    handle_context: ProtocolContext,
    sessions: HashMap<SessionId, Arc<SessionContext>>,
    receiver: mpsc::Receiver<ServiceProtocolEvent>,
    shutdown: Arc<AtomicBool>,
}

impl<T> ServiceProtocolStream<T>
where
    T: ServiceProtocol + Send,
{
    pub fn new(
        handle: T,
        service_context: ServiceContext,
        receiver: mpsc::Receiver<ServiceProtocolEvent>,
        proto_id: ProtocolId,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        ServiceProtocolStream {
            handle,
            handle_context: ProtocolContext::new(service_context, proto_id),
            sessions: HashMap::default(),
            receiver,
            shutdown,
        }
    }

    #[inline]
    pub fn handle_event(&mut self, event: ServiceProtocolEvent) {
        use self::ServiceProtocolEvent::*;

        if self.shutdown.load(Ordering::SeqCst) {
            match event {
                Disconnected { .. } => (),
                _ => return,
            }
        }

        let closed_sessions = self
            .sessions
            .iter()
            .filter(|(_, context)| context.closed.load(Ordering::SeqCst))
            .map(|(session_id, _)| *session_id)
            .collect::<Vec<_>>();
        for session_id in closed_sessions {
            if let Some(session) = self.sessions.remove(&session_id) {
                self.handle
                    .disconnected(self.handle_context.as_mut(&session));
            }
        }

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
            }
            Received { id, data } => {
                if let Some(session) = self.sessions.get(&id) {
                    if !session.closed.load(Ordering::SeqCst) {
                        self.handle
                            .received(self.handle_context.as_mut(&session), data);
                    }
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

impl<T> Stream for ServiceProtocolStream<T>
where
    T: ServiceProtocol + Send,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match self.receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_event(event),
                Ok(Async::Ready(None)) => {
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

pub struct SessionProtocolStream<T> {
    handle: T,
    /// External event is passed in from this
    handle_context: ProtocolContext,
    context: Arc<SessionContext>,
    receiver: mpsc::Receiver<SessionProtocolEvent>,
    shutdown: Arc<AtomicBool>,
}

impl<T> SessionProtocolStream<T>
where
    T: SessionProtocol + Send,
{
    pub fn new(
        handle: T,
        service_context: ServiceContext,
        context: Arc<SessionContext>,
        receiver: mpsc::Receiver<SessionProtocolEvent>,
        proto_id: ProtocolId,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        SessionProtocolStream {
            handle,
            handle_context: ProtocolContext::new(service_context, proto_id),
            receiver,
            context,
            shutdown,
        }
    }

    #[inline]
    fn handle_event(&mut self, mut event: SessionProtocolEvent) {
        use self::SessionProtocolEvent::*;

        if self.shutdown.load(Ordering::SeqCst) {
            match event {
                Disconnected {} => (),
                _ => return,
            }
        }

        if self.context.closed.load(Ordering::SeqCst) {
            event = SessionProtocolEvent::Disconnected;
        }

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
        self.receiver.close();
    }
}

impl<T> Stream for SessionProtocolStream<T>
where
    T: SessionProtocol + Send,
{
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

        Ok(Async::NotReady)
    }
}
