use futures::{
    channel::{mpsc, oneshot},
    future::poll_fn,
    SinkExt, StreamExt,
};
use log::{debug, trace};
use nohash_hasher::IntMap;
use std::collections::HashMap;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    context::{ProtocolContext, ServiceContext, SessionContext},
    error::ProtocolHandleErrorKind,
    multiaddr::Multiaddr,
    service::future_task::BoxedFutureTask,
    session::SessionEvent,
    traits::{ServiceProtocol, SessionProtocol},
    ProtocolId, SessionId,
};

#[derive(Clone)]
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
    SetNotify {
        /// Timer interval
        interval: Duration,
        /// The timer token
        token: u64,
    },
    RemoveNotify {
        token: u64,
    },
    Notify {
        token: u64,
    },
    Update {
        listen_addrs: Vec<Multiaddr>,
    },
}

enum CurrentTask {
    Idle,
    Run(Option<SessionId>),
}

impl CurrentTask {
    fn run_with_id(&mut self, id: SessionId) {
        *self = CurrentTask::Run(Some(id))
    }

    fn run(&mut self) {
        *self = CurrentTask::Run(None)
    }

    fn idle(&mut self) {
        *self = CurrentTask::Idle
    }
}

pub struct ServiceProtocolStream<T> {
    handle: T,
    /// External event is passed in from this
    handle_context: ProtocolContext,
    sessions: IntMap<SessionId, Arc<SessionContext>>,
    receiver: mpsc::Receiver<ServiceProtocolEvent>,
    notify: IntMap<u64, Duration>,
    notify_sender: mpsc::Sender<u64>,
    notify_receiver: mpsc::Receiver<u64>,
    panic_report: mpsc::Sender<SessionEvent>,
    current_task: CurrentTask,
    shutdown: Arc<AtomicBool>,
    future_task_sender: mpsc::Sender<BoxedFutureTask>,
    need_poll: bool,
}

impl<T> ServiceProtocolStream<T>
where
    T: ServiceProtocol + Send + Unpin,
{
    pub(crate) fn new(
        handle: T,
        service_context: ServiceContext,
        receiver: mpsc::Receiver<ServiceProtocolEvent>,
        proto_id: ProtocolId,
        panic_report: mpsc::Sender<SessionEvent>,
        (shutdown, future_task_sender): (Arc<AtomicBool>, mpsc::Sender<BoxedFutureTask>),
    ) -> Self {
        let (notify_sender, notify_receiver) = mpsc::channel(16);
        ServiceProtocolStream {
            handle,
            handle_context: ProtocolContext::new(service_context, proto_id),
            sessions: HashMap::default(),
            receiver,
            notify_sender,
            notify_receiver,
            notify: HashMap::default(),
            current_task: CurrentTask::Idle,
            shutdown,
            panic_report,
            future_task_sender,
            need_poll: true,
        }
    }

    #[inline]
    pub async fn handle_event(&mut self, event: ServiceProtocolEvent) {
        use self::ServiceProtocolEvent::*;

        let shutdown = self.shutdown.load(Ordering::SeqCst);

        if shutdown {
            match event {
                Disconnected { .. } => (),
                _ => {
                    return;
                }
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
                    .disconnected(self.handle_context.as_mut(&session))
                    .await;
            }
        }

        match event {
            Init => {
                self.current_task.run();
                self.handle.init(&mut self.handle_context).await
            }
            Connected { session, version } => {
                self.current_task.run_with_id(session.id);
                self.handle
                    .connected(self.handle_context.as_mut(&session), &version)
                    .await;
                self.sessions.insert(session.id, session);
            }
            Disconnected { id } => {
                self.current_task.run_with_id(id);
                if let Some(session) = self.sessions.remove(&id) {
                    self.handle
                        .disconnected(self.handle_context.as_mut(&session))
                        .await
                }
            }
            Received { id, data } => {
                self.current_task.run_with_id(id);
                if let Some(session) = self.sessions.get(&id).cloned() {
                    if !session.closed.load(Ordering::SeqCst)
                        && !self.shutdown.load(Ordering::SeqCst)
                    {
                        self.handle
                            .received(self.handle_context.as_mut(&session), data)
                            .await
                    }
                }
            }
            Notify { token } => {
                self.current_task.run();
                self.handle.notify(&mut self.handle_context, token).await;
                self.set_notify(token);
            }
            SetNotify { interval, token } => {
                self.current_task.run();
                self.notify.entry(token).or_insert(interval);
                self.set_notify(token);
            }
            RemoveNotify { token } => {
                self.current_task.run();
                self.notify.remove(&token);
            }
            Update { listen_addrs } => {
                self.current_task.run();
                self.handle_context.update_listens(listen_addrs);
            }
        }
        self.current_task.idle();
    }

    fn set_notify(&mut self, token: u64) {
        if let Some(&interval) = self.notify.get(&token) {
            let mut sender = self.notify_sender.clone();
            // NOTE: A Interval/Delay will block tokio runtime from gracefully shutdown.
            //       So we spawn it in FutureTaskManager
            let task = async move {
                crate::runtime::delay_for(interval).await;
                if sender.send(token).await.is_err() {
                    trace!("service notify token {} send err", token)
                }
            };
            let mut future_task_sender = self.future_task_sender.clone();
            crate::runtime::spawn(async move {
                if future_task_sender.send(Box::pin(task)).await.is_err() {
                    trace!("service notify task send err")
                }
            });
        }
    }

    pub async fn run(&mut self, mut recv: oneshot::Receiver<()>) {
        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                debug!(
                    "ServiceProtocolStream({:?}) finished, shutdown",
                    self.handle_context.proto_id
                );
                self.current_task.idle();
                break;
            }
            poll_fn(crate::runtime::poll_proceed).await;
            tokio::select! {
                event = self.receiver.next() => {
                    match event {
                        Some(event) => self.handle_event(event).await,
                        None => {
                            self.current_task.idle();
                            break
                        }
                    }
                },
                Some(token) = self.notify_receiver.next() => {
                    self.handle_event(ServiceProtocolEvent::Notify { token }).await;
                },
                res = &mut self.handle.poll(&mut self.handle_context), if self.need_poll => {
                    self.need_poll = res.is_some();
                },
                _ = &mut recv => break,
                else => break
            }
        }
    }
}

impl<T> Drop for ServiceProtocolStream<T> {
    fn drop(&mut self) {
        if !self.shutdown.load(Ordering::SeqCst) {
            if let CurrentTask::Run(session_id) = self.current_task {
                let proto_id = self.handle_context.proto_id;
                let event = match session_id {
                    Some(id) => SessionEvent::ProtocolHandleError {
                        error: ProtocolHandleErrorKind::AbnormallyClosed(Some(id)),
                        proto_id,
                    },
                    None => SessionEvent::ProtocolHandleError {
                        error: ProtocolHandleErrorKind::AbnormallyClosed(None),
                        proto_id,
                    },
                };
                let mut panic_sender = self.panic_report.clone();
                crate::runtime::spawn(async move {
                    if panic_sender.send(event).await.is_err() {
                        trace!("service panic message send err")
                    }
                });
            }
        }
    }
}

#[derive(Clone)]
pub enum SessionProtocolEvent {
    Opened {
        version: String,
    },
    Closed,
    Disconnected,
    /// Protocol data
    Received {
        /// Data
        data: bytes::Bytes,
    },
    Notify {
        token: u64,
    },
    SetNotify {
        /// Timer interval
        interval: Duration,
        /// The timer token
        token: u64,
    },
    RemoveNotify {
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
    notify: IntMap<u64, Duration>,
    notify_sender: mpsc::Sender<u64>,
    notify_receiver: mpsc::Receiver<u64>,
    current_task: bool,
    panic_report: mpsc::Sender<SessionEvent>,
    shutdown: Arc<AtomicBool>,
    future_task_sender: mpsc::Sender<BoxedFutureTask>,
    need_poll: bool,
}

impl<T> SessionProtocolStream<T>
where
    T: SessionProtocol + Send + Unpin,
{
    pub(crate) fn new(
        handle: T,
        service_context: ServiceContext,
        context: Arc<SessionContext>,
        receiver: mpsc::Receiver<SessionProtocolEvent>,
        proto_id: ProtocolId,
        panic_report: mpsc::Sender<SessionEvent>,
        (shutdown, future_task_sender): (Arc<AtomicBool>, mpsc::Sender<BoxedFutureTask>),
    ) -> Self {
        let (notify_sender, notify_receiver) = mpsc::channel(16);
        SessionProtocolStream {
            handle,
            handle_context: ProtocolContext::new(service_context, proto_id),
            receiver,
            notify_sender,
            notify_receiver,
            notify: HashMap::default(),
            context,
            panic_report,
            current_task: false,
            shutdown,
            future_task_sender,
            need_poll: true,
        }
    }

    #[inline]
    async fn handle_event(&mut self, mut event: SessionProtocolEvent) {
        use self::SessionProtocolEvent::*;

        self.current_task = true;
        let shutdown = self.shutdown.load(Ordering::SeqCst);
        if shutdown {
            match event {
                Disconnected | Closed => (),
                _ => {
                    self.current_task = false;
                    return;
                }
            }
        }

        if self.context.closed.load(Ordering::SeqCst) {
            event = SessionProtocolEvent::Disconnected;
        }

        match event {
            Opened { version } => {
                self.handle
                    .connected(self.handle_context.as_mut(&self.context), &version)
                    .await
            }
            Closed => {
                self.handle
                    .disconnected(self.handle_context.as_mut(&self.context))
                    .await
            }
            Disconnected => {
                self.close();
            }
            Received { data } => {
                self.handle
                    .received(self.handle_context.as_mut(&self.context), data)
                    .await
            }
            Notify { token } => {
                self.handle
                    .notify(self.handle_context.as_mut(&self.context), token)
                    .await;
                self.set_notify(token);
            }
            SetNotify { token, interval } => {
                self.notify.entry(token).or_insert(interval);
                self.set_notify(token);
            }
            RemoveNotify { token } => {
                self.notify.remove(&token);
            }
            Update { listen_addrs } => {
                self.handle_context.update_listens(listen_addrs);
            }
        }
        self.current_task = false;
    }

    fn set_notify(&mut self, token: u64) {
        if let Some(&interval) = self.notify.get(&token) {
            let mut sender = self.notify_sender.clone();
            // NOTE: A Interval/Delay will block tokio runtime from gracefully shutdown.
            //       So we spawn it in FutureTaskManager
            let task = async move {
                crate::runtime::delay_for(interval).await;
                if sender.send(token).await.is_err() {
                    trace!("session notify token {} send err", token)
                }
            };
            let mut future_task_sender = self.future_task_sender.clone();
            crate::runtime::spawn(async move {
                if future_task_sender.send(Box::pin(task)).await.is_err() {
                    trace!("session notify task send err")
                }
            });
        }
    }

    #[inline(always)]
    fn close(&mut self) {
        self.receiver.close();
        self.current_task = false;
    }

    pub async fn run(&mut self, mut recv: oneshot::Receiver<()>) {
        loop {
            poll_fn(crate::runtime::poll_proceed).await;
            tokio::select! {
                event = self.receiver.next() => {
                    match event {
                        Some(event) => self.handle_event(event).await,
                        None => {
                            self.close();
                            break
                        }
                    }
                }
                Some(token) = self.notify_receiver.next() => {
                    self.handle_event(SessionProtocolEvent::Notify { token }).await;
                }
                res = self.handle.poll(self.handle_context.as_mut(&self.context)), if self.need_poll => {
                    self.need_poll = res.is_some();
                },
                _ = &mut recv => break,
                else => break
            }
        }
    }
}

impl<T> Drop for SessionProtocolStream<T> {
    fn drop(&mut self) {
        if !self.shutdown.load(Ordering::SeqCst) && self.current_task {
            let event = SessionEvent::ProtocolHandleError {
                error: ProtocolHandleErrorKind::AbnormallyClosed(Some(self.context.id)),
                proto_id: self.handle_context.proto_id,
            };
            let mut panic_sender = self.panic_report.clone();
            crate::runtime::spawn(async move {
                if panic_sender.send(event).await.is_err() {
                    trace!("session panic message send err")
                }
            });
        }
    }
}
