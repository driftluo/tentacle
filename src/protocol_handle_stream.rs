use futures::{channel::mpsc, SinkExt, Stream};
use log::debug;
use std::collections::HashMap;
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    context::{ProtocolContext, ServiceContext, SessionContext},
    error::Error,
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
    sessions: HashMap<SessionId, Arc<SessionContext>>,
    receiver: mpsc::Receiver<ServiceProtocolEvent>,
    notify: HashMap<u64, Duration>,
    notify_sender: mpsc::Sender<u64>,
    notify_receiver: mpsc::Receiver<u64>,
    panic_report: mpsc::Sender<SessionEvent>,
    current_task: CurrentTask,
    delay: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    future_task_sender: mpsc::Sender<BoxedFutureTask>,
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
            notify: HashMap::new(),
            current_task: CurrentTask::Idle,
            delay: Arc::new(AtomicBool::new(false)),
            shutdown,
            panic_report,
            future_task_sender,
        }
    }

    #[inline]
    pub fn handle_event(&mut self, event: ServiceProtocolEvent) {
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
                    .disconnected(self.handle_context.as_mut(&session));
            }
        }

        match event {
            Init => {
                self.current_task.run();
                self.handle.init(&mut self.handle_context)
            }
            Connected { session, version } => {
                self.current_task.run_with_id(session.id);
                tokio::task::block_in_place(|| {
                    self.handle
                        .connected(self.handle_context.as_mut(&session), &version)
                });
                self.sessions.insert(session.id, session);
            }
            Disconnected { id } => {
                self.current_task.run_with_id(id);
                if let Some(session) = self.sessions.remove(&id) {
                    if shutdown {
                        self.handle
                            .disconnected(self.handle_context.as_mut(&session))
                    } else {
                        tokio::task::block_in_place(|| {
                            self.handle
                                .disconnected(self.handle_context.as_mut(&session))
                        });
                    }
                }
            }
            Received { id, data } => {
                self.current_task.run_with_id(id);
                if let Some(session) = self.sessions.get(&id).cloned() {
                    if !session.closed.load(Ordering::SeqCst)
                        && !self.shutdown.load(Ordering::SeqCst)
                    {
                        tokio::task::block_in_place(|| {
                            self.handle
                                .received(self.handle_context.as_mut(&session), data.clone())
                        })
                    }
                }
            }
            Notify { token } => {
                self.current_task.run();
                tokio::task::block_in_place(|| self.handle.notify(&mut self.handle_context, token));
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

    fn handle_poll(&mut self, cx: &mut Context) {
        Pin::new(&mut self.handle).poll(cx, &mut self.handle_context);
    }

    fn set_notify(&mut self, token: u64) {
        if let Some(&interval) = self.notify.get(&token) {
            let mut sender = self.notify_sender.clone();
            // NOTE: A Interval/Delay will block tokio runtime from gracefully shutdown.
            //       So we spawn it in FutureTaskManager
            let task = async move {
                tokio::time::delay_until(tokio::time::Instant::now() + interval).await;
                let _ = sender.send(token).await;
            };
            let mut future_task_sender = self.future_task_sender.clone();
            tokio::spawn(async move {
                let _ = future_task_sender.send(Box::pin(task)).await;
            });
        }
    }

    fn set_delay(&mut self, cx: &mut Context) {
        // Why use `delay` instead of `notify`?
        //
        // In fact, on machines that can use multi-core normally, there is almost no problem with the `notify` behavior,
        // and even the efficiency will be higher.
        //
        // However, if you are on a single-core bully machine, `notify` may have a very amazing starvation behavior.
        //
        // Under a single-core machine, `notify` may fall into the loop of infinitely preemptive CPU, causing starvation.
        if !self.delay.load(Ordering::Acquire) {
            self.delay.store(true, Ordering::Release);
            let waker = cx.waker().clone();
            let delay = self.delay.clone();
            tokio::spawn(async move {
                tokio::time::delay_until(tokio::time::Instant::now() + Duration::from_millis(200))
                    .await;
                waker.wake();
                delay.store(false, Ordering::Release);
            });
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
                        error: Error::SessionProtoHandleAbnormallyClosed(id),
                        proto_id,
                    },
                    None => SessionEvent::ProtocolHandleError {
                        error: Error::ServiceProtoHandleAbnormallyClosed,
                        proto_id,
                    },
                };
                let mut panic_sender = self.panic_report.clone();
                tokio::spawn(async move {
                    let _ = panic_sender.send(event).await;
                });
            }
        }
    }
}

impl<T> Stream for ServiceProtocolStream<T>
where
    T: ServiceProtocol + Send + Unpin,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if self.shutdown.load(Ordering::SeqCst) {
            debug!(
                "ServiceProtocolStream({:?}) finished, shutdown",
                self.handle_context.proto_id
            );
            self.current_task.idle();
            return Poll::Ready(None);
        }

        let mut finished = false;
        for _ in 0..64 {
            match Pin::new(&mut self.receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(event)) => self.handle_event(event),
                Poll::Ready(None) => {
                    debug!(
                        "ServiceProtocolStream({:?}) finished",
                        self.handle_context.proto_id
                    );
                    self.current_task.idle();
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    finished = true;
                    break;
                }
            }
        }
        if !finished {
            self.set_delay(cx);
        }

        loop {
            match Pin::new(&mut self.notify_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(token)) => {
                    self.handle_event(ServiceProtocolEvent::Notify { token })
                }
                Poll::Ready(None) => unreachable!(),
                Poll::Pending => {
                    break;
                }
            }
        }

        self.handle_poll(cx);

        if self.shutdown.load(Ordering::SeqCst) {
            debug!(
                "ServiceProtocolStream({:?}) finished, shutdown",
                self.handle_context.proto_id
            );
            self.current_task.idle();
            return Poll::Ready(None);
        }

        Poll::Pending
    }
}

#[derive(Clone)]
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
    notify: HashMap<u64, Duration>,
    notify_sender: mpsc::Sender<u64>,
    notify_receiver: mpsc::Receiver<u64>,
    current_task: bool,
    panic_report: mpsc::Sender<SessionEvent>,
    delay: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    future_task_sender: mpsc::Sender<BoxedFutureTask>,
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
            notify: HashMap::new(),
            context,
            panic_report,
            current_task: false,
            shutdown,
            delay: Arc::new(AtomicBool::new(false)),
            future_task_sender,
        }
    }

    #[inline]
    fn handle_event(&mut self, mut event: SessionProtocolEvent) {
        use self::SessionProtocolEvent::*;

        self.current_task = true;
        let shutdown = self.shutdown.load(Ordering::SeqCst);
        if shutdown {
            match event {
                Disconnected {} => (),
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
            Connected { version } => tokio::task::block_in_place(|| {
                self.handle
                    .connected(self.handle_context.as_mut(&self.context), &version)
            }),
            Disconnected => {
                if shutdown {
                    self.handle
                        .disconnected(self.handle_context.as_mut(&self.context))
                } else {
                    tokio::task::block_in_place(|| {
                        self.handle
                            .disconnected(self.handle_context.as_mut(&self.context))
                    });
                }
                self.close();
            }
            Received { data } => tokio::task::block_in_place(|| {
                self.handle
                    .received(self.handle_context.as_mut(&self.context), data.clone())
            }),
            Notify { token } => {
                tokio::task::block_in_place(|| {
                    self.handle
                        .notify(self.handle_context.as_mut(&self.context), token)
                });
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

    fn handle_poll(&mut self, cx: &mut Context) {
        Pin::new(&mut self.handle)
            .as_mut()
            .poll(cx, self.handle_context.as_mut(&self.context));
    }

    fn set_notify(&mut self, token: u64) {
        if let Some(&interval) = self.notify.get(&token) {
            let mut sender = self.notify_sender.clone();
            // NOTE: A Interval/Delay will block tokio runtime from gracefully shutdown.
            //       So we spawn it in FutureTaskManager
            let task = async move {
                tokio::time::delay_until(tokio::time::Instant::now() + interval).await;
                let _ = sender.send(token).await;
            };
            let mut future_task_sender = self.future_task_sender.clone();
            tokio::spawn(async move {
                let _ = future_task_sender.send(Box::pin(task)).await;
            });
        }
    }

    fn set_delay(&mut self, cx: &mut Context) {
        // Why use `delay` instead of `notify`?
        //
        // In fact, on machines that can use multi-core normally, there is almost no problem with the `notify` behavior,
        // and even the efficiency will be higher.
        //
        // However, if you are on a single-core bully machine, `notify` may have a very amazing starvation behavior.
        //
        // Under a single-core machine, `notify` may fall into the loop of infinitely preemptive CPU, causing starvation.
        if !self.delay.load(Ordering::Acquire) {
            self.delay.store(true, Ordering::Release);
            let waker = cx.waker().clone();
            let delay = self.delay.clone();
            tokio::spawn(async move {
                tokio::time::delay_until(tokio::time::Instant::now() + Duration::from_millis(200))
                    .await;
                waker.wake();
                delay.store(false, Ordering::Release);
            });
        }
    }

    #[inline(always)]
    fn close(&mut self) {
        self.receiver.close();
        self.current_task = false;
    }
}

impl<T> Drop for SessionProtocolStream<T> {
    fn drop(&mut self) {
        if !self.shutdown.load(Ordering::SeqCst) && self.current_task {
            let event = SessionEvent::ProtocolHandleError {
                error: Error::SessionProtoHandleAbnormallyClosed(self.context.id),
                proto_id: self.handle_context.proto_id,
            };
            let mut panic_sender = self.panic_report.clone();
            tokio::spawn(async move {
                let _ = panic_sender.send(event).await;
            });
        }
    }
}

impl<T> Stream for SessionProtocolStream<T>
where
    T: SessionProtocol + Send + Unpin,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut finished = false;
        for _ in 0..64 {
            match Pin::new(&mut self.receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(event)) => self.handle_event(event),
                Poll::Ready(None) => {
                    self.close();
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    finished = true;
                    break;
                }
            }
        }

        if !finished {
            self.set_delay(cx);
        }

        loop {
            match Pin::new(&mut self.notify_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(token)) => {
                    self.handle_event(SessionProtocolEvent::Notify { token })
                }
                Poll::Ready(None) => unreachable!(),
                Poll::Pending => {
                    break;
                }
            }
        }

        self.handle_poll(cx);

        Poll::Pending
    }
}
