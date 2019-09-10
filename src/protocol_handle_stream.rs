use futures::{channel::mpsc, prelude::*};
use log::debug;
use std::collections::HashMap;
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
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
    current_task: Option<ServiceProtocolEvent>,
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
            current_task: Some(ServiceProtocolEvent::Init),
            delay: Arc::new(AtomicBool::new(false)),
            shutdown,
            panic_report,
            future_task_sender,
        }
    }

    #[inline]
    pub fn handle_event(&mut self) -> bool {
        use self::ServiceProtocolEvent::*;

        if self.current_task.is_none() {
            return false;
        }

        if self.shutdown.load(Ordering::SeqCst) {
            match self.current_task.as_ref().unwrap() {
                Disconnected { .. } => (),
                _ => {
                    self.current_task.take();
                    return false;
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

        match self.current_task.clone().unwrap() {
            Init => self.handle.init(&mut self.handle_context),
            Connected { session, version } => {
                match tokio_executor::threadpool::blocking(|| {
                    self.handle
                        .connected(self.handle_context.as_mut(&session), &version)
                }) {
                    Poll::Ready(res) => match res {
                        Ok(_) => (),
                        Err(_) => self
                            .handle
                            .connected(self.handle_context.as_mut(&session), &version),
                    },
                    Poll::Pending => return true,
                }
                self.sessions.insert(session.id, session);
            }
            Disconnected { id } => {
                if let Some(session) = self.sessions.remove(&id) {
                    match tokio_executor::threadpool::blocking(|| {
                        self.handle
                            .disconnected(self.handle_context.as_mut(&session))
                    }) {
                        Poll::Ready(res) => match res {
                            Ok(_) => (),
                            Err(_) => self
                                .handle
                                .disconnected(self.handle_context.as_mut(&session)),
                        },
                        Poll::Pending => return true,
                    }
                }
            }
            Received { id, data } => {
                if let Some(session) = self.sessions.get(&id).cloned() {
                    if !session.closed.load(Ordering::SeqCst) {
                        match tokio_executor::threadpool::blocking(|| {
                            self.handle
                                .received(self.handle_context.as_mut(&session), data.clone())
                        }) {
                            Poll::Ready(res) => match res {
                                Ok(_) => (),
                                Err(_) => self
                                    .handle
                                    .received(self.handle_context.as_mut(&session), data),
                            },
                            Poll::Pending => return true,
                        }
                    }
                }
            }
            Notify { token } => {
                match tokio_executor::threadpool::blocking(|| {
                    self.handle.notify(&mut self.handle_context, token)
                }) {
                    Poll::Ready(res) => match res {
                        Ok(_) => (),
                        Err(_) => self.handle.notify(&mut self.handle_context, token),
                    },
                    Poll::Pending => return true,
                }
                self.set_notify(token);
            }
            SetNotify { interval, token } => {
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
        self.current_task.take();
        false
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
                tokio::timer::delay(Instant::now() + interval).await;
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
                tokio::timer::delay(Instant::now() + Duration::from_millis(200)).await;
                waker.wake();
                delay.store(false, Ordering::Release);
            });
        }
    }
}

impl<T> Drop for ServiceProtocolStream<T> {
    fn drop(&mut self) {
        if !self.shutdown.load(Ordering::SeqCst) {
            use ServiceProtocolEvent::*;
            if let Some(event) = self.current_task.take() {
                let session_id = match event {
                    Received { id, .. } => Some(id),
                    Disconnected { id } => Some(id),
                    Connected { session, .. } => Some(session.id),
                    _ => None,
                };
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
                tokio::spawn(
                    self.panic_report
                        .clone()
                        .send(event)
                        .map(|_| ())
                        .map_err(|_| ()),
                );
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
        if self.handle_event() {
            self.set_delay(cx);
            return Poll::Pending;
        }
        let mut finished = false;
        for _ in 0..64 {
            match Pin::new(&mut self.receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(event)) => {
                    self.current_task = Some(event);
                    if self.handle_event() {
                        break;
                    }
                }
                Poll::Ready(None) => {
                    debug!(
                        "ServiceProtocolStream({:?}) finished",
                        self.handle_context.proto_id
                    );
                    self.current_task.take();
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
                    self.current_task = Some(ServiceProtocolEvent::Notify { token });
                    if self.handle_event() {
                        self.set_delay(cx);
                        break;
                    }
                }
                Poll::Ready(None) => unreachable!(),
                Poll::Pending => {
                    self.set_delay(cx);
                    break;
                }
            }
        }

        self.handle_poll(cx);

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
    current_task: Option<SessionProtocolEvent>,
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
            current_task: None,
            shutdown,
            delay: Arc::new(AtomicBool::new(false)),
            future_task_sender,
        }
    }

    #[inline]
    fn handle_event(&mut self) -> bool {
        use self::SessionProtocolEvent::*;

        if self.current_task.is_none() {
            return false;
        }
        if self.shutdown.load(Ordering::SeqCst) {
            match self.current_task.as_ref().unwrap() {
                Disconnected {} => (),
                _ => {
                    self.current_task.take();
                    return false;
                }
            }
        }

        if self.context.closed.load(Ordering::SeqCst) {
            self.current_task = Some(SessionProtocolEvent::Disconnected);
        }

        match self.current_task.clone().unwrap() {
            Connected { version } => {
                match tokio_executor::threadpool::blocking(|| {
                    self.handle
                        .connected(self.handle_context.as_mut(&self.context), &version)
                }) {
                    Poll::Ready(res) => match res {
                        Ok(_) => (),
                        Err(_) => self
                            .handle
                            .connected(self.handle_context.as_mut(&self.context), &version),
                    },
                    Poll::Pending => return true,
                }
            }
            Disconnected => {
                match tokio_executor::threadpool::blocking(|| {
                    self.handle
                        .disconnected(self.handle_context.as_mut(&self.context))
                }) {
                    Poll::Ready(res) => match res {
                        Ok(_) => (),
                        Err(_) => self
                            .handle
                            .disconnected(self.handle_context.as_mut(&self.context)),
                    },
                    Poll::Pending => return true,
                }
                self.close();
            }
            Received { data } => {
                match tokio_executor::threadpool::blocking(|| {
                    self.handle
                        .received(self.handle_context.as_mut(&self.context), data.clone())
                }) {
                    Poll::Ready(res) => match res {
                        Ok(_) => (),
                        Err(_) => self
                            .handle
                            .received(self.handle_context.as_mut(&self.context), data),
                    },
                    Poll::Pending => return true,
                }
            }
            Notify { token } => {
                match tokio_executor::threadpool::blocking(|| {
                    self.handle
                        .notify(self.handle_context.as_mut(&self.context), token)
                }) {
                    Poll::Ready(res) => match res {
                        Ok(_) => (),
                        Err(_) => self
                            .handle
                            .notify(self.handle_context.as_mut(&self.context), token),
                    },
                    Poll::Pending => return true,
                }
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
        self.current_task.take();
        false
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
                tokio::timer::delay(Instant::now() + interval).await;
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
                tokio::timer::delay(Instant::now() + Duration::from_millis(200)).await;
                waker.wake();
                delay.store(false, Ordering::Release);
            });
        }
    }

    #[inline(always)]
    fn close(&mut self) {
        self.receiver.close();
        self.current_task.take();
    }
}

impl<T> Drop for SessionProtocolStream<T> {
    fn drop(&mut self) {
        if !self.shutdown.load(Ordering::SeqCst) && self.current_task.is_some() {
            let event = SessionEvent::ProtocolHandleError {
                error: Error::SessionProtoHandleAbnormallyClosed(self.context.id),
                proto_id: self.handle_context.proto_id,
            };
            tokio::spawn(
                self.panic_report
                    .clone()
                    .send(event)
                    .map(|_| ())
                    .map_err(|_| ()),
            );
        }
    }
}

impl<T> Stream for SessionProtocolStream<T>
where
    T: SessionProtocol + Send + Unpin,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if self.handle_event() {
            self.set_delay(cx);
            return Poll::Pending;
        }
        loop {
            match Pin::new(&mut self.receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(event)) => {
                    self.current_task = Some(event);
                    if self.handle_event() {
                        self.set_delay(cx);
                        break;
                    }
                }
                Poll::Ready(None) => {
                    self.close();
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    self.set_delay(cx);
                    break;
                }
            }
        }

        loop {
            match Pin::new(&mut self.notify_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(token)) => {
                    self.current_task = Some(SessionProtocolEvent::Notify { token });
                    if self.handle_event() {
                        self.set_delay(cx);
                        break;
                    }
                }
                Poll::Ready(None) => unreachable!(),
                Poll::Pending => {
                    self.set_delay(cx);
                    break;
                }
            }
        }

        self.handle_poll(cx);

        Poll::Pending
    }
}
