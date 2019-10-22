use futures::{prelude::*, sync::mpsc};
use log::{debug, warn};
use std::collections::HashMap;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::timer::Delay;

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
    T: ServiceProtocol + Send,
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
    pub fn handle_event(&mut self) -> Async<()> {
        use self::ServiceProtocolEvent::*;

        if self.current_task.is_none() {
            return Async::Ready(());
        }

        if self.shutdown.load(Ordering::SeqCst) {
            match self.current_task.as_ref().unwrap() {
                Disconnected { .. } => (),
                _ => {
                    self.current_task.take();
                    return Async::Ready(());
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
                match tokio_threadpool::blocking(|| {
                    self.handle
                        .connected(self.handle_context.as_mut(&session), &version)
                }) {
                    Ok(Async::Ready(_)) => (),
                    Ok(Async::NotReady) => return Async::NotReady,
                    Err(_) => self
                        .handle
                        .connected(self.handle_context.as_mut(&session), &version),
                }
                self.sessions.insert(session.id, session);
            }
            Disconnected { id } => {
                if let Some(session) = self.sessions.remove(&id) {
                    match tokio_threadpool::blocking(|| {
                        self.handle
                            .disconnected(self.handle_context.as_mut(&session))
                    }) {
                        Ok(Async::Ready(_)) => (),
                        Ok(Async::NotReady) => return Async::NotReady,
                        Err(_) => self
                            .handle
                            .disconnected(self.handle_context.as_mut(&session)),
                    }
                }
            }
            Received { id, data } => {
                if let Some(session) = self.sessions.get(&id).cloned() {
                    if !session.closed.load(Ordering::SeqCst) {
                        match tokio_threadpool::blocking(|| {
                            self.handle
                                .received(self.handle_context.as_mut(&session), data.clone())
                        }) {
                            Ok(Async::Ready(_)) => (),
                            Ok(Async::NotReady) => return Async::NotReady,
                            Err(_) => self
                                .handle
                                .received(self.handle_context.as_mut(&session), data),
                        }
                    }
                }
            }
            Notify { token } => {
                match tokio_threadpool::blocking(|| {
                    self.handle.notify(&mut self.handle_context, token)
                }) {
                    Ok(Async::Ready(_)) => (),
                    Ok(Async::NotReady) => return Async::NotReady,
                    Err(_) => self.handle.notify(&mut self.handle_context, token),
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
        Async::Ready(())
    }

    fn set_notify(&mut self, token: u64) {
        if let Some(interval) = self.notify.get(&token) {
            let sender = self.notify_sender.clone();
            // NOTE: A Interval/Delay will block tokio runtime from gracefully shutdown.
            //       So we spawn it in FutureTaskManager
            let task = Delay::new(Instant::now() + *interval).then(move |_| {
                tokio::spawn(sender.send(token).map(|_| ()).map_err(|_| ()));
                Ok(())
            });
            tokio::spawn(
                self.future_task_sender
                    .clone()
                    .send(Box::new(task))
                    .map(|_| ())
                    .map_err(|_| ()),
            );
        }
    }

    fn set_delay(&mut self) {
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
            let notify = futures::task::current();
            let delay = self.delay.clone();
            let delay_task =
                Delay::new(Instant::now() + Duration::from_millis(200)).then(move |_| {
                    notify.notify();
                    delay.store(false, Ordering::Release);
                    Ok(())
                });
            tokio::spawn(delay_task);
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
    T: ServiceProtocol + Send,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if let Async::NotReady = self.handle_event() {
            self.set_delay();
            return Ok(Async::NotReady);
        }
        let mut finished = false;
        for _ in 0..64 {
            match self.receiver.poll() {
                Ok(Async::Ready(Some(event))) => {
                    self.current_task = Some(event);
                    if let Async::NotReady = self.handle_event() {
                        break;
                    }
                }
                Ok(Async::Ready(None)) => {
                    debug!(
                        "ServiceProtocolStream({:?}) finished",
                        self.handle_context.proto_id
                    );
                    self.current_task.take();
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => {
                    finished = true;
                    break;
                }
                Err(err) => {
                    warn!(
                        "service proto [{}] handle receive message error: {:?}",
                        self.handle_context.proto_id, err
                    );
                    return Err(());
                }
            }
        }
        if !finished {
            self.set_delay();
        }

        loop {
            match self.notify_receiver.poll() {
                Ok(Async::Ready(Some(token))) => {
                    self.current_task = Some(ServiceProtocolEvent::Notify { token });
                    if let Async::NotReady = self.handle_event() {
                        self.set_delay();
                        break;
                    }
                }
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => {
                    self.set_delay();
                    break;
                }
                Err(_) => {
                    warn!(
                        "service proto [{}] handle receive message error",
                        self.handle_context.proto_id
                    );
                    return Err(());
                }
            }
        }

        self.handle.poll(&mut self.handle_context);

        Ok(Async::NotReady)
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
    T: SessionProtocol + Send,
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
    fn handle_event(&mut self) -> Async<()> {
        use self::SessionProtocolEvent::*;

        if self.current_task.is_none() {
            return Async::Ready(());
        }
        if self.shutdown.load(Ordering::SeqCst) {
            match self.current_task.as_ref().unwrap() {
                Disconnected {} => (),
                _ => {
                    self.current_task.take();
                    return Async::Ready(());
                }
            }
        }

        if self.context.closed.load(Ordering::SeqCst) {
            self.current_task = Some(SessionProtocolEvent::Disconnected);
        }

        match self.current_task.clone().unwrap() {
            Connected { version } => {
                match tokio_threadpool::blocking(|| {
                    self.handle
                        .connected(self.handle_context.as_mut(&self.context), &version)
                }) {
                    Ok(Async::Ready(_)) => (),
                    Ok(Async::NotReady) => return Async::NotReady,
                    Err(_) => self
                        .handle
                        .connected(self.handle_context.as_mut(&self.context), &version),
                }
            }
            Disconnected => {
                match tokio_threadpool::blocking(|| {
                    self.handle
                        .disconnected(self.handle_context.as_mut(&self.context))
                }) {
                    Ok(Async::Ready(_)) => (),
                    Ok(Async::NotReady) => return Async::NotReady,
                    Err(_) => self
                        .handle
                        .disconnected(self.handle_context.as_mut(&self.context)),
                }
                self.close();
            }
            Received { data } => {
                match tokio_threadpool::blocking(|| {
                    self.handle
                        .received(self.handle_context.as_mut(&self.context), data.clone())
                }) {
                    Ok(Async::Ready(_)) => (),
                    Ok(Async::NotReady) => return Async::NotReady,
                    Err(_) => self
                        .handle
                        .received(self.handle_context.as_mut(&self.context), data),
                }
            }
            Notify { token } => {
                match tokio_threadpool::blocking(|| {
                    self.handle
                        .notify(self.handle_context.as_mut(&self.context), token)
                }) {
                    Ok(Async::Ready(_)) => (),
                    Ok(Async::NotReady) => return Async::NotReady,
                    Err(_) => self
                        .handle
                        .notify(self.handle_context.as_mut(&self.context), token),
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
        Async::Ready(())
    }

    fn set_notify(&mut self, token: u64) {
        if let Some(interval) = self.notify.get(&token) {
            let sender = self.notify_sender.clone();
            // NOTE: A Interval/Delay will block tokio runtime from gracefully shutdown.
            //       So we spawn it in FutureTaskManager
            let task = Delay::new(Instant::now() + *interval).then(move |_| {
                tokio::spawn(sender.send(token).map(|_| ()).map_err(|_| ()));
                Ok(())
            });
            tokio::spawn(
                self.future_task_sender
                    .clone()
                    .send(Box::new(task))
                    .map(|_| ())
                    .map_err(|_| ()),
            );
        }
    }

    fn set_delay(&mut self) {
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
            let notify = futures::task::current();
            let delay = self.delay.clone();
            let delay_task =
                Delay::new(Instant::now() + Duration::from_millis(200)).then(move |_| {
                    notify.notify();
                    delay.store(false, Ordering::Release);
                    Ok(())
                });
            tokio::spawn(delay_task);
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
    T: SessionProtocol + Send,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if let Async::NotReady = self.handle_event() {
            self.set_delay();
            return Ok(Async::NotReady);
        }
        loop {
            match self.receiver.poll() {
                Ok(Async::Ready(Some(event))) => {
                    self.current_task = Some(event);
                    if let Async::NotReady = self.handle_event() {
                        self.set_delay();
                        break;
                    }
                }
                Ok(Async::Ready(None)) => {
                    self.close();
                    return Ok(Async::Ready(None));
                }
                Ok(Async::NotReady) => {
                    self.set_delay();
                    break;
                }
                Err(err) => {
                    warn!(
                        "session proto [{}] handle receive message error: {:?}",
                        self.handle_context.proto_id, err
                    );
                    return Err(());
                }
            }
        }

        loop {
            match self.notify_receiver.poll() {
                Ok(Async::Ready(Some(token))) => {
                    self.current_task = Some(SessionProtocolEvent::Notify { token });
                    if let Async::NotReady = self.handle_event() {
                        self.set_delay();
                        break;
                    }
                }
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => {
                    self.set_delay();
                    break;
                }
                Err(_) => {
                    warn!(
                        "service proto [{}] handle receive message error",
                        self.handle_context.proto_id
                    );
                    return Err(());
                }
            }
        }

        self.handle.poll(self.handle_context.as_mut(&self.context));

        Ok(Async::NotReady)
    }
}
