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
    multiaddr::Multiaddr,
    service::future_task::BoxedFutureTask,
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

pub struct ServiceProtocolStream<T> {
    handle: T,
    /// External event is passed in from this
    handle_context: ProtocolContext,
    sessions: HashMap<SessionId, Arc<SessionContext>>,
    receiver: mpsc::Receiver<ServiceProtocolEvent>,
    notify: HashMap<u64, Duration>,
    notify_sender: mpsc::Sender<u64>,
    notify_receiver: mpsc::Receiver<u64>,
    delay: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    future_task_sender: mpsc::Sender<BoxedFutureTask>,
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
            delay: Arc::new(AtomicBool::new(false)),
            shutdown,
            future_task_sender,
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

impl<T> Stream for ServiceProtocolStream<T>
where
    T: ServiceProtocol + Send,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut finished = false;
        for _ in 0..64 {
            match self.receiver.poll() {
                Ok(Async::Ready(Some(event))) => self.handle_event(event),
                Ok(Async::Ready(None)) => {
                    debug!(
                        "ServiceProtocolStream({:?}) finished",
                        self.handle_context.proto_id
                    );
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
                    self.handle.notify(&mut self.handle_context, token);
                    self.set_notify(token);
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
    delay: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    future_task_sender: mpsc::Sender<BoxedFutureTask>,
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
            shutdown,
            delay: Arc::new(AtomicBool::new(false)),
            future_task_sender,
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
                    self.handle
                        .notify(self.handle_context.as_mut(&self.context), token);
                    self.set_notify(token);
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
