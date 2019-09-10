use futures::{
    channel::{mpsc, oneshot},
    prelude::*,
};
use log::{debug, trace};
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

use crate::service::SEND_SIZE;

pub(crate) type FutureTaskId = u64;
pub(crate) type BoxedFutureTask = Pin<Box<dyn Future<Output = ()> + 'static + Send>>;

/// A future task manager
pub(crate) struct FutureTaskManager {
    signals: HashMap<FutureTaskId, oneshot::Sender<()>>,
    next_id: FutureTaskId,
    id_sender: mpsc::Sender<FutureTaskId>,
    id_receiver: mpsc::Receiver<FutureTaskId>,
    task_receiver: mpsc::Receiver<BoxedFutureTask>,
    delay: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
}

impl FutureTaskManager {
    pub(crate) fn new(
        task_receiver: mpsc::Receiver<BoxedFutureTask>,
        shutdown: Arc<AtomicBool>,
    ) -> FutureTaskManager {
        let (id_sender, id_receiver) = mpsc::channel(SEND_SIZE);
        FutureTaskManager {
            signals: HashMap::default(),
            next_id: 0,
            id_sender,
            id_receiver,
            task_receiver,
            delay: Arc::new(AtomicBool::new(false)),
            shutdown,
        }
    }

    fn add_task(&mut self, task: BoxedFutureTask) {
        let (sender, receiver) = oneshot::channel();
        self.next_id += 1;
        self.signals.insert(self.next_id, sender);

        let task_id = self.next_id;
        let mut id_sender = self.id_sender.clone();
        tokio::spawn(async move {
            future::select(task, receiver).await;
            trace!("future task({}) finished", task_id);
            let _ = id_sender.send(task_id);
        });
    }

    // bounded future task has finished
    fn remove_task(&mut self, id: FutureTaskId) {
        self.signals.remove(&id);
    }

    fn set_delay(&mut self, cx: &mut Context) {
        if !self.delay.load(Ordering::Acquire) {
            self.delay.store(true, Ordering::Release);
            let waker = cx.waker().clone();
            let delay = self.delay.clone();
            tokio::spawn(async move {
                tokio::timer::delay(Instant::now() + Duration::from_millis(100)).await;
                waker.wake();
                delay.store(false, Ordering::Release);
            });
        }
    }
}

impl Drop for FutureTaskManager {
    fn drop(&mut self) {
        // Because of https://docs.rs/futures/0.1.26/src/futures/sync/oneshot.rs.html#205-209
        // just drop may can't notify the receiver, and receiver will block on runtime, we use send to drop
        // all future task as soon as possible
        self.signals.drain().for_each(|(id, sender)| {
            trace!("future task send stop signal to {}", id);
            let _ = sender.send(());
        })
    }
}

impl Stream for FutureTaskManager {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut task_finished = false;
        let mut id_finished = false;
        for _ in 0..128 {
            if self.shutdown.load(Ordering::SeqCst) {
                debug!("future task finished because service shutdown");
                return Poll::Ready(None);
            }

            match Pin::new(&mut self.task_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(task)) => self.add_task(task),
                Poll::Ready(None) => {
                    debug!("future task receiver finished");
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    task_finished = true;
                    break;
                }
            }
        }

        for _ in 0..64 {
            if self.shutdown.load(Ordering::SeqCst) {
                debug!("future task finished because service shutdown");
                return Poll::Ready(None);
            }

            match Pin::new(&mut self.id_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(id)) => self.remove_task(id),
                Poll::Ready(None) => {
                    debug!("future task id receiver finished");
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    id_finished = true;
                    break;
                }
            }
        }

        if !task_finished || !id_finished {
            self.set_delay(cx);
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod test {
    use super::{Arc, AtomicBool, BoxedFutureTask, FutureTaskManager};

    use std::{thread, time};

    use futures::{
        channel::mpsc::channel,
        stream::{iter, pending},
        SinkExt, StreamExt,
    };

    #[test]
    fn test_manager_drop() {
        let (sender, receiver) = channel(128);
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut manager = FutureTaskManager::new(receiver, shutdown.clone());

        let mut send_task = sender.clone();

        let handle = thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.spawn(async move {
                loop {
                    if manager.next().await.is_none() {
                        break;
                    }
                }
            });
            rt.spawn(async move {
                let mut tasks = iter(
                    (1..100)
                        .map(|_| {
                            Box::pin(async {
                                let mut stream = pending::<()>();
                                loop {
                                    stream.next().await;
                                }
                            }) as BoxedFutureTask
                        })
                        .collect::<Vec<_>>(),
                );
                let _ = send_task.send_all(&mut tasks).await;
            });

            rt.shutdown_on_idle();
        });

        thread::sleep(time::Duration::from_millis(300));
        drop(sender);

        handle.join().unwrap()
    }
}
