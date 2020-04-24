use futures::{
    channel::{mpsc, oneshot},
    prelude::*,
};
use log::{debug, trace};
use std::collections::{hash_map::Entry, HashMap};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
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
            shutdown,
        }
    }

    fn add_task(&mut self, task: BoxedFutureTask) {
        let (sender, receiver) = oneshot::channel();

        loop {
            self.next_id = self.next_id.wrapping_add(1);
            match self.signals.entry(self.next_id) {
                Entry::Occupied(_) => continue,
                Entry::Vacant(entry) => {
                    entry.insert(sender);
                    break;
                }
            }
        }

        let task_id = self.next_id;
        let mut id_sender = self.id_sender.clone();
        tokio::spawn(async move {
            future::select(task, receiver).await;
            trace!("future task({}) finished", task_id);
            let _ = id_sender.send(task_id).await;
        });
    }

    // bounded future task has finished
    fn remove_task(&mut self, id: FutureTaskId) {
        self.signals.remove(&id);
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
        loop {
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
                    break;
                }
            }
        }

        loop {
            match Pin::new(&mut self.id_receiver).as_mut().poll_next(cx) {
                Poll::Ready(Some(id)) => self.remove_task(id),
                Poll::Ready(None) => {
                    debug!("future task id receiver finished");
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    break;
                }
            }
        }

        // double check here
        if self.shutdown.load(Ordering::SeqCst) {
            debug!("future task finished because service shutdown");
            return Poll::Ready(None);
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod test {
    use super::{Arc, AtomicBool, BoxedFutureTask, FutureTaskManager};

    use std::{thread, time};

    use futures::{channel::mpsc::channel, stream::pending, SinkExt, StreamExt};

    #[test]
    fn test_manager_drop() {
        let (sender, receiver) = channel(128);
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut manager = FutureTaskManager::new(receiver, shutdown);

        let mut send_task = sender.clone();

        let handle = thread::spawn(|| {
            let mut rt = tokio::runtime::Runtime::new().unwrap();
            rt.spawn(async move {
                for _ in 1..100 {
                    let _ = send_task
                        .send(Box::pin(async {
                            let mut stream = pending::<()>();
                            loop {
                                stream.next().await;
                            }
                        }) as BoxedFutureTask)
                        .await;
                }
            });
            rt.block_on(async move {
                loop {
                    if manager.next().await.is_none() {
                        break;
                    }
                }
            });
        });

        thread::sleep(time::Duration::from_millis(300));
        drop(sender);

        handle.join().unwrap()
    }
}
