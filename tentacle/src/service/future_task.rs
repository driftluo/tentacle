use futures::{
    channel::{mpsc, oneshot},
    prelude::*,
};
use log::{debug, trace};
use nohash_hasher::IntMap;
use std::collections::{hash_map::Entry, HashMap};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

pub(crate) type FutureTaskId = u64;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) type BoxedFutureTask = Pin<Box<dyn Future<Output = ()> + 'static + Send>>;
#[cfg(target_arch = "wasm32")]
pub(crate) type BoxedFutureTask = Pin<Box<dyn Future<Output = ()> + 'static>>;

/// A future task manager
pub(crate) struct FutureTaskManager {
    signals: IntMap<FutureTaskId, oneshot::Sender<()>>,
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
        let (id_sender, id_receiver) = mpsc::channel(32);
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
        crate::runtime::spawn(async move {
            future::select(task, receiver).await;
            trace!("future task({}) finished", task_id);
            if id_sender.send(task_id).await.is_err() {
                trace!("future task({}) send back err", task_id)
            }
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
            let _ignore = sender.send(());
        })
    }
}

impl Stream for FutureTaskManager {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if self.shutdown.load(Ordering::SeqCst) {
            debug!("future task finished because service shutdown");
            return Poll::Ready(None);
        }

        futures::ready!(crate::runtime::poll_proceed(cx));

        let mut is_pending = match Pin::new(&mut self.task_receiver).as_mut().poll_next(cx) {
            Poll::Ready(Some(task)) => {
                self.add_task(task);
                false
            }
            Poll::Ready(None) => {
                debug!("future task receiver finished");
                return Poll::Ready(None);
            }
            Poll::Pending => true,
        };

        match Pin::new(&mut self.id_receiver).as_mut().poll_next(cx) {
            Poll::Ready(Some(id)) => {
                self.remove_task(id);
                is_pending &= false
            }
            Poll::Ready(None) => {
                debug!("future task id receiver finished");
                return Poll::Ready(None);
            }
            Poll::Pending => is_pending &= true,
        }

        // double check here
        if self.shutdown.load(Ordering::SeqCst) {
            debug!("future task finished because service shutdown");
            return Poll::Ready(None);
        }

        if is_pending {
            Poll::Pending
        } else {
            Poll::Ready(Some(()))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Arc, AtomicBool, BoxedFutureTask, FutureTaskManager, Ordering};

    use crate::runtime::delay_for;
    use futures::{channel::mpsc::channel, stream::pending, SinkExt, StreamExt};
    use std::sync::atomic::AtomicUsize;
    use std::{thread, time};

    #[test]
    fn test_manager_drop() {
        let (sender, receiver) = channel(128);
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut manager = FutureTaskManager::new(receiver, shutdown);

        let mut send_task = sender.clone();

        let handle = thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.spawn(async move {
                for _ in 1..100 {
                    let _res = send_task
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

    #[test]
    fn test_ensure_finish_signals_received() {
        let (sender, receiver) = channel(128);
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut manager = FutureTaskManager::new(receiver, shutdown);
        let finished_tasks = Arc::new(AtomicUsize::new(0));
        let finished_tasks_inner = Arc::clone(&finished_tasks);
        let signals_len = Arc::new(AtomicUsize::new(usize::max_value()));
        let signals_len_inner = Arc::clone(&signals_len);

        let mut send_task = sender.clone();

        let handle = thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.spawn(async move {
                for i in 1..100u64 {
                    let finished_tasks_inner_clone = Arc::clone(&finished_tasks_inner);
                    let _res = send_task
                        .send(Box::pin(async move {
                            delay_for(time::Duration::from_millis(i * 2)).await;
                            finished_tasks_inner_clone.fetch_add(1, Ordering::SeqCst);
                        }) as BoxedFutureTask)
                        .await;
                }
            });
            rt.block_on(async move {
                loop {
                    // When `sender` dropped, FutureTaskManager will stop
                    if manager.next().await.is_none() {
                        signals_len_inner.store(manager.signals.len(), Ordering::SeqCst);
                        break;
                    }
                }
            });
        });

        // Wait for tasks finish, and manager receive all signals
        thread::sleep(time::Duration::from_millis(300));
        drop(sender);
        // Wait for FutureTaskManager stop
        thread::sleep(time::Duration::from_millis(100));
        assert_eq!(finished_tasks.load(Ordering::SeqCst), 99);
        assert_eq!(signals_len.load(Ordering::SeqCst), 0);

        handle.join().unwrap()
    }
}
