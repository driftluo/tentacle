use futures::{
    prelude::*,
    sync::{mpsc, oneshot},
};
use log::{debug, trace};
use std::collections::HashMap;

use crate::service::SEND_SIZE;

pub(crate) type FutureTaskId = u64;
pub(crate) type BoxedFutureTask = Box<dyn Future<Item = (), Error = ()> + 'static + Send>;

/// A future task manager
pub(crate) struct FutureTaskManager {
    signals: HashMap<FutureTaskId, oneshot::Sender<()>>,
    next_id: FutureTaskId,
    id_sender: mpsc::Sender<FutureTaskId>,
    id_receiver: mpsc::Receiver<FutureTaskId>,
    task_receiver: mpsc::Receiver<BoxedFutureTask>,
}

impl FutureTaskManager {
    pub(crate) fn new(task_receiver: mpsc::Receiver<BoxedFutureTask>) -> FutureTaskManager {
        let (id_sender, id_receiver) = mpsc::channel(SEND_SIZE);
        FutureTaskManager {
            signals: HashMap::default(),
            next_id: 0,
            id_sender,
            id_receiver,
            task_receiver,
        }
    }

    fn add_task(&mut self, task: BoxedFutureTask) {
        let (sender, receiver) = oneshot::channel();
        self.next_id += 1;
        self.signals.insert(self.next_id, sender);

        let task_id = self.next_id;
        let id_sender = self.id_sender.clone();
        let task_wrapper = receiver
            .select2(task)
            .then(move |_| {
                trace!("future task({}) finished", task_id);
                id_sender.send(task_id)
            })
            .map(|_| ())
            .map_err(|_| ());
        trace!("starting future task({})", task_id);
        tokio::spawn(task_wrapper);
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
        self.signals.drain().for_each(|(_, sender)| {
            let _ = sender.send(());
        })
    }
}

impl Stream for FutureTaskManager {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match self.task_receiver.poll()? {
                Async::Ready(Some(task)) => self.add_task(task),
                Async::Ready(None) => {
                    debug!("future task receiver finished");
                    return Ok(Async::Ready(None));
                }
                Async::NotReady => break,
            }
        }

        loop {
            match self.id_receiver.poll()? {
                Async::Ready(Some(id)) => self.remove_task(id),
                Async::Ready(None) => {
                    debug!("future task id receiver finished");
                    return Ok(Async::Ready(None));
                }
                Async::NotReady => break,
            }
        }

        Ok(Async::NotReady)
    }
}
