use futures::{
    prelude::*,
    sync::{mpsc, oneshot},
    try_ready,
};
use log::{debug, trace};
use std::collections::HashMap;

pub(crate) type FutureTaskId = u64;
pub(crate) type BoxedFutureTask = Box<dyn Future<Item = (), Error = ()> + 'static + Send>;

pub struct FutureTaskManager {
    signals: HashMap<FutureTaskId, oneshot::Sender<()>>,
    next_id: FutureTaskId,
    id_sender: mpsc::Sender<FutureTaskId>,
    id_receiver: mpsc::Receiver<FutureTaskId>,
    task_receiver: mpsc::Receiver<BoxedFutureTask>,
}

impl FutureTaskManager {
    pub(crate) fn new(task_receiver: mpsc::Receiver<BoxedFutureTask>) -> FutureTaskManager {
        let (id_sender, id_receiver) = mpsc::channel(128);
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

impl Stream for FutureTaskManager {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.task_receiver.poll()? {
            Async::Ready(Some(task)) => self.add_task(task),
            Async::Ready(None) => {
                debug!("future task receiver finished");
                return Ok(Async::Ready(None));
            }
            Async::NotReady => {}
        }

        match try_ready!(self.id_receiver.poll()) {
            Some(id) => self.remove_task(id),
            None => {
                debug!("future task id receiver finished");
                return Ok(Async::Ready(None));
            }
        }
        Ok(Async::Ready(Some(())))
    }
}
