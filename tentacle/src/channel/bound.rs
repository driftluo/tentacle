use crate::channel::{
    decode_state, encode_state, queue::Queue, Priority, SendError, SendErrorKind, TryRecvError,
    TrySendError, INIT_STATE, MAX_BUFFER, MAX_CAPACITY, OPEN_MASK,
};
use crate::lock::Mutex;

use futures::{
    future::poll_fn,
    stream::{FusedStream, Stream},
    task::{AtomicWaker, Waker},
};
use std::{
    pin::Pin,
    sync::{
        atomic::{
            AtomicBool, AtomicUsize,
            Ordering::{Relaxed, SeqCst},
        },
        Arc,
    },
    task::{Context, Poll},
};

/// Creates a bounded mpsc channel for communicating between asynchronous tasks.
///
/// Being bounded, this channel provides backpressure to ensure that the sender
/// outpaces the receiver by only a limited amount. The channel's capacity is
/// equal to `buffer + num-senders`. In other words, each sender gets a
/// guaranteed slot in the channel capacity, and on top of that there are
/// `buffer` "first come, first serve" slots available to all senders.
///
/// The [`Receiver`](Receiver) returned implements the
/// [`Stream`](futures_core::stream::Stream) trait, while [`Sender`](Sender) implements
/// `Sink`.
pub fn channel<T>(buffer: usize) -> (Sender<T>, Receiver<T>) {
    // Check that the requested buffer size does not exceed the maximum buffer
    // size permitted by the system.
    assert!(buffer < MAX_BUFFER, "requested buffer size too large");

    let inner = Arc::new(BoundedInner {
        buffer,
        state: AtomicUsize::new(INIT_STATE),
        message_queue: Queue::new(),
        quick_message_queue: Queue::new(),
        parked_queue: Queue::new(),
        num_senders: AtomicUsize::new(1),
        recv_task: AtomicWaker::new(),
    });

    let tx = BoundedSenderInner {
        inner: inner.clone(),
        sender_task: Arc::new(Mutex::new(SenderTask::new())),
        maybe_parked: AtomicBool::new(false),
    };

    let rx = Receiver { inner: Some(inner) };

    (Sender(Some(tx)), rx)
}

#[derive(Debug)]
struct BoundedInner<T> {
    // Max buffer size of the channel. If `None` then the channel is unbounded.
    buffer: usize,

    // Internal channel state. Consists of the number of messages stored in the
    // channel as well as a flag signalling that the channel is closed.
    state: AtomicUsize,

    // Atomic, FIFO queue used to send messages to the receiver
    message_queue: Queue<T>,

    // Atomic, FIFO queue used to send messages to the receiver
    quick_message_queue: Queue<T>,

    // Atomic, FIFO queue used to send parked task handles to the receiver.
    parked_queue: Queue<Arc<Mutex<SenderTask>>>,

    // Number of senders in existence
    num_senders: AtomicUsize,

    // Handle to the receiver's task.
    recv_task: AtomicWaker,
}

impl<T> BoundedInner<T> {
    // The return value is such that the total number of messages that can be
    // enqueued into the channel will never exceed MAX_CAPACITY
    fn max_senders(&self) -> usize {
        MAX_CAPACITY - self.buffer
    }

    // Clear `open` flag in the state, keep `num_messages` intact.
    fn set_closed(&self) {
        let curr = self.state.load(SeqCst);
        if !decode_state(curr).is_open {
            return;
        }

        self.state.fetch_and(!OPEN_MASK, SeqCst);
    }
}

unsafe impl<T: Send> Send for BoundedInner<T> {}
unsafe impl<T: Send> Sync for BoundedInner<T> {}

// Sent to the consumer to wake up blocked producers
#[derive(Debug)]
struct SenderTask {
    task: Option<Waker>,
    is_parked: bool,
}

impl SenderTask {
    fn new() -> Self {
        SenderTask {
            task: None,
            is_parked: false,
        }
    }

    fn notify(&mut self) {
        self.is_parked = false;

        if let Some(task) = self.task.take() {
            task.wake();
        }
    }
}

#[derive(Debug)]
struct BoundedSenderInner<T> {
    // Channel state shared between the sender and receiver.
    inner: Arc<BoundedInner<T>>,

    // Handle to the task that is blocked on this sender. This handle is sent
    // to the receiver half in order to be notified when the sender becomes
    // unblocked.
    sender_task: Arc<Mutex<SenderTask>>,

    // `true` if the sender might be blocked. This is an optimization to avoid
    // having to lock the mutex most of the time.
    maybe_parked: AtomicBool,
}

impl<T> BoundedSenderInner<T> {
    /// Attempts to send a message on this `Sender`, returning the message
    /// if there was an error.
    fn try_send(&self, msg: T, priority: Priority) -> Result<(), TrySendError<T>> {
        // If the sender is currently blocked, reject the message
        if !self.poll_unparked(None).is_ready() {
            return Err(TrySendError {
                err: SendError {
                    kind: SendErrorKind::Full,
                },
                val: msg,
            });
        }

        // The channel has capacity to accept the message, so send it
        self.do_send_b(msg, priority)
    }

    // Do the send without failing.
    // Can be called only by bounded sender.
    #[allow(clippy::debug_assert_with_mut_call)]
    fn do_send_b(&self, msg: T, priority: Priority) -> Result<(), TrySendError<T>> {
        // Anyone callig do_send *should* make sure there is room first,
        // but assert here for tests as a sanity check.
        debug_assert!(self.poll_unparked(None).is_ready());

        // First, increment the number of messages contained by the channel.
        // This operation will also atomically determine if the sender task
        // should be parked.
        //
        // `None` is returned in the case that the channel has been closed by the
        // receiver. This happens when `Receiver::close` is called or the
        // receiver is dropped.
        let park_self = match self.inc_num_messages() {
            Some(num_messages) => {
                // Block if the current number of pending messages has exceeded
                // the configured buffer size
                num_messages > self.inner.buffer
            }
            None => {
                return Err(TrySendError {
                    err: SendError {
                        kind: SendErrorKind::Disconnected,
                    },
                    val: msg,
                })
            }
        };

        // If the channel has reached capacity, then the sender task needs to
        // be parked. This will send the task handle on the parked task queue.
        //
        // However, when `do_send` is called while dropping the `Sender`,
        // `task::current()` can't be called safely. In this case, in order to
        // maintain internal consistency, a blank message is pushed onto the
        // parked task queue.
        if park_self {
            self.park();
        }

        self.queue_push_and_signal(msg, priority);

        Ok(())
    }

    // Push message to the queue and signal to the receiver
    fn queue_push_and_signal(&self, msg: T, priority: Priority) {
        // Push the message onto the message queue
        match priority {
            Priority::High => self.inner.quick_message_queue.push(msg),
            Priority::Normal => self.inner.message_queue.push(msg),
        }

        // Signal to the receiver that a message has been enqueued. If the
        // receiver is parked, this will unpark the task.
        self.inner.recv_task.wake();
    }

    // Increment the number of queued messages. Returns the resulting number.
    fn inc_num_messages(&self) -> Option<usize> {
        let mut curr = self.inner.state.load(SeqCst);

        loop {
            let mut state = decode_state(curr);

            // The receiver end closed the channel.
            if !state.is_open {
                return None;
            }

            // This probably is never hit? Odds are the process will run out of
            // memory first. It may be worth to return something else in this
            // case?
            assert!(
                state.num_messages < MAX_CAPACITY,
                "buffer space \
                    exhausted; sending this messages would overflow the state"
            );

            state.num_messages += 1;

            let next = encode_state(&state);
            match self
                .inner
                .state
                .compare_exchange(curr, next, SeqCst, SeqCst)
            {
                Ok(_) => return Some(state.num_messages),
                Err(actual) => curr = actual,
            }
        }
    }

    fn park(&self) {
        {
            let mut sender = self.sender_task.lock();
            sender.task = None;
            sender.is_parked = true;
        }

        // Send handle over queue
        let t = self.sender_task.clone();
        self.inner.parked_queue.push(t);

        // Check to make sure we weren't closed after we sent our task on the
        // queue
        let state = decode_state(self.inner.state.load(SeqCst));
        self.maybe_parked.store(state.is_open, Relaxed);
    }

    /// Polls the channel to determine if there is guaranteed capacity to send
    /// at least one item without waiting.
    ///
    /// # Return value
    ///
    /// This method returns:
    ///
    /// - `Poll::Ready(Ok(_))` if there is sufficient capacity;
    /// - `Poll::Pending` if the channel may not have
    ///   capacity, in which case the current task is queued to be notified once
    ///   capacity is available;
    /// - `Poll::Ready(Err(SendError))` if the receiver has been dropped.
    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), SendError>> {
        let state = decode_state(self.inner.state.load(SeqCst));
        if !state.is_open {
            return Poll::Ready(Err(SendError {
                kind: SendErrorKind::Disconnected,
            }));
        }

        self.poll_unparked(Some(cx)).map(Ok)
    }

    /// Returns whether the senders send to the same receiver.
    fn same_receiver(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Returns pointer to the Arc containing sender
    ///
    /// The returned pointer is not referenced and should be only used for hashing!
    fn ptr(&self) -> *const BoundedInner<T> {
        &*self.inner
    }

    /// Returns whether this channel is closed without needing a context.
    fn is_closed(&self) -> bool {
        !decode_state(self.inner.state.load(SeqCst)).is_open
    }

    /// Closes this channel from the sender side, preventing any new messages.
    fn close_channel(&self) {
        // There's no need to park this sender, its dropping,
        // and we don't want to check for capacity, so skip
        // that stuff from `do_send`.

        self.inner.set_closed();
        self.inner.recv_task.wake();
    }

    fn poll_unparked(&self, cx: Option<&mut Context<'_>>) -> Poll<()> {
        // First check the `maybe_parked` variable. This avoids acquiring the
        // lock in most cases
        if self.maybe_parked.load(Relaxed) {
            // Get a lock on the task handle
            let mut task = self.sender_task.lock();

            if !task.is_parked {
                self.maybe_parked.store(false, Relaxed);
                return Poll::Ready(());
            }

            // At this point, an unpark request is pending, so there will be an
            // unpark sometime in the future. We just need to make sure that
            // the correct task will be notified.
            //
            // Update the task in case the `Sender` has been moved to another
            // task
            task.task = cx.map(|cx| cx.waker().clone());

            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

impl<T> Clone for BoundedSenderInner<T> {
    fn clone(&self) -> BoundedSenderInner<T> {
        // Since this atomic op isn't actually guarding any memory and we don't
        // care about any orderings besides the ordering on the single atomic
        // variable, a relaxed ordering is acceptable.
        let mut curr = self.inner.num_senders.load(SeqCst);

        loop {
            // If the maximum number of senders has been reached, then fail
            if curr == self.inner.max_senders() {
                panic!("cannot clone `Sender` -- too many outstanding senders");
            }

            debug_assert!(curr < self.inner.max_senders());

            let next = curr + 1;
            match self
                .inner
                .num_senders
                .compare_exchange(curr, next, SeqCst, SeqCst)
            {
                Ok(actual) => {
                    // The ABA problem doesn't matter here. We only care that the
                    // number of senders never exceeds the maximum.
                    if actual == curr {
                        return BoundedSenderInner {
                            inner: self.inner.clone(),
                            sender_task: Arc::new(Mutex::new(SenderTask::new())),
                            maybe_parked: AtomicBool::new(false),
                        };
                    }
                }
                Err(actual) => curr = actual,
            }
        }
    }
}

impl<T> Drop for BoundedSenderInner<T> {
    fn drop(&mut self) {
        // Ordering between variables don't matter here
        let prev = self.inner.num_senders.fetch_sub(1, SeqCst);

        if prev == 1 {
            self.close_channel();
        }
    }
}

/// The transmission end of a bounded mpsc channel.
///
/// This value is created by the [`channel`](channel) function.
#[derive(Debug)]
pub struct Sender<T>(Option<BoundedSenderInner<T>>);

impl<T> Sender<T> {
    /// Attempts to send a message on this `Sender`, returning the message
    /// if there was an error.
    pub fn try_send(&self, msg: T) -> Result<(), TrySendError<T>> {
        if let Some(inner) = &self.0 {
            inner.try_send(msg, Priority::Normal)
        } else {
            Err(TrySendError {
                err: SendError {
                    kind: SendErrorKind::Disconnected,
                },
                val: msg,
            })
        }
    }

    /// Attempts to send a message on this `Sender`, returning the message
    /// if there was an error.
    pub fn try_quick_send(&self, msg: T) -> Result<(), TrySendError<T>> {
        if let Some(inner) = &self.0 {
            inner.try_send(msg, Priority::High)
        } else {
            Err(TrySendError {
                err: SendError {
                    kind: SendErrorKind::Disconnected,
                },
                val: msg,
            })
        }
    }

    // Send a message on the channel with async fn, doesn't use Sink trait
    pub async fn async_send(&self, msg: T) -> Result<(), SendError> {
        let mut msg = Some(msg);
        poll_fn(|cx| {
            let item = msg.take().unwrap();
            match self.poll_ready(cx)? {
                Poll::Ready(()) => Poll::Ready(self.start_send(item)),
                Poll::Pending => {
                    msg = Some(item);
                    Poll::Pending
                }
            }
        })
        .await
    }

    // Send a message on the channel with async fn, doesn't use Sink trait
    pub async fn async_quick_send(&self, msg: T) -> Result<(), SendError> {
        let mut msg = Some(msg);
        poll_fn(|cx| {
            let item = msg.take().unwrap();
            match self.poll_ready(cx)? {
                Poll::Ready(()) => Poll::Ready(self.start_quick_send(item)),
                Poll::Pending => {
                    msg = Some(item);
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// Send a message on the channel.
    ///
    /// This function should only be called after
    /// [`poll_ready`](Sender::poll_ready) has reported that the channel is
    /// ready to receive a message.
    pub fn start_send(&self, msg: T) -> Result<(), SendError> {
        self.try_send(msg).map_err(|e| e.err)
    }

    /// Send a message on the channel.
    ///
    /// This function should only be called after
    /// [`poll_ready`](Sender::poll_ready) has reported that the channel is
    /// ready to receive a message.
    pub fn start_quick_send(&self, msg: T) -> Result<(), SendError> {
        self.try_quick_send(msg).map_err(|e| e.err)
    }

    /// Polls the channel to determine if there is guaranteed capacity to send
    /// at least one item without waiting.
    ///
    /// # Return value
    ///
    /// This method returns:
    ///
    /// - `Poll::Ready(Ok(_))` if there is sufficient capacity;
    /// - `Poll::Pending` if the channel may not have
    ///   capacity, in which case the current task is queued to be notified once
    ///   capacity is available;
    /// - `Poll::Ready(Err(SendError))` if the receiver has been dropped.
    pub fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), SendError>> {
        let inner = self.0.as_ref().ok_or(SendError {
            kind: SendErrorKind::Disconnected,
        })?;
        inner.poll_ready(cx)
    }

    /// Returns whether this channel is closed without needing a context.
    pub fn is_closed(&self) -> bool {
        self.0
            .as_ref()
            .map(BoundedSenderInner::is_closed)
            .unwrap_or(true)
    }

    /// Closes this channel from the sender side, preventing any new messages.
    pub fn close_channel(&mut self) {
        if let Some(inner) = &mut self.0 {
            inner.close_channel();
        }
    }

    /// Disconnects this sender from the channel, closing it if there are no more senders left.
    pub fn disconnect(&mut self) {
        self.0 = None;
    }

    /// Returns whether the senders send to the same receiver.
    pub fn same_receiver(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Some(inner), Some(other)) => inner.same_receiver(other),
            _ => false,
        }
    }

    /// Hashes the receiver into the provided hasher
    pub fn hash_receiver<H>(&self, hasher: &mut H)
    where
        H: std::hash::Hasher,
    {
        use std::hash::Hash;

        let ptr = self.0.as_ref().map(|inner| inner.ptr());
        ptr.hash(hasher);
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Sender<T> {
        Sender(self.0.clone())
    }
}

/// The receiving end of a bounded mpsc channel.
///
/// This value is created by the [`channel`](channel) function.
#[derive(Debug)]
pub struct Receiver<T> {
    inner: Option<Arc<BoundedInner<T>>>,
}

impl<T> Receiver<T> {
    /// Closes the receiving half of a channel, without dropping it.
    ///
    /// This prevents any further messages from being sent on the channel while
    /// still enabling the receiver to drain messages that are buffered.
    pub fn close(&mut self) {
        if let Some(inner) = &mut self.inner {
            inner.set_closed();

            // Wake up any threads waiting as they'll see that we've closed the
            // channel and will continue on their merry way.
            while let Some(task) = unsafe { inner.parked_queue.pop_spin() } {
                task.lock().notify();
            }
        }
    }

    /// Tries to receive the next message without notifying a context if empty.
    ///
    /// It is not recommended to call this function from inside of a future,
    /// only when you've otherwise arranged to be notified when the channel is
    /// no longer empty.
    ///
    /// This function will panic if called after `try_next` or `poll_next` has
    /// returned `None`.
    pub fn try_next(&mut self) -> Result<Option<(Priority, T)>, TryRecvError> {
        match self.next_message() {
            Poll::Ready(msg) => Ok(msg),
            Poll::Pending => Err(TryRecvError { _priv: () }),
        }
    }

    fn next_message(&mut self) -> Poll<Option<(Priority, T)>> {
        let inner = self
            .inner
            .as_mut()
            .expect("Receiver::next_message called after `None`");
        // Pop off a message
        match unsafe { inner.quick_message_queue.pop_spin() } {
            Some(msg) => {
                // If there are any parked task handles in the parked queue,
                // pop one and unpark it.
                self.unpark_one();

                // Decrement number of messages
                self.dec_num_messages();

                Poll::Ready(Some((Priority::High, msg)))
            }
            None => {
                match unsafe { inner.message_queue.pop_spin() } {
                    Some(msg) => {
                        // If there are any parked task handles in the parked queue,
                        // pop one and unpark it.
                        self.unpark_one();

                        // Decrement number of messages
                        self.dec_num_messages();

                        Poll::Ready(Some((Priority::Normal, msg)))
                    }
                    None => {
                        let state = decode_state(inner.state.load(SeqCst));
                        if state.is_closed() {
                            // If closed flag is set AND there are no pending messages
                            // it means end of stream
                            self.inner = None;
                            Poll::Ready(None)
                        } else {
                            // If queue is open, we need to return Pending
                            // to be woken up when new messages arrive.
                            // If queue is closed but num_messages is non-zero,
                            // it means that senders updated the state,
                            // but didn't put message to queue yet,
                            // so we need to park until sender unparks the task
                            // after queueing the message.
                            Poll::Pending
                        }
                    }
                }
            }
        }
    }

    // Unpark a single task handle if there is one pending in the parked queue
    fn unpark_one(&mut self) {
        if let Some(inner) = &mut self.inner {
            if let Some(task) = unsafe { inner.parked_queue.pop_spin() } {
                task.lock().notify();
            }
        }
    }

    fn dec_num_messages(&self) {
        if let Some(inner) = &self.inner {
            // OPEN_MASK is highest bit, so it's unaffected by subtraction
            // unless there's underflow, and we know there's no underflow
            // because number of messages at this point is always > 0.
            inner.state.fetch_sub(1, SeqCst);
        }
    }
}

// The receiver does not ever take a Pin to the inner T
impl<T> Unpin for Receiver<T> {}

impl<T> FusedStream for Receiver<T> {
    fn is_terminated(&self) -> bool {
        self.inner.is_none()
    }
}

impl<T> Stream for Receiver<T> {
    type Item = (Priority, T);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Try to read a message off of the message queue.
        match self.next_message() {
            Poll::Ready(msg) => {
                if msg.is_none() {
                    self.inner = None;
                }
                Poll::Ready(msg)
            }
            Poll::Pending => {
                // There are no messages to read, in this case, park.
                self.inner.as_ref().unwrap().recv_task.register(cx.waker());
                // Check queue again after parking to prevent race condition:
                // a message could be added to the queue after previous `next_message`
                // before `register` call.
                self.next_message()
            }
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        // Drain the channel of all pending messages
        self.close();
        if self.inner.is_some() {
            loop {
                match self.next_message() {
                    Poll::Ready(Some(_)) => {}
                    Poll::Ready(None) => break,
                    Poll::Pending => {
                        let state = decode_state(self.inner.as_ref().unwrap().state.load(SeqCst));

                        // If the channel is closed, then there is no need to park.
                        if state.is_closed() {
                            break;
                        }

                        // TODO: Spinning isn't ideal, it might be worth
                        // investigating using a condvar or some other strategy
                        // here. That said, if this case is hit, then another thread
                        // is about to push the value into the queue and this isn't
                        // the only spinlock in the impl right now.
                        #[cfg(any(
                            target_arch = "x86",
                            target_arch = "x86_64",
                            target_arch = "aarch64",
                            target_arch = "arm"
                        ))]
                        std::hint::spin_loop();
                        #[cfg(not(any(
                            target_arch = "x86",
                            target_arch = "x86_64",
                            target_arch = "aarch64",
                            target_arch = "arm"
                        )))]
                        std::thread::yield_now();
                    }
                }
            }
        }
    }
}
