use crate::channel::{
    decode_state, encode_state, queue::Queue, Priority, SendError, SendErrorKind, TryRecvError,
    TrySendError, INIT_STATE, MAX_BUFFER, MAX_CAPACITY, OPEN_MASK,
};
use futures::{
    future::poll_fn,
    stream::{FusedStream, Stream},
    task::AtomicWaker,
};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc,
    },
    task::{Context, Poll},
};

/// Creates an unbounded mpsc channel for communicating between asynchronous
/// tasks.
///
/// A `send` on this channel will always succeed as long as the receive half has
/// not been closed. If the receiver falls behind, messages will be arbitrarily
/// buffered.
///
/// **Note** that the amount of available system memory is an implicit bound to
/// the channel. Using an `unbounded` channel has the ability of causing the
/// process to run out of memory. In this case, the process will be aborted.
pub fn unbounded<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    let inner = Arc::new(UnboundedInner {
        state: AtomicUsize::new(INIT_STATE),
        message_queue: Queue::new(),
        quick_message_queue: Queue::new(),
        num_senders: AtomicUsize::new(1),
        recv_task: AtomicWaker::new(),
    });

    let tx = UnboundedSenderInner {
        inner: inner.clone(),
    };

    let rx = UnboundedReceiver { inner: Some(inner) };

    (UnboundedSender(Some(tx)), rx)
}

#[derive(Debug)]
struct UnboundedInner<T> {
    // Internal channel state. Consists of the number of messages stored in the
    // channel as well as a flag signalling that the channel is closed.
    state: AtomicUsize,

    // Atomic, FIFO queue used to send messages to the receiver
    message_queue: Queue<T>,

    // Atomic, FIFO queue used to send messages to the receiver, quick queue
    quick_message_queue: Queue<T>,

    // Number of senders in existence
    num_senders: AtomicUsize,

    // Handle to the receiver's task.
    recv_task: AtomicWaker,
}

impl<T> UnboundedInner<T> {
    // Clear `open` flag in the state, keep `num_messages` intact.
    fn set_closed(&self) {
        let curr = self.state.load(SeqCst);
        if !decode_state(curr).is_open {
            return;
        }

        self.state.fetch_and(!OPEN_MASK, SeqCst);
    }
}

unsafe impl<T: Send> Send for UnboundedInner<T> {}
unsafe impl<T: Send> Sync for UnboundedInner<T> {}

#[derive(Debug)]
struct UnboundedSenderInner<T> {
    // Channel state shared between the sender and receiver.
    inner: Arc<UnboundedInner<T>>,
}

// We never project Pin<&mut SenderInner> to `Pin<&mut T>`
impl<T> Unpin for UnboundedSenderInner<T> {}

impl<T> UnboundedSenderInner<T> {
    fn poll_ready_nb(&self) -> Poll<Result<(), SendError>> {
        let state = decode_state(self.inner.state.load(SeqCst));
        if state.is_open {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(SendError {
                kind: SendErrorKind::Disconnected,
            }))
        }
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

    /// Returns whether the senders send to the same receiver.
    fn same_receiver(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Returns pointer to the Arc containing sender
    ///
    /// The returned pointer is not referenced and should be only used for hashing!
    fn ptr(&self) -> *const UnboundedInner<T> {
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
}

impl<T> Clone for UnboundedSenderInner<T> {
    fn clone(&self) -> UnboundedSenderInner<T> {
        // Since this atomic op isn't actually guarding any memory and we don't
        // care about any orderings besides the ordering on the single atomic
        // variable, a relaxed ordering is acceptable.
        let mut curr = self.inner.num_senders.load(SeqCst);

        loop {
            // If the maximum number of senders has been reached, then fail
            if curr == MAX_BUFFER {
                panic!("cannot clone `Sender` -- too many outstanding senders");
            }

            debug_assert!(curr < MAX_BUFFER);

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
                        return UnboundedSenderInner {
                            inner: self.inner.clone(),
                        };
                    }
                }
                Err(actual) => curr = actual,
            }
        }
    }
}

impl<T> Drop for UnboundedSenderInner<T> {
    fn drop(&mut self) {
        // Ordering between variables don't matter here
        let prev = self.inner.num_senders.fetch_sub(1, SeqCst);

        if prev == 1 {
            self.close_channel();
        }
    }
}

/// The transmission end of an unbounded mpsc channel.
///
/// This value is created by the [`unbounded`](unbounded) function.
#[derive(Debug)]
pub struct UnboundedSender<T>(Option<UnboundedSenderInner<T>>);

impl<T> UnboundedSender<T> {
    /// Check if the channel is ready to receive a message.
    pub fn poll_ready(&self, _: &mut Context<'_>) -> Poll<Result<(), SendError>> {
        let inner = self.0.as_ref().ok_or(SendError {
            kind: SendErrorKind::Disconnected,
        })?;
        inner.poll_ready_nb()
    }

    /// Returns whether this channel is closed without needing a context.
    pub fn is_closed(&self) -> bool {
        self.0
            .as_ref()
            .map(UnboundedSenderInner::is_closed)
            .unwrap_or(true)
    }

    /// Closes this channel from the sender side, preventing any new messages.
    pub fn close_channel(&self) {
        if let Some(inner) = &self.0 {
            inner.close_channel();
        }
    }

    /// Disconnects this sender from the channel, closing it if there are no more senders left.
    pub fn disconnect(&mut self) {
        self.0 = None;
    }

    /// Try get inner queue len, if close or disconnect, it will be none
    pub fn len(&self) -> Option<usize> {
        self.0.as_ref().and_then(|inner| {
            let state = decode_state(inner.inner.state.load(SeqCst));
            if state.is_open {
                Some(state.num_messages)
            } else {
                None
            }
        })
    }

    // Do the send without parking current task.
    fn do_send_nb(&self, msg: T, priority: Priority) -> Result<(), TrySendError<T>> {
        if let Some(inner) = &self.0 {
            if inner.inc_num_messages().is_some() {
                inner.queue_push_and_signal(msg, priority);
                return Ok(());
            }
        }

        Err(TrySendError {
            err: SendError {
                kind: SendErrorKind::Disconnected,
            },
            val: msg,
        })
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
    /// This method should only be called after `poll_ready` has been used to
    /// verify that the channel is ready to receive a message.
    pub fn start_send(&self, msg: T) -> Result<(), SendError> {
        self.do_send_nb(msg, Priority::Normal).map_err(|e| e.err)
    }

    /// Send a message on the channel.
    ///
    /// This method should only be called after `poll_ready` has been used to
    /// verify that the channel is ready to receive a message.
    pub fn start_quick_send(&self, msg: T) -> Result<(), SendError> {
        self.do_send_nb(msg, Priority::High).map_err(|e| e.err)
    }

    /// Sends a message along this channel.
    ///
    /// This is an unbounded sender, so this function differs from `Sink::send`
    /// by ensuring the return type reflects that the channel is always ready to
    /// receive messages.
    pub fn unbounded_send(&self, msg: T) -> Result<(), TrySendError<T>> {
        self.do_send_nb(msg, Priority::Normal)
    }

    /// Sends a message along this channel.
    ///
    /// This is an unbounded sender, so this function differs from `Sink::send`
    /// by ensuring the return type reflects that the channel is always ready to
    /// receive messages.
    pub fn unbounded_quick_send(&self, msg: T) -> Result<(), TrySendError<T>> {
        self.do_send_nb(msg, Priority::High)
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

impl<T> Clone for UnboundedSender<T> {
    fn clone(&self) -> UnboundedSender<T> {
        UnboundedSender(self.0.clone())
    }
}

/// The receiving end of an unbounded mpsc channel.
///
/// This value is created by the [`unbounded`](unbounded) function.
#[derive(Debug)]
pub struct UnboundedReceiver<T> {
    inner: Option<Arc<UnboundedInner<T>>>,
}

// `Pin<&mut UnboundedReceiver<T>>` is never projected to `Pin<&mut T>`
impl<T> Unpin for UnboundedReceiver<T> {}

impl<T> UnboundedReceiver<T> {
    /// Closes the receiving half of a channel, without dropping it.
    ///
    /// This prevents any further messages from being sent on the channel while
    /// still enabling the receiver to drain messages that are buffered.
    pub fn close(&mut self) {
        if let Some(inner) = &mut self.inner {
            inner.set_closed();
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

        match unsafe { inner.quick_message_queue.pop_spin() } {
            Some(msg) => {
                // Decrement number of messages
                self.dec_num_messages();

                Poll::Ready(Some((Priority::High, msg)))
            }
            None => {
                match unsafe { inner.message_queue.pop_spin() } {
                    Some(msg) => {
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

    fn dec_num_messages(&self) {
        if let Some(inner) = &self.inner {
            // OPEN_MASK is highest bit, so it's unaffected by subtraction
            // unless there's underflow, and we know there's no underflow
            // because number of messages at this point is always > 0.
            inner.state.fetch_sub(1, SeqCst);
        }
    }
}

impl<T> FusedStream for UnboundedReceiver<T> {
    fn is_terminated(&self) -> bool {
        self.inner.is_none()
    }
}

impl<T> Stream for UnboundedReceiver<T> {
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

impl<T> Drop for UnboundedReceiver<T> {
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
