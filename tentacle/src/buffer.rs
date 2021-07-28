use crate::channel::mpsc::Sender as PrioritySender;
use futures::channel::mpsc::Sender;
use std::{
    collections::VecDeque,
    task::{Context, Poll},
};

/// If the buffer unused capacity is greater than u8 max, shrink it
const BUF_SHRINK_THRESHOLD: usize = u8::max_value() as usize;

pub enum SendResult {
    Ok,
    Pending,
    Disconnect,
}

pub struct PriorityBuffer<T> {
    sender: PrioritySender<T>,
    high_buffer: VecDeque<T>,
    normal_buffer: VecDeque<T>,
}

impl<T> PriorityBuffer<T> {
    pub fn new(sender: PrioritySender<T>) -> Self {
        PriorityBuffer {
            sender,
            high_buffer: VecDeque::default(),
            normal_buffer: VecDeque::default(),
        }
    }

    pub fn push_high(&mut self, item: T) {
        self.high_buffer.push_back(item)
    }

    pub fn push_normal(&mut self, item: T) {
        self.normal_buffer.push_back(item)
    }

    pub fn len(&self) -> usize {
        self.high_buffer.len() + self.normal_buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.high_buffer.is_empty() && self.normal_buffer.is_empty()
    }

    fn shrink_to_fit(&mut self) {
        if self.high_buffer.capacity() - self.high_buffer.len() > BUF_SHRINK_THRESHOLD {
            self.high_buffer.shrink_to_fit();
        }
        if self.normal_buffer.capacity() - self.normal_buffer.len() > BUF_SHRINK_THRESHOLD {
            self.normal_buffer.shrink_to_fit();
        }
    }

    pub fn try_send(&mut self, cx: &mut Context) -> SendResult {
        while let Some(event) = self.high_buffer.pop_front() {
            match self.sender.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    if let Err(e) = self.sender.try_quick_send(event) {
                        if e.is_full() {
                            self.high_buffer.push_front(e.into_inner());
                            return SendResult::Pending;
                        } else {
                            self.clear();
                            return SendResult::Disconnect;
                        }
                    }
                }
                Poll::Pending => {
                    self.high_buffer.push_front(event);
                    return SendResult::Pending;
                }
                Poll::Ready(Err(_)) => {
                    self.clear();
                    return SendResult::Disconnect;
                }
            }
        }
        while let Some(event) = self.normal_buffer.pop_front() {
            match self.sender.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    if let Err(e) = self.sender.try_send(event) {
                        if e.is_full() {
                            self.normal_buffer.push_front(e.into_inner());
                            return SendResult::Pending;
                        } else {
                            self.clear();
                            return SendResult::Disconnect;
                        }
                    }
                }
                Poll::Pending => {
                    self.normal_buffer.push_front(event);
                    return SendResult::Pending;
                }
                Poll::Ready(Err(_)) => {
                    self.clear();
                    return SendResult::Disconnect;
                }
            }
        }
        self.shrink_to_fit();
        SendResult::Ok
    }

    pub fn clear(&mut self) {
        self.high_buffer.clear();
        self.normal_buffer.clear();
    }
}

pub struct Buffer<T> {
    sender: Sender<T>,
    buffer: VecDeque<T>,
}

impl<T> Buffer<T> {
    pub fn new(sender: Sender<T>) -> Self {
        Buffer {
            sender,
            buffer: VecDeque::default(),
        }
    }

    pub fn push(&mut self, item: T) {
        self.buffer.push_back(item)
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn shrink_to_fit(&mut self) {
        if self.buffer.capacity() - self.buffer.len() > BUF_SHRINK_THRESHOLD {
            self.buffer.shrink_to_fit();
        }
    }

    pub fn try_send(&mut self, cx: &mut Context) -> SendResult {
        while let Some(event) = self.buffer.pop_front() {
            match self.sender.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    if let Err(e) = self.sender.try_send(event) {
                        if e.is_full() {
                            self.buffer.push_front(e.into_inner());
                            return SendResult::Pending;
                        } else {
                            self.clear();
                            return SendResult::Disconnect;
                        }
                    }
                }
                Poll::Pending => {
                    self.buffer.push_front(event);
                    return SendResult::Pending;
                }
                Poll::Ready(Err(_)) => {
                    self.clear();
                    return SendResult::Disconnect;
                }
            }
        }
        self.shrink_to_fit();
        SendResult::Ok
    }

    pub fn take(&mut self) -> (Sender<T>, VecDeque<T>) {
        (self.sender.clone(), ::std::mem::take(&mut self.buffer))
    }

    pub fn clear(&mut self) {
        self.buffer.clear()
    }
}

impl<T> Clone for Buffer<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            buffer: Default::default(),
        }
    }
}

impl<T> Clone for PriorityBuffer<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            high_buffer: Default::default(),
            normal_buffer: Default::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Buffer, PriorityBuffer};
    use crate::channel::mpsc::channel as priority_channel;
    use futures::{channel::mpsc::channel, executor::block_on, future::poll_fn, StreamExt};
    use std::{
        collections::VecDeque,
        task::{Context, Poll},
    };

    #[test]
    fn test_priority_buffer() {
        let (tx, mut rx) = priority_channel::<u32>(1);
        let mut buffer = PriorityBuffer::new(tx);

        buffer.push_high(1);
        buffer.push_high(2);
        buffer.push_high(3);
        buffer.push_high(4);
        buffer.push_normal(5);
        buffer.push_normal(6);

        let send_1 = |cx: &mut Context<'_>| -> Poll<()> {
            buffer.try_send(cx);
            Poll::Ready(())
        };
        block_on(poll_fn(send_1));

        assert_eq!(buffer.high_buffer, VecDeque::from(vec![3, 4]));
        assert_eq!(buffer.normal_buffer, VecDeque::from(vec![5, 6]));

        let res: Vec<_> = block_on(async {
            let v1 = rx.next().await.unwrap().1;
            let v2 = rx.next().await.unwrap().1;
            vec![v1, v2]
        });

        assert_eq!(res, vec![1, 2]);

        let send_2 = |cx: &mut Context<'_>| -> Poll<()> {
            buffer.try_send(cx);
            Poll::Ready(())
        };
        block_on(poll_fn(send_2));

        assert!(buffer.high_buffer.is_empty());
        assert_eq!(buffer.normal_buffer, VecDeque::from(vec![5, 6]));

        let res: Vec<_> = block_on(async {
            let v1 = rx.next().await.unwrap().1;
            let v2 = rx.next().await.unwrap().1;
            vec![v1, v2]
        });

        assert_eq!(res, vec![3, 4]);

        let send_3 = |cx: &mut Context<'_>| -> Poll<()> {
            buffer.try_send(cx);
            Poll::Ready(())
        };
        block_on(poll_fn(send_3));

        assert!(buffer.high_buffer.is_empty());
        assert!(buffer.normal_buffer.is_empty());
    }

    #[test]
    fn test_buffer() {
        let (tx, mut rx) = channel::<u32>(1);
        let mut buffer = Buffer::new(tx);

        buffer.push(1);
        buffer.push(2);
        buffer.push(3);
        buffer.push(4);
        buffer.push(5);

        let send_1 = |cx: &mut Context<'_>| -> Poll<()> {
            buffer.try_send(cx);
            Poll::Ready(())
        };
        block_on(poll_fn(send_1));

        assert_eq!(buffer.buffer, VecDeque::from(vec![3, 4, 5]));

        let res: Vec<_> = block_on(async {
            let v1 = rx.next().await.unwrap();
            let v2 = rx.next().await.unwrap();
            vec![v1, v2]
        });

        assert_eq!(res, vec![1, 2]);

        let send_2 = |cx: &mut Context<'_>| -> Poll<()> {
            buffer.try_send(cx);
            Poll::Ready(())
        };
        block_on(poll_fn(send_2));

        assert_eq!(buffer.buffer, VecDeque::from(vec![5]));
    }
}
