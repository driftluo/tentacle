use super::{bound::Sender, unbound::UnboundedSender, SendError, TrySendError};
use futures::{ready, Sink};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

impl<T> Sink<T> for Sender<T> {
    type Error = SendError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        (*self).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, msg: T) -> Result<(), Self::Error> {
        (*self).start_send(msg)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match (*self).poll_ready(cx) {
            Poll::Ready(Err(ref e)) if e.is_disconnected() => {
                // If the receiver disconnected, we consider the sink to be flushed.
                Poll::Ready(Ok(()))
            }
            x => x,
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.disconnect();
        Poll::Ready(Ok(()))
    }
}

impl<T> Sink<T> for UnboundedSender<T> {
    type Error = SendError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        UnboundedSender::poll_ready(&*self, cx)
    }

    fn start_send(self: Pin<&mut Self>, msg: T) -> Result<(), Self::Error> {
        UnboundedSender::start_send(&*self, msg)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.disconnect();
        Poll::Ready(Ok(()))
    }
}

impl<T> Sink<T> for &UnboundedSender<T> {
    type Error = SendError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        UnboundedSender::poll_ready(*self, cx)
    }

    fn start_send(self: Pin<&mut Self>, msg: T) -> Result<(), Self::Error> {
        self.unbounded_send(msg)
            .map_err(TrySendError::into_send_error)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.close_channel();
        Poll::Ready(Ok(()))
    }
}

/// Since the priority channel comes with two sending methods, the normal sink uses normal level sending,
/// while the `QuickSinkExt` will use the quick series interface as the sending method.
/// Currently, only simple send async is implemented.
pub trait QuickSinkExt<Item>: Sink<Item> {
    fn start_quick_send(&mut self, item: Item) -> Result<(), Self::Error>;

    fn quick_send(&mut self, item: Item) -> QuickSend<'_, Self, Item>
    where
        Self: Unpin,
    {
        QuickSend::new(self, item)
    }
}

impl<T> QuickSinkExt<T> for Sender<T> {
    fn start_quick_send(&mut self, msg: T) -> Result<(), Self::Error> {
        (*self).start_quick_send(msg)
    }
}

impl<T> QuickSinkExt<T> for UnboundedSender<T> {
    fn start_quick_send(&mut self, msg: T) -> Result<(), Self::Error> {
        UnboundedSender::start_quick_send(self, msg)
    }
}

impl<T> QuickSinkExt<T> for &UnboundedSender<T> {
    fn start_quick_send(&mut self, msg: T) -> Result<(), Self::Error> {
        self.unbounded_quick_send(msg)
            .map_err(TrySendError::into_send_error)
    }
}

pub struct QuickSend<'a, Si: ?Sized, Item> {
    sink: &'a mut Si,
    item: Option<Item>,
}

impl<Si: Unpin + ?Sized, Item> Unpin for QuickSend<'_, Si, Item> {}

impl<'a, Si: QuickSinkExt<Item> + Unpin + ?Sized, Item> QuickSend<'a, Si, Item> {
    pub(super) fn new(sink: &'a mut Si, item: Item) -> Self {
        QuickSend {
            sink,
            item: Some(item),
        }
    }
}

impl<Si: QuickSinkExt<Item> + Unpin + ?Sized, Item> Future for QuickSend<'_, Si, Item> {
    type Output = Result<(), Si::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        if let Some(item) = this.item.take() {
            let mut sink = Pin::new(&mut this.sink);
            match sink.as_mut().poll_ready(cx)? {
                Poll::Ready(()) => sink.as_mut().start_quick_send(item)?,
                Poll::Pending => {
                    this.item = Some(item);
                    return Poll::Pending;
                }
            }
        }

        // we're done sending the item, but want to block on flushing the
        // sink
        ready!(Pin::new(&mut this.sink).poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }
}
