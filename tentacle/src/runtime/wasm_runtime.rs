use wasm_bindgen_futures::spawn_local;

use futures::{channel::oneshot, future::poll_fn};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

pub fn block_in_place<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

pub struct JoinHandle<T> {
    recv: oneshot::Receiver<T>,
}

impl<T> Unpin for JoinHandle<T> {}

impl<T> Future for JoinHandle<T> {
    type Output = io::Result<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.recv)
            .poll(cx)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}

#[inline]
pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + 'static,
    F::Output: 'static,
{
    let (tx, rx) = oneshot::channel();
    spawn_local(async {
        let res = future.await;
        let _ignore = tx.send(res);
    });

    JoinHandle { recv: rx }
}

pub async fn yield_now() {
    let mut yielded = false;

    poll_fn(|cx| {
        if yielded {
            return Poll::Ready(());
        }

        yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}
