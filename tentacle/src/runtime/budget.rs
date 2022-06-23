//! Since tokio does not make the coop module public, a similar collaborative yield
//! strategy had to be implemented manually

use std::{
    cell::RefCell,
    task::{Context, Poll},
};

thread_local! {
    static CURRENT: RefCell<u8> = RefCell::new(128);
}

/// Returns `Poll::Pending` if the current task has exceeded its budget and should yield.
///
/// User can insert this logic into your own implementation of future to actively yield the execution state
#[inline]
pub fn poll_proceed(cx: &mut Context<'_>) -> Poll<()> {
    CURRENT.with(|cell| {
        let mut budget = cell.borrow_mut();

        *budget -= 1;
        if *budget != 0 {
            Poll::Ready(())
        } else {
            *budget = 128;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use futures::{executor::block_on, future::poll_fn};
    use std::thread;

    fn get() -> u8 {
        CURRENT.with(|cell| *cell.borrow())
    }

    #[test]
    fn test_budget() {
        assert_eq!(get(), 128);
        block_on(poll_fn(poll_proceed));
        assert_eq!(get(), 127);

        thread::spawn(|| {
            assert_eq!(get(), 128);
            block_on(async {
                for _ in 0..2 {
                    poll_fn(poll_proceed).await
                }
            });
            assert_eq!(get(), 126);
        })
        .join()
        .unwrap();
        assert_eq!(get(), 127);
        block_on(async {
            for _ in 0..127 {
                poll_fn(poll_proceed).await
            }
        });
        assert_eq!(get(), 127);
    }
}
