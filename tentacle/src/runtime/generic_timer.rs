use futures::{Future, Stream};
use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub use futures_timer::Delay;

pub struct Interval {
    delay: Delay,
    period: Duration,
}

impl Interval {
    pub fn new(period: Duration) -> Self {
        Self {
            delay: Delay::new(period),
            period,
        }
    }
}

impl Stream for Interval {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        match Pin::new(&mut self.delay).poll(cx) {
            Poll::Ready(_) => {
                let dur = self.period;
                self.delay.reset(dur);
                Poll::Ready(Some(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub fn interval(period: Duration) -> Interval {
    assert!(period > Duration::new(0, 0), "`period` must be non-zero.");

    Interval::new(period)
}

pub fn delay_for(duration: Duration) -> Delay {
    Delay::new(duration)
}

pub fn timeout<T>(duration: Duration, future: T) -> Timeout<T>
where
    T: Future,
{
    Timeout {
        task: future,
        delay: Delay::new(duration),
    }
}

#[derive(Debug, PartialEq)]
pub struct Elapsed(());

impl fmt::Display for Elapsed {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        "deadline has elapsed".fmt(fmt)
    }
}

#[derive(Debug)]
pub struct Timeout<T> {
    task: T,
    delay: Delay,
}

impl<T> Future for Timeout<T>
where
    T: Future,
{
    type Output = Result<T::Output, Elapsed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Safety: we never move `self.task`
        unsafe {
            if let Poll::Ready(v) = self.as_mut().map_unchecked_mut(|s| &mut s.task).poll(cx) {
                return Poll::Ready(Ok(v));
            }
        }

        unsafe {
            match self.as_mut().map_unchecked_mut(|s| &mut s.delay).poll(cx) {
                Poll::Ready(_) => Poll::Ready(Err(Elapsed(()))),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}
