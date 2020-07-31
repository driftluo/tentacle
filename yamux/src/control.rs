use futures::{
    channel::{mpsc, oneshot},
    sink::SinkExt,
    FutureExt,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::{error::Error, stream::StreamHandle};

pub(crate) enum Command {
    OpenStream(oneshot::Sender<Result<StreamHandle, Error>>),
    Shutdown(oneshot::Sender<()>),
}

/// A session control is used to open the stream or close the session
pub struct Control {
    sender: mpsc::Sender<Command>,
    pending_open: Option<oneshot::Receiver<Result<StreamHandle, Error>>>,
    pending_close: Option<oneshot::Receiver<()>>,
}

impl Control {
    pub(crate) fn new(sender: mpsc::Sender<Command>) -> Self {
        Control {
            sender,
            pending_open: None,
            pending_close: None,
        }
    }

    /// Open a new stream to remote session
    pub async fn open_stream(&mut self) -> Result<StreamHandle, Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Command::OpenStream(tx))
            .await
            .map_err(|_| Error::SessionShutdown)?;
        rx.await.map_err(|_| Error::SessionShutdown)?
    }

    /// shutdown is used to close the session and all streams.
    pub async fn close(&mut self) {
        if self.sender.is_closed() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let _ignore = self.sender.send(Command::Shutdown(tx)).await;
        let _ignore = rx.await;
    }

    /// Poll base open stream
    pub fn poll_open_stream(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<StreamHandle, Error>> {
        loop {
            match self.pending_open.take() {
                None => match self.sender.poll_ready(cx) {
                    Poll::Ready(Ok(_)) => {
                        let (tx, rx) = oneshot::channel();
                        match self.sender.start_send(Command::OpenStream(tx)) {
                            Err(err) => {
                                if err.is_full() {
                                    return Poll::Pending;
                                } else {
                                    return Poll::Ready(Err(Error::SessionShutdown));
                                }
                            }
                            Ok(_) => {
                                self.pending_open = Some(rx);
                                continue;
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        if e.is_full() {
                            return Poll::Pending;
                        } else {
                            return Poll::Ready(Err(Error::SessionShutdown));
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                },
                Some(mut rx) => match rx.poll_unpin(cx) {
                    Poll::Ready(Ok(result)) => return Poll::Ready(result),
                    Poll::Pending => {
                        self.pending_open = Some(rx);
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(_)) => {
                        // drop return means session is gone
                        return Poll::Ready(Err(Error::SessionShutdown));
                    }
                },
            }
        }
    }

    /// Poll base close session
    pub fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        loop {
            match self.pending_close.take() {
                None => match self.sender.poll_ready(cx) {
                    Poll::Ready(Ok(_)) => {
                        let (tx, rx) = oneshot::channel();
                        match self.sender.start_send(Command::Shutdown(tx)) {
                            Ok(_) => {
                                self.pending_close = Some(rx);
                                continue;
                            }
                            Err(e) => {
                                if e.is_full() {
                                    return Poll::Pending;
                                } else {
                                    return Poll::Ready(());
                                }
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        if e.is_full() {
                            return Poll::Pending;
                        } else {
                            return Poll::Ready(());
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                },
                Some(mut rx) => match rx.poll_unpin(cx) {
                    Poll::Ready(Ok(())) => return Poll::Ready(()),
                    Poll::Ready(Err(_)) => {
                        // drop return means session is gone
                        return Poll::Ready(());
                    }
                    Poll::Pending => {
                        self.pending_close = Some(rx);
                        return Poll::Pending;
                    }
                },
            }
        }
    }
}

impl Clone for Control {
    fn clone(&self) -> Self {
        Control {
            sender: self.sender.clone(),
            pending_open: None,
            pending_close: None,
        }
    }
}
