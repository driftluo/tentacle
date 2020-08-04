use futures::{
    channel::{mpsc, oneshot},
    sink::SinkExt,
};

use crate::{error::Error, stream::StreamHandle};

pub(crate) enum Command {
    OpenStream(oneshot::Sender<Result<StreamHandle, Error>>),
    Shutdown(oneshot::Sender<()>),
}

/// A session control is used to open the stream or close the session
#[derive(Clone)]
pub struct Control(mpsc::Sender<Command>);

impl Control {
    pub(crate) fn new(sender: mpsc::Sender<Command>) -> Self {
        Control(sender)
    }

    /// Open a new stream to remote session
    pub async fn open_stream(&mut self) -> Result<StreamHandle, Error> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(Command::OpenStream(tx))
            .await
            .map_err(|_| Error::SessionShutdown)?;
        rx.await.map_err(|_| Error::SessionShutdown)?
    }

    /// shutdown is used to close the session and all streams.
    pub async fn close(&mut self) {
        if self.0.is_closed() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let _ignore = self.0.send(Command::Shutdown(tx)).await;
        let _ignore = rx.await;
    }
}
