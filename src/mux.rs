//! Thin driver around `tokio_yamux::Session`: the session must be polled to
//! move bytes, so it lives in its own task and hands out inbound streams over
//! a channel while callers open outbound streams through the `Control`.

use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_yamux::{Control, Session, StreamHandle};

/// Shareable handle: opens outbound streams and reports session death.
/// Inbound streams arrive on the receiver returned alongside it.
#[derive(Clone)]
pub struct Mux {
    control: Control,
    /// Cancelled when the underlying session ends for any reason.
    pub closed: CancellationToken,
}

pub type Inbound = mpsc::Receiver<StreamHandle>;

impl Mux {
    pub fn client<T>(io: T) -> (Self, Inbound)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::spawn(Session::new_client(io, crate::proto::yamux_config()))
    }

    pub fn server<T>(io: T) -> (Self, Inbound)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::spawn(Session::new_server(io, crate::proto::yamux_config()))
    }

    fn spawn<T>(mut session: Session<T>) -> (Self, Inbound)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let control = session.control();
        let (tx, rx) = mpsc::channel(16);
        let closed = CancellationToken::new();
        let done = closed.clone();
        tokio::spawn(async move {
            while let Some(item) = session.next().await {
                match item {
                    Ok(stream) => {
                        if tx.send(stream).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("yamux session error: {e}");
                        break;
                    }
                }
            }
            done.cancel();
        });
        (Self { control, closed }, rx)
    }

    pub async fn open_stream(&self) -> crate::Result<StreamHandle> {
        Ok(self.control.clone().open_stream().await?)
    }

    pub async fn close(&self) {
        self.control.clone().close().await;
    }
}
