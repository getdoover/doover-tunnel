//! `AsyncRead + AsyncWrite` over a WebSocket, so yamux can run on top of
//! either axum's server-side socket or tokio-tungstenite's client socket.
//! Each write becomes one binary frame; text and ping/pong frames are
//! ignored on read; a close frame is EOF.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The two WebSocket message enums we run over, reduced to what we need.
pub trait WsMessage: Sized {
    fn binary(data: Bytes) -> Self;
    /// `Some(bytes)` for a binary frame, `None` to skip (text, ping, pong).
    /// Close frames are reported through [`Self::is_close`].
    fn into_binary(self) -> Option<Bytes>;
    fn is_close(&self) -> bool;
}

pub struct WsByteStream<S, M> {
    inner: S,
    read_buf: Bytes,
    eof: bool,
    _msg: std::marker::PhantomData<fn() -> M>,
}

impl<S, M> WsByteStream<S, M> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: Bytes::new(),
            eof: false,
            _msg: std::marker::PhantomData,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

impl<S, M, E> AsyncRead for WsByteStream<S, M>
where
    S: Stream<Item = Result<M, E>> + Unpin,
    M: WsMessage,
    E: std::fmt::Display,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                None => {
                    self.eof = true;
                }
                Some(Err(e)) => return Poll::Ready(Err(to_io(e))),
                Some(Ok(m)) if m.is_close() => {
                    self.eof = true;
                }
                Some(Ok(m)) => {
                    if let Some(b) = m.into_binary() {
                        self.read_buf = b;
                    }
                }
            }
        }
    }
}

impl<S, M, E> AsyncWrite for WsByteStream<S, M>
where
    S: Sink<M, Error = E> + Unpin,
    M: WsMessage,
    E: std::fmt::Display,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(to_io)?;
        Pin::new(&mut self.inner)
            .start_send(M::binary(Bytes::copy_from_slice(data)))
            .map_err(to_io)?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx).map_err(to_io)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx).map_err(to_io)
    }
}

#[cfg(feature = "axum-ws")]
impl WsMessage for axum::extract::ws::Message {
    fn binary(data: Bytes) -> Self {
        Self::Binary(data)
    }
    fn into_binary(self) -> Option<Bytes> {
        match self {
            Self::Binary(b) => Some(b),
            _ => None,
        }
    }
    fn is_close(&self) -> bool {
        matches!(self, Self::Close(_))
    }
}

impl WsMessage for tokio_tungstenite::tungstenite::Message {
    fn binary(data: Bytes) -> Self {
        Self::Binary(data)
    }
    fn into_binary(self) -> Option<Bytes> {
        match self {
            Self::Binary(b) => Some(b),
            _ => None,
        }
    }
    fn is_close(&self) -> bool {
        matches!(self, Self::Close(_))
    }
}
