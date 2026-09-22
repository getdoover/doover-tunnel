//! Dial a relay: WebSocket over TLS (rustls, webpki roots), then yamux
//! client, then the hello exchange on the first stream.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tokio_yamux::StreamHandle;

use crate::mux::{Inbound, Mux};
use crate::proto::ws::WsByteStream;
use crate::proto::{Hello, HelloAck, PROTOCOL_VERSION, Role, read_msg, write_msg};
use crate::{Error, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

pub type WsIo = WsByteStream<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

/// A dialled, admitted session: the mux plus the control stream.
pub struct Connected {
    pub mux: Mux,
    pub inbound: Inbound,
    pub control: StreamHandle,
    pub ack: HelloAck,
}

pub async fn connect(
    relay_url: &str,
    role: Role,
    session_id: &str,
    token: &str,
) -> Result<Connected> {
    let (ws, _resp) =
        tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(relay_url))
            .await
            .map_err(|_| {
                Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect"))
            })??;
    let io: WsIo = WsByteStream::new(ws);
    let (mux, inbound) = Mux::client(io);

    let mut control = mux.open_stream().await?;
    write_msg(
        &mut control,
        &Hello {
            version: PROTOCOL_VERSION,
            role,
            session_id: session_id.to_string(),
            token: token.to_string(),
        },
    )
    .await?;
    let ack: HelloAck = tokio::time::timeout(CONNECT_TIMEOUT, read_msg(&mut control))
        .await
        .map_err(|_| Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "hello")))??;
    if !ack.ok {
        return Err(Error::Refused(
            ack.reason.unwrap_or_else(|| "no reason".into()),
        ));
    }
    Ok(Connected {
        mux,
        inbound,
        control,
        ack,
    })
}

/// Reconnect schedule: 1 s doubling to a 30 s ceiling, with jitter so a fleet
/// coming back after an outage doesn't hit the relay in lockstep.
pub struct Backoff {
    cur: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            cur: Duration::from_secs(1),
        }
    }
}

impl Backoff {
    const MAX: Duration = Duration::from_secs(30);

    pub fn reset(&mut self) {
        self.cur = Duration::from_secs(1);
    }

    pub fn next_delay(&mut self) -> Duration {
        let jitter = rand::random_range(0..=self.cur.as_millis() as u64 / 4);
        let d = self.cur + Duration::from_millis(jitter);
        self.cur = (self.cur * 2).min(Self::MAX);
        d
    }
}
