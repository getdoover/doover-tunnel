//! Client role: dial the relay with a user token for a session the cloud
//! created, then either forward a local TCP listener through it (CLI) or
//! open streams programmatically (app).

use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_yamux::StreamHandle;

use crate::dial::connect;
use crate::mux::Mux;
use crate::proto::{Open, OpenAck, Protocol, Role, read_msg, write_msg};
use crate::{Error, Result};

/// What the client needs to know about the session: where its streams go.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
}

pub struct ClientSession {
    mux: Mux,
    target: Target,
    _control: StreamHandle,
}

impl ClientSession {
    pub async fn connect(
        relay_url: &str,
        session_id: &str,
        token: &str,
        target: Target,
    ) -> Result<Self> {
        // Right after the cloud mints a session the relay may not have the
        // reservation or the device yet; give it a moment before giving up.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        let conn = loop {
            match connect(relay_url, Role::Client, session_id, token).await {
                Ok(c) => break c,
                Err(Error::Refused(r))
                    if (r.contains("unknown session") || r.contains("not connected"))
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Err(e) => return Err(e),
            }
        };
        Ok(Self {
            mux: conn.mux,
            target,
            _control: conn.control,
        })
        // conn.inbound is dropped: the relay never opens streams to a client.
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Hang up on the relay. Streams still open end with it.
    pub async fn close(&self) {
        self.mux.close().await;
    }

    pub fn closed(&self) -> CancellationToken {
        self.mux.closed.clone()
    }

    /// One stream to the session's target, ready for bytes.
    pub async fn open(&self) -> Result<StreamHandle> {
        let mut stream = self.mux.open_stream().await?;
        write_msg(
            &mut stream,
            &Open {
                target_host: self.target.host.clone(),
                target_port: self.target.port,
                protocol: self.target.protocol,
                source: None,
            },
        )
        .await?;
        let ack: OpenAck = read_msg(&mut stream).await?;
        if !ack.ok {
            return Err(Error::Refused(
                ack.reason.unwrap_or_else(|| "open refused".into()),
            ));
        }
        Ok(stream)
    }

    /// Accept local connections on `listen` and forward each through a new
    /// stream until cancelled or the session drops.
    pub async fn serve_local(&self, listen: SocketAddr, cancel: CancellationToken) -> Result<()> {
        let listener = TcpListener::bind(listen).await?;
        self.serve_listener(listener, cancel).await
    }

    /// [`Self::serve_local`] on a listener the caller bound, so the chosen
    /// port can be shown before serving starts.
    pub async fn serve_listener(
        &self,
        listener: TcpListener,
        cancel: CancellationToken,
    ) -> Result<()> {
        let listen = listener.local_addr()?;
        tracing::info!(%listen, target = %format!("{}:{}", self.target.host, self.target.port), "local proxy listening");
        loop {
            let (sock, peer) = tokio::select! {
                r = listener.accept() => r?,
                _ = cancel.cancelled() => return Ok(()),
                _ = self.mux.closed.cancelled() => {
                    return Err(Error::Closed("relay connection dropped".into()));
                }
            };
            let _ = sock.set_nodelay(true);
            match self.open().await {
                Ok(stream) => {
                    tokio::spawn(async move {
                        match crate::device::splice(sock, stream).await {
                            Ok((up, down)) => tracing::info!(%peer, up, down, "closed"),
                            Err(e) => tracing::debug!(%peer, "closed: {e}"),
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(%peer, "open failed: {e}");
                    drop(sock);
                }
            }
        }
    }
}

/// Convenience for one-shot use, e.g. an SSH `ProxyCommand`: connect, open a
/// single stream, and pipe it to stdio.
pub async fn pipe_stdio(
    relay_url: &str,
    session_id: &str,
    token: &str,
    target: Target,
) -> Result<()> {
    let session = ClientSession::connect(relay_url, session_id, token, target).await?;
    let mut stream = session.open().await?;
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut stdio = tokio::io::join(stdin, stdout);
    tokio::io::copy_bidirectional(&mut stdio, &mut stream).await?;
    Ok(())
}

pub async fn connect_tcp(addr: SocketAddr) -> Result<TcpStream> {
    Ok(TcpStream::connect(addr).await?)
}
