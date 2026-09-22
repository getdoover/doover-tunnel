//! Device role: keep a session to the relay alive until it expires, is
//! cancelled, or the relay says close; serve every inbound stream by
//! dialling the target pinned in the session record.
//!
//! The device authenticates with the device agent's token, re-read on every
//! dial because the agent rotates it. It never trusts the relay's `Open`: the
//! target must equal what its own tunnel config says.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tokio_yamux::StreamHandle;

use crate::dial::{Backoff, connect};
use crate::proto::{Control, Open, OpenAck, Role, TunnelSession, now_unix, read_msg, write_msg};
use crate::{Error, Result};

const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Counters a caller can read after the session ends.
#[derive(Debug, Default, Clone)]
pub struct SessionStats {
    pub streams_opened: u64,
    pub streams_refused: u64,
    pub reconnects: u64,
}

/// Supplies the device credential for each dial.
pub trait TokenSource: Send + Sync {
    fn token(&self) -> std::result::Result<String, String>;
}

impl<F> TokenSource for F
where
    F: Fn() -> std::result::Result<String, String> + Send + Sync,
{
    fn token(&self) -> std::result::Result<String, String> {
        self()
    }
}

/// Reads `auth_token` from the device agent's `config.json`, mounted into
/// the app container. Read fresh each time: the agent rotates it.
pub struct AgentConfigToken {
    pub path: std::path::PathBuf,
}

impl TokenSource for AgentConfigToken {
    fn token(&self) -> std::result::Result<String, String> {
        let raw = std::fs::read_to_string(&self.path)
            .map_err(|e| format!("read {}: {e}", self.path.display()))?;
        let v: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| format!("parse {}: {e}", self.path.display()))?;
        v.get("auth_token")
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("{} has no auth_token", self.path.display()))
    }
}

/// Run one device session to completion. Returns `Ok` when the session ended
/// cleanly (expiry, cancel, or relay close) and `Err` when we gave up.
pub async fn run_session(
    relay_url: &str,
    session: &TunnelSession,
    token: &dyn TokenSource,
    cancel: CancellationToken,
) -> Result<SessionStats> {
    let mut stats = SessionStats::default();
    let mut backoff = Backoff::default();
    loop {
        if cancel.is_cancelled() {
            return Ok(stats);
        }
        if now_unix() >= session.exp {
            tracing::info!(sid = %session.sid, "session expired");
            return Ok(stats);
        }
        let tok = match token.token() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(sid = %session.sid, "device token unavailable: {e}");
                stats.reconnects += 1;
                let wait = backoff.next_delay();
                tokio::select! {
                    _ = tokio::time::sleep(wait) => continue,
                    _ = cancel.cancelled() => return Ok(stats),
                }
            }
        };
        match connect(relay_url, Role::Device, &session.sid, &tok).await {
            Ok(conn) => {
                backoff.reset();
                tracing::info!(sid = %session.sid, "device session connected");
                match serve(conn, session, &cancel, &mut stats).await {
                    Ok(()) => return Ok(stats),
                    Err(Error::Closed(reason)) => {
                        tracing::info!(sid = %session.sid, %reason, "relay closed session");
                        return Ok(stats);
                    }
                    Err(e) => tracing::warn!(sid = %session.sid, "session dropped: {e}"),
                }
            }
            Err(Error::Refused(reason)) => {
                // Unknown session, wrong agent, closed: retrying won't help.
                return Err(Error::Refused(reason));
            }
            Err(e) => tracing::warn!(sid = %session.sid, "connect failed: {e}"),
        }
        stats.reconnects += 1;
        let wait = backoff.next_delay();
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = cancel.cancelled() => return Ok(stats),
        }
    }
}

async fn serve(
    conn: crate::dial::Connected,
    session: &TunnelSession,
    cancel: &CancellationToken,
    stats: &mut SessionStats,
) -> Result<()> {
    let crate::dial::Connected {
        mux,
        mut inbound,
        mut control,
        ..
    } = conn;
    let expires_in = Duration::from_secs(session.exp.saturating_sub(now_unix()));
    let expiry = tokio::time::sleep(expires_in);
    tokio::pin!(expiry);

    // The control read is pinned across iterations so a partially received
    // Close is never lost, and it is polled first so a relay that sends
    // Close and then drops the socket is seen as a close, not a drop.
    let control_read = read_msg::<_, Control>(&mut control);
    tokio::pin!(control_read);

    loop {
        tokio::select! {
            biased;
            msg = &mut control_read => {
                match msg? {
                    Control::Close { reason } => return Err(Error::Closed(reason)),
                }
            }
            _ = cancel.cancelled() => {
                mux.close().await;
                return Ok(());
            }
            _ = &mut expiry => {
                mux.close().await;
                return Ok(());
            }
            _ = mux.closed.cancelled() => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset, "mux closed")));
            }
            stream = inbound.recv() => {
                let Some(stream) = stream else {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset, "inbound closed")));
                };
                stats.streams_opened += 1;
                let session = session.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(stream, &session).await {
                        tracing::debug!(sid = %session.sid, "stream ended: {e}");
                    }
                });
            }
        }
    }
}

async fn handle_stream(mut stream: StreamHandle, session: &TunnelSession) -> Result<()> {
    let open: Open = read_msg(&mut stream).await?;
    if open.target_host != session.target_host
        || open.target_port != session.target_port
        || open.protocol != session.protocol
    {
        tracing::warn!(
            sid = %session.sid,
            requested = %format!("{}:{}", open.target_host, open.target_port),
            pinned = %format!("{}:{}", session.target_host, session.target_port),
            "refusing stream: target does not match session"
        );
        write_msg(
            &mut stream,
            &OpenAck {
                ok: false,
                reason: Some("target not permitted for this session".into()),
            },
        )
        .await?;
        return Ok(());
    }

    let target = format!("{}:{}", session.target_host, session.target_port);
    let upstream = match connect_target(&session.target_host, session.target_port).await {
        Ok(s) => s,
        Err(e) => {
            write_msg(
                &mut stream,
                &OpenAck {
                    ok: false,
                    reason: Some(format!("connect {target}: {e}")),
                },
            )
            .await?;
            return Ok(());
        }
    };
    let _ = upstream.set_nodelay(true);
    write_msg(
        &mut stream,
        &OpenAck {
            ok: true,
            reason: None,
        },
    )
    .await?;
    tracing::info!(
        sid = %session.sid,
        source = open.source.as_deref().unwrap_or("-"),
        %target,
        "stream open"
    );
    let (up, down) = splice(stream, upstream).await?;
    tracing::info!(sid = %session.sid, %target, up, down, "stream closed");
    Ok(())
}

/// Dial every address `host` resolves to, IPv4 first, until one answers.
/// In a container `localhost` often resolves to `::1` ahead of `127.0.0.1`
/// while the service on the host only listens on IPv4.
async fn connect_target(host: &str, port: u16) -> Result<TcpStream> {
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    addrs.sort_by_key(|a| a.is_ipv6());
    let mut last = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("{host} did not resolve"),
    );
    for addr in addrs {
        match tokio::time::timeout(TARGET_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = std::io::Error::new(e.kind(), format!("{addr}: {e}")),
            Err(_) => {
                last =
                    std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{addr}: timed out"))
            }
        }
    }
    Err(Error::Io(last))
}

/// Copy both directions until either side closes. Returns bytes (a→b, b→a).
pub async fn splice<A, B>(mut a: A, mut b: B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    Ok(tokio::io::copy_bidirectional(&mut a, &mut b).await?)
}
