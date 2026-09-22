//! Length-prefixed MessagePack messages exchanged on the control stream and
//! at the head of every data stream.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on a single control/open message. Anything larger is a bug or
/// an attack, never a legitimate message.
const MAX_MSG_LEN: u32 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum MsgError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("message too large: {0} bytes")]
    TooLarge(u32),
    #[error("encode: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("decode: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The on-device tunnel app. Dials targets on behalf of the relay.
    Device,
    /// A CLI or app user. Asks the relay for streams to a device.
    Client,
}

/// What the relay does with a stream: splice raw bytes, or proxy HTTP.
/// Whether an http target speaks TLS is detected by the relay, not
/// declared; `Https` remains only so definitions written before that keep
/// parsing, and means the same as `Http`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Http,
    Https,
}

impl Protocol {
    pub fn is_http(self) -> bool {
        matches!(self, Self::Http | Self::Https)
    }
}

impl Protocol {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Self::Tcp),
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }
}

/// First message on the control stream, sent by whoever dialled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub version: u8,
    pub role: Role,
    /// Session this connection is for (reserved by the cloud).
    pub session_id: String,
    /// Doover bearer credential: the device agent's token for `Role::Device`,
    /// a user token for `Role::Client`. Verified by the relay with the Doover API.
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Session id the relay admitted this connection to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// Anything sent on the control stream after the hello exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// Sender is closing the session; peer should tear down and not retry.
    Close { reason: String },
}

/// Head of every data stream. The device compares the target against the
/// claims it received from the cloud and refuses anything else, so a relay
/// cannot redirect a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Open {
    pub target_host: String,
    pub target_port: u16,
    pub protocol: Protocol,
    /// Where the user connection came from, for the device's audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAck {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> Result<(), MsgError> {
    let body = rmp_serde::to_vec_named(msg)?;
    let len = u32::try_from(body.len()).map_err(|_| MsgError::TooLarge(u32::MAX))?;
    if len > MAX_MSG_LEN {
        return Err(MsgError::TooLarge(len));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T, MsgError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len);
    if len > MAX_MSG_LEN {
        return Err(MsgError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok(rmp_serde::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let open = Open {
            target_host: "10.0.0.5".into(),
            target_port: 22,
            protocol: Protocol::Tcp,
            source: Some("1.2.3.4:5555".into()),
        };
        write_msg(&mut a, &open).await.unwrap();
        let got: Open = read_msg(&mut b).await.unwrap();
        assert_eq!(got.target_port, 22);
        assert_eq!(got.protocol, Protocol::Tcp);
        assert_eq!(got.source.as_deref(), Some("1.2.3.4:5555"));
    }

    #[tokio::test]
    async fn rejects_oversized() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&(MAX_MSG_LEN + 1).to_be_bytes()).await.unwrap();
        let err = read_msg::<_, Open>(&mut b).await.unwrap_err();
        assert!(matches!(err, MsgError::TooLarge(_)));
    }
}
