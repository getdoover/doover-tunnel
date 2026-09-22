//! Tunnel peer library: the wire protocol plus the two peer roles, both
//! over the same yamux-over-WSS session:
//!
//! - [`device`]: dials the relay with the device agent's token for a session
//!   the cloud announced over the agent channel, then serves streams by
//!   dialling the pinned target.
//! - [`client`]: dials the relay with a user token and forwards a local
//!   listener (or programmatic streams) through it.
//!
//! The first stream a dialler opens is the control stream carrying the
//! [`proto::Hello`]; everything after is a data stream.

pub mod client;
pub mod device;
pub mod dial;
pub mod mux;

pub mod proto;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("websocket: {0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("mux: {0}")]
    Mux(#[from] tokio_yamux::error::Error),
    #[error("protocol: {0}")]
    Proto(#[from] proto::MsgError),
    #[error("relay refused: {0}")]
    Refused(String),
    #[error("session closed by relay: {0}")]
    Closed(String),
}

pub type Result<T> = std::result::Result<T, Error>;
