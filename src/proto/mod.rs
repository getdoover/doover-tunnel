//! Wire protocol between the Doover tunnel relay and its peers.
//!
//! Stack, bottom up: TLS → WebSocket binary frames → yamux →
//! streams. Stream 0 is the control stream (hello/ack, close reason); every
//! other stream carries one user TCP connection, prefixed by an [`Open`]
//! message and its [`OpenAck`], after which it is raw bytes.
//!
//! Peers authenticate with their normal Doover credentials: the device with
//! the device agent's token, a CLI user with their own bearer token. The
//! relay asks the Doover API to verify the token against the session's agent.
//! The device checks every stream's target against its own tunnel config.

pub mod events;
pub mod msg;
pub mod session;
pub mod ws;

pub use events::*;
pub use msg::*;
pub use session::*;

/// Bumped on any incompatible change to the control or open messages.
pub const PROTOCOL_VERSION: u8 = 1;

/// Yamux config shared by every peer. Small stream count so a runaway
/// browser or a port scanner can't exhaust the device.
pub fn yamux_config() -> tokio_yamux::Config {
    tokio_yamux::Config {
        max_stream_count: 64,
        enable_keepalive: true,
        keepalive_interval: std::time::Duration::from_secs(30),
        ..Default::default()
    }
}
