//! The session record. Created by the Doover API, held by the relay (via the
//! reservation), and mirrored on the device from its own tunnel config. No
//! signature: peers prove who they are with their normal Doover credentials
//! and the relay asks the Doover API to verify them.

use serde::{Deserialize, Serialize};

use super::msg::Protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Relay binds a public TCP port; anyone reaching it gets a stream.
    Public,
    /// No port; clients connect over WSS with their own token.
    Cli,
    /// Relay terminates HTTP on a per-session hostname.
    Http,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelSession {
    pub sid: String,
    /// Which relay instance holds it (e.g. `r1`).
    pub relay_id: String,
    pub agent_id: String,
    pub tunnel_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub protocol: Protocol,
    pub mode: Mode,
    /// Public port bound on the relay for `Mode::Public`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    /// Source IPs/CIDRs allowed in public mode; empty means any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_ips: Vec<String>,
    /// User who opened the session, for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Http mode: requests must carry a Doover login cookie for a user with
    /// tunnel permission. False makes the URL open to anyone `allow_ips`
    /// admits.
    #[serde(default = "default_true")]
    pub http_auth: bool,
    /// Http mode: credentials the relay sends to Cockpit's login so the user
    /// skips its login page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_basic_auth: Option<BasicAuth>,
    /// Unix seconds.
    pub exp: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuth")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

fn default_true() -> bool {
    true
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
