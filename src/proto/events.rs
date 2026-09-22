//! Audit events a relay reports back to the cloud. The relay is the only
//! party that sees every user connection, so it is the source of the
//! per-stream record; the cloud turns these into audit log entries.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayEventKind {
    /// A user connection through the session was accepted and reached the
    /// device. Carries who connected (source IP; user for cli/http).
    StreamOpened,
    /// A user connection through the session ended.
    StreamClosed,
    /// The session ended (expiry, cloud close, device gone, bind failure).
    SessionClosed,
}

impl RelayEventKind {
    /// Audit action string, matching the cloud-side create/close actions.
    pub fn action(self) -> &'static str {
        match self {
            Self::StreamOpened => "tunnel.stream.opened",
            Self::StreamClosed => "tunnel.stream.closed",
            Self::SessionClosed => "tunnel.session.ended",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEvent {
    /// Random, unique per event, so a retried batch is not double-counted.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid: String,
    pub kind: RelayEventKind,
    pub at: u64,
    pub relay_id: String,
    pub session_id: String,
    pub agent_id: String,
    pub tunnel_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub target: String,
    /// Source address of the user connection (stream events).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Authenticated user behind the connection when the leg is authenticated
    /// (cli, http); public TCP has only the source address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed_by: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub duration_secs: u64,
    /// Stream count for session events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Session events: the user who asked the cloud to close it, when the
    /// close was a user action rather than expiry or device loss.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_by: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayEventBatch {
    pub events: Vec<RelayEvent>,
}
