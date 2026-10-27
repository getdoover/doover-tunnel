//! `doover-tunnel`: the user side of a Doover tunnel session. Shipped as the
//! `doover-tunnel` binary wheel; the `doover` CLI execs it as `doover tunnel`.
//!
//! `open` asks the cloud for a session on a device tunnel. By default that
//! is a private (cli-mode) session: nothing is bound in the cloud, the
//! binary dials the relay with the user's token and forwards a localhost
//! port until Ctrl-C (or the `--ssh` child exits), then closes the session.
//! `--mode public` prints the public address instead. `ssh` is `open --ssh`
//! that also creates the device's SSH tunnel when it has none. `proxy`,
//! `stdio` and `close` are the pieces on their own, for scripting; `device`
//! plays the on-device app for developing against a relay.
//!
//! Devices are named by id or by their control name / display name. Cloud
//! auth is a `~/.doover/config` profile or `--token` / `DOOVER_TOKEN`.

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use doover_tunnel::client::{ClientSession, Target, pipe_stdio};
use doover_tunnel::device::{TokenSource, run_session};
use doover_tunnel::proto::{Mode, Protocol, TunnelSession, now_unix};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

type CliResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn print_json(value: &Value) {
    println!("{}", serde_json::to_string_pretty(value).expect("json"));
}

#[derive(Parser)]
#[command(
    name = "doover-tunnel",
    version,
    about = "Doover tunnel relay user client"
)]
struct Cli {
    #[command(subcommand)]
    cmd: TunnelCmd,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    // rustls needs exactly one crypto provider compiled in or one installed
    // before the first TLS use, which is the wss dial to the relay.
    let _ = rustls::crypto::ring::default_provider().install_default();
    match run(Cli::parse().cmd).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Where the cloud credentials come from. A `~/.doover` profile (as written
/// by `doover login`) is the default; an explicit token overrides it.
#[derive(clap::Args, Debug)]
pub struct AuthArgs {
    /// `~/.doover/config` profile to use.
    #[arg(long, env = "DOOVER_PROFILE", default_value = "default", global = true)]
    profile: String,
    /// Bearer token; overrides the profile.
    #[arg(long, env = "DOOVER_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Data API base URL; overrides the profile's BASE_DATA_URL.
    #[arg(long, env = "DOOVER_DATA_ENDPOINT")]
    api: Option<String>,
    /// Control API base URL; overrides the profile's BASE_URL.
    #[arg(long, env = "DOOVER_CONTROL_ENDPOINT")]
    control_api: Option<String>,
    #[arg(long, env = "DOOVER_ORG_ID")]
    org_id: Option<String>,
}

/// Where the cloud is and how to talk to it.
struct Cloud {
    /// Data API base (tunnels, sessions).
    api: String,
    /// Control API base (devices, device types).
    control: String,
    token: String,
}

impl AuthArgs {
    /// Resolve the cloud endpoints and token, refreshing the profile token
    /// if it has expired, the way pydoover's `ensure_token` does.
    async fn resolve(&self) -> Result<Cloud, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(t) = &self.token {
            return Ok(Cloud {
                api: self
                    .api
                    .clone()
                    .unwrap_or_else(|| profile::DEFAULT_DATA_URL.into()),
                control: self
                    .control_api
                    .clone()
                    .unwrap_or_else(|| profile::DEFAULT_CONTROL_URL.into()),
                token: t.clone(),
            });
        }
        let mut prof = profile::load(&self.profile)?;
        if prof.needs_refresh() {
            prof.refresh().await?;
            prof.save()?;
            eprintln!("refreshed token for profile {}", self.profile);
        }
        Ok(Cloud {
            api: self.api.clone().unwrap_or_else(|| prof.data_url()),
            control: self
                .control_api
                .clone()
                .unwrap_or_else(|| prof.control_url()),
            token: prof
                .token
                .clone()
                .ok_or("profile has no token; run `doover login`")?,
        })
    }
}

mod profile {
    //! Minimal reader/writer for `~/.doover/config` blocks:
    //! `[profile=name]` followed by `KEY=value` lines. Only TOKEN and
    //! TOKEN_EXPIRES are rewritten; everything else is left byte-for-byte.
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    pub const DEFAULT_DATA_URL: &str = "https://data.doover.com/api";
    pub const DEFAULT_CONTROL_URL: &str = "https://api.doover.com";
    const DEFAULT_AUTH_URL: &str = "https://auth.doover.com";
    const EXPIRY_BUFFER_SECS: f64 = 30.0;

    type Err = Box<dyn std::error::Error + Send + Sync>;

    pub struct Profile {
        name: String,
        path: PathBuf,
        fields: BTreeMap<String, String>,
        pub token: Option<String>,
    }

    fn config_path() -> Result<PathBuf, Err> {
        let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
        Ok(PathBuf::from(home).join(".doover").join("config"))
    }

    fn block_bounds(text: &str, name: &str) -> Option<(usize, usize)> {
        let header = format!("[profile={name}]");
        let start = text.find(&header)?;
        let after = start + header.len();
        let end = text[after..]
            .find("\n[")
            .map(|i| after + i)
            .unwrap_or(text.len());
        Some((start, end))
    }

    pub fn load(name: &str) -> Result<Profile, Err> {
        let path = config_path()?;
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: {e}; run `doover login`", path.display()))?;
        let (s, e) = block_bounds(&text, name)
            .ok_or_else(|| format!("no [profile={name}] in {}", path.display()))?;
        let mut fields = BTreeMap::new();
        for line in text[s..e].lines().skip(1) {
            if let Some((k, v)) = line.split_once('=') {
                fields.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        let token = fields.get("TOKEN").filter(|t| !t.is_empty()).cloned();
        Ok(Profile {
            name: name.to_string(),
            path,
            fields,
            token,
        })
    }

    impl Profile {
        fn get(&self, k: &str) -> Option<&str> {
            self.fields
                .get(k)
                .map(String::as_str)
                .filter(|v| !v.is_empty())
        }

        pub fn data_url(&self) -> String {
            self.get("BASE_DATA_URL")
                .unwrap_or(DEFAULT_DATA_URL)
                .trim_end_matches('/')
                .to_string()
        }

        pub fn control_url(&self) -> String {
            self.get("BASE_URL")
                .unwrap_or(DEFAULT_CONTROL_URL)
                .trim_end_matches('/')
                .to_string()
        }

        pub fn needs_refresh(&self) -> bool {
            let Some(_) = self.token else { return true };
            match self
                .get("TOKEN_EXPIRES")
                .and_then(|v| v.parse::<f64>().ok())
            {
                Some(exp) => now() >= exp - EXPIRY_BUFFER_SECS,
                None => false,
            }
        }

        /// Same call pydoover makes: `POST {auth}/oauth2/token` with the
        /// grant in the query string.
        pub async fn refresh(&mut self) -> Result<(), Err> {
            let refresh = self
                .get("REFRESH_TOKEN")
                .ok_or("profile has no refresh token; run `doover login`")?;
            let client_id = self
                .get("AUTH_SERVER_CLIENT_ID")
                .ok_or("profile has no AUTH_SERVER_CLIENT_ID; run `doover login`")?;
            let auth = self
                .get("AUTH_SERVER_URL")
                .unwrap_or(DEFAULT_AUTH_URL)
                .trim_end_matches('/');
            let resp = reqwest::Client::new()
                .post(format!("{auth}/oauth2/token"))
                .query(&[
                    ("grant_type", "refresh_token"),
                    ("access_token", self.token.as_deref().unwrap_or("")),
                    ("refresh_token", refresh),
                    ("client_id", client_id),
                ])
                .send()
                .await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(
                    format!("token refresh failed: {status} {body}; run `doover login`").into(),
                );
            }
            let data: serde_json::Value = resp.json().await?;
            let token = data["access_token"]
                .as_str()
                .ok_or("refresh response has no access_token")?
                .to_string();
            let expires_in = data["expires_in"].as_f64().unwrap_or(3600.0);
            self.fields.insert("TOKEN".into(), token.clone());
            self.fields
                .insert("TOKEN_EXPIRES".into(), format!("{}", now() + expires_in));
            if let Some(rt) = data["refresh_token"].as_str() {
                self.fields.insert("REFRESH_TOKEN".into(), rt.to_string());
            }
            self.token = Some(token);
            Ok(())
        }

        /// Rewrite only this profile's TOKEN / TOKEN_EXPIRES / REFRESH_TOKEN
        /// lines in place.
        pub fn save(&self) -> Result<(), Err> {
            let text = std::fs::read_to_string(&self.path)?;
            let (s, e) = block_bounds(&text, &self.name).ok_or("profile vanished")?;
            let mut block = String::new();
            for line in text[s..e].lines() {
                match line.split_once('=') {
                    Some((k, _))
                        if matches!(k.trim(), "TOKEN" | "TOKEN_EXPIRES" | "REFRESH_TOKEN") =>
                    {
                        block.push_str(&format!(
                            "{}={}\n",
                            k.trim(),
                            self.fields.get(k.trim()).cloned().unwrap_or_default()
                        ));
                    }
                    _ => {
                        block.push_str(line);
                        block.push('\n');
                    }
                }
            }
            let block = block.trim_end_matches('\n');
            let out = format!("{}{}{}", &text[..s], block, &text[e..]);
            std::fs::write(&self.path, out)?;
            Ok(())
        }
    }

    fn now() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }
}

#[derive(clap::Args, Debug)]
pub struct OpenArgs {
    /// Device id, or its name / display name in Doover.
    device: String,
    /// Tunnel name or id as configured on the device. Optional when the
    /// device has exactly one tunnel of the right kind.
    tunnel: Option<String>,
    /// `cli` (default) forwards a localhost port through the relay;
    /// `public` binds a port on the relay and prints the address.
    #[arg(long, default_value = "cli", value_parser = parse_mode)]
    mode: Mode,
    /// Local listen address; port 0 picks a free one.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// Local port to listen on (overrides the port in --listen).
    #[arg(short = 'p', long)]
    port: Option<u16>,
    /// Start ssh through the tunnel; the session closes when it exits.
    /// Picks the device's SSH tunnel, creating one if it has none.
    /// Arguments after `--` are passed to ssh.
    #[arg(long)]
    ssh: bool,
    #[arg(last = true, hide = true)]
    ssh_args: Vec<String>,
    /// Extra source IPs/CIDRs allowed in public mode.
    #[arg(long = "allow-ip")]
    allow_ips: Vec<String>,
    /// Public mode: restrict the port to your own public IP.
    #[arg(long)]
    auto_knock: bool,
    /// Session lifetime in minutes; defaults to the tunnel's timeout.
    #[arg(long, conflicts_with = "ttl_ms")]
    ttl: Option<u64>,
    #[arg(long, hide = true)]
    ttl_ms: Option<u64>,
    #[command(flatten)]
    auth: AuthArgs,
}

#[derive(Subcommand, Debug)]
pub enum TunnelCmd {
    /// Open a tunnel to a device and forward it to localhost until Ctrl-C.
    Open(OpenArgs),
    /// SSH to a device through a private tunnel. Uses the device's SSH
    /// tunnel, creating one (localhost:22, the device type's ssh user) if
    /// it has none. Arguments after `--` are passed to ssh.
    Ssh {
        /// Device id, or its name / display name in Doover.
        device: String,
        /// Tunnel name or id; defaults to the device's SSH tunnel.
        tunnel: Option<String>,
        /// Local port to listen on; default a free one.
        #[arg(short = 'p', long)]
        port: Option<u16>,
        /// Session lifetime in minutes; defaults to the tunnel's timeout.
        #[arg(long)]
        ttl: Option<u64>,
        #[arg(last = true, hide = true)]
        ssh_args: Vec<String>,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Close a session opened with `open`.
    #[command(hide = true)]
    Close {
        agent_id: String,
        tunnel_id: String,
        session_id: String,
        #[arg(long)]
        relay_id: String,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Forward a local port through the relay for an existing session.
    #[command(hide = true)]
    Proxy {
        #[arg(long, env = "TUNNEL_RELAY_URL")]
        relay_url: String,
        #[arg(long)]
        session_id: String,
        /// Target the session was created for, `host:port`.
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "127.0.0.1:2222")]
        listen: SocketAddr,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// One stream on stdin/stdout, for `ssh -o ProxyCommand="doover-tunnel stdio ..."`.
    #[command(hide = true)]
    Stdio {
        #[arg(long, env = "TUNNEL_RELAY_URL")]
        relay_url: String,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        target: String,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Play the device side of a session (development; the tunnels app does
    /// this on devices with the device agent's token).
    #[command(hide = true)]
    Device {
        #[arg(long, env = "TUNNEL_RELAY_URL")]
        relay_url: String,
        #[arg(long)]
        session_id: String,
        #[arg(long, default_value = "agent")]
        agent_id: String,
        #[arg(long, default_value = "tunnel")]
        tunnel_id: String,
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "tcp", value_parser = parse_protocol)]
        protocol: Protocol,
        /// Credential presented to the relay (a device agent token).
        #[arg(long, env = "TUNNEL_DEVICE_TOKEN", hide_env_values = true)]
        token: String,
        #[arg(long, default_value_t = 900_000)]
        ttl_ms: u64,
    },
}

/// Split `ssh` arguments given after `--` into options (which go before the
/// destination) and the remote command (which goes after), the way ssh's
/// own getopt reads them: options stop at the first non-option word.
fn split_ssh_args(args: &[String]) -> (Vec<String>, Vec<String>) {
    // ssh's flags that take a value, from its getopt string.
    const WITH_VALUE: &[char] = &[
        'b', 'c', 'e', 'i', 'l', 'm', 'o', 'p', 'B', 'D', 'E', 'F', 'I', 'J', 'L', 'O', 'P', 'Q',
        'R', 'S', 'w', 'W',
    ];
    let mut opts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let Some(flag) = a.strip_prefix('-').filter(|f| !f.is_empty()) else {
            break;
        };
        opts.push(a.clone());
        i += 1;
        // `-l user` takes the next word; `-luser` does not.
        let mut chars = flag.chars();
        if let (Some(c), None) = (chars.next(), chars.next())
            && WITH_VALUE.contains(&c)
            && i < args.len()
        {
            opts.push(args[i].clone());
            i += 1;
        }
    }
    (opts, args[i..].to_vec())
}

fn parse_target(t: &str) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    let (h, p) = t.rsplit_once(':').ok_or("target must be host:port")?;
    Ok((h.to_string(), p.parse()?))
}

/// A tunnel definition as the device's `tunnels` aggregate holds it.
#[derive(Debug, serde::Deserialize)]
struct TunnelDef {
    #[serde(default)]
    id: String,
    name: String,
    port: u16,
    protocol: Protocol,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

impl TunnelDef {
    fn is_ssh(&self) -> bool {
        match &self.service {
            Some(s) => s == "ssh",
            None => self.protocol == Protocol::Tcp && self.port == 22,
        }
    }

    /// `user@localhost` for an ssh tunnel, or nothing.
    fn ssh_destination(&self) -> Option<String> {
        self.is_ssh().then(|| match &self.username {
            Some(u) if !u.is_empty() => format!("{u}@localhost"),
            _ => "localhost".into(),
        })
    }
}

/// The device id `device` names: itself when numeric, else the device in
/// control whose name or display name is exactly `device`.
async fn resolve_agent(
    client: &reqwest::Client,
    control: &str,
    device: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if !device.is_empty() && device.chars().all(|c| c.is_ascii_digit()) {
        return Ok(device.to_string());
    }
    let resp = client
        .get(format!("{control}/devices/"))
        .query(&[
            ("search", device),
            ("archived", "false"),
            ("per_page", "50"),
        ])
        .send()
        .await?;
    let page = check(resp).await?;
    let results = page["results"].as_array().cloned().unwrap_or_default();
    let name_of = |d: &Value, k: &str| d[k].as_str().unwrap_or_default().to_string();
    let id_of = |d: &Value| match &d["id"] {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let matches: Vec<&Value> = results
        .iter()
        .filter(|d| {
            name_of(d, "name").eq_ignore_ascii_case(device)
                || name_of(d, "display_name").eq_ignore_ascii_case(device)
        })
        .collect();
    let describe = |ds: &[&Value]| {
        ds.iter()
            .take(10)
            .map(|d| {
                format!(
                    "  {} ({}, {})",
                    name_of(d, "display_name"),
                    name_of(d, "name"),
                    id_of(d)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    match matches.as_slice() {
        [d] => Ok(id_of(d)),
        [] if results.is_empty() => Err(format!("no device named \"{device}\"").into()),
        [] => Err(format!(
            "no device named \"{device}\"; did you mean:\n{}",
            describe(&results.iter().collect::<Vec<_>>())
        )
        .into()),
        _ => Err(format!(
            "several devices are named \"{device}\"; use an id:\n{}",
            describe(&matches)
        )
        .into()),
    }
}

/// The device's tunnel definitions, sorted by name.
async fn fetch_tunnels(
    client: &reqwest::Client,
    api: &str,
    agent_id: &str,
) -> Result<Vec<TunnelDef>, Box<dyn std::error::Error + Send + Sync>> {
    let resp = client
        .get(format!(
            "{api}/agents/{agent_id}/channels/tunnels/aggregate"
        ))
        .send()
        .await?;
    let agg = check(resp).await?;
    let entries = agg["data"]["tunnels"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let mut defs: Vec<TunnelDef> = entries
        .into_iter()
        .filter_map(|(id, v)| {
            let mut d: TunnelDef = serde_json::from_value(v).ok()?;
            d.id = id;
            Some(d)
        })
        .collect();
    defs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(defs)
}

fn describe_tunnels(ds: &[TunnelDef]) -> String {
    ds.iter()
        .map(|d| {
            format!(
                "  {} ({}, {} port {})",
                d.name,
                d.id,
                if d.protocol.is_http() { "http" } else { "tcp" },
                d.port
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Pick the tunnel `lookup` names (id or name); without a name, the
/// device's SSH tunnel when `ssh`, else its only tunnel suited to `mode`.
/// `Ok(None)` means the device has no SSH tunnel to pick (and none was
/// named), so the caller may create one.
fn pick_tunnel(
    mut defs: Vec<TunnelDef>,
    agent_id: &str,
    lookup: Option<&str>,
    mode: Mode,
    ssh: bool,
) -> Result<Option<TunnelDef>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(l) = lookup {
        if let Some(i) = defs.iter().position(|d| d.id == l) {
            return Ok(Some(defs.swap_remove(i)));
        }
        let matches: Vec<usize> = defs
            .iter()
            .enumerate()
            .filter(|(_, d)| d.name.eq_ignore_ascii_case(l))
            .map(|(i, _)| i)
            .collect();
        return match matches.as_slice() {
            [i] => Ok(Some(defs.swap_remove(*i))),
            [] => Err(format!(
                "no tunnel \"{l}\" on {agent_id}; it has:\n{}",
                describe_tunnels(&defs)
            )
            .into()),
            _ => Err(format!(
                "several tunnels are named \"{l}\"; use an id:\n{}",
                describe_tunnels(&defs)
            )
            .into()),
        };
    }
    if ssh {
        let candidates: Vec<usize> = defs
            .iter()
            .enumerate()
            .filter(|(_, d)| d.is_ssh())
            .map(|(i, _)| i)
            .collect();
        return match candidates.as_slice() {
            [i] => Ok(Some(defs.swap_remove(*i))),
            [] => Ok(None),
            _ => Err(format!(
                "{agent_id} has several SSH tunnels; name one:\n{}",
                describe_tunnels(&defs)
            )
            .into()),
        };
    }
    if defs.is_empty() {
        return Err(format!("device {agent_id} has no tunnels").into());
    }
    let wanted_http = mode == Mode::Http;
    let candidates: Vec<usize> = defs
        .iter()
        .enumerate()
        .filter(|(_, d)| d.protocol.is_http() == wanted_http)
        .map(|(i, _)| i)
        .collect();
    match candidates.as_slice() {
        [i] => Ok(Some(defs.swap_remove(*i))),
        [] => Err(format!(
            "{agent_id} has no {} tunnel; it has:\n{}",
            if wanted_http { "http" } else { "tcp" },
            describe_tunnels(&defs)
        )
        .into()),
        _ => Err(format!(
            "{agent_id} has several tunnels; name one:\n{}",
            describe_tunnels(&defs)
        )
        .into()),
    }
}

/// The ssh login user the device's type declares (`config.ssh_username`).
async fn device_type_ssh_username(
    client: &reqwest::Client,
    control: &str,
    agent_id: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let resp = client
        .get(format!("{control}/devices/{agent_id}/"))
        .send()
        .await?;
    let device = check(resp).await?;
    Ok(device["type"]["config"]["ssh_username"]
        .as_str()
        .filter(|u| !u.is_empty())
        .map(str::to_string))
}

/// Create the device's SSH tunnel the way the admin's SSH preset does.
async fn create_ssh_tunnel(
    client: &reqwest::Client,
    api: &str,
    agent_id: &str,
    username: Option<&str>,
) -> Result<TunnelDef, Box<dyn std::error::Error + Send + Sync>> {
    let resp = client
        .post(format!("{api}/agents/{agent_id}/tunnels"))
        .json(&json!({
            "name": "SSH",
            "hostname": "localhost",
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
            "username": username,
            "timeout_ms": 30 * 60_000,
        }))
        .send()
        .await?;
    let entry = check(resp).await?;
    let def: TunnelDef = serde_json::from_value(entry)
        .map_err(|e| format!("unexpected tunnel in create response: {e}"))?;
    eprintln!(
        "Created tunnel \"{}\" (localhost:22{}) on {agent_id}.",
        def.name,
        username.map(|u| format!(", user {u}")).unwrap_or_default()
    );
    Ok(def)
}

fn parse_protocol(s: &str) -> Result<Protocol, String> {
    Protocol::parse(s).ok_or_else(|| "tcp|http|https".into())
}
fn parse_mode(s: &str) -> Result<Mode, String> {
    match s {
        "public" => Ok(Mode::Public),
        "cli" => Ok(Mode::Cli),
        "http" => Ok(Mode::Http),
        _ => Err("public|cli|http".into()),
    }
}

fn ctrl_c_token() -> CancellationToken {
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        c.cancel();
    });
    cancel
}

fn api_client(token: &str, org_id: Option<&str>) -> Result<reqwest::Client, reqwest::Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("token header"),
    );
    if let Some(org) = org_id {
        headers.insert("X-Doover-Organisation", org.parse().expect("org header"));
    }
    reqwest::Client::builder().default_headers(headers).build()
}

async fn check(resp: reqwest::Response) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(format!("{status}: {body}").into());
    }
    Ok(if body.is_empty() {
        json!({})
    } else {
        serde_json::from_str(&body)?
    })
}

pub async fn run(cmd: TunnelCmd) -> CliResult {
    match cmd {
        TunnelCmd::Open(args) => open(args).await?,
        TunnelCmd::Ssh {
            device,
            tunnel,
            port,
            ttl,
            ssh_args,
            auth,
        } => {
            open(OpenArgs {
                device,
                tunnel,
                mode: Mode::Cli,
                listen: "127.0.0.1:0".parse().expect("listen addr"),
                port,
                ssh: true,
                ssh_args,
                allow_ips: vec![],
                auto_knock: false,
                ttl,
                ttl_ms: None,
                auth,
            })
            .await?
        }
        TunnelCmd::Close {
            agent_id,
            tunnel_id,
            session_id,
            relay_id,
            auth,
        } => {
            let Cloud { api, token, .. } = auth.resolve().await?;
            let client = api_client(&token, auth.org_id.as_deref())?;
            let resp = client
                .delete(format!(
                    "{api}/agents/{agent_id}/tunnels/{tunnel_id}/sessions/{session_id}"
                ))
                .query(&[("relay_id", relay_id)])
                .send()
                .await?;
            check(resp).await?;
            print_json(&json!({ "closed": session_id }));
        }
        TunnelCmd::Proxy {
            relay_url,
            session_id,
            target,
            listen,
            auth,
        } => {
            let Cloud { token, .. } = auth.resolve().await?;
            let (host, port) = parse_target(&target)?;
            let s = ClientSession::connect(
                &relay_url,
                &session_id,
                &token,
                Target {
                    host,
                    port,
                    protocol: Protocol::Tcp,
                },
            )
            .await?;
            s.serve_local(listen, ctrl_c_token()).await?;
        }
        TunnelCmd::Stdio {
            relay_url,
            session_id,
            target,
            auth,
        } => {
            let Cloud { token, .. } = auth.resolve().await?;
            let (host, port) = parse_target(&target)?;
            pipe_stdio(
                &relay_url,
                &session_id,
                &token,
                Target {
                    host,
                    port,
                    protocol: Protocol::Tcp,
                },
            )
            .await?;
        }
        TunnelCmd::Device {
            relay_url,
            session_id,
            agent_id,
            tunnel_id,
            target,
            protocol,
            token,
            ttl_ms,
        } => {
            let (host, port) = parse_target(&target)?;
            let record = TunnelSession {
                sid: session_id,
                relay_id: "r1".into(),
                agent_id,
                tunnel_id,
                target_host: host,
                target_port: port,
                protocol,
                mode: Mode::Public,
                public_port: None,
                allow_ips: vec![],
                user_id: None,
                http_auth: true,
                http_basic_auth: None,
                exp: now_unix() + ttl_ms.div_ceil(1000),
            };
            struct Fixed(String);
            impl TokenSource for Fixed {
                fn token(&self) -> Result<String, String> {
                    Ok(self.0.clone())
                }
            }
            let stats = run_session(&relay_url, &record, &Fixed(token), ctrl_c_token()).await?;
            eprintln!("session ended: {stats:?}");
        }
    }
    Ok(())
}

async fn open(args: OpenArgs) -> CliResult {
    let OpenArgs {
        device,
        tunnel,
        mode,
        listen,
        port,
        ssh,
        ssh_args,
        allow_ips,
        auto_knock,
        ttl,
        ttl_ms,
        auth,
    } = args;
    let Cloud {
        api,
        control,
        token,
    } = auth.resolve().await?;
    let client = api_client(&token, auth.org_id.as_deref())?;
    let agent_id = resolve_agent(&client, &control, &device).await?;
    let defs = fetch_tunnels(&client, &api, &agent_id).await?;
    let def = match pick_tunnel(defs, &agent_id, tunnel.as_deref(), mode, ssh)? {
        Some(def) => def,
        None => {
            let user = device_type_ssh_username(&client, &control, &agent_id).await?;
            create_ssh_tunnel(&client, &api, &agent_id, user.as_deref()).await?
        }
    };
    let tunnel_id = def.id.clone();
    let ttl_ms = ttl.map(|m| m * 60_000).or(ttl_ms);
    let resp = client
        .post(format!(
            "{api}/agents/{agent_id}/tunnels/{tunnel_id}/sessions"
        ))
        .json(&json!({
            "mode": mode,
            "allow_ips": allow_ips,
            "auto_knock": auto_knock,
            "ttl_ms": ttl_ms,
        }))
        .send()
        .await?;
    let session = check(resp).await?;
    if mode != Mode::Cli {
        print_json(&session);
        return Ok(());
    }
    let relay_url = session["client_ws_url"]
        .as_str()
        .ok_or("response has no client_ws_url")?;
    let sid = session["session_id"]
        .as_str()
        .ok_or("response has no session_id")?
        .to_string();
    let relay_id = session["relay_id"].as_str().unwrap_or_default().to_string();
    let target = Target {
        host: session["target_host"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        port: session["target_port"].as_u64().unwrap_or_default() as u16,
        protocol: serde_json::from_value(session["protocol"].clone()).unwrap_or(Protocol::Tcp),
    };
    let close = || async {
        let r = client
            .delete(format!(
                "{api}/agents/{agent_id}/tunnels/{tunnel_id}/sessions/{sid}"
            ))
            .query(&[("relay_id", relay_id.as_str())])
            .send()
            .await;
        match r {
            Ok(resp) if resp.status().is_success() => eprintln!("session closed"),
            Ok(resp) => eprintln!("could not close session: {}", resp.status()),
            Err(e) => eprintln!("could not close session: {e}"),
        }
    };

    let mut listen = listen;
    if let Some(p) = port {
        listen.set_port(p);
    }
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            close().await;
            return Err(format!("cannot listen on {listen}: {e}").into());
        }
    };
    let local = listener.local_addr()?;
    let s = match ClientSession::connect(relay_url, &sid, &token, target).await {
        Ok(s) => s,
        Err(e) => {
            close().await;
            return Err(e.into());
        }
    };

    let ssh_dest = def.ssh_destination();
    let ssh_line = ssh_dest
        .as_ref()
        .map(|dest| format!("ssh -p {} {dest}", local.port()));
    let expires = session["expires_at"]
        .as_u64()
        .map(|ms| (ms / 1000).saturating_sub(now_unix()) / 60);
    eprintln!(
        "Tunnel \"{}\" on {agent_id} is open at {local}{}. Ctrl-C closes it.",
        def.name,
        expires.map(|m| format!(" for {m} min")).unwrap_or_default()
    );
    if let (Some(line), false) = (&ssh_line, ssh) {
        eprintln!("  {line}");
    }

    let cancel = ctrl_c_token();
    let served = {
        let cancel = cancel.clone();
        async { s.serve_listener(listener, cancel).await }
    };
    let mut ssh_exit: Option<i32> = None;
    let result = if ssh {
        let dest = ssh_dest.unwrap_or_else(|| "localhost".into());
        let (opts, command) = split_ssh_args(&ssh_args);
        let mut cmd = tokio::process::Command::new("ssh");
        cmd.arg("-p").arg(local.port().to_string());
        // The host key is the device's; localhost's known_hosts entry
        // would collide across devices and ports.
        cmd.args(["-o", &format!("HostKeyAlias={agent_id}")]);
        cmd.args(opts).arg(&dest).args(command);
        tokio::select! {
            r = served => r.map(|_| ()),
            status = cmd.status() => {
                cancel.cancel();
                match status {
                    Ok(st) => {
                        ssh_exit = st.code().or(Some(1));
                        Ok(())
                    }
                    Err(e) => Err(doover_tunnel::Error::Closed(format!("cannot start ssh: {e}"))),
                }
            }
        }
    } else {
        served.await
    };
    s.close().await;
    close().await;
    result?;
    if let Some(code) = ssh_exit.filter(|c| *c != 0) {
        std::process::exit(code);
    }
    Ok(())
}
