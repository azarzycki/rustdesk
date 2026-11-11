//! Built-in SSH tunnel for the home build.
//!
//! Hosts listen for remote-control sessions on loopback only, so the controller has to arrive
//! through SSH. This module opens that path from inside the app: one SSH hop to the gateway,
//! optional further hops through it, then a `direct-tcpip` channel to the loopback listener on
//! the last machine. The channel is handed to the rest of the client as an ordinary local TCP
//! port that accepts exactly one connection.
//!
//! Address form, typed where a peer ID would go:
//!
//! ```text
//! ssh:user@gateway[:port][,user@host[:port]...]
//! ```
//!
//! Trust: the device has its own Ed25519 key, created on first use. Server host keys are pinned
//! on first contact and a later change is refused.

use std::{
    io::Write,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use hbb_common::{
    anyhow::{anyhow, bail, Context, Result},
    config::Config,
    log, tokio,
};
use russh::{
    client,
    keys::{
        ssh_key::LineEnding, Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg,
        PublicKeyOrCertificate,
    },
};
use tokio::{io::copy_bidirectional, net::TcpListener, time::timeout};

/// The loopback port a home-build host listens on.
pub const REMOTE_PORT: u16 = 21118;

pub const PREFIX: &str = "ssh:";
pub const DEFAULT_SSH_PORT: u16 = 22;
pub const MAX_HOPS: usize = 4;
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub user: String,
    pub host: String,
    pub port: u16,
}

impl Hop {
    /// The name a host key is pinned under.
    pub fn id(&self) -> String {
        format!("[{}]:{}", self.host.to_ascii_lowercase(), self.port)
    }
}

pub fn is_tunnel_address(addr: &str) -> bool {
    addr.starts_with(PREFIX)
}

fn valid_user(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn valid_host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
}

/// Parses `ssh:user@host[:port][,user@host[:port]...]`. IPv6 hosts go in brackets.
pub fn parse(addr: &str) -> Result<Vec<Hop>> {
    let rest = addr
        .strip_prefix(PREFIX)
        .ok_or_else(|| anyhow!("not an ssh: address"))?;
    let mut hops = Vec::new();
    for part in rest.split(',') {
        let (user, host_port) = part
            .split_once('@')
            .ok_or_else(|| anyhow!("each hop must look like user@host[:port]: '{part}'"))?;
        let (host, port) = if let Some(v6) = host_port.strip_prefix('[') {
            let (host, tail) = v6
                .split_once(']')
                .ok_or_else(|| anyhow!("missing ] in '{host_port}'"))?;
            let port = match tail.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| anyhow!("bad port in '{host_port}'"))?,
                None if tail.is_empty() => DEFAULT_SSH_PORT,
                None => bail!("unexpected text after ] in '{host_port}'"),
            };
            (host, port)
        } else {
            match host_port.rsplit_once(':') {
                Some((h, p)) => (
                    h,
                    p.parse().map_err(|_| anyhow!("bad port in '{host_port}'"))?,
                ),
                None => (host_port, DEFAULT_SSH_PORT),
            }
        };
        if !valid_user(user) {
            bail!("bad user name '{user}'");
        }
        if !valid_host(host) || port == 0 {
            bail!("bad host or port in '{host_port}'");
        }
        hops.push(Hop {
            user: user.to_owned(),
            host: host.to_owned(),
            port,
        });
    }
    if hops.len() > MAX_HOPS {
        bail!("too many hops");
    }
    Ok(hops)
}

/// Loads this device's SSH key, creating it (and a `.pub` beside it) on first use.
pub fn load_or_create_key(path: &Path, comment: &str) -> Result<PrivateKey> {
    if path.exists() {
        return russh::keys::load_secret_key(path, None)
            .with_context(|| format!("cannot read the SSH key {}", path.display()));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let mut key = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519)
        .map_err(|e| anyhow!("cannot create an SSH key: {e}"))?;
    key.set_comment(comment);
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow!("cannot encode the SSH key: {e}"))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot write the SSH key {}", path.display()))?;
    file.write_all(pem.as_bytes())?;
    std::fs::write(public_key_path(path), public_key_line(&key) + "\n").ok();
    Ok(key)
}

pub fn public_key_path(private_key_path: &Path) -> PathBuf {
    let mut p = private_key_path.as_os_str().to_owned();
    p.push(".pub");
    p.into()
}

/// The one-line public key to authorize on each SSH server.
pub fn public_key_line(key: &PrivateKey) -> String {
    key.public_key().to_openssh().unwrap_or_default()
}

fn known_key(known_hosts: &Path, id: &str) -> Option<String> {
    let text = std::fs::read_to_string(known_hosts).ok()?;
    text.lines().find_map(|line| {
        let (host, key) = line.split_once(' ')?;
        (host == id).then(|| key.trim().to_owned())
    })
}

fn remember_key(known_hosts: &Path, id: &str, key: &str) -> std::io::Result<()> {
    if let Some(dir) = known_hosts.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(known_hosts)?;
    writeln!(file, "{id} {key}")
}

/// Pins each server's host key on first contact and refuses a different key afterwards.
struct HostCheck {
    id: String,
    known_hosts: PathBuf,
    problem: Arc<Mutex<Option<String>>>,
}

impl client::Handler for HostCheck {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_key else {
            *self.problem.lock().unwrap() = Some(format!(
                "{} presented a certificate, which is not supported",
                self.id
            ));
            return Ok(false);
        };
        // "algorithm base64", without any comment.
        let presented: String = key
            .to_openssh()
            .unwrap_or_default()
            .split(' ')
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        if presented.is_empty() {
            return Ok(false);
        }
        match known_key(&self.known_hosts, &self.id) {
            Some(stored) if stored == presented => Ok(true),
            Some(_) => {
                *self.problem.lock().unwrap() = Some(format!(
                    "The SSH host key of {} has CHANGED (now {}). Refusing to connect. \
                     If the server was reinstalled, delete its line from {}.",
                    self.id,
                    key.fingerprint(HashAlg::Sha256),
                    self.known_hosts.display()
                ));
                Ok(false)
            }
            None => {
                log::info!(
                    "Pinning SSH host key of {}: {}",
                    self.id,
                    key.fingerprint(HashAlg::Sha256)
                );
                if let Err(e) = remember_key(&self.known_hosts, &self.id, &presented) {
                    *self.problem.lock().unwrap() =
                        Some(format!("cannot save the SSH host key of {}: {e}", self.id));
                    return Ok(false);
                }
                Ok(true)
            }
        }
    }
}

/// Opens the hop chain and a channel to `127.0.0.1:target_port` on the last machine.
/// Returns a local loopback port that accepts exactly one connection and carries it there.
/// The tunnel lives as long as that connection.
pub async fn open(
    hops: &[Hop],
    key: Arc<PrivateKey>,
    known_hosts: &Path,
    target_port: u16,
) -> Result<u16> {
    if hops.is_empty() {
        bail!("no SSH hop given");
    }
    let config = Arc::new(client::Config {
        nodelay: true,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let mut sessions: Vec<client::Handle<HostCheck>> = Vec::new();
    for hop in hops {
        let problem = Arc::new(Mutex::new(None));
        let handler = HostCheck {
            id: hop.id(),
            known_hosts: known_hosts.to_owned(),
            problem: problem.clone(),
        };
        let connected = match sessions.last() {
            None => {
                timeout(
                    STEP_TIMEOUT,
                    client::connect(config.clone(), (hop.host.as_str(), hop.port), handler),
                )
                .await
            }
            Some(previous) => {
                let channel = timeout(
                    STEP_TIMEOUT,
                    previous.channel_open_direct_tcpip(
                        hop.host.clone(),
                        hop.port as u32,
                        "127.0.0.1",
                        0,
                    ),
                )
                .await
                .map_err(|_| anyhow!("timed out reaching {} through the previous hop", hop.id()))?
                .map_err(|e| {
                    anyhow!(
                        "the previous SSH server would not connect to {}: {e}",
                        hop.id()
                    )
                })?;
                timeout(
                    STEP_TIMEOUT,
                    client::connect_stream(config.clone(), channel.into_stream(), handler),
                )
                .await
            }
        };
        let mut session = connected
            .map_err(|_| anyhow!("timed out connecting to SSH server {}", hop.id()))?
            .map_err(|e| match problem.lock().unwrap().take() {
                Some(p) => anyhow!(p),
                None => anyhow!("cannot connect to SSH server {}: {e}", hop.id()),
            })?;
        let auth = timeout(
            STEP_TIMEOUT,
            session.authenticate_publickey(
                hop.user.clone(),
                PrivateKeyWithHashAlg::new(key.clone(), None),
            ),
        )
        .await
        .map_err(|_| anyhow!("timed out logging in to {}", hop.id()))?
        .map_err(|e| anyhow!("SSH login to {} failed: {e}", hop.id()))?;
        if !auth.success() {
            bail!(
                "{}@{} did not accept this device's SSH key. Authorize this public key there:\n{}",
                hop.user,
                hop.id(),
                public_key_line(&key)
            );
        }
        sessions.push(session);
    }

    let last = sessions.last().ok_or_else(|| anyhow!("no SSH session"))?;
    let channel = timeout(
        STEP_TIMEOUT,
        last.channel_open_direct_tcpip("127.0.0.1", target_port as u32, "127.0.0.1", 0),
    )
    .await
    .map_err(|_| anyhow!("timed out opening the remote-control port"))?
    .map_err(|e| {
        anyhow!(
            "the SSH server would not open 127.0.0.1:{target_port} ({e}). \
             Is RustDesk running there, and is that forward allowed for this account?"
        )
    })?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _sessions = sessions; // keep every hop alive for the life of the connection
        let accepted = timeout(ACCEPT_TIMEOUT, listener.accept()).await;
        drop(listener); // one connection only
        if let Ok(Ok((mut tcp, _))) = accepted {
            tcp.set_nodelay(true).ok();
            let mut ssh = channel.into_stream();
            let _ = copy_bidirectional(&mut tcp, &mut ssh).await;
        }
    });
    Ok(port)
}

/// This device's SSH private key, in the app's own configuration folder.
pub fn key_path() -> PathBuf {
    Config::path("ssh_tunnel_key")
}

/// Pinned host keys of the SSH servers this device has connected to.
pub fn known_hosts_path() -> PathBuf {
    Config::path("ssh_known_hosts")
}

/// Opens the tunnel described by an `ssh:` address and returns the local port to dial.
/// Every failure is labelled, so the caller can tell an SSH problem from a dropped session
/// and does not retry it automatically.
pub async fn connect(addr: &str) -> Result<u16> {
    connect_inner(addr)
        .await
        .map_err(|e| anyhow!("SSH tunnel: {e:#}"))
}

async fn connect_inner(addr: &str) -> Result<u16> {
    let hops = parse(addr)?;
    let comment = format!("rustdesk-{}", crate::common::hostname());
    let key = Arc::new(load_or_create_key(&key_path(), &comment)?);
    open(&hops, key, &known_hosts_path(), REMOTE_PORT).await
}
