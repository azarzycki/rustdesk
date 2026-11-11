//! Home build policy.
//!
//! This fork is meant for one deployment shape: hosts are reached only through an SSH tunnel
//! to the direct-access listener on loopback. Nothing registers with, or asks anything of, a
//! rendezvous, relay, API, STUN or update server.
//!
//! The option maps filled here are the same ones a vendor-signed `custom.txt` fills in the
//! stock client (see `read_custom_client` in common.rs). Values placed in the override maps
//! cannot be changed from the UI, over local IPC, or by a server "strategy" reply.

use hbb_common::config;

/// Never run the rendezvous registration loop, the NAT test, the STUN probe, the API
/// heartbeat, the LAN discovery listener or the online-status query.
pub const DIRECT_ONLY: bool = true;

/// Refuse every login on a host that has no working 2FA secret, instead of silently
/// falling back to password only.
pub const REQUIRE_2FA: bool = true;

/// Settings the user cannot change.
pub const PINNED: &[(&str, &str)] = &[
    // Keep anything that still asks for a rendezvous or relay server on this machine.
    ("custom-rendezvous-server", "127.0.0.1"),
    ("relay-server", "127.0.0.1"),
    ("allow-websocket", "N"),
    ("allow-insecure-tls-fallback", "N"),
    ("enable-udp-punch", "N"),
    ("enable-ipv6-punch", "N"),
    ("enable-webrtc", "N"),
    // No announcements, no update traffic.
    ("enable-lan-discovery", "N"),
    ("enable-check-update", "N"),
    ("allow-auto-update", "N"),
    // Login: permanent password plus 2FA only. No click approval, no one-time password,
    // no remembered devices, no code sent through a chat bot, no hidden sessions.
    ("approve-mode", "password"),
    ("verification-method", "use-permanent-password"),
    ("allow-numeric-one-time-password", "N"),
    ("enable-trusted-devices", "N"),
    ("bot", ""),
    ("allow-hide-cm", "N"),
    ("allow-remote-config-modification", "N"),
    ("allow-scope-violation-close", "Y"),
];

/// Starting values the owner may change on a host.
pub const DEFAULTS: &[(&str, &str)] = &[
    ("enable-terminal", "N"),
    ("enable-tunnel", "N"),
    ("enable-camera", "N"),
    ("enable-remote-printer", "N"),
    ("enable-remote-restart", "N"),
];

/// Policy switches in the built-in namespace.
const BUILTIN: &[(&str, &str)] = &[
    // No API server at all: no heartbeat, no system-information upload, no audit posts,
    // and therefore no configuration accepted from one.
    ("register-device", "N"),
    ("allow-logon-screen-password", "N"),
    ("allow-deep-link-password", "N"),
    ("allow-deep-link-server-settings", "N"),
];

/// True only for a literal loopback address, with or without a port: `127.0.0.1:21118`,
/// `[::1]:21118`, `127.0.0.1`. Names, IDs and `id@server` forms are all rejected, so a
/// link or a typo can never send this device to a server somebody else chose.
pub fn is_loopback_target(peer: &str) -> bool {
    if let Ok(addr) = peer.parse::<std::net::SocketAddr>() {
        return addr.ip().is_loopback();
    }
    peer.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

pub fn apply() {
    {
        let mut over = config::OVERWRITE_SETTINGS.write().unwrap();
        let mut over_local = config::OVERWRITE_LOCAL_SETTINGS.write().unwrap();
        for (k, v) in PINNED {
            over.insert(k.to_string(), v.to_string());
            over_local.insert(k.to_string(), v.to_string());
        }
        // Windows PCs are hosts: the loopback direct-access listener is their only way in.
        #[cfg(target_os = "windows")]
        over.insert("direct-server".to_owned(), "Y".to_owned());
    }
    {
        let mut defaults = config::DEFAULT_SETTINGS.write().unwrap();
        for (k, v) in DEFAULTS {
            defaults.entry(k.to_string()).or_insert_with(|| v.to_string());
        }
    }
    {
        let mut builtin = config::BUILTIN_SETTINGS.write().unwrap();
        for (k, v) in BUILTIN {
            builtin.insert(k.to_string(), v.to_string());
        }
    }
    // Phones and Macs only ever control. They never listen and never act as a host.
    #[cfg(any(target_os = "macos", target_os = "android", target_os = "ios"))]
    config::HARD_SETTINGS
        .write()
        .unwrap()
        .insert("conn-type".to_owned(), "outgoing".to_owned());
}
