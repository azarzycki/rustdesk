//! End-to-end tests for the built-in SSH tunnel, against SSH servers started inside the test.

use std::{
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use russh::{
    keys::{Algorithm, PrivateKey, PublicKey},
    server::{self, Msg, Server as _, Session, VerifiedPublicKey},
    Channel, ChannelOpenFailure,
};
use librustdesk::ssh_tunnel;
use ssh_tunnel::Hop;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// A minimal SSH server: one authorized key, and forwarding to one loopback port only.
#[derive(Clone)]
struct TestServer {
    authorized: PublicKey,
    allowed_port: u16,
}

impl server::Server for TestServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        if key.public_key.key_data() == self.authorized.key_data() {
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::reject())
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if host_to_connect != "127.0.0.1" || port_to_connect != self.allowed_port as u32 {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        match TcpStream::connect((Ipv4Addr::LOCALHOST, self.allowed_port)).await {
            Ok(mut tcp) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut ssh = channel.into_stream();
                    let _ = copy_bidirectional(&mut tcp, &mut ssh).await;
                });
            }
            Err(_) => reply.reject(ChannelOpenFailure::ConnectFailed).await,
        }
        Ok(())
    }
}

async fn start_ssh_server(authorized: PublicKey, allowed_port: u16) -> u16 {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519).unwrap()],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut server = TestServer {
            authorized,
            allowed_port,
        };
        let _ = server.run_on_socket(config, &listener).await;
    });
    port
}

/// Stands in for the host's loopback remote-control listener: echoes what it receives.
async fn start_echo() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

fn scratch_dir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ssh-tunnel-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn hop(port: u16) -> Hop {
    Hop {
        user: "desk".into(),
        host: "127.0.0.1".into(),
        port,
    }
}

async fn round_trip(local_port: u16, message: &[u8]) -> Vec<u8> {
    let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
        .await
        .unwrap();
    tcp.write_all(message).await.unwrap();
    let mut back = vec![0u8; message.len()];
    tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut back))
        .await
        .expect("no echo within 10 s")
        .unwrap();
    back
}

#[tokio::test]
async fn one_hop_carries_data_and_pins_the_host_key() {
    let dir = scratch_dir();
    let key = Arc::new(ssh_tunnel::load_or_create_key(&dir.join("key"), "test").unwrap());
    let echo = start_echo().await;
    let ssh = start_ssh_server(key.public_key().clone(), echo).await;

    let known_hosts = dir.join("known_hosts");
    let local = ssh_tunnel::open(&[hop(ssh)], key.clone(), &known_hosts, echo)
        .await
        .unwrap();
    assert_eq!(round_trip(local, b"hello through ssh").await, b"hello through ssh");

    let pinned = std::fs::read_to_string(&known_hosts).unwrap();
    assert!(pinned.starts_with(&format!("[127.0.0.1]:{ssh} ssh-ed25519 ")));

    // A second connection reuses the pinned key and still works.
    let local = ssh_tunnel::open(&[hop(ssh)], key, &known_hosts, echo)
        .await
        .unwrap();
    assert_eq!(round_trip(local, b"again").await, b"again");
    assert_eq!(std::fs::read_to_string(&known_hosts).unwrap().lines().count(), 1);
}

#[tokio::test]
async fn two_hops_carry_data() {
    let dir = scratch_dir();
    let key = Arc::new(ssh_tunnel::load_or_create_key(&dir.join("key"), "test").unwrap());
    let echo = start_echo().await;
    let inner = start_ssh_server(key.public_key().clone(), echo).await;
    // The gateway only forwards to the inner SSH server, like the real one.
    let gateway = start_ssh_server(key.public_key().clone(), inner).await;

    let local = ssh_tunnel::open(
        &[hop(gateway), hop(inner)],
        key,
        &dir.join("known_hosts"),
        echo,
    )
    .await
    .unwrap();
    let payload = vec![7u8; 200_000];
    assert_eq!(round_trip(local, &payload).await, payload);
    assert_eq!(
        std::fs::read_to_string(dir.join("known_hosts"))
            .unwrap()
            .lines()
            .count(),
        2
    );
}

#[tokio::test]
async fn an_unauthorized_key_is_refused_and_the_error_shows_the_public_key() {
    let dir = scratch_dir();
    let key = Arc::new(ssh_tunnel::load_or_create_key(&dir.join("key"), "phone").unwrap());
    let someone_else = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519).unwrap();
    let echo = start_echo().await;
    let ssh = start_ssh_server(someone_else.public_key().clone(), echo).await;

    let err = ssh_tunnel::open(&[hop(ssh)], key.clone(), &dir.join("known_hosts"), echo)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("did not accept this device's SSH key"), "{err}");
    assert!(err.contains(&ssh_tunnel::public_key_line(&key)), "{err}");
    assert!(err.contains("ssh-ed25519 "), "{err}");
}

#[tokio::test]
async fn a_changed_host_key_is_refused() {
    let dir = scratch_dir();
    let key = Arc::new(ssh_tunnel::load_or_create_key(&dir.join("key"), "test").unwrap());
    let echo = start_echo().await;
    let ssh = start_ssh_server(key.public_key().clone(), echo).await;

    // Pretend an earlier visit pinned a different key for this server.
    let other = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519).unwrap();
    let other_line = other.public_key().to_openssh().unwrap();
    let known_hosts = dir.join("known_hosts");
    std::fs::write(&known_hosts, format!("[127.0.0.1]:{ssh} {other_line}\n")).unwrap();

    let err = ssh_tunnel::open(&[hop(ssh)], key, &known_hosts, echo)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("has CHANGED"), "{err}");
}

#[tokio::test]
async fn a_forward_the_server_does_not_allow_is_reported() {
    let dir = scratch_dir();
    let key = Arc::new(ssh_tunnel::load_or_create_key(&dir.join("key"), "test").unwrap());
    let echo = start_echo().await;
    let ssh = start_ssh_server(key.public_key().clone(), echo).await;

    let err = ssh_tunnel::open(&[hop(ssh)], key, &dir.join("known_hosts"), echo.wrapping_add(1))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("would not open 127.0.0.1"), "{err}");
}

#[tokio::test]
async fn the_local_port_takes_exactly_one_connection() {
    let dir = scratch_dir();
    let key = Arc::new(ssh_tunnel::load_or_create_key(&dir.join("key"), "test").unwrap());
    let echo = start_echo().await;
    let ssh = start_ssh_server(key.public_key().clone(), echo).await;
    let local = ssh_tunnel::open(&[hop(ssh)], key, &dir.join("known_hosts"), echo)
        .await
        .unwrap();

    let mut first = TcpStream::connect((Ipv4Addr::LOCALHOST, local)).await.unwrap();
    first.write_all(b"x").await.unwrap();
    let mut one = [0u8; 1];
    first.read_exact(&mut one).await.unwrap();

    // The listener is gone once the first connection is taken.
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, local)).await.is_err());
}

#[test]
fn the_key_is_created_once_and_reloaded() {
    let dir = scratch_dir();
    let path = dir.join("key");
    let first = ssh_tunnel::load_or_create_key(&path, "my-device").unwrap();
    let again = ssh_tunnel::load_or_create_key(&path, "ignored").unwrap();
    assert_eq!(first.public_key().key_data(), again.public_key().key_data());
    let public = std::fs::read_to_string(ssh_tunnel::public_key_path(&path)).unwrap();
    assert!(public.starts_with("ssh-ed25519 "));
    assert!(public.trim_end().ends_with("my-device"));
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
}

#[test]
fn addresses_are_parsed_strictly() {
    let hops = ssh_tunnel::parse("ssh:desk@home.example.net:2222").unwrap();
    assert_eq!(
        hops,
        vec![Hop {
            user: "desk".into(),
            host: "home.example.net".into(),
            port: 2222
        }]
    );
    let hops = ssh_tunnel::parse("ssh:desk@home.example.net:2222,andy@10.0.0.193").unwrap();
    assert_eq!(hops.len(), 2);
    assert_eq!((hops[1].host.as_str(), hops[1].port), ("10.0.0.193", 22));
    let hops = ssh_tunnel::parse("ssh:a@[fd00::1]:2200,b@[fd00::2]").unwrap();
    assert_eq!((hops[0].host.as_str(), hops[0].port), ("fd00::1", 2200));
    assert_eq!((hops[1].host.as_str(), hops[1].port), ("fd00::2", 22));
    assert_eq!(hops[0].id(), "[fd00::1]:2200");

    for bad in [
        "desk@home.example.net",
        "ssh:",
        "ssh:home.example.net",
        "ssh:@home.example.net",
        "ssh:desk@",
        "ssh:desk@home.example.net:0",
        "ssh:desk@home.example.net:99999",
        "ssh:desk@home.example.net:22,",
        "ssh:de sk@home.example.net",
        "ssh:desk@home.exa mple.net",
        "ssh:desk@-oProxyCommand=x",
        "ssh:desk@home.example.net/evil",
        "ssh:desk;rm@home.example.net",
        "ssh:a@h,b@h,c@h,d@h,e@h",
    ] {
        assert!(ssh_tunnel::parse(bad).is_err(), "should refuse {bad}");
    }
    assert!(ssh_tunnel::is_tunnel_address("ssh:desk@h"));
    assert!(!ssh_tunnel::is_tunnel_address("127.0.0.1:21118"));
}
