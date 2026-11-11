//! Tests for the home build policy. They live in their own test program because the policy
//! writes process-wide settings, which would disturb unrelated unit tests in the library.

use hbb_common::config::{self, Config};
use librustdesk::home_policy::{apply, is_loopback_target, DEFAULTS, PINNED};

#[test]
fn only_literal_loopback_targets_are_accepted() {
    for ok in [
        "127.0.0.1",
        "127.0.0.1:21118",
        "127.5.6.7:1",
        "::1",
        "[::1]",
        "[::1]:21118",
    ] {
        assert!(is_loopback_target(ok), "should accept {ok}");
    }
    for bad in [
        "",
        "123456789",
        "1.1.1.1",
        "10.0.0.193",
        "10.0.0.193:21118",
        "0.0.0.0:21118",
        "[::]:21118",
        "localhost:21118",
        "example.com:21118",
        "123456789@evil.example",
        "127.0.0.1@evil.example",
        "127.0.0.1:21118/r@evil.example",
        "127.0.0.1:21118?key=abc",
    ] {
        assert!(!is_loopback_target(bad), "should refuse {bad}");
    }
}

#[test]
fn policy_pins_win_over_stored_and_default_values() {
    apply();
    for (k, v) in PINNED {
        assert_eq!(&Config::get_option(k), v, "pinned option {k}");
        assert_eq!(
            config::OVERWRITE_SETTINGS
                .read()
                .unwrap()
                .get(*k)
                .map(|x| x.as_str()),
            Some(*v)
        );
    }
    assert_eq!(Config::get_option("approve-mode"), "password");
    assert_eq!(
        hbb_common::password_security::approve_mode(),
        hbb_common::password_security::ApproveMode::Password
    );
    #[cfg(target_os = "windows")]
    assert_eq!(Config::get_option("direct-server"), "Y");
}

#[test]
fn nothing_resolves_to_a_public_rendezvous_or_api_server() {
    apply();
    let servers = Config::get_rendezvous_servers();
    assert!(!servers.is_empty());
    for s in servers {
        assert!(s.starts_with("127.0.0.1"), "rendezvous server {s}");
    }
    assert!(Config::get_rendezvous_server().starts_with("127.0.0.1"));
    assert_eq!(
        config::BUILTIN_SETTINGS
            .read()
            .unwrap()
            .get("register-device")
            .map(|x| x.as_str()),
        Some("N")
    );
    // With device registration off there is no API server to poll or obey.
    assert_eq!(
        librustdesk::common::get_api_server(String::new(), String::new()),
        ""
    );
}

#[test]
fn owner_changeable_defaults_start_off() {
    apply();
    let defaults = config::DEFAULT_SETTINGS.read().unwrap();
    for (k, v) in DEFAULTS {
        assert_eq!(defaults.get(*k).map(|x| x.as_str()), Some(*v), "default {k}");
    }
}
