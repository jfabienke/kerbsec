//! Tests for DCE-style and delegation configuration flags

use fabi_kerbsec::{AuthLevel, KerberosConfig};

#[test]
fn test_dce_style_default_enabled() {
    // DCE-style should be enabled by default for DCE/RPC compatibility
    let config = KerberosConfig::builder()
        .realm("TEST.REALM")
        .target_host("test.example.com")
        .build()
        .unwrap();

    assert!(config.enable_dce_style);
}

#[test]
fn test_dce_style_can_be_disabled() {
    let config = KerberosConfig::builder()
        .realm("TEST.REALM")
        .target_host("test.example.com")
        .dce_style(false)
        .build()
        .unwrap();

    assert!(!config.enable_dce_style);
}

#[test]
fn test_delegation_default_disabled() {
    // Delegation should be disabled by default for security
    let config = KerberosConfig::builder()
        .realm("TEST.REALM")
        .target_host("test.example.com")
        .build()
        .unwrap();

    assert!(!config.enable_delegation);
}

#[test]
fn test_delegation_can_be_enabled() {
    let config = KerberosConfig::builder()
        .realm("TEST.REALM")
        .target_host("test.example.com")
        .delegation(true)
        .build()
        .unwrap();

    assert!(config.enable_delegation);
}

#[test]
fn test_mutual_auth_default_enabled() {
    // Mutual authentication should be enabled by default for security
    let config = KerberosConfig::builder()
        .realm("TEST.REALM")
        .target_host("test.example.com")
        .build()
        .unwrap();

    assert!(config.require_mutual_auth);
}

#[test]
fn test_mutual_auth_can_be_disabled() {
    let config = KerberosConfig::builder()
        .realm("TEST.REALM")
        .target_host("test.example.com")
        .mutual_auth(false)
        .build()
        .unwrap();

    assert!(!config.require_mutual_auth);
}

#[test]
fn test_all_flags_combination() {
    let config = KerberosConfig::builder()
        .realm("TEST.REALM")
        .target_host("test.example.com")
        .default_auth(AuthLevel::Privacy)
        .dce_style(true)
        .delegation(true)
        .mutual_auth(true)
        .build()
        .unwrap();

    assert!(config.enable_dce_style);
    assert!(config.enable_delegation);
    assert!(config.require_mutual_auth);
    assert!(matches!(config.default_auth, AuthLevel::Privacy));
}

#[test]
fn test_builder_defaults_match_impl_default() {
    use std::time::Duration;

    let builder = KerberosConfig::builder();

    // These values are set in impl Default for KerberosConfigBuilder
    let config = builder
        .realm("TEST.REALM")
        .target_host("test.example.com")
        .build()
        .unwrap();

    assert!(config.enable_dce_style);
    assert!(!config.enable_delegation);
    assert!(config.require_mutual_auth);
    assert!(matches!(config.default_auth, AuthLevel::Privacy));
    assert_eq!(config.dns_timeout, Duration::from_secs(5));
    assert_eq!(config.gss_timeout, Duration::from_secs(30));
}
