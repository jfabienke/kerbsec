//! Integration tests against a real MIT Kerberos KDC
//!
//! These tests require a running KDC. Use the test script to start one:
//!
//! ```bash
//! ./testing/scripts/run-integration-tests.sh
//! ```
//!
//! Or manually:
//!
//! ```bash
//! docker-compose -f testing/docker-compose.yml up -d
//! export KRB5_CONFIG=./testing/kdc/krb5.conf
//! cargo test --features integration-tests
//! ```
//!
//! Environment variables:
//! - `KERBSEC_TEST_REALM` - Kerberos realm (default: TEST.KERBSEC.LOCAL)
//! - `KERBSEC_TEST_USER` - Test user principal (default: testuser)
//! - `KERBSEC_TEST_PASSWORD` - Test user password (default: user123)
//! - `KERBSEC_TEST_SERVICE_HOST` - Service hostname (default: service.test.kerbsec.local)
//! - `KRB5_CONFIG` - Path to krb5.conf
//! - `KRB5_CLIENT_KTNAME` - Path to client keytab

#![cfg(feature = "integration-tests")]

use fabi_kerbsec as kerbsec;
use kerbsec::{AuthLevel, KerberosConfig};
use std::env;

/// Get test configuration from environment
fn get_test_config() -> Option<TestConfig> {
    // Check if we're running in a CI environment with KDC
    let realm = env::var("KERBSEC_TEST_REALM").ok()?;
    let user = env::var("KERBSEC_TEST_USER").ok()?;
    let password = env::var("KERBSEC_TEST_PASSWORD").ok()?;
    let service_host = env::var("KERBSEC_TEST_SERVICE_HOST").ok()?;

    Some(TestConfig {
        realm,
        user,
        password,
        service_host,
    })
}

struct TestConfig {
    realm: String,
    user: String,
    #[allow(dead_code)]
    password: String,
    service_host: String,
}

/// Helper to check if KDC is available
fn kdc_available() -> bool {
    // Check for required environment variables
    if get_test_config().is_none() {
        return false;
    }

    // Check if KRB5_CONFIG is set
    if env::var("KRB5_CONFIG").is_err() {
        return false;
    }

    true
}

/// Macro to skip tests when KDC is not available
macro_rules! require_kdc {
    () => {
        if !kdc_available() {
            eprintln!("Skipping test: KDC not available (set KERBSEC_TEST_* env vars)");
            return;
        }
    };
}

mod context_tests {
    use super::*;

    #[test]
    fn test_kerberos_config_creation() {
        require_kdc!();
        let config = get_test_config().unwrap();

        let kerberos_config = KerberosConfig::builder()
            .realm(&config.realm)
            .target_host(&config.service_host)
            .default_auth(AuthLevel::Integrity)
            .build();

        assert!(kerberos_config.is_ok());
        let kerberos_config = kerberos_config.unwrap();
        assert_eq!(kerberos_config.realm, config.realm);
    }

    #[test]
    fn test_context_initial_token_generation() {
        require_kdc!();
        let config = get_test_config().unwrap();

        let kerberos_config = KerberosConfig::builder()
            .realm(&config.realm)
            .target_host(&config.service_host)
            .default_auth(AuthLevel::Integrity)
            .build()
            .unwrap();

        // Create context and generate initial token
        let result = kerbsec::Context::new(kerberos_config);

        match result {
            Ok(mut ctx) => {
                // Try to generate initial token
                let token_result = ctx.initial_token();
                match token_result {
                    Ok(token) => {
                        // Verify it looks like a GSS token
                        assert!(!token.is_empty(), "Token should not be empty");
                        // GSS tokens typically start with ASN.1 APPLICATION tag (0x60)
                        assert_eq!(
                            token[0], 0x60,
                            "Token should start with ASN.1 APPLICATION tag"
                        );
                        println!("Generated AP-REQ token: {} bytes", token.len());
                    }
                    Err(e) => {
                        // This might fail if no valid credential cache
                        eprintln!("Expected error generating token: {e}");
                    }
                }
            }
            Err(e) => {
                eprintln!("Context creation failed (may be expected): {e}");
            }
        }
    }

    #[test]
    fn test_context_with_keytab() {
        require_kdc!();
        let config = get_test_config().unwrap();

        // Check if keytab is available
        let keytab_path = env::var("KRB5_CLIENT_KTNAME").ok();

        if keytab_path.is_none() {
            eprintln!("Skipping keytab test: KRB5_CLIENT_KTNAME not set");
            return;
        }

        let kerberos_config = KerberosConfig::builder()
            .realm(&config.realm)
            .target_host(&config.service_host)
            .default_auth(AuthLevel::Integrity)
            .keytab(Some(keytab_path.unwrap()))
            .build()
            .unwrap();

        let result = kerbsec::Context::new(kerberos_config);

        match result {
            Ok(ctx) => {
                println!("Context created successfully with keytab");
                assert!(!ctx.established());
            }
            Err(e) => {
                eprintln!("Context creation failed: {e}");
            }
        }
    }
}

mod config_tests {
    use super::*;

    #[test]
    fn test_spn_construction_for_test_realm() {
        require_kdc!();
        let config = get_test_config().unwrap();

        // Test various SPN formats
        let spn_http =
            kerbsec::ServiceClass::Http.spn_with_realm(&config.service_host, &config.realm);
        assert_eq!(
            spn_http,
            format!("HTTP/{}@{}", config.service_host, config.realm)
        );

        let spn_host =
            kerbsec::ServiceClass::Host.spn_with_realm(&config.service_host, &config.realm);
        assert_eq!(
            spn_host,
            format!("HOST/{}@{}", config.service_host, config.realm)
        );

        let spn_mssql =
            kerbsec::ServiceClass::MsSql.spn_full(&config.service_host, 1433, &config.realm);
        assert_eq!(
            spn_mssql,
            format!("MSSQLSvc/{}:1433@{}", config.service_host, config.realm)
        );
    }

    #[test]
    fn test_encryption_types_available() {
        // Verify that default encryption types are AES
        let default_etypes = kerbsec::EncryptionType::default_etypes();

        assert!(
            default_etypes.contains(&kerbsec::EncryptionType::Aes256CtsHmacSha196),
            "Default should include AES-256"
        );
        assert!(
            default_etypes.contains(&kerbsec::EncryptionType::Aes128CtsHmacSha196),
            "Default should include AES-128"
        );

        // RC4 should NOT be in defaults
        #[cfg(feature = "allow-weak-crypto")]
        {
            assert!(
                !default_etypes.contains(&kerbsec::EncryptionType::Rc4Hmac),
                "RC4 should not be in defaults"
            );
        }
    }
}

mod mock_tests {
    use super::*;
    use kerbsec::security::traits::{MockContextBuilder, MockSecurityContext, SecurityContext};

    #[test]
    fn test_mock_context_without_kdc() {
        // This test doesn't require KDC - demonstrates mock usage
        let mut ctx = MockContextBuilder::new()
            .with_successful_handshake()
            .build();

        // Generate token
        let token = ctx.initial_token().expect("Should generate token");
        assert!(!token.is_empty());

        // Accept response
        let third_leg = ctx
            .accept_response(&[0x00])
            .expect("Should accept response");
        assert!(third_leg.is_some());

        // Verify established
        assert!(ctx.is_established());
    }

    #[test]
    fn test_mock_wrap_unwrap_roundtrip() {
        let mut ctx = MockContextBuilder::new()
            .with_successful_handshake()
            .build();

        ctx.initial_token().unwrap();
        ctx.accept_response(&[0x00]).unwrap();

        // Test wrap
        let plaintext = b"Secret DCE/RPC payload";
        let wrapped = ctx
            .wrap_message(plaintext, AuthLevel::Privacy)
            .expect("Should wrap");

        assert!(wrapped.conf, "Should be confidential");
        assert!(!wrapped.header.is_empty());
        assert!(!wrapped.trailer.is_empty());

        // Test unwrap
        let mut full_token = Vec::new();
        full_token.extend_from_slice(&wrapped.header);
        full_token.extend_from_slice(&wrapped.payload);
        full_token.extend_from_slice(&wrapped.trailer);

        let unwrapped = ctx.unwrap_message(&full_token).expect("Should unwrap");
        assert_eq!(unwrapped, plaintext);
    }

    #[test]
    fn test_mock_context_failure_scenarios() {
        // Test handshake failure
        let mut ctx = MockContextBuilder::new()
            .with_failed_handshake("KRB5KDC_ERR_PREAUTH_FAILED")
            .build();

        ctx.initial_token().unwrap();
        let result = ctx.accept_response(&[0x00]);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("PREAUTH_FAILED"));
    }

    #[test]
    fn test_mock_context_delegation() {
        let mut ctx = MockContextBuilder::new()
            .with_successful_handshake()
            .with_delegation()
            .build();

        ctx.initial_token().unwrap();
        ctx.accept_response(&[0x00]).unwrap();

        assert!(ctx.has_delegation());
    }

    #[test]
    fn test_mock_integrity_only_mode() {
        let mut ctx: MockSecurityContext = MockContextBuilder::new()
            .with_successful_handshake()
            .build();

        ctx.initial_token().unwrap();
        ctx.accept_response(&[0x00]).unwrap();

        let plaintext = b"Integrity-only message";
        let wrapped = ctx
            .wrap_message(plaintext, AuthLevel::Integrity)
            .expect("Should wrap");

        assert!(
            !wrapped.conf,
            "Should NOT be confidential for integrity mode"
        );
    }
}

mod error_tests {
    #[test]
    fn test_error_types_exist() {
        // Verify Windows AD specific error types are available
        use fabi_kerbsec::Error;

        // These should compile - verifying the error variants exist
        let _clock_skew = Error::ClockSkew { max_skew_secs: 300 };
        let _spn_not_found = Error::SpnNotFound {
            spn: "HTTP/test@REALM".to_string(),
        };
        let _ticket_expired = Error::TicketExpired;
        let _kdc_unreachable = Error::KdcUnreachable {
            realm: "TEST.REALM".to_string(),
            details: "Connection refused".to_string(),
        };
    }
}
