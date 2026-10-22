//! Negative tests for error conditions and security checks
//!
//! These tests verify that kerbsec rejects invalid configuration:
//! - IP address targets without an SPN override
//! - Malformed SPN overrides
//!
//! Message-level negative cases (integrity-only tokens on a Privacy context,
//! handshake misuse) need a real context and live in `tests/e2e_kdc.rs`.

#[cfg(test)]
mod tests {
    use kerbsec::KerberosConfig;

    /// Test that IP address targets without SPN override fail appropriately
    #[test]
    fn test_ip_address_without_spn_override_negative() {
        // IP addresses cannot be used as Kerberos principals directly
        let config = KerberosConfig::builder()
            .realm("CORP.EXAMPLE.COM")
            .target_host("192.168.1.100")
            .build();

        // Should fail because IP address requires SPN override
        assert!(config.is_err());

        // With SPN override, it should succeed
        let config_with_override = KerberosConfig::builder()
            .realm("CORP.EXAMPLE.COM")
            .target_host("192.168.1.100")
            .spn_override(Some("HOST/server.corp.example.com".to_string()))
            .build();

        assert!(config_with_override.is_ok());
        let cfg = config_with_override.unwrap();
        assert_eq!(cfg.target_fqdn, "192.168.1.100");
        assert_eq!(
            cfg.spn_override,
            Some("HOST/server.corp.example.com".to_string())
        );
    }

    /// Test that SPN override validation rejects invalid formats
    #[test]
    fn test_invalid_spn_format() {
        // Test various invalid SPN formats - these should be rejected at build time
        let invalid_spns = vec![
            "",                  // Empty SPN
            "invalid",           // Missing service/host separator
            "/hostname",         // Missing service part
            "SERVICE/",          // Missing hostname part
            "SERVICE//hostname", // Double slash
            "@REALM",            // Missing SPN entirely
        ];

        for invalid_spn in invalid_spns {
            let config = KerberosConfig::builder()
                .realm("TEST.REALM")
                .target_host("host")
                .spn_override(Some(invalid_spn.to_string()))
                .build();

            // SPN validation should reject invalid formats early
            assert!(
                config.is_err(),
                "Expected error for invalid SPN '{invalid_spn}', but got Ok"
            );
        }

        // Test that valid SPNs are accepted
        let valid_spns = vec![
            "HOST/server.example.com",
            "HTTP/web.example.com",
            "service/host",
            "MSSQLSvc/sql.example.com:1433",
        ];

        for valid_spn in valid_spns {
            let config = KerberosConfig::builder()
                .realm("TEST.REALM")
                .target_host("host")
                .spn_override(Some(valid_spn.to_string()))
                .build();

            assert!(
                config.is_ok(),
                "Expected Ok for valid SPN '{}', but got error: {:?}",
                valid_spn,
                config.err()
            );
        }
    }
}
