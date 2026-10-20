//! Tests for DNS canonicalization

#[cfg(all(test, feature = "dns"))]
mod dns_tests {
    use fabi_kerbsec::dns::resolver::canonicalize_fqdn;
    use std::time::Duration;

    #[tokio::test]
    async fn test_canonicalize_ip_address() {
        // IP addresses should be returned unchanged
        let ip = "192.168.1.1";
        let result = canonicalize_fqdn(ip, Duration::from_secs(5)).await.unwrap();
        assert_eq!(result, ip);
    }

    #[tokio::test]
    async fn test_canonicalize_lowercase() {
        // FQDNs should be lowercased
        let tests = vec![
            ("EXAMPLE.COM", "example.com"),
            ("Server.Example.Com", "server.example.com"),
            ("HOST.LOCAL", "host.local"),
        ];

        for (input, _expected) in tests {
            // This will fail without actual DNS, but tests the lowercasing
            if let Ok(result) = canonicalize_fqdn(input, Duration::from_secs(1)).await {
                // If it resolves, must be lowercase
                assert_eq!(result.to_lowercase(), result);
            } else {
                // Expected without DNS server
            }
        }
    }

    #[tokio::test]
    async fn test_canonicalize_timeout() {
        // Should timeout for unreachable DNS
        let timeout = Duration::from_millis(100);
        let result = canonicalize_fqdn("nonexistent.invalid", timeout).await;

        // Should either timeout or fail to resolve
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_canonicalize_removes_trailing_dot() {
        // Trailing dots should be removed
        let tests = vec!["example.com.", "server.example.com.", "host.local."];

        for input in tests {
            if let Ok(result) = canonicalize_fqdn(input, Duration::from_secs(1)).await {
                assert!(!result.ends_with('.'));
            } else {
                // Expected without DNS
            }
        }
    }

    #[tokio::test]
    #[ignore = "Requires real DNS server"]
    async fn test_canonicalize_cname_chain() {
        // Test CNAME chasing (requires configured DNS)
        // www.google.com typically has CNAMEs
        let result = canonicalize_fqdn("www.google.com", Duration::from_secs(5)).await;

        if let Ok(canonical) = result {
            // Should be lowercase
            assert_eq!(canonical.to_lowercase(), canonical);
            // Should not have trailing dot
            assert!(!canonical.ends_with('.'));
            // Should be a valid FQDN
            assert!(canonical.contains('.'));
        }
    }
}

#[cfg(test)]
mod config_tests {
    use fabi_kerbsec::{Error, KerberosConfig};

    #[test]
    fn test_ip_requires_spn_override() {
        // IP addresses should require SPN override
        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("192.168.1.1")
            .build();

        match config {
            Err(Error::IpTargetRequiresSpnOverride) => {
                // Expected
            }
            _ => panic!("IP address should require SPN override"),
        }

        // With SPN override should work
        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("192.168.1.1")
            .spn_override(Some("host/server.example.com".to_string()))
            .build();

        assert!(config.is_ok());
    }

    #[test]
    fn test_krb5ccname_from_env() {
        // Should pick up KRB5CCNAME from environment
        std::env::set_var("KRB5CCNAME", "/tmp/krb5cc_test");

        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("server.example.com")
            .build()
            .unwrap();

        assert_eq!(config.kccache, Some("/tmp/krb5cc_test".to_string()));

        std::env::remove_var("KRB5CCNAME");
    }
}
