//! Tests for DNS canonicalization

#[cfg(all(test, feature = "dns"))]
mod dns_tests {
    use kerbsec::dns::resolver::canonicalize_fqdn;
    use std::time::Duration;

    #[tokio::test]
    async fn test_canonicalize_ip_address() {
        // IP addresses should be returned unchanged
        let ip = "192.168.1.1";
        let result = canonicalize_fqdn(ip, Duration::from_secs(5)).await.unwrap();
        assert_eq!(result, ip);
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
    #[ignore = "requires public DNS"]
    async fn test_canonicalize_cname_chain() {
        // www.google.com typically has CNAMEs
        let canonical = canonicalize_fqdn("www.google.com", Duration::from_secs(5))
            .await
            .expect("www.google.com should resolve");

        assert_eq!(canonical.to_lowercase(), canonical);
        assert!(!canonical.ends_with('.'));
        assert!(canonical.contains('.'));
    }
}

#[cfg(test)]
mod config_tests {
    use kerbsec::{Error, KerberosConfig};

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
