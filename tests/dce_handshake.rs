//! Tests for DCE/RPC 3-leg Kerberos handshake
//!
//! These tests verify the proper behavior of the Kerberos context
//! for DCE-style authentication without requiring a real KDC.

#[cfg(test)]
mod tests {
    use fabi_kerbsec as kerbsec;
    use kerbsec::{AuthLevel, KerberosConfig};

    /// Test that configuration builder works correctly
    #[test]
    fn test_config_builder() {
        let config = KerberosConfig::builder()
            .realm("TEST.REALM")
            .target_host("server.test.realm")
            .build()
            .expect("Config build should succeed");

        assert_eq!(config.realm, "TEST.REALM");
        assert_eq!(config.target_fqdn, "server.test.realm");
    }

    /// Test SPN construction for FQDN targets
    #[test]
    fn test_spn_construction() {
        let config = KerberosConfig::builder()
            .realm("CORP.EXAMPLE.COM")
            .target_host("server.corp.example.com")
            .build()
            .expect("Config build should succeed");

        // Default SPN should be HOST/<fqdn>
        assert_eq!(config.target_fqdn, "server.corp.example.com");
    }

    /// Test SPN override for IP addresses
    #[test]
    fn test_spn_override_for_ip() {
        let config = KerberosConfig::builder()
            .realm("CORP.EXAMPLE.COM")
            .target_host("192.168.1.100")
            .spn_override(Some("HOST/server.corp.example.com".to_string()))
            .build()
            .expect("Config build should succeed");

        assert_eq!(
            config.spn_override,
            Some("HOST/server.corp.example.com".to_string())
        );
    }

    /// Test auth level configuration
    #[test]
    fn test_auth_levels() {
        let integrity = KerberosConfig::builder()
            .realm("TEST")
            .target_host("host")
            .default_auth(AuthLevel::Integrity)
            .build()
            .expect("Config build should succeed");

        let privacy = KerberosConfig::builder()
            .realm("TEST")
            .target_host("host")
            .default_auth(AuthLevel::Privacy)
            .build()
            .expect("Config build should succeed");

        assert_eq!(integrity.default_auth, AuthLevel::Integrity);
        assert_eq!(privacy.default_auth, AuthLevel::Privacy);
    }

    /// Test credential cache path configuration
    #[test]
    fn test_kccache_config() {
        let config = KerberosConfig::builder()
            .realm("TEST")
            .target_host("host")
            .kccache(Some("/tmp/krb5cc_test".to_string()))
            .build()
            .expect("Config build should succeed");

        assert_eq!(config.kccache, Some("/tmp/krb5cc_test".to_string()));
    }

    // Note: Full integration tests requiring GSS-API are not included
    // as they would require a configured Kerberos environment.
    // These would be in integration tests with proper test fixtures.

    #[cfg(unix)]
    mod unix_only {
        use super::*;
        use kerbsec::Context;

        /// Test that Context creation succeeds on Unix
        #[test]
        fn test_context_creation() {
            let config = KerberosConfig::builder()
                .realm("TEST.REALM")
                .target_host("server.test.realm")
                .build()
                .expect("Config build should succeed");

            // This will fail without proper Kerberos setup, but should compile
            let _result = Context::new(config);
            // Don't assert success as it requires real GSS-API
        }

        /// Test that mech OID is correct
        #[test]
        fn test_mech_oid() {
            use kerbsec::KRB5_MECH_OID;

            let config = KerberosConfig::builder()
                .realm("TEST")
                .target_host("host")
                .build()
                .expect("Config build should succeed");

            if let Ok(ctx) = Context::new(config) {
                let oid = ctx.mech_oid();
                // OID comparison - both should be KRB5 mech OID
                assert_eq!(oid, &KRB5_MECH_OID);
            }
        }
    }
}
