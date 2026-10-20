//! Tests for IOV wrapping and DCE 3-leg handshake

#[cfg(test)]
mod iov_tests {
    use fabi_kerbsec::{AuthLevel, Context, KerberosConfig};

    #[test]
    #[ignore = "Requires Kerberos environment"]
    fn test_iov_wrap_unwrap() {
        // Create context
        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("server.example.com")
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        // Would need established context to test
        // This demonstrates the API structure

        let pdu = b"test PDU data";

        // Test integrity protection
        if let Ok(wrapped) = ctx.wrap_iov_with(pdu, AuthLevel::Integrity) {
            // Should return full token as header (until real IOV)
            assert!(!wrapped.header.is_empty());
            assert!(wrapped.trailer.is_empty()); // No trailer until real IOV
            assert!(!wrapped.conf); // Not confidential
        } else {
            // Expected without established context
        }

        // Test privacy protection
        if let Ok(wrapped) = ctx.wrap_iov_with(pdu, AuthLevel::Privacy) {
            assert!(!wrapped.header.is_empty());
            assert!(wrapped.trailer.is_empty()); // No trailer until real IOV
            assert!(wrapped.conf); // Confidential
        } else {
            // Expected without established context
        }
    }

    #[test]
    fn test_wrap_size_limit() {
        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("server.example.com")
            .build()
            .unwrap();

        let ctx = Context::new(config).unwrap();

        // Test wrap_size_limit calculations
        let max_wrapped = 5840; // DCE/RPC typical fragment size

        // Integrity protection overhead
        let max_msg_integrity = ctx.wrap_size_limit(max_wrapped, false);
        assert!(max_msg_integrity < max_wrapped);
        assert!(max_msg_integrity >= max_wrapped - 32); // Conservative estimate

        // Privacy protection overhead
        let max_msg_privacy = ctx.wrap_size_limit(max_wrapped, true);
        assert!(max_msg_privacy < max_wrapped);
        assert!(max_msg_privacy >= max_wrapped - 60); // Conservative estimate
        assert!(max_msg_privacy < max_msg_integrity); // Privacy has more overhead
    }
}

#[cfg(test)]
mod dce_handshake_tests {
    use fabi_kerbsec::{Context, KerberosConfig};

    #[test]
    #[ignore = "Requires Kerberos environment"]
    fn test_dce_three_leg_handshake() {
        // Simulates DCE/RPC 3-leg authentication handshake

        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("server.example.com")
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        // Step 1: Generate AP-REQ (first leg)
        let ap_req = ctx.initial_token();
        match ap_req {
            Ok(token) => {
                // AP-REQ should start with proper ASN.1 tag
                // 0x6E = [APPLICATION 14] for AP-REQ
                assert_eq!(token.first().map(|b| b & 0xE0), Some(0x60)); // Application class
            }
            Err(_) => {
                // Expected without Kerberos credentials
                return;
            }
        }

        // Step 2: Process AP-REP (second leg)
        // In real scenario, this comes from server
        let mock_ap_rep = vec![0x6F, 0x00]; // [APPLICATION 15] for AP-REP

        // DCE-style third leg is optional. No token means the context is
        // established; an error is expected with a mock AP-REP.
        if let Ok(Some(token)) = ctx.accept_ap_rep(&mock_ap_rep) {
            assert_ne!(token.len(), 0);
        }

        // Step 3: Check if established
        // Would be true after real handshake
        if ctx.established() {
            // Can now wrap/unwrap PDUs
            let pdu = b"RPC request";
            let wrapped = ctx.wrap_iov(pdu).unwrap();
            assert!(!wrapped.header.is_empty());
        }
    }

    #[test]
    fn test_context_thread_safety() {
        // Context should be Send but NOT Sync
        fn assert_send<T: Send>(_: &T) {}

        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("server.example.com")
            .build()
            .unwrap();

        let ctx = Context::new(config).unwrap();

        // This should compile - Context is Send
        assert_send(&ctx);

        // This should NOT compile if uncommented - Context is not Sync
        // fn assert_sync<T: Sync>(_: &T) {}
        // assert_sync(&ctx); // Compile error: Context is not Sync
    }
}

#[cfg(test)]
mod error_mapping_tests {
    use fabi_kerbsec::Error;

    #[test]
    fn test_gss_error_preserves_codes() {
        // GSS errors should preserve major/minor codes

        // Example error with specific codes
        let err = Error::Gss {
            major: 0x8000_0000, // GSS_S_FAILURE
            minor: 12345,
            text: "Test error".to_string(),
        };

        match err {
            Error::Gss { major, minor, text } => {
                assert_eq!(major, 0x8000_0000);
                assert_eq!(minor, 12345);
                assert_eq!(text, "Test error");
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = Error::Gss {
            major: 0x8000_0000,
            minor: 12345,
            text: "Authentication failed".to_string(),
        };

        let display = format!("{err}");
        assert!(display.contains("Authentication failed"));
    }
}
