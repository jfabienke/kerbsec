//! Tests for IOV wrapping and DCE 3-leg handshake ordering that need no KDC
//!
//! The full handshake and message protection are exercised against a real KDC
//! in `tests/e2e_kdc.rs`.

#[cfg(test)]
mod iov_tests {
    use kerbsec::{AuthLevel, Context, Error, KerberosConfig};

    fn context() -> Context {
        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("server.example.com")
            .build()
            .unwrap();
        Context::new(config).unwrap()
    }

    #[test]
    fn test_wrap_unwrap_require_established_context() {
        let mut ctx = context();

        for level in [AuthLevel::Integrity, AuthLevel::Privacy] {
            assert!(matches!(
                ctx.wrap_iov_with(b"test PDU data", level),
                Err(Error::NotEstablished)
            ));
        }
        assert!(matches!(
            ctx.unwrap_iov(b"token"),
            Err(Error::NotEstablished)
        ));
    }

    #[test]
    fn test_wrap_size_limit() {
        let ctx = context();

        // Before establishment there is no mechanism to ask, so a conservative
        // estimate is returned (gss_wrap_size_limit is used once established).
        let max_wrapped = 5840; // DCE/RPC typical fragment size

        // Integrity protection overhead
        let max_msg_integrity = ctx.wrap_size_limit(max_wrapped, false);
        assert!(max_msg_integrity < max_wrapped);
        assert!(max_msg_integrity >= max_wrapped - 32);

        // Privacy protection overhead
        let max_msg_privacy = ctx.wrap_size_limit(max_wrapped, true);
        assert!(max_msg_privacy < max_wrapped);
        assert!(max_msg_privacy >= max_wrapped - 60);
        assert!(max_msg_privacy < max_msg_integrity); // Privacy has more overhead
    }
}

#[cfg(test)]
mod dce_handshake_tests {
    use kerbsec::{Context, Error, KerberosConfig};

    #[test]
    fn test_ap_rep_before_initial_token_is_rejected() {
        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("server.example.com")
            .build()
            .unwrap();
        let mut ctx = Context::new(config).unwrap();

        assert!(matches!(
            ctx.accept_ap_rep(&[0x6F, 0x00]),
            Err(Error::HandshakeState(_))
        ));
        assert!(!ctx.established());
    }

    #[test]
    fn test_context_thread_safety() {
        fn assert_send<T: Send>(_: &T) {}

        // Context should be Send but NOT Sync
        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("server.example.com")
            .build()
            .unwrap();

        let ctx = Context::new(config).unwrap();

        // This should compile - Context is Send
        assert_send(&ctx);

        // !Sync is checked by a compile_fail doctest on `Context`
    }
}

#[cfg(test)]
mod error_mapping_tests {
    use kerbsec::Error;

    #[test]
    fn test_error_display() {
        let err = Error::Gss {
            major: 0x8000_0000,
            minor: 12345,
            text: "Authentication failed".to_string(),
        };

        let display = err.to_string();
        assert!(display.contains("Authentication failed"));
    }
}
