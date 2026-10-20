//! Trait abstractions for GSS-API operations
//!
//! This module provides trait-based abstractions over GSS-API operations,
//! enabling:
//!
//! 1. **Unit testing** - Mock implementations that don't require a real KDC
//! 2. **Integration testing** - Test against real Kerberos infrastructure
//! 3. **Flexibility** - Swap implementations at runtime or compile time
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Application Code                        │
//! │                         uses                                │
//! │                    SecurityContext trait                    │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!              ┌───────────────┼───────────────┐
//!              ▼               ▼               ▼
//!     ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
//!     │ GssContext  │  │ MockContext │  │  Custom     │
//!     │   (real)    │  │   (test)    │  │ (user impl) │
//!     └─────────────┘  └─────────────┘  └─────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use kerbsec::security::traits::{SecurityContextFactory, MockSecurityContextFactory};
//!
//! // In production
//! let factory = GssSecurityContextFactory::new();
//! let ctx = factory.create_context(config)?;
//!
//! // In tests
//! let factory = MockSecurityContextFactory::new()
//!     .with_successful_handshake()
//!     .with_wrap_unwrap_passthrough();
//! let ctx = factory.create_context(config)?;
//! ```

use crate::config::{AuthLevel, KerberosConfig};
use crate::error::Result;
use crate::security::IovWrap;
#[cfg(any(test, feature = "mock"))]
use bytes::Bytes;

/// Trait for GSS-API security context operations
///
/// This trait abstracts the core operations needed for Kerberos authentication
/// and message protection in DCE/RPC.
pub trait SecurityContext: Send {
    /// Generate the initial authentication token (AP-REQ)
    ///
    /// This is the first step in the GSS-API handshake.
    fn initial_token(&mut self) -> Result<Vec<u8>>;

    /// Process the server's response (AP-REP) and optionally return a final token
    ///
    /// This is the second/third step in DCE/RPC 3-leg authentication.
    fn accept_response(&mut self, response: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Check if the security context is fully established
    fn is_established(&self) -> bool;

    /// Wrap (sign/encrypt) a message using IOV semantics
    ///
    /// Returns header, payload, and trailer separately for DCE/RPC framing.
    fn wrap_message(&mut self, data: &[u8], level: AuthLevel) -> Result<IovWrap>;

    /// Unwrap (verify/decrypt) a message
    fn unwrap_message(&mut self, token: &[u8]) -> Result<Vec<u8>>;

    /// Check if delegation was negotiated
    fn has_delegation(&self) -> bool;

    /// Get the session key (if available)
    fn session_key(&self) -> Option<Vec<u8>>;
}

/// Factory trait for creating security contexts
///
/// This abstraction allows swapping the context implementation at runtime,
/// useful for testing and dependency injection.
pub trait SecurityContextFactory: Send + Sync {
    /// The type of context this factory creates
    type Context: SecurityContext;

    /// Create a new security context with the given configuration
    fn create_context(&self, config: KerberosConfig) -> Result<Self::Context>;
}

/// Mock security context for unit testing
///
/// This implementation simulates GSS-API operations without requiring
/// a real KDC. It can be configured to:
///
/// - Succeed or fail at specific points in the handshake
/// - Return predetermined tokens
/// - Simulate various error conditions
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "mock"))]
pub struct MockSecurityContext {
    config: MockContextConfig,
    state: MockContextState,
    call_count: MockCallCount,
}

#[derive(Debug, Clone, Default)]
#[cfg(any(test, feature = "mock"))]
struct MockCallCount {
    initial_token: usize,
    accept_response: usize,
    wrap_message: usize,
    unwrap_message: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(test, feature = "mock"))]
enum MockContextState {
    New,
    TokenSent,
    Established,
    Failed,
}

/// Configuration for mock context behavior
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "mock"))]
pub struct MockContextConfig {
    /// Token to return from `initial_token()`
    pub initial_token: Vec<u8>,

    /// Token to return from `accept_response()` (None = no third leg)
    pub third_leg_token: Option<Vec<u8>>,

    /// Whether handshake should succeed
    pub handshake_succeeds: bool,

    /// Error to return on handshake failure
    pub handshake_error: Option<String>,

    /// Whether delegation is available
    pub delegation_available: bool,

    /// Session key to return
    pub session_key: Option<Vec<u8>>,

    /// Whether wrap/unwrap should pass through data unchanged
    pub wrap_passthrough: bool,

    /// Fixed header for wrap operations
    pub wrap_header: Vec<u8>,

    /// Fixed trailer for wrap operations
    pub wrap_trailer: Vec<u8>,

    /// Error to inject on wrap
    pub wrap_error: Option<String>,

    /// Error to inject on unwrap
    pub unwrap_error: Option<String>,
}

#[cfg(any(test, feature = "mock"))]
impl Default for MockContextConfig {
    fn default() -> Self {
        Self {
            // Default AP-REQ token (fake but recognizable)
            initial_token: vec![
                0x60, 0x82, // ASN.1 APPLICATION tag
                0x00, 0x10, // length
                0x06, 0x09, // OID tag
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, // Kerberos OID
                0x01, 0x00, // token type (AP-REQ)
                0xDE, 0xAD, 0xBE, 0xEF, // mock data
            ],
            third_leg_token: Some(vec![0x00]), // Empty third leg
            handshake_succeeds: true,
            handshake_error: None,
            delegation_available: false,
            session_key: Some(vec![0x42; 32]), // 256-bit mock key
            wrap_passthrough: true,
            wrap_header: vec![0x60, 0x00, 0x00, 0x00], // Mock GSS header
            wrap_trailer: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Mock checksum
            wrap_error: None,
            unwrap_error: None,
        }
    }
}

#[cfg(any(test, feature = "mock"))]
impl MockSecurityContext {
    /// Create a new mock context with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(MockContextConfig::default())
    }

    /// Create a mock context with custom configuration
    #[must_use]
    pub fn with_config(config: MockContextConfig) -> Self {
        Self {
            config,
            state: MockContextState::New,
            call_count: MockCallCount::default(),
        }
    }

    /// Get the number of times each method was called
    #[must_use]
    pub const fn call_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.call_count.initial_token,
            self.call_count.accept_response,
            self.call_count.wrap_message,
            self.call_count.unwrap_message,
        )
    }
}

#[cfg(any(test, feature = "mock"))]
impl Default for MockSecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "mock"))]
impl SecurityContext for MockSecurityContext {
    fn initial_token(&mut self) -> Result<Vec<u8>> {
        self.call_count.initial_token += 1;

        if self.state != MockContextState::New {
            return Err(crate::error::Error::Protocol(
                "initial_token called in wrong state".into(),
            ));
        }

        self.state = MockContextState::TokenSent;
        Ok(self.config.initial_token.clone())
    }

    fn accept_response(&mut self, _response: &[u8]) -> Result<Option<Vec<u8>>> {
        self.call_count.accept_response += 1;

        if self.state != MockContextState::TokenSent {
            return Err(crate::error::Error::Protocol(
                "accept_response called in wrong state".into(),
            ));
        }

        if !self.config.handshake_succeeds {
            self.state = MockContextState::Failed;
            return Err(crate::error::Error::Gss {
                major: 0x000D_0000, // GSS_S_FAILURE
                minor: 0,
                text: self
                    .config
                    .handshake_error
                    .clone()
                    .unwrap_or_else(|| "Mock handshake failure".into()),
            });
        }

        self.state = MockContextState::Established;
        Ok(self.config.third_leg_token.clone())
    }

    fn is_established(&self) -> bool {
        self.state == MockContextState::Established
    }

    fn wrap_message(&mut self, data: &[u8], level: AuthLevel) -> Result<IovWrap> {
        self.call_count.wrap_message += 1;

        if self.state != MockContextState::Established {
            return Err(crate::error::Error::NotEstablished);
        }

        if let Some(ref error) = self.config.wrap_error {
            return Err(crate::error::Error::Gss {
                major: 0x000D_0000,
                minor: 0,
                text: error.clone(),
            });
        }

        let conf = matches!(level, AuthLevel::Privacy);

        if self.config.wrap_passthrough {
            // In passthrough mode, return data unchanged with mock header/trailer
            Ok(IovWrap {
                header: Bytes::from(self.config.wrap_header.clone()),
                payload: Bytes::copy_from_slice(data),
                trailer: Bytes::from(self.config.wrap_trailer.clone()),
                conf,
            })
        } else {
            // Simulate encryption by XORing with 0x42
            let encrypted: Vec<u8> = data.iter().map(|b| b ^ 0x42).collect();
            Ok(IovWrap {
                header: Bytes::from(self.config.wrap_header.clone()),
                payload: Bytes::from(encrypted),
                trailer: Bytes::from(self.config.wrap_trailer.clone()),
                conf,
            })
        }
    }

    fn unwrap_message(&mut self, token: &[u8]) -> Result<Vec<u8>> {
        self.call_count.unwrap_message += 1;

        if self.state != MockContextState::Established {
            return Err(crate::error::Error::NotEstablished);
        }

        if let Some(ref error) = self.config.unwrap_error {
            return Err(crate::error::Error::Gss {
                major: 0x000D_0000,
                minor: 0,
                text: error.clone(),
            });
        }

        // Extract payload from header and trailer
        let header_len = self.config.wrap_header.len();
        let trailer_len = self.config.wrap_trailer.len();

        if token.len() < header_len + trailer_len {
            return Err(crate::error::Error::TokenShape);
        }

        let payload = &token[header_len..token.len() - trailer_len];

        if self.config.wrap_passthrough {
            // In passthrough mode, return payload unchanged
            Ok(payload.to_vec())
        } else {
            // Simulate decryption by XORing with 0x42
            Ok(payload.iter().map(|b| b ^ 0x42).collect())
        }
    }

    fn has_delegation(&self) -> bool {
        self.state == MockContextState::Established && self.config.delegation_available
    }

    fn session_key(&self) -> Option<Vec<u8>> {
        if self.state == MockContextState::Established {
            self.config.session_key.clone()
        } else {
            None
        }
    }
}

#[cfg(any(test, feature = "mock"))]
impl MockSecurityContext {
    fn compute_dce_auth_token(
        header: &[u8],
        plaintext_stub: &[u8],
        sec_trailer: &[u8],
        sealed: bool,
    ) -> Vec<u8> {
        let len = if sealed { 60 } else { 28 };
        let mut token = vec![0u8; len];
        // RFC 4121 wrap token ID (0x0504)
        token[0] = 0x05;
        token[1] = 0x04;
        token[2] = u8::from(sealed) << 1;
        token[3] = 0xFF;
        // Fold header (SIGN_ONLY), plaintext_stub (DATA), and sec_trailer (SIGN_ONLY)
        // into the 12-byte rotated HMAC region (token[16..28]) so any tampering with
        // header, stub, or sec_trailer is detected.
        let mut acc = [0xA5u8; 12];
        for (i, &b) in header
            .iter()
            .chain(plaintext_stub.iter())
            .chain(sec_trailer.iter())
            .enumerate()
        {
            let idx = i % acc.len();
            acc[idx] = acc[idx].wrapping_mul(31).wrapping_add(b) ^ (i as u8);
        }
        token[16..28].copy_from_slice(&acc);
        token
    }

    /// Query the DCE/RPC `auth_value` length for a padded stub of `padded_stub_len` bytes.
    pub fn dce_auth_value_len(&self, conf_req: bool, padded_stub_len: usize) -> Result<usize> {
        if conf_req && !padded_stub_len.is_multiple_of(16) {
            return Err(crate::error::Error::Iov(format!(
                "DCE/RPC sealed stub must be a multiple of 16 bytes (got {padded_stub_len})"
            )));
        }
        Ok(if conf_req { 60 } else { 28 })
    }

    /// Protect a DCE/RPC PDU using the 4-buffer `GSS_C_DCE_STYLE` IOV layout.
    pub fn wrap_dce_iov(
        &mut self,
        header: &[u8],
        stub: &mut [u8],
        sec_trailer: &[u8],
        conf_req: bool,
    ) -> Result<Vec<u8>> {
        if self.state != MockContextState::Established {
            return Err(crate::error::Error::NotEstablished);
        }
        self.dce_auth_value_len(conf_req, stub.len())?;
        let token = Self::compute_dce_auth_token(header, stub, sec_trailer, conf_req);
        if conf_req && !self.config.wrap_passthrough {
            for b in stub.iter_mut() {
                *b ^= 0x42;
            }
        }
        Ok(token)
    }

    /// Verify and (when `expect_conf = true`) decrypt in-place a DCE/RPC PDU.
    pub fn unwrap_dce_iov(
        &mut self,
        header: &[u8],
        stub: &mut [u8],
        sec_trailer: &[u8],
        auth_value: &[u8],
        expect_conf: bool,
    ) -> Result<()> {
        if self.state != MockContextState::Established {
            return Err(crate::error::Error::NotEstablished);
        }
        self.dce_auth_value_len(expect_conf, stub.len())?;
        if expect_conf && !self.config.wrap_passthrough {
            for b in stub.iter_mut() {
                *b ^= 0x42;
            }
        }
        let expected = Self::compute_dce_auth_token(header, stub, sec_trailer, expect_conf);
        if auth_value != expected.as_slice() {
            return Err(crate::error::Error::Iov(
                "Kerberos DCE/RPC MIC verification failed".into(),
            ));
        }
        Ok(())
    }
}

/// Builder for configuring mock contexts
#[cfg(any(test, feature = "mock"))]
pub struct MockContextBuilder {
    config: MockContextConfig,
}

#[cfg(any(test, feature = "mock"))]
impl MockContextBuilder {
    /// Create a new builder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: MockContextConfig::default(),
        }
    }

    /// Configure for successful handshake
    #[must_use]
    pub const fn with_successful_handshake(mut self) -> Self {
        self.config.handshake_succeeds = true;
        self
    }

    /// Configure for failed handshake
    #[must_use]
    pub fn with_failed_handshake(mut self, error: &str) -> Self {
        self.config.handshake_succeeds = false;
        self.config.handshake_error = Some(error.to_string());
        self
    }

    /// Enable delegation
    #[must_use]
    pub const fn with_delegation(mut self) -> Self {
        self.config.delegation_available = true;
        self
    }

    /// Set custom initial token
    #[must_use]
    pub fn with_initial_token(mut self, token: Vec<u8>) -> Self {
        self.config.initial_token = token;
        self
    }

    /// Set custom session key
    #[must_use]
    pub fn with_session_key(mut self, key: Vec<u8>) -> Self {
        self.config.session_key = Some(key);
        self
    }

    /// Configure wrap to simulate encryption
    #[must_use]
    pub const fn with_encryption_simulation(mut self) -> Self {
        self.config.wrap_passthrough = false;
        self
    }

    /// Configure wrap to fail
    #[must_use]
    pub fn with_wrap_failure(mut self, error: &str) -> Self {
        self.config.wrap_error = Some(error.to_string());
        self
    }

    /// Configure unwrap to fail
    #[must_use]
    pub fn with_unwrap_failure(mut self, error: &str) -> Self {
        self.config.unwrap_error = Some(error.to_string());
        self
    }

    /// Build the mock context
    #[must_use]
    pub fn build(self) -> MockSecurityContext {
        MockSecurityContext::with_config(self.config)
    }
}

#[cfg(any(test, feature = "mock"))]
impl Default for MockContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory for creating mock security contexts
#[cfg(any(test, feature = "mock"))]
pub struct MockSecurityContextFactory {
    config: MockContextConfig,
}

#[cfg(any(test, feature = "mock"))]
impl MockSecurityContextFactory {
    /// Create a new mock factory with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: MockContextConfig::default(),
        }
    }

    /// Create with custom configuration
    #[must_use]
    pub const fn with_config(config: MockContextConfig) -> Self {
        Self { config }
    }
}

#[cfg(any(test, feature = "mock"))]
impl Default for MockSecurityContextFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "mock"))]
impl SecurityContextFactory for MockSecurityContextFactory {
    type Context = MockSecurityContext;

    fn create_context(&self, _config: KerberosConfig) -> Result<Self::Context> {
        Ok(MockSecurityContext::with_config(self.config.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_context_successful_handshake() {
        let mut ctx = MockContextBuilder::new()
            .with_successful_handshake()
            .build();

        // Initial state
        assert!(!ctx.is_established());
        assert!(!ctx.has_delegation());
        assert!(ctx.session_key().is_none());

        // Generate initial token
        let token = ctx.initial_token().unwrap();
        assert!(!token.is_empty());
        assert!(!ctx.is_established());

        // Accept response
        let third_leg = ctx.accept_response(&[0x00]).unwrap();
        assert!(third_leg.is_some());
        assert!(ctx.is_established());
        assert!(ctx.session_key().is_some());
    }

    #[test]
    fn test_mock_context_failed_handshake() {
        let mut ctx = MockContextBuilder::new()
            .with_failed_handshake("Authentication failed")
            .build();

        let _token = ctx.initial_token().unwrap();

        let result = ctx.accept_response(&[0x00]);
        assert!(result.is_err());
        assert!(!ctx.is_established());
    }

    #[test]
    fn test_mock_context_wrap_unwrap_passthrough() {
        let mut ctx = MockContextBuilder::new()
            .with_successful_handshake()
            .build();

        ctx.initial_token().unwrap();
        ctx.accept_response(&[0x00]).unwrap();

        let plaintext = b"Hello, Kerberos!";
        let wrapped = ctx.wrap_message(plaintext, AuthLevel::Privacy).unwrap();

        // Verify structure
        assert!(!wrapped.header.is_empty());
        assert_eq!(wrapped.payload.as_ref(), plaintext);
        assert!(!wrapped.trailer.is_empty());
        assert!(wrapped.conf);

        // Reconstruct and unwrap
        let mut full_token = Vec::new();
        full_token.extend_from_slice(&wrapped.header);
        full_token.extend_from_slice(&wrapped.payload);
        full_token.extend_from_slice(&wrapped.trailer);

        let unwrapped = ctx.unwrap_message(&full_token).unwrap();
        assert_eq!(unwrapped, plaintext);
    }

    #[test]
    fn test_mock_context_wrap_unwrap_with_encryption() {
        let mut ctx = MockContextBuilder::new()
            .with_successful_handshake()
            .with_encryption_simulation()
            .build();

        ctx.initial_token().unwrap();
        ctx.accept_response(&[0x00]).unwrap();

        let plaintext = b"Secret data";
        let wrapped = ctx.wrap_message(plaintext, AuthLevel::Privacy).unwrap();

        // Payload should be different (XOR encrypted)
        assert_ne!(wrapped.payload.as_ref(), plaintext);

        // But should decrypt correctly
        let mut full_token = Vec::new();
        full_token.extend_from_slice(&wrapped.header);
        full_token.extend_from_slice(&wrapped.payload);
        full_token.extend_from_slice(&wrapped.trailer);

        let unwrapped = ctx.unwrap_message(&full_token).unwrap();
        assert_eq!(unwrapped, plaintext);
    }

    #[test]
    fn test_mock_context_delegation() {
        let mut ctx = MockContextBuilder::new()
            .with_successful_handshake()
            .with_delegation()
            .build();

        assert!(!ctx.has_delegation()); // Not established yet

        ctx.initial_token().unwrap();
        ctx.accept_response(&[0x00]).unwrap();

        assert!(ctx.has_delegation()); // Now available
    }

    #[test]
    fn test_mock_context_call_counts() {
        let mut ctx = MockContextBuilder::new()
            .with_successful_handshake()
            .build();

        ctx.initial_token().unwrap();
        ctx.accept_response(&[0x00]).unwrap();

        let plaintext = b"test";
        ctx.wrap_message(plaintext, AuthLevel::Integrity).unwrap();
        ctx.wrap_message(plaintext, AuthLevel::Privacy).unwrap();

        let (init, accept, wrap, unwrap) = ctx.call_counts();
        assert_eq!(init, 1);
        assert_eq!(accept, 1);
        assert_eq!(wrap, 2);
        assert_eq!(unwrap, 0);
    }

    #[test]
    fn test_mock_factory() {
        let factory = MockSecurityContextFactory::new();
        let config = KerberosConfig::builder()
            .realm("TEST.REALM")
            .target_host("test.example.com")
            .build()
            .unwrap();

        let mut ctx = factory.create_context(config).unwrap();
        assert!(!ctx.is_established());

        ctx.initial_token().unwrap();
        ctx.accept_response(&[0x00]).unwrap();
        assert!(ctx.is_established());
    }

    #[test]
    fn test_mock_context_dce_iov_seal_and_sign() {
        let mut ctx = MockContextBuilder::new()
            .with_successful_handshake()
            .with_encryption_simulation()
            .build();
        let _ap_req = ctx.initial_token().unwrap();
        let _third_leg = ctx.accept_response(&[0x00]).unwrap();

        let header = [0x05u8; 24];
        let sec_trailer = [0x10, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let plaintext = *b"0123456789abcdef0123456789abcdef";
        let mut stub = plaintext;

        let auth_value = ctx
            .wrap_dce_iov(&header, &mut stub, &sec_trailer, true)
            .unwrap();
        assert_eq!(auth_value.len(), 60);
        assert_ne!(stub, plaintext);

        // Tampering with the SIGN_ONLY header or sec_trailer must fail unwrap_dce_iov
        let mut bad_header = header;
        bad_header[12] ^= 0xFF;
        let mut stub_copy = stub;
        assert!(ctx
            .unwrap_dce_iov(&bad_header, &mut stub_copy, &sec_trailer, &auth_value, true)
            .is_err());

        // Valid unwrap_dce_iov decrypts in place and verifies SIGN_ONLY buffers
        ctx.unwrap_dce_iov(&header, &mut stub, &sec_trailer, &auth_value, true)
            .unwrap();
        assert_eq!(stub, plaintext);

        // Integrity-only (conf_req = false) leaves stub cleartext and produces 28-byte token
        let mut signed_stub = *b"0123456789ab";
        let mic_token = ctx
            .wrap_dce_iov(&header, &mut signed_stub, &sec_trailer, false)
            .unwrap();
        assert_eq!(mic_token.len(), 28);
        assert_eq!(&signed_stub, b"0123456789ab");
        ctx.unwrap_dce_iov(&header, &mut signed_stub, &sec_trailer, &mic_token, false)
            .unwrap();
    }
}
