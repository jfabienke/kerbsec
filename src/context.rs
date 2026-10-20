//! Main security context API for DCE/RPC Kerberos authentication
//!
//! This module provides the primary [`Context`] type which manages the
//! GSS-API security context lifecycle for DCE/RPC authentication. It handles
//! the three-leg Kerberos handshake, message protection, and proper cleanup.
//!
//! # Thread Safety
//!
//! [`Context`] is `Send` but NOT `Sync` - it can be moved between threads
//! but cannot be shared between threads without external synchronization.
//!
//! # Example
//!
//! ```no_run
//! use fabi_kerbsec::{Context, KerberosConfig};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = KerberosConfig::builder()
//!     .realm("CORP.EXAMPLE.COM")
//!     .target_host("server.example.com")
//!     .build()?;
//!
//! let mut ctx = Context::new(config)?;
//!
//! // Generate AP-REQ
//! let ap_req = ctx.initial_token()?;
//! // Send ap_req to server...
//!
//! // Process AP-REP
//! # let ap_rep = vec![];
//! let third_leg = ctx.accept_ap_rep(&ap_rep)?;
//! // Send third_leg to server...
//!
//! // Context is now established for message protection
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "trace")]
use tracing::{debug, info, instrument, warn};

use crate::config::{AuthLevel, ChannelBindings, KerberosConfig};
use crate::error::Result;
use crate::security::{IovWrap, Oid, KRB5_MECH_OID};

#[cfg(unix)]
use crate::security::gss::GssContext;

/// Kerberos security context for DCE/RPC
///
/// # Thread Safety
///
/// `Context` is `Send` but **NOT** `Sync`. This means:
/// - ✅ Can be moved between threads
/// - ❌ Cannot be shared between threads (no `&Context` across threads)
/// - ❌ Cannot be used concurrently from multiple threads
///
/// This limitation comes from the underlying GSS-API context which maintains
/// internal state (sequence numbers, replay cache) that is not thread-safe.
///
/// For concurrent usage, each thread must have its own Context, or you must
/// use external synchronization (e.g., `Mutex<Context>`).
///
/// # Example
/// ```ignore
/// // OK: Move context to another thread
/// let ctx = Context::new(config)?;
/// std::thread::spawn(move || {
///     ctx.initial_token()?;
/// });
///
/// // NOT OK: Share context between threads
/// let ctx = Arc::new(Context::new(config)?);
/// let ctx2 = ctx.clone();
/// std::thread::spawn(move || {
///     ctx2.initial_token()?; // Compile error: Context is not Sync
/// });
/// ```
pub struct Context {
    #[cfg(unix)]
    inner: GssContext,
    config: KerberosConfig,
}

impl Context {
    /// Create context from config
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Platform is not Unix
    /// - GSS context creation fails
    #[cfg_attr(feature = "trace", instrument(
        target = "kerbsec::ctx",
        level = "info",
        skip_all,
        fields(
            realm = %config.realm,
            fqdn = %config.target_fqdn,
            auth = ?config.default_auth
        )
    ))]
    pub fn new(config: KerberosConfig) -> Result<Self> {
        #[cfg(unix)]
        {
            #[cfg(feature = "trace")]
            info!(target: "kerbsec::ctx", "creating Kerberos context");

            let inner = GssContext::new(config.clone())?;

            #[cfg(feature = "trace")]
            debug!(target: "kerbsec::ctx", "context created successfully");

            Ok(Self { inner, config })
        }

        #[cfg(not(unix))]
        {
            Err(crate::error::Error::Config(
                "kerbsec only supports Unix platforms".into(),
            ))
        }
    }

    /// Build config from target with DNS canonicalization
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - DNS resolution fails
    /// - Target is IP without SPN override
    #[cfg(feature = "dns")]
    #[cfg_attr(feature = "trace", instrument(
        target = "kerbsec::ctx",
        level = "debug",
        skip_all,
        fields(realm, target = %target_host.as_ref())
    ))]
    pub async fn config_from_target(
        realm: impl Into<String>,
        target_host: impl AsRef<str>,
    ) -> Result<KerberosConfig> {
        let realm_str = realm.into();
        let target = target_host.as_ref();

        #[cfg(feature = "trace")]
        debug!(target: "kerbsec::ctx", realm = %realm_str, target = %target, "building config with DNS canonicalization");

        let config = KerberosConfig::builder()
            .realm(realm_str)
            .target_host(target)
            .build_async()
            .await?;

        #[cfg(feature = "trace")]
        debug!(target: "kerbsec::ctx", fqdn = %config.target_fqdn, "config built successfully");

        Ok(config)
    }

    /// Get the mechanism OID
    #[must_use]
    pub const fn mech_oid(&self) -> &'static Oid {
        &KRB5_MECH_OID
    }

    /// Set channel bindings
    pub fn set_channel_bindings(&mut self, cb: Option<ChannelBindings>) {
        self.config.channel_bindings.clone_from(&cb);

        #[cfg(unix)]
        {
            self.inner.set_channel_bindings(cb);
        }
    }

    /// Generate initial token (AP-REQ) for bind PDU
    ///
    /// The returned token must be sent to the server in the bind PDU.
    /// Ignoring this token will result in an incomplete handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - GSS context initialization fails
    /// - Credentials are not available
    #[must_use = "the AP-REQ token must be sent to the server"]
    #[cfg_attr(
        feature = "trace",
        instrument(target = "kerbsec::ctx", level = "info", skip_all)
    )]
    pub fn initial_token(&mut self) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            #[cfg(feature = "trace")]
            debug!(target: "kerbsec::ctx", "generating initial token (AP-REQ)");

            let token = self.inner.initial_token()?;

            #[cfg(feature = "trace")]
            info!(target: "kerbsec::ctx", token_size = token.len(), "initial token generated");

            Ok(token)
        }

        #[cfg(not(unix))]
        {
            Err(crate::error::Error::Config(
                "kerbsec only supports Unix platforms".into(),
            ))
        }
    }

    /// Accept AP-REP and return final token for `alter_context`
    ///
    /// Always returns `Some()` for DCE-style (even if empty).
    /// The returned token must be sent to the server even if empty,
    /// as DCE/RPC requires the third leg of the handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Token processing fails
    /// - Invalid AP-REP format
    #[must_use = "the third leg token must be sent to the server, even if empty"]
    #[cfg_attr(feature = "trace", instrument(
        target = "kerbsec::ctx",
        level = "info",
        skip_all,
        fields(ap_rep_size = ap_rep.len())
    ))]
    pub fn accept_ap_rep(&mut self, ap_rep: &[u8]) -> Result<Option<Vec<u8>>> {
        #[cfg(unix)]
        {
            #[cfg(feature = "trace")]
            debug!(target: "kerbsec::ctx", "processing AP-REP");

            let result = self.inner.accept_ap_rep(ap_rep)?;

            #[cfg(feature = "trace")]
            {
                match &result {
                    Some(token) => {
                        info!(target: "kerbsec::ctx", third_leg_size = token.len(), "context established with third leg");
                    }
                    None => {
                        info!(target: "kerbsec::ctx", "context established (no third leg)");
                    }
                }
            }

            Ok(result)
        }

        #[cfg(not(unix))]
        {
            Err(crate::error::Error::Config(
                "kerbsec only supports Unix platforms".into(),
            ))
        }
    }

    /// Check if context is established
    #[must_use]
    pub const fn established(&self) -> bool {
        #[cfg(unix)]
        {
            self.inner.established()
        }

        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Wrap PDU with default auth level
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Context not established
    /// - Wrapping fails
    pub fn wrap_iov(&mut self, pdu: &[u8]) -> Result<IovWrap> {
        self.wrap_iov_with(pdu, self.config.default_auth)
    }

    /// Wrap PDU with specified auth level
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Context not established
    /// - Wrapping fails
    pub fn wrap_iov_with(&mut self, pdu: &[u8], level: AuthLevel) -> Result<IovWrap> {
        #[cfg(unix)]
        {
            self.inner.wrap_iov(pdu, level)
        }

        #[cfg(not(unix))]
        {
            Err(crate::error::Error::Config(
                "kerbsec only supports Unix platforms".into(),
            ))
        }
    }

    /// Unwrap received token
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Context not established
    /// - Token is invalid or tampered
    pub fn unwrap_iov(&mut self, token: &[u8]) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            self.inner.unwrap_iov(token)
        }

        #[cfg(not(unix))]
        {
            Err(crate::error::Error::Config(
                "kerbsec only supports Unix platforms".into(),
            ))
        }
    }

    /// Query the DCE/RPC `auth_value` length for a padded stub of `padded_stub_len` bytes.
    pub fn dce_auth_value_len(&self, conf_req: bool, padded_stub_len: usize) -> Result<usize> {
        #[cfg(unix)]
        {
            self.inner.dce_auth_value_len(conf_req, padded_stub_len)
        }

        #[cfg(not(unix))]
        {
            let _ = (conf_req, padded_stub_len);
            Err(crate::error::Error::Config(
                "kerbsec only supports Unix platforms".into(),
            ))
        }
    }

    /// Protect a DCE/RPC PDU using the 4-buffer `GSS_C_DCE_STYLE` IOV layout
    /// (`SIGN_ONLY` header, `DATA` stub, `SIGN_ONLY` `sec_trailer`, `HEADER` `auth_value`).
    pub fn wrap_dce_iov(
        &mut self,
        header: &[u8],
        stub: &mut [u8],
        sec_trailer: &[u8],
        conf_req: bool,
    ) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            self.inner.wrap_dce_iov(header, stub, sec_trailer, conf_req)
        }

        #[cfg(not(unix))]
        {
            let _ = (header, stub, sec_trailer, conf_req);
            Err(crate::error::Error::Config(
                "kerbsec only supports Unix platforms".into(),
            ))
        }
    }

    /// Verify and (when `expect_conf = true`) decrypt in-place a DCE/RPC PDU
    /// using the 4-buffer `GSS_C_DCE_STYLE` IOV layout.
    pub fn unwrap_dce_iov(
        &mut self,
        header: &[u8],
        stub: &mut [u8],
        sec_trailer: &[u8],
        auth_value: &[u8],
        expect_conf: bool,
    ) -> Result<()> {
        #[cfg(unix)]
        {
            self.inner
                .unwrap_dce_iov(header, stub, sec_trailer, auth_value, expect_conf)
        }

        #[cfg(not(unix))]
        {
            let _ = (header, stub, sec_trailer, auth_value, expect_conf);
            Err(crate::error::Error::Config(
                "kerbsec only supports Unix platforms".into(),
            ))
        }
    }

    /// Calculate maximum message size for wrapping
    ///
    /// Given a desired wrapped token size, returns the maximum message size
    /// that can be wrapped without exceeding the limit.
    ///
    /// TODO: Implement using `gss_wrap_size_limit` when available in libgssapi.
    /// Currently returns a conservative estimate.
    #[must_use]
    pub const fn wrap_size_limit(&self, max_wrapped_size: usize, conf_req: bool) -> usize {
        // Conservative estimates based on typical Kerberos overhead
        // Real implementation would use gss_wrap_size_limit
        let overhead = if conf_req {
            60 // Privacy: header + encryption padding + trailer
        } else {
            32 // Integrity: header + MIC
        };

        max_wrapped_size.saturating_sub(overhead)
    }

    /// Get session key (if available)
    ///
    /// Returns the negotiated session key for diagnostic purposes.
    ///
    /// TODO: Implement using `gss_inquire_context` with `GSS_C_INQ_SSPI_SESSION_KEY` OID.
    /// Currently returns None as libgssapi doesn't expose the necessary APIs.
    ///
    /// Note: The session key should NEVER be logged or transmitted. It's only
    /// useful for debugging protocol issues in controlled environments.
    #[must_use]
    pub const fn session_key(&self) -> Option<Vec<u8>> {
        #[cfg(unix)]
        {
            // TODO: Use gss_inquire_context or gss_inquire_sec_context_by_oid
            // with appropriate OID to extract session key when available
            self.inner.session_key()
        }

        #[cfg(not(unix))]
        {
            None
        }
    }

    /// Check if delegated credentials are available
    ///
    /// Returns true if the context has received delegated credentials.
    /// This is only applicable for acceptor contexts in server scenarios.
    ///
    /// For client contexts where delegation was requested, this indicates
    /// whether the delegation was successful.
    #[must_use]
    pub fn has_delegated_credentials(&self) -> bool {
        #[cfg(unix)]
        {
            self.inner.has_delegated_credentials()
        }

        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Export delegated credentials
    ///
    /// Returns the delegated credentials that can be used to impersonate
    /// the client for accessing other services (S4U2Self/S4U2Proxy).
    ///
    /// # Security Warning
    ///
    /// Handle these credentials with extreme care as they allow
    /// impersonation of the original client.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No delegated credentials are available
    /// - Export operation fails
    /// - Platform doesn't support credential export
    pub fn export_delegated_credentials(&self) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            self.inner.export_delegated_credentials()
        }

        #[cfg(not(unix))]
        {
            Err(crate::error::Error::Config(
                "Credential export not supported on this platform".into(),
            ))
        }
    }
}

// Static assertions for thread safety bounds.
// These are compile-time checks that verify Context implements
// the expected thread safety traits.
//
// Context is Send but NOT Sync:
// - Send: Can be moved between threads
// - !Sync: Cannot be shared between threads without external synchronization
#[cfg(unix)]
mod _static_assertions {
    use super::Context;

    /// Trait bound to verify a type implements Send at compile time.
    /// This function is never called - it exists only for the type check.
    #[allow(dead_code)]
    const fn require_send<T: Send>() {}

    /// Compile-time assertion that Context implements Send.
    /// If Context ever stops implementing Send, this will fail to compile.
    #[allow(dead_code)]
    const ASSERT_CONTEXT_IS_SEND: () = require_send::<Context>();

    // Note: We explicitly do NOT assert Sync because Context is not Sync.
    // The underlying GSS context maintains internal state (sequence numbers,
    // replay cache) that is not thread-safe for concurrent access.
    //
    // Users who need concurrent access should use Mutex<Context> or similar.
}
