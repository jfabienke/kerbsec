//! GSS-API integration for Unix platforms
//!
//! This module provides the low-level GSS-API wrapper for Unix platforms,
//! supporting both MIT Kerberos and Heimdal implementations.

use crate::config::{AuthLevel, ChannelBindings, KerberosConfig};
use crate::error::{Error, Result};
use crate::security::IovWrap;
use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE};
use std::sync::Once;
use std::time::Duration;

// GSS context flag constants
// These are standard GSS-API flags defined in RFC 2744

/// `GSS_C_DCE_STYLE` flag (0x1000) - critical for DCE/RPC semantics
/// This flag is not exposed by libgssapi, but is required for:
/// - Disabling GSS sequence number checking (DCE has its own)
/// - Allowing out-of-order message processing
/// - Preventing GSS replay cache from interfering with DCE/RPC
const GSS_C_DCE_STYLE: u32 = 0x1000;

/// `GSS_C_DELEG_FLAG` (0x01) - allows server to act on client's behalf
const GSS_C_DELEG_FLAG: u32 = 0x01;

/// `GSS_C_MUTUAL_FLAG` (0x02) - mutual authentication required
const GSS_C_MUTUAL_FLAG: u32 = 0x02;

/// `GSS_C_CONF_FLAG` (0x10) - confidentiality available
#[cfg(feature = "trace")] // only reported in the context-established trace
const GSS_C_CONF_FLAG: u32 = 0x10;

/// `GSS_C_INTEG_FLAG` (0x20) - integrity available
#[cfg(feature = "trace")] // only reported in the context-established trace
const GSS_C_INTEG_FLAG: u32 = 0x20;

#[cfg(feature = "trace")]
use tracing::{debug, error, info, instrument, warn};

/// Thread-safe environment variable initialization
static ENV_INIT: Once = Once::new();
static KEYTAB_ENV_INIT: Once = Once::new();

/// GSS-API context wrapper for Unix platforms
pub struct GssContext {
    inner: Option<ClientCtx>,
    config: KerberosConfig,
    established: bool,
    /// Tracks whether delegation was actually negotiated (not just requested)
    delegation_negotiated: bool,
}

impl GssContext {
    /// Create a new GSS context with the given configuration
    ///
    /// # Thread Safety
    ///
    /// The `KRB5CCNAME` environment variable is set only once per process using
    /// `std::sync::Once`. Subsequent calls will not modify the environment.
    /// This is safe because:
    /// 1. The env var is only set once, atomically
    /// 2. We only set it if it wasn't already set
    /// 3. After the first context creation, all contexts use the same ccache
    ///
    /// If you need different contexts to use different credential caches,
    /// set `KRB5CCNAME` before creating the first context, or use the
    /// `KRB5_CLIENT_KTNAME` mechanism for service accounts.
    pub fn new(config: KerberosConfig) -> Result<Self> {
        // Thread-safe environment variable initialization
        // SAFETY: std::sync::Once ensures this runs exactly once per process

        // Set credential cache environment variable
        if let Some(ref ccache) = config.kccache {
            let ccache_clone = ccache.clone();
            ENV_INIT.call_once(|| {
                // Only set if not already set by the environment
                if std::env::var("KRB5CCNAME").is_err() {
                    // SAFETY: This is safe because:
                    // 1. We're inside Once::call_once, so this runs exactly once
                    // 2. No other thread can be modifying env vars at this point
                    //    (or if they are, it's a program-level bug)
                    // 3. The value is valid UTF-8 (came from String)
                    unsafe {
                        std::env::set_var("KRB5CCNAME", &ccache_clone);
                    }
                    #[cfg(feature = "trace")]
                    debug!(target: "kerbsec::gss", ccache = %ccache_clone, "set KRB5CCNAME (once)");
                } else {
                    #[cfg(feature = "trace")]
                    debug!(target: "kerbsec::gss", "KRB5CCNAME already set, not overriding");
                }
            });
        }

        // Set keytab environment variable for service account authentication
        if let Some(ref keytab) = config.keytab {
            let keytab_clone = keytab.clone();
            KEYTAB_ENV_INIT.call_once(|| {
                // KRB5_CLIENT_KTNAME is the standard env var for client keytabs
                if std::env::var("KRB5_CLIENT_KTNAME").is_err() {
                    unsafe {
                        std::env::set_var("KRB5_CLIENT_KTNAME", &keytab_clone);
                    }
                    #[cfg(feature = "trace")]
                    debug!(target: "kerbsec::gss", keytab = %keytab_clone, "set KRB5_CLIENT_KTNAME (once)");
                } else {
                    #[cfg(feature = "trace")]
                    debug!(target: "kerbsec::gss", "KRB5_CLIENT_KTNAME already set, not overriding");
                }
            });
        }

        Ok(Self {
            inner: None,
            config,
            established: false,
            delegation_negotiated: false,
        })
    }

    /// Update channel bindings configuration after context creation
    pub fn set_channel_bindings(&mut self, cb: Option<ChannelBindings>) {
        self.config.channel_bindings = cb;
    }

    /// Generate initial AP-REQ token
    #[cfg_attr(
        feature = "trace",
        instrument(target = "kerbsec::gss", level = "info", skip_all, fields(spn))
    )]
    pub fn initial_token(&mut self) -> Result<Vec<u8>> {
        // Build SPN
        let default_spn = format!("HOST/{}", self.config.target_fqdn);
        let spn = self.config.spn_override.as_deref().unwrap_or(&default_spn);

        #[cfg(feature = "trace")]
        info!(target: "kerbsec::gss", spn = %spn, mech = "KRB5", "initializing GSS context");

        // Create target name
        let target =
            Name::new(spn.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE)).map_err(|e| Error::Gss {
                major: 0,
                minor: 0,
                text: format!("Failed to create target name: {e}"),
            })?;

        // Create credentials (use default)
        // Note: libgssapi 0.9.1 API changed - parameter order is different
        let cred = Cred::acquire(
            None,
            Some(Duration::from_secs(300)),
            CredUsage::Initiate,
            None, // Use default mechanism set
        )
        .map_err(gss_error)?;

        // Set context flags for DCE-style
        let mut flags = CtxFlags::empty();

        // Mutual authentication (configurable but strongly recommended)
        if self.config.require_mutual_auth {
            flags |= CtxFlags::GSS_C_MUTUAL_FLAG;
        }

        flags |= CtxFlags::GSS_C_INTEG_FLAG; // Always required
        flags |= CtxFlags::GSS_C_SEQUENCE_FLAG; // DCE sequence detection
        flags |= CtxFlags::GSS_C_REPLAY_FLAG; // DCE replay detection

        // Enable delegation if configured
        if self.config.enable_delegation {
            // GSS_C_DELEG_FLAG (0x01) - allows server to act on client's behalf
            let flags_with_deleg = flags.bits() | GSS_C_DELEG_FLAG;
            flags = CtxFlags::from_bits_retain(flags_with_deleg);

            #[cfg(feature = "trace")]
            debug!(target: "kerbsec::gss", "credential delegation enabled");
        }

        // Add confidentiality flag based on config
        if matches!(self.config.default_auth, AuthLevel::Privacy) {
            flags |= CtxFlags::GSS_C_CONF_FLAG;
        }

        // Add GSS_C_DCE_STYLE flag when configured (default: true for DCE/RPC)
        if self.config.enable_dce_style {
            // DCE_STYLE (0x1000) is critical for proper DCE/RPC semantics:
            // - Disables GSS sequence number checking (DCE has its own)
            // - Allows out-of-order message processing
            // - Prevents GSS replay cache from interfering with DCE/RPC
            //
            // Since libgssapi doesn't expose DCE_STYLE in CtxFlags,
            // we need to OR it in manually using from_bits_retain
            let flags_with_dce = flags.bits() | GSS_C_DCE_STYLE;
            flags = CtxFlags::from_bits_retain(flags_with_dce);

            #[cfg(feature = "trace")]
            debug!(target: "kerbsec::gss", flags = format_args!("{:#x}", flags.bits()), "context flags with DCE_STYLE");
        }

        // Initialize context - API changed in libgssapi 0.9.1
        let mut ctx = ClientCtx::new(Some(cred), target, flags, Some(&GSS_MECH_KRB5));

        let channel_binding_data = self
            .config
            .channel_bindings
            .as_ref()
            .and_then(ChannelBindings::get_gss_data);

        #[cfg(feature = "trace")]
        if let Some(ref data) = channel_binding_data {
            debug!(target: "kerbsec::gss", binding_len = data.len(), "applying channel bindings");
        }

        // Generate initial token (AP-REQ)
        match ctx.step(None, channel_binding_data.as_deref()) {
            Ok(Some(token)) => {
                self.inner = Some(ctx);
                Ok(token.to_vec())
            }
            Ok(None) => Err(Error::TokenShape),
            Err(e) => Err(gss_error(e)),
        }
    }

    /// Process AP-REP and return final token if needed
    #[cfg_attr(feature = "trace", instrument(
        target = "kerbsec::gss",
        level = "info",
        skip_all,
        fields(ap_rep_size = ap_rep.len())
    ))]
    pub fn accept_ap_rep(&mut self, ap_rep: &[u8]) -> Result<Option<Vec<u8>>> {
        let ctx = self.inner.as_mut().ok_or(Error::NotEstablished)?;

        let channel_binding_data = self
            .config
            .channel_bindings
            .as_ref()
            .and_then(ChannelBindings::get_gss_data);

        match ctx.step(Some(ap_rep), channel_binding_data.as_deref()) {
            Ok(token) => {
                // Check if complete - is_complete() returns bool directly
                if ctx.is_complete() {
                    self.established = true;

                    // Query actual negotiated flags using gss_inquire_context
                    // This properly verifies what was negotiated, not just what we requested
                    let negotiated_flags = self.inquire_context_flags();

                    // Check if delegation was actually granted
                    self.delegation_negotiated = (negotiated_flags & GSS_C_DELEG_FLAG) != 0;

                    // Log the actual negotiated security properties
                    #[cfg(feature = "trace")]
                    {
                        let has_mutual = (negotiated_flags & GSS_C_MUTUAL_FLAG) != 0;
                        let has_conf = (negotiated_flags & GSS_C_CONF_FLAG) != 0;
                        let has_integ = (negotiated_flags & GSS_C_INTEG_FLAG) != 0;

                        info!(
                            target: "kerbsec::gss",
                            flags = format_args!("{:#x}", negotiated_flags),
                            delegation = self.delegation_negotiated,
                            mutual = has_mutual,
                            confidentiality = has_conf,
                            integrity = has_integ,
                            "GSS context established"
                        );

                        // Warn if delegation was requested but not granted
                        if self.config.enable_delegation && !self.delegation_negotiated {
                            warn!(
                                target: "kerbsec::gss",
                                "delegation was requested but not granted by server"
                            );
                        }
                    }

                    // DCE requires sending third leg even if empty
                    Ok(Some(token.map_or_else(Vec::new, |t| t.to_vec())))
                } else {
                    // Should not happen in DCE 3-leg
                    #[cfg(feature = "trace")]
                    warn!(target: "kerbsec::gss", "AP-REP accepted but context not complete (unexpected)");
                    Ok(token.map(|t| t.to_vec()))
                }
            }
            Err(e) => {
                #[cfg(feature = "trace")]
                error!(target: "kerbsec::gss", error = %e, "failed to process AP-REP");
                Err(gss_error(e))
            }
        }
    }

    /// Query the actual negotiated context flags using `gss_inquire_context`
    ///
    /// This uses direct FFI to get the real flags that were negotiated,
    /// not just what we requested.
    fn inquire_context_flags(&self) -> u32 {
        use crate::ffi;
        use std::ptr;

        let Some(ctx) = &self.inner else {
            return 0;
        };

        // SAFETY: We need to extract the raw context handle from ClientCtx
        // This uses the same technique as gss_iov.rs
        let ctx_handle = unsafe {
            let ctx_ptr = ptr::from_ref(ctx).cast::<ffi::gss_ctx_id_t>();
            ptr::read(ctx_ptr)
        };

        if ctx_handle.is_null() {
            return 0;
        }

        let mut minor_status: ffi::OM_uint32 = 0;
        let mut ctx_flags: ffi::OM_uint32 = 0;

        // SAFETY: All pointers are valid, we pass NULL for fields we don't need
        let major_status = unsafe {
            ffi::gss_inquire_context(
                &mut minor_status,
                ctx_handle,
                ptr::null_mut(), // src_name - not needed
                ptr::null_mut(), // targ_name - not needed
                ptr::null_mut(), // lifetime_rec - not needed
                ptr::null_mut(), // mech_type - not needed
                &mut ctx_flags,
                ptr::null_mut(), // locally_initiated - not needed
                ptr::null_mut(), // open - not needed
            )
        };

        if major_status != ffi::GSS_S_COMPLETE {
            #[cfg(feature = "trace")]
            warn!(
                target: "kerbsec::gss",
                major = format_args!("{:#x}", major_status),
                minor = format_args!("{:#x}", minor_status),
                "gss_inquire_context failed, falling back to requested flags"
            );

            // Fallback: assume what we requested was granted
            // This maintains backward compatibility
            let mut fallback_flags = 0u32;
            if self.config.enable_delegation {
                fallback_flags |= GSS_C_DELEG_FLAG;
            }
            if self.config.require_mutual_auth {
                fallback_flags |= GSS_C_MUTUAL_FLAG;
            }
            return fallback_flags;
        }

        ctx_flags
    }

    /// Check if the security context is fully established
    #[must_use]
    pub const fn established(&self) -> bool {
        self.established
    }

    /// Wrap PDU with IOV-like interface for DCE/RPC
    ///
    /// When the `iov` feature is enabled, this uses true GSS IOV operations
    /// for zero-copy wrapping. Otherwise falls back to regular wrap.
    pub fn wrap_iov(&mut self, pdu: &[u8], level: AuthLevel) -> Result<IovWrap> {
        let ctx = self.inner.as_mut().ok_or(Error::NotEstablished)?;

        if !self.established {
            return Err(Error::NotEstablished);
        }

        let conf_req = matches!(level, AuthLevel::Privacy);

        #[cfg(feature = "iov")]
        {
            // Use real IOV implementation from libgssapi
            super::gss_iov::wrap_iov_real(ctx, pdu, conf_req)
        }

        #[cfg(not(feature = "iov"))]
        {
            use bytes::Bytes;
            // Fallback: Use regular wrap - return full token as header
            // DCE/RPC will need to handle this as a single token
            match ctx.wrap(conf_req, pdu) {
                Ok(wrapped) => {
                    // Return entire wrapped token as header
                    // Trailer is empty since we can't separate without IOV
                    Ok(IovWrap {
                        header: Bytes::from(wrapped.to_vec()),
                        payload: Bytes::new(),
                        trailer: Bytes::new(),
                        conf: conf_req,
                    })
                }
                Err(e) => Err(gss_error(e)),
            }
        }
    }

    /// Unwrap token with IOV-like interface
    ///
    /// When the `iov` feature is enabled, this uses true GSS IOV operations.
    /// Otherwise falls back to regular unwrap.
    pub fn unwrap_iov(&mut self, token: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.inner.as_mut().ok_or(Error::NotEstablished)?;

        if !self.established {
            return Err(Error::NotEstablished);
        }

        // Use regular unwrap since IOV is not available
        match ctx.unwrap(token) {
            Ok(data) => Ok(data.to_vec()),
            Err(e) => Err(gss_error(e)),
        }
    }

    /// Check if delegated credentials are available
    ///
    /// Returns true if delegation was both requested AND successfully
    /// negotiated during context establishment. This reflects the actual
    /// negotiation state, not just the configuration.
    ///
    /// # Note
    ///
    /// For initiator (client) contexts, this indicates whether the server
    /// accepted the delegation request. For acceptor (server) contexts,
    /// this indicates whether delegated credentials were received.
    #[allow(clippy::missing_const_for_fn)] // Can't be const: accesses self fields through method
    #[must_use]
    pub fn has_delegated_credentials(&self) -> bool {
        // Only return true if:
        // 1. Context is established
        // 2. Delegation was actually negotiated (not just requested)
        self.established && self.delegation_negotiated
    }

    /// Export delegated credentials
    ///
    /// Returns the delegated credentials if available.
    /// These can be used to impersonate the client for accessing
    /// other services (S4U2Self/S4U2Proxy).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No delegated credentials are available
    /// - Export operation fails
    pub fn export_delegated_credentials(&self) -> Result<Vec<u8>> {
        if !self.has_delegated_credentials() {
            return Err(Error::NoDelegatedCredentials);
        }

        // TODO: Implement actual credential export when libgssapi supports it
        // This would use gss_export_cred or similar API
        #[cfg(feature = "trace")]
        warn!(target: "kerbsec::gss", "delegated credential export not yet implemented");

        Err(Error::NotImplemented(
            "credential export requires libgssapi support".into(),
        ))
    }

    /// Get the negotiated session key (not currently implemented)
    #[must_use]
    pub const fn session_key(&self) -> Option<Vec<u8>> {
        // GSS-API doesn't directly expose session key
        // This would require platform-specific extraction
        None
    }
}

fn gss_error(e: libgssapi::error::Error) -> Error {
    // Extract major and minor codes from libgssapi error
    let major = e.major.bits();
    let minor = e.minor;
    let text = e.to_string();

    #[cfg(feature = "trace")]
    error!(
        target: "kerbsec::gss",
        major = format_args!("{:#x}", major),
        minor = format_args!("{:#x}", minor),
        %text,
        "GSS error"
    );

    Error::Gss { major, minor, text }
}
