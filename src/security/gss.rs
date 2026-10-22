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
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL};
use std::sync::Mutex;
use std::time::Duration;

// GSS context flag constants
// These are standard GSS-API flags defined in RFC 2744

/// `GSS_C_DCE_STYLE` flag (0x1000) - critical for DCE/RPC semantics
/// This flag is not exposed by libgssapi's `CtxFlags` names, but is required for:
/// - The three-leg handshake (the initiator sends a final token after the AP-REP)
/// - `gss_wrap_iov` without PADDING/TRAILER buffers, as DCE/RPC frames its PDUs
///
/// It does not switch off sequence or replay detection; those are requested
/// separately (see `initial_token`).
const GSS_C_DCE_STYLE: u32 = 0x1000;

/// `GSS_C_DELEG_FLAG` (0x01) - allows server to act on client's behalf
const GSS_C_DELEG_FLAG: u32 = 0x01;

/// `GSS_C_MUTUAL_FLAG` (0x02) - mutual authentication required
const GSS_C_MUTUAL_FLAG: u32 = 0x02;

/// `GSS_C_CONF_FLAG` (0x10) - confidentiality available
const GSS_C_CONF_FLAG: u32 = 0x10;

/// `GSS_C_INTEG_FLAG` (0x20) - integrity available
const GSS_C_INTEG_FLAG: u32 = 0x20;

#[cfg(feature = "trace")]
use tracing::{debug, error, info, instrument, warn};

/// Serializes the check-and-set of the process-global credential variables
static CRED_ENV_LOCK: Mutex<()> = Mutex::new(());

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
    /// # Credential selection
    ///
    /// MIT Kerberos selects credentials from process-global environment
    /// variables, so a configured `kccache` / `keytab` is applied by setting
    /// `KRB5CCNAME` / `KRB5_CLIENT_KTNAME`. That means all contexts in a process
    /// share one credential source: if the variable is already set to a
    /// *different* value (by the environment or an earlier context), this returns
    /// an error rather than silently authenticating as the wrong principal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the configured credential cache or keytab
    /// conflicts with the one already in use by this process.
    pub fn new(config: KerberosConfig) -> Result<Self> {
        if let Some(ref ccache) = config.kccache {
            apply_cred_env("KRB5CCNAME", ccache)?;
        }
        if let Some(ref keytab) = config.keytab {
            apply_cred_env("KRB5_CLIENT_KTNAME", keytab)?;
        }

        Ok(Self {
            inner: None,
            config,
            established: false,
            delegation_negotiated: false,
        })
    }

    /// Update channel bindings configuration after context creation
    ///
    /// # Errors
    ///
    /// Returns an error once the handshake has started: the bindings are part of
    /// the first token, so changing them afterwards would make later legs
    /// inconsistent with it.
    pub fn set_channel_bindings(&mut self, cb: Option<ChannelBindings>) -> Result<()> {
        if self.inner.is_some() {
            return Err(Error::HandshakeState(
                "channel bindings must be set before initial_token",
            ));
        }
        self.config.channel_bindings = cb;
        Ok(())
    }

    /// Channel binding data for the GSS calls, rejecting bindings GSS cannot carry
    ///
    /// Only `application_data` is passed to GSS-API; address-only bindings would be
    /// silently dropped, so they are an error rather than "no bindings".
    fn channel_binding_data(&self) -> Result<Option<Vec<u8>>> {
        let Some(cb) = self.config.channel_bindings.as_ref() else {
            return Ok(None);
        };
        cb.get_gss_data().map(Some).ok_or_else(|| {
            Error::Config(
                "channel bindings have no application data; address-only bindings are not supported"
                    .into(),
            )
        })
    }

    /// Generate initial AP-REQ token
    #[cfg_attr(
        feature = "trace",
        instrument(target = "kerbsec::gss", level = "info", skip_all, fields(spn))
    )]
    pub fn initial_token(&mut self) -> Result<Vec<u8>> {
        if self.inner.is_some() {
            return Err(Error::HandshakeState(
                "initial_token already called on this context",
            ));
        }

        let spn = target_principal(&self.config);

        #[cfg(feature = "trace")]
        info!(target: "kerbsec::gss", spn = %spn, mech = "KRB5", "initializing GSS context");

        // Import as a Kerberos principal name. `GSS_NT_HOSTBASED_SERVICE` would be
        // wrong here: it expects `service@host`, so `HOST/fqdn` was read as a bare
        // service name with the *local* hostname appended.
        let target = Name::new(spn.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL)).map_err(gss_error)?;

        // Create credentials (use default)
        // Note: libgssapi 0.9.1 API changed - parameter order is different
        let cred = Cred::acquire(
            None,
            Some(Duration::from_mins(5)),
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
                                             // Sequence and replay detection stay on alongside DCE_STYLE: they protect the
                                             // message stream, and DCE_STYLE only changes handshake/buffer-layout rules.
        flags |= CtxFlags::GSS_C_SEQUENCE_FLAG;
        flags |= CtxFlags::GSS_C_REPLAY_FLAG;

        // Enable delegation if configured
        if self.config.enable_delegation {
            // GSS_C_DELEG_FLAG (0x01) - allows server to act on client's behalf
            let flags_with_deleg = flags.bits() | GSS_C_DELEG_FLAG;
            flags = CtxFlags::from_bits_retain(flags_with_deleg);

            #[cfg(feature = "trace")]
            debug!(target: "kerbsec::gss", "credential delegation enabled");
        }

        // Always request confidentiality so a per-call `AuthLevel::Privacy` wrap
        // works on a context whose default is Integrity. Whether a given message is
        // sealed is still decided per call by `conf_req`.
        flags |= CtxFlags::GSS_C_CONF_FLAG;

        // Add GSS_C_DCE_STYLE flag when configured (default: true for DCE/RPC)
        if self.config.enable_dce_style {
            // DCE_STYLE (0x1000) selects the DCE/RPC three-leg handshake and its
            // IOV buffer rules. libgssapi's CtxFlags has no name for it, so OR it
            // in with from_bits_retain.
            let flags_with_dce = flags.bits() | GSS_C_DCE_STYLE;
            flags = CtxFlags::from_bits_retain(flags_with_dce);

            #[cfg(feature = "trace")]
            debug!(target: "kerbsec::gss", flags = format_args!("{:#x}", flags.bits()), "context flags with DCE_STYLE");
        }

        // Initialize context - API changed in libgssapi 0.9.1
        let mut ctx = ClientCtx::new(Some(cred), target, flags, Some(&GSS_MECH_KRB5));

        let channel_binding_data = self.channel_binding_data()?;

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
        if self.established {
            return Err(Error::HandshakeState("context is already established"));
        }
        let channel_binding_data = self.channel_binding_data()?;
        let ctx = self.inner.as_mut().ok_or(Error::HandshakeState(
            "accept_ap_rep called before initial_token",
        ))?;

        let token = match ctx.step(Some(ap_rep), channel_binding_data.as_deref()) {
            Ok(token) => token,
            Err(e) => {
                #[cfg(feature = "trace")]
                error!(target: "kerbsec::gss", error = %e, "failed to process AP-REP");
                return Err(gss_error(e));
            }
        };

        if !ctx.is_complete() {
            // DCE/RPC is a fixed 3-leg exchange; a further round trip means the
            // peer did not behave like one. Don't report it as established.
            #[cfg(feature = "trace")]
            warn!(target: "kerbsec::gss", "AP-REP accepted but context not complete");
            return Err(Error::HandshakeState(
                "context not complete after AP-REP; expected a 3-leg exchange",
            ));
        }

        // Query the flags the mechanism actually negotiated, not what we
        // requested. Failing to learn them is an error: assuming the requested
        // flags were granted would fail open.
        let negotiated_flags = ctx.flags().map_err(gss_error)?.bits();
        if let Err(e) = verify_negotiated_flags(&self.config, negotiated_flags) {
            // Don't leave a context with weaker protection than configured
            // around where it could be wrapped/unwrapped through.
            self.inner = None;
            return Err(e);
        }

        self.established = true;
        self.delegation_negotiated = (negotiated_flags & GSS_C_DELEG_FLAG) != 0;

        #[cfg(feature = "trace")]
        {
            info!(
                target: "kerbsec::gss",
                flags = format_args!("{:#x}", negotiated_flags),
                delegation = self.delegation_negotiated,
                mutual = (negotiated_flags & GSS_C_MUTUAL_FLAG) != 0,
                confidentiality = (negotiated_flags & GSS_C_CONF_FLAG) != 0,
                integrity = (negotiated_flags & GSS_C_INTEG_FLAG) != 0,
                "GSS context established"
            );

            // Delegation is best-effort: warn if requested but not granted
            if self.config.enable_delegation && !self.delegation_negotiated {
                warn!(
                    target: "kerbsec::gss",
                    "delegation was requested but not granted by server"
                );
            }
        }

        // DCE requires sending third leg even if empty
        Ok(Some(token.map_or_else(Vec::new, |t| t.to_vec())))
    }

    /// Check if the security context is fully established
    #[must_use]
    pub const fn established(&self) -> bool {
        self.established
    }

    /// Wrap PDU with IOV-like interface for DCE/RPC
    ///
    /// Uses native GSS IOV on Linux with the `iov` feature, otherwise regular
    /// `gss_wrap`. Requesting [`AuthLevel::Privacy`] fails if the mechanism does
    /// not actually encrypt.
    pub fn wrap_iov(&mut self, pdu: &[u8], level: AuthLevel) -> Result<IovWrap> {
        let ctx = self.inner.as_mut().ok_or(Error::NotEstablished)?;

        if !self.established {
            return Err(Error::NotEstablished);
        }

        let conf_req = matches!(level, AuthLevel::Privacy);

        super::gss_iov::wrap_iov_real(ctx, pdu, conf_req)
    }

    /// Unwrap a complete `gss_wrap` token
    ///
    /// Concatenated `IovWrap` fragments (header, payload, trailer) are a valid
    /// token. If the context was configured for [`AuthLevel::Privacy`], a token
    /// that was not encrypted is rejected, so a peer cannot downgrade the
    /// session to integrity-only.
    pub fn unwrap_iov(&mut self, token: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.inner.as_mut().ok_or(Error::NotEstablished)?;

        if !self.established {
            return Err(Error::NotEstablished);
        }

        let require_conf = matches!(self.config.default_auth, AuthLevel::Privacy);
        super::gss_iov::unwrap_token(ctx, token, require_conf)
    }

    /// Maximum message size that wraps into at most `max_wrapped` bytes
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotEstablished`] before the handshake completes, or a GSS
    /// error if the mechanism cannot answer.
    pub fn wrap_size_limit(&self, max_wrapped: usize, conf_req: bool) -> Result<usize> {
        let ctx = self.inner.as_ref().ok_or(Error::NotEstablished)?;
        if !self.established {
            return Err(Error::NotEstablished);
        }
        super::gss_iov::wrap_size_limit_real(ctx, conf_req, max_wrapped)
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

/// Make `var` (a Kerberos credential-source variable) equal `wanted`
///
/// Sets it if unset; accepts it if already equal; otherwise errors, because
/// GSS-API would use the other value for every context in the process.
fn apply_cred_env(var: &str, wanted: &str) -> Result<()> {
    // A poisoned lock only means another thread panicked mid-check; the guarded
    // data is `()`, so continuing is sound.
    let _guard = CRED_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    match std::env::var_os(var) {
        Some(current) if current == std::ffi::OsStr::new(wanted) => Ok(()),
        Some(current) => Err(Error::Config(format!(
            "{var} is already set to '{}' for this process, which conflicts with the \
             configured value '{wanted}'; GSS-API credentials are process-global",
            current.to_string_lossy()
        ))),
        None => {
            // SAFETY: access is serialized against other kerbsec callers by
            // CRED_ENV_LOCK. Mutating the environment is still unsound if unrelated
            // threads read it concurrently, so set the variable before starting
            // threads (or in the launching environment) in multi-threaded programs.
            unsafe { std::env::set_var(var, wanted) };
            #[cfg(feature = "trace")]
            debug!(target: "kerbsec::gss", var, value = wanted, "set credential environment variable");
            Ok(())
        }
    }
}

/// The service principal to authenticate to: `spn[@realm]`
///
/// The SPN is the configured override, or `HOST/<fqdn>`. The configured realm is
/// appended unless the SPN already names one.
fn target_principal(config: &KerberosConfig) -> String {
    let spn = config
        .spn_override
        .clone()
        .unwrap_or_else(|| format!("HOST/{}", config.target_fqdn));
    if spn.contains('@') {
        spn
    } else {
        format!("{spn}@{}", config.realm)
    }
}

/// Check the negotiated flags against what the configuration requires.
///
/// Integrity is always required. Mutual authentication, confidentiality (for
/// `AuthLevel::Privacy`) and DCE style are required when configured. Delegation
/// is deliberately not enforced: it is best-effort and reported separately.
const fn verify_negotiated_flags(config: &KerberosConfig, flags: u32) -> Result<()> {
    if flags & GSS_C_INTEG_FLAG == 0 {
        return Err(Error::FlagNotNegotiated("integrity"));
    }
    if config.require_mutual_auth && flags & GSS_C_MUTUAL_FLAG == 0 {
        return Err(Error::FlagNotNegotiated("mutual authentication"));
    }
    if matches!(config.default_auth, AuthLevel::Privacy) && flags & GSS_C_CONF_FLAG == 0 {
        return Err(Error::FlagNotNegotiated("confidentiality"));
    }
    if config.enable_dce_style && flags & GSS_C_DCE_STYLE == 0 {
        return Err(Error::FlagNotNegotiated("DCE style"));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config(spn_override: Option<&str>) -> KerberosConfig {
        KerberosConfig::builder()
            .realm("CORP.EXAMPLE.COM")
            .target_host("web.corp.example.com")
            .spn_override(spn_override.map(str::to_owned))
            .build()
            .expect("config")
    }

    #[test]
    fn default_principal_is_host_spn_in_configured_realm() {
        assert_eq!(
            target_principal(&config(None)),
            "HOST/web.corp.example.com@CORP.EXAMPLE.COM"
        );
    }

    #[test]
    fn override_gets_realm_appended() {
        assert_eq!(
            target_principal(&config(Some("HTTP/api.corp.example.com"))),
            "HTTP/api.corp.example.com@CORP.EXAMPLE.COM"
        );
    }

    #[test]
    fn override_with_realm_is_kept() {
        assert_eq!(
            target_principal(&config(Some("cifs/fs.other.example@OTHER.EXAMPLE"))),
            "cifs/fs.other.example@OTHER.EXAMPLE"
        );
    }

    #[test]
    fn cred_env_is_set_once_and_conflicts_are_errors() {
        // A variable unique to this test so parallel tests don't interact with it
        const VAR: &str = "KERBSEC_TEST_CRED_ENV";
        std::env::remove_var(VAR);

        apply_cred_env(VAR, "FILE:/tmp/a").expect("first set");
        assert_eq!(std::env::var(VAR).as_deref(), Ok("FILE:/tmp/a"));
        apply_cred_env(VAR, "FILE:/tmp/a").expect("same value is fine");

        let err = apply_cred_env(VAR, "FILE:/tmp/b").expect_err("different value conflicts");
        assert!(matches!(err, Error::Config(_)), "{err:?}");
        assert_eq!(
            std::env::var(VAR).as_deref(),
            Ok("FILE:/tmp/a"),
            "unchanged"
        );

        std::env::remove_var(VAR);
    }
}
