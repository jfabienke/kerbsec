//! Configuration types and builder for Kerberos contexts
//!
//! This module provides the configuration structures needed to establish
//! Kerberos security contexts for DCE/RPC authentication. The primary
//! entry point is [`KerberosConfigBuilder`] which provides a fluent API
//! for constructing configurations with sensible defaults.
//!
//! # Example
//!
//! ```no_run
//! use kerbsec::{KerberosConfig, AuthLevel};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = KerberosConfig::builder()
//!     .realm("CORP.EXAMPLE.COM")
//!     .target_host("server.example.com")
//!     .default_auth(AuthLevel::Privacy)
//!     .build_async()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};
use std::net::SocketAddr;
use std::time::Duration;

#[cfg(feature = "trace")]
use tracing::{debug, instrument, warn};

// ============================================================================
// SPN Helpers
// ============================================================================

/// Common Windows service classes for SPN construction
///
/// These are the standard service class prefixes used in Windows AD
/// for different types of services.
///
/// # Example
///
/// ```
/// use kerbsec::ServiceClass;
///
/// // Build SPN for a web server
/// let http_spn = ServiceClass::Http.spn("web.example.com");
/// assert_eq!(http_spn, "HTTP/web.example.com");
///
/// // Build SPN for SQL Server with port
/// let sql_spn = ServiceClass::MsSql.spn_with_port("sql.example.com", 1433);
/// assert_eq!(sql_spn, "MSSQLSvc/sql.example.com:1433");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceClass {
    /// Generic host service (HOST/) - registered for all Windows machines
    Host,
    /// HTTP/HTTPS web services (HTTP/)
    Http,
    /// SQL Server (`MSSQLSvc/`)
    MsSql,
    /// LDAP/Active Directory (LDAP/)
    Ldap,
    /// Windows file shares (cifs/)
    Cifs,
    /// Exchange/SMTP (SMTP/)
    Smtp,
    /// Hyper-V replication (Hyper-V Replica Broker/)
    HyperV,
    /// Windows Remote Management (WSMAN/)
    WsMan,
    /// Terminal Services/Remote Desktop (TERMSRV/)
    TerminalServices,
    /// DNS (DNS/)
    Dns,
    /// Custom service class
    Custom(String),
}

impl ServiceClass {
    /// Get the SPN prefix for this service class
    #[must_use]
    pub fn prefix(&self) -> &str {
        match self {
            Self::Host => "HOST",
            Self::Http => "HTTP",
            Self::MsSql => "MSSQLSvc",
            Self::Ldap => "LDAP",
            Self::Cifs => "cifs",
            Self::Smtp => "SMTP",
            Self::HyperV => "Hyper-V Replica Broker",
            Self::WsMan => "WSMAN",
            Self::TerminalServices => "TERMSRV",
            Self::Dns => "DNS",
            Self::Custom(s) => s,
        }
    }

    /// Build an SPN for a given hostname
    #[must_use]
    pub fn spn(&self, hostname: &str) -> String {
        format!("{}/{}", self.prefix(), hostname)
    }

    /// Build an SPN with a port number (for services like SQL Server)
    #[must_use]
    pub fn spn_with_port(&self, hostname: &str, port: u16) -> String {
        format!("{}/{}:{}", self.prefix(), hostname, port)
    }

    /// Build an SPN with an explicit realm
    #[must_use]
    pub fn spn_with_realm(&self, hostname: &str, realm: &str) -> String {
        format!("{}/{}@{}", self.prefix(), hostname, realm)
    }

    /// Build a full SPN with port and realm
    #[must_use]
    pub fn spn_full(&self, hostname: &str, port: u16, realm: &str) -> String {
        format!("{}/{}:{}@{}", self.prefix(), hostname, port, realm)
    }
}

// ============================================================================
// Authentication Level
// ============================================================================

/// Authentication protection level for Kerberos/GSS operations
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum AuthLevel {
    /// Message Integrity Code (MIC) only - authenticates but doesn't encrypt
    Integrity,
    /// Seal + MIC - both encrypts and authenticates messages
    #[default]
    Privacy,
}

/// Channel bindings for mutual authentication
///
/// This supports both legacy address-based bindings and modern TLS-based bindings.
/// When the channel-bindings feature is enabled, this wraps the enhanced implementation.
#[derive(Clone, Debug, Default)]
pub struct ChannelBindings {
    /// Address of the context initiator (client)
    pub initiator_addr: Option<SocketAddr>,
    /// Address of the context acceptor (server)
    pub acceptor_addr: Option<SocketAddr>,
    /// Optional application-specific binding data
    pub application_data: Option<Vec<u8>>,

    /// Enhanced TLS channel bindings (when feature enabled)
    #[cfg(feature = "channel-bindings")]
    pub tls_bindings: Option<crate::channel_bindings::ChannelBindings>,
}

impl ChannelBindings {
    /// Create channel bindings from TLS data
    #[cfg(feature = "channel-bindings")]
    #[must_use]
    pub fn from_tls(tls_bindings: crate::channel_bindings::ChannelBindings) -> Self {
        Self {
            initiator_addr: tls_bindings.initiator_addr,
            acceptor_addr: tls_bindings.acceptor_addr,
            application_data: tls_bindings
                .application_data
                .as_ref()
                .map(|buf| buf.as_ref().to_vec()),
            tls_bindings: Some(tls_bindings),
        }
    }

    /// Get the channel binding data for GSS-API
    #[must_use]
    pub fn get_gss_data(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "channel-bindings")]
        if let Some(ref tls) = self.tls_bindings {
            if let Some(ref data) = tls.application_data {
                return Some(data.as_ref().to_vec());
            }
        }

        self.application_data.clone()
    }
}

/// Kerberos configuration for GSS context
#[derive(Clone, Debug)]
pub struct KerberosConfig {
    /// Kerberos realm (e.g., "EXAMPLE.COM")
    pub realm: String,
    /// Target server's fully-qualified domain name (canonicalized via DNS)
    pub target_fqdn: String,
    /// Override Service Principal Name (required for IP address targets)
    pub spn_override: Option<String>,
    /// Default authentication level for wrapped messages
    pub default_auth: AuthLevel,
    /// Timeout for DNS resolution operations
    pub dns_timeout: Duration,
    /// Path to Kerberos credential cache (honors KRB5CCNAME environment variable)
    pub kccache: Option<String>,
    /// Path to Kerberos keytab file (for service accounts)
    ///
    /// When set, credentials will be acquired from this keytab instead of
    /// the default credential cache. This is useful for service accounts
    /// that authenticate using a keytab rather than interactive login.
    ///
    /// The keytab must contain keys for the service principal you're
    /// authenticating as.
    ///
    /// # Environment Variable
    ///
    /// If not set, honors the `KRB5_CLIENT_KTNAME` environment variable. (`KRB5_KTNAME` is the
    /// *acceptor* keytab and is deliberately not used for client credentials.)
    pub keytab: Option<String>,
    /// Optional channel bindings for enhanced security
    pub channel_bindings: Option<ChannelBindings>,
    /// Enable `GSS_C_DCE_STYLE` flag for DCE/RPC compatibility
    ///
    /// When enabled, this flag:
    /// - Selects the DCE/RPC three-leg handshake and relaxed IOV padding/trailer rules
    /// - Does not disable sequence/replay detection
    ///
    /// Default: true (recommended for DCE/RPC)
    pub enable_dce_style: bool,
    /// Enable credential delegation (`GSS_C_DELEG_FLAG`)
    ///
    /// When enabled, allows the server to impersonate the client
    /// for accessing other services (S4U2Self/S4U2Proxy scenarios).
    ///
    /// Default: false (for security)
    pub enable_delegation: bool,
    /// Require mutual authentication (`GSS_C_MUTUAL_FLAG`)
    ///
    /// Already enabled by default for security, but exposed
    /// for cases where you might need to disable it (not recommended).
    ///
    /// Default: true
    pub require_mutual_auth: bool,
}

impl KerberosConfig {
    /// Create a builder for fluent configuration
    #[must_use]
    pub fn builder() -> KerberosConfigBuilder {
        KerberosConfigBuilder::default()
    }
}

/// Builder for `KerberosConfig` with sensible defaults
#[derive(Debug)]
pub struct KerberosConfigBuilder {
    realm: Option<String>,
    target_host: Option<String>,
    spn_override: Option<String>,
    default_auth: AuthLevel,
    dns_timeout: Duration,
    kccache: Option<String>,
    keytab: Option<String>,
    channel_bindings: Option<ChannelBindings>,
    enable_dce_style: bool,
    enable_delegation: bool,
    require_mutual_auth: bool,
}

impl Default for KerberosConfigBuilder {
    fn default() -> Self {
        Self {
            realm: None,
            target_host: None,
            spn_override: None,
            default_auth: AuthLevel::Privacy,
            dns_timeout: Duration::from_secs(5),
            kccache: None,
            keytab: None,
            channel_bindings: None,
            enable_dce_style: true,    // Default true for DCE/RPC
            enable_delegation: false,  // Default false for security
            require_mutual_auth: true, // Default true for security
        }
    }
}

impl KerberosConfigBuilder {
    /// Create a new builder with defaults
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Kerberos realm
    #[must_use]
    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Set the target hostname (will be canonicalized)
    #[must_use]
    pub fn target_host(mut self, host: impl Into<String>) -> Self {
        self.target_host = Some(host.into());
        self
    }

    /// Override the SPN (required for IP addresses)
    #[must_use]
    pub fn spn_override(mut self, spn: Option<String>) -> Self {
        self.spn_override = spn;
        self
    }

    /// Set the default authentication level
    #[must_use]
    pub const fn default_auth(mut self, level: AuthLevel) -> Self {
        self.default_auth = level;
        self
    }

    /// Set the DNS resolution timeout
    #[must_use]
    pub const fn dns_timeout(mut self, timeout: Duration) -> Self {
        self.dns_timeout = timeout;
        self
    }

    /// Set the credential cache path
    #[must_use]
    pub fn kccache(mut self, path: Option<String>) -> Self {
        self.kccache = path;
        self
    }

    /// Set the keytab file path for service account authentication
    ///
    /// Keytabs are used for non-interactive authentication, typically for
    /// service accounts or daemons that need to authenticate without user
    /// intervention.
    ///
    /// # Example
    ///
    /// ```
    /// use kerbsec::KerberosConfig;
    ///
    /// let config = KerberosConfig::builder()
    ///     .realm("CORP.EXAMPLE.COM")
    ///     .target_host("server.example.com")
    ///     .keytab(Some("/etc/krb5.keytab".to_string()))
    ///     .build();
    /// ```
    ///
    /// # Note
    ///
    /// If both `kccache` and `keytab` are set, the credential cache takes
    /// precedence and the keytab is used as a fallback.
    #[must_use]
    pub fn keytab(mut self, path: Option<String>) -> Self {
        self.keytab = path;
        self
    }

    /// Set channel bindings
    #[must_use]
    pub fn channel_bindings(mut self, cb: Option<ChannelBindings>) -> Self {
        self.channel_bindings = cb;
        self
    }

    /// Enable or disable `GSS_C_DCE_STYLE` flag
    ///
    /// When enabled (default), this flag:
    /// - Selects the DCE/RPC three-leg handshake and relaxed IOV padding/trailer rules
    /// - Does not disable sequence/replay detection
    ///
    /// You should only disable this if you're not using DCE/RPC.
    #[must_use]
    pub const fn dce_style(mut self, enable: bool) -> Self {
        self.enable_dce_style = enable;
        self
    }

    /// Enable credential delegation (`GSS_C_DELEG_FLAG`)
    ///
    /// When enabled, allows the server to impersonate the client
    /// for accessing other services (S4U2Self/S4U2Proxy scenarios).
    ///
    /// # Security Warning
    ///
    /// Only enable delegation when you trust the server completely,
    /// as it allows the server to act on your behalf.
    #[must_use]
    pub const fn delegation(mut self, enable: bool) -> Self {
        self.enable_delegation = enable;
        self
    }

    /// Require mutual authentication (`GSS_C_MUTUAL_FLAG`)
    ///
    /// Enabled by default for security. Only disable if you have
    /// a specific reason and understand the security implications.
    #[must_use]
    pub const fn mutual_auth(mut self, require: bool) -> Self {
        self.require_mutual_auth = require;
        self
    }

    /// Build config synchronously (requires canonicalized FQDN)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required fields are missing
    /// - IP address target is used without SPN override
    /// - SPN override has invalid format
    #[cfg_attr(
        feature = "trace",
        instrument(target = "kerbsec::config", level = "debug", skip_all)
    )]
    pub fn build(self) -> Result<KerberosConfig> {
        let realm = required("realm", self.realm)?;
        let target_fqdn = normalize_host(&required("target_host", self.target_host)?);

        // Validate SPN format if provided
        if let Some(ref spn) = self.spn_override {
            validate_spn(spn)?;
        }

        // Check if target is IP and requires override
        if is_ip_literal(&target_fqdn) && self.spn_override.is_none() {
            #[cfg(feature = "trace")]
            warn!(target: "kerbsec::config", target = %target_fqdn, "IP target requires SPN override");
            return Err(Error::IpTargetRequiresSpnOverride);
        }

        let config = KerberosConfig {
            realm,
            target_fqdn,
            spn_override: self.spn_override,
            default_auth: self.default_auth,
            dns_timeout: self.dns_timeout,
            kccache: self.kccache.or_else(|| std::env::var("KRB5CCNAME").ok()),
            keytab: self
                .keytab
                .or_else(|| std::env::var("KRB5_CLIENT_KTNAME").ok()),
            channel_bindings: self.channel_bindings,
            enable_dce_style: self.enable_dce_style,
            enable_delegation: self.enable_delegation,
            require_mutual_auth: self.require_mutual_auth,
        };

        #[cfg(feature = "trace")]
        debug!(
            target: "kerbsec::config",
            realm = %config.realm,
            fqdn = %config.target_fqdn,
            has_spn_override = config.spn_override.is_some(),
            auth_level = ?config.default_auth,
            has_ccache = config.kccache.is_some(),
            has_keytab = config.keytab.is_some(),
            "config built successfully"
        );

        Ok(config)
    }

    /// Build with async DNS canonicalization
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required fields are missing
    /// - IP address target is used without SPN override
    /// - SPN override has invalid format
    /// - DNS canonicalization fails
    #[cfg(feature = "dns")]
    #[cfg_attr(
        feature = "trace",
        instrument(target = "kerbsec::config", level = "debug", skip_all)
    )]
    pub async fn build_async(self) -> Result<KerberosConfig> {
        use crate::dns::resolver::canonicalize_fqdn;

        let realm = required("realm", self.realm)?;
        let target_host = normalize_host(&required("target_host", self.target_host)?);

        // Validate SPN format if provided
        if let Some(ref spn) = self.spn_override {
            validate_spn(spn)?;
        }

        // Canonicalize via DNS (CNAME → A/AAAA); IP literals have nothing to resolve
        let target_fqdn = if is_ip_literal(&target_host) {
            target_host.clone()
        } else {
            canonicalize_fqdn(&target_host, self.dns_timeout).await?
        };

        // Check if target is IP and requires override
        if is_ip_literal(&target_fqdn) && self.spn_override.is_none() {
            #[cfg(feature = "trace")]
            warn!(target: "kerbsec::config", target = %target_fqdn, "IP target requires SPN override");
            return Err(Error::IpTargetRequiresSpnOverride);
        }

        let config = KerberosConfig {
            realm,
            target_fqdn,
            spn_override: self.spn_override,
            default_auth: self.default_auth,
            dns_timeout: self.dns_timeout,
            kccache: self.kccache.or_else(|| std::env::var("KRB5CCNAME").ok()),
            keytab: self
                .keytab
                .or_else(|| std::env::var("KRB5_CLIENT_KTNAME").ok()),
            channel_bindings: self.channel_bindings,
            enable_dce_style: self.enable_dce_style,
            enable_delegation: self.enable_delegation,
            require_mutual_auth: self.require_mutual_auth,
        };

        #[cfg(feature = "trace")]
        debug!(
            target: "kerbsec::config",
            realm = %config.realm,
            target_host = %target_host,
            canonical_fqdn = %config.target_fqdn,
            has_spn_override = config.spn_override.is_some(),
            auth_level = ?config.default_auth,
            has_ccache = config.kccache.is_some(),
            has_keytab = config.keytab.is_some(),
            "config built with DNS canonicalization"
        );

        Ok(config)
    }
}

/// A required builder field, trimmed and non-empty
fn required(name: &str, value: Option<String>) -> Result<String> {
    let value = value.ok_or_else(|| Error::Config(format!("{name} is required")))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::Config(format!("{name} cannot be empty")));
    }
    Ok(value.to_owned())
}

/// Normalize a target host: lowercase, no trailing root dot, and no brackets
/// around an IPv6 literal. Applied identically by `build` and `build_async`.
fn normalize_host(host: &str) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.trim_end_matches('.').to_lowercase()
}

/// Whether `host` is an IPv4/IPv6 literal (an IPv6 zone id like `%eth0` is ignored)
fn is_ip_literal(host: &str) -> bool {
    let addr = host.split_once('%').map_or(host, |(addr, _zone)| addr);
    addr.parse::<std::net::IpAddr>().is_ok()
}

/// Validate SPN (Service Principal Name) format
///
/// SPNs must follow the format: `service/hostname[@REALM]`
///
/// # Valid Examples
/// - `HOST/server.example.com`
/// - `HTTP/web.example.com`
/// - `MSSQLSvc/sql.example.com:1433`
/// - `cifs/fileserver.example.com@EXAMPLE.COM`
///
/// # Invalid Examples
/// - `""` (empty)
/// - `invalid` (missing slash)
/// - `/hostname` (missing service)
/// - `SERVICE/` (missing hostname)
fn validate_spn(spn: &str) -> Result<()> {
    if spn.is_empty() {
        return Err(Error::Config("SPN cannot be empty".into()));
    }

    if spn.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::Config(
            "SPN cannot contain whitespace or control characters".into(),
        ));
    }

    if spn.matches('@').count() > 1 {
        return Err(Error::Config("SPN can contain at most one '@'".into()));
    }

    // Remove optional realm suffix for validation
    let spn_without_realm = if let Some(at_pos) = spn.rfind('@') {
        // Ensure realm is not empty
        if at_pos + 1 >= spn.len() {
            return Err(Error::Config("SPN realm cannot be empty after '@'".into()));
        }
        &spn[..at_pos]
    } else {
        spn
    };

    // Check for service/hostname format
    let slash_pos = spn_without_realm.find('/').ok_or_else(|| {
        Error::Config("SPN must contain '/' separator (format: service/hostname)".into())
    })?;

    // Service part must not be empty
    if slash_pos == 0 {
        return Err(Error::Config(
            "SPN service part cannot be empty (before '/')".into(),
        ));
    }

    // Hostname part must not be empty
    let hostname = &spn_without_realm[slash_pos + 1..];
    if hostname.is_empty() {
        return Err(Error::Config(
            "SPN hostname part cannot be empty (after '/')".into(),
        ));
    }

    // A trailing ':' means an empty port
    if hostname.ends_with(':') {
        return Err(Error::Config("SPN port cannot be empty after ':'".into()));
    }

    // Check for double slashes
    if spn_without_realm.contains("//") {
        return Err(Error::Config(
            "SPN cannot contain '//' (double slash)".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_spns() {
        assert!(validate_spn("HOST/server.example.com").is_ok());
        assert!(validate_spn("HTTP/web.example.com").is_ok());
        assert!(validate_spn("MSSQLSvc/sql.example.com:1433").is_ok());
        assert!(validate_spn("cifs/fileserver.example.com@EXAMPLE.COM").is_ok());
        assert!(validate_spn("service/host").is_ok());
    }

    #[test]
    fn test_invalid_spns() {
        // Empty SPN
        assert!(validate_spn("").is_err());

        // Missing slash
        assert!(validate_spn("invalid").is_err());

        // Missing service
        assert!(validate_spn("/hostname").is_err());

        // Missing hostname
        assert!(validate_spn("SERVICE/").is_err());

        // Double slash
        assert!(validate_spn("SERVICE//hostname").is_err());

        // Empty realm
        assert!(validate_spn("SERVICE/hostname@").is_err());
    }

    #[test]
    fn test_service_class_spn_construction() {
        assert_eq!(
            ServiceClass::Host.spn("server.example.com"),
            "HOST/server.example.com"
        );
        assert_eq!(
            ServiceClass::Http.spn("web.example.com"),
            "HTTP/web.example.com"
        );
        assert_eq!(
            ServiceClass::Ldap.spn("dc.example.com"),
            "LDAP/dc.example.com"
        );
        assert_eq!(
            ServiceClass::Cifs.spn("fileserver.example.com"),
            "cifs/fileserver.example.com"
        );
    }

    #[test]
    fn test_service_class_spn_with_port() {
        assert_eq!(
            ServiceClass::MsSql.spn_with_port("sql.example.com", 1433),
            "MSSQLSvc/sql.example.com:1433"
        );
        assert_eq!(
            ServiceClass::Http.spn_with_port("web.example.com", 8443),
            "HTTP/web.example.com:8443"
        );
    }

    #[test]
    fn test_service_class_spn_with_realm() {
        assert_eq!(
            ServiceClass::Http.spn_with_realm("web.example.com", "EXAMPLE.COM"),
            "HTTP/web.example.com@EXAMPLE.COM"
        );
    }

    #[test]
    fn test_service_class_spn_full() {
        assert_eq!(
            ServiceClass::MsSql.spn_full("sql.example.com", 1433, "EXAMPLE.COM"),
            "MSSQLSvc/sql.example.com:1433@EXAMPLE.COM"
        );
    }

    #[test]
    fn test_service_class_custom() {
        let custom = ServiceClass::Custom("MYSERVICE".to_string());
        assert_eq!(custom.prefix(), "MYSERVICE");
        assert_eq!(
            custom.spn("server.example.com"),
            "MYSERVICE/server.example.com"
        );
    }

    #[test]
    fn test_stricter_spn_validation() {
        assert!(validate_spn("HOST/a b.example.com").is_err());
        assert!(validate_spn("HOST/host\n").is_err());
        assert!(validate_spn("HOST/h@A@B").is_err());
        assert!(validate_spn("MSSQLSvc/sql.example.com:").is_err());
    }

    #[test]
    fn test_required_fields_reject_empty() {
        assert!(required("realm", None).is_err());
        assert!(required("realm", Some("  ".into())).is_err());
        assert_eq!(
            required("realm", Some(" EX.COM ".into())).unwrap(),
            "EX.COM"
        );
    }

    #[test]
    fn test_host_normalization_and_ip_detection() {
        assert_eq!(normalize_host("Web.Example.COM."), "web.example.com");
        assert_eq!(normalize_host("[::1]"), "::1");
        assert!(is_ip_literal("192.0.2.1"));
        assert!(is_ip_literal("::1"));
        assert!(is_ip_literal("fe80::1%eth0"));
        assert!(!is_ip_literal("web.example.com"));
    }

    #[test]
    fn test_build_normalizes_host_and_rejects_empty() {
        let cfg = KerberosConfig::builder()
            .realm("EX.COM")
            .target_host("Web.Example.Com.")
            .build()
            .unwrap();
        assert_eq!(cfg.target_fqdn, "web.example.com");

        assert!(KerberosConfig::builder()
            .realm("EX.COM")
            .target_host("")
            .build()
            .is_err());
        assert!(KerberosConfig::builder()
            .realm(" ")
            .target_host("h.ex.com")
            .build()
            .is_err());
        assert!(matches!(
            KerberosConfig::builder()
                .realm("EX.COM")
                .target_host("[::1]")
                .build(),
            Err(Error::IpTargetRequiresSpnOverride)
        ));
    }
}
