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
//! use fabi_kerbsec::{KerberosConfig, AuthLevel};
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
// Encryption Types
// ============================================================================

/// Kerberos encryption types for Windows AD compatibility
///
/// These encryption types are listed in order of preference (strongest first).
/// Windows AD supports these encryption types, with AES being preferred.
///
/// # Security Note
///
/// RC4-HMAC (etype 23) is **disabled by default** because:
/// - It uses the weak RC4 cipher which has known cryptographic weaknesses
/// - Microsoft has deprecated RC4 in favor of AES
/// - It's vulnerable to various attacks including related-key attacks
///
/// Only enable RC4 via the `allow-weak-crypto` feature if you must support
/// legacy Windows systems (pre-2008 R2) that don't support AES.
///
/// DES encryption types are **not supported** at all as they are completely broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EncryptionType {
    /// AES-256 with CTS mode and HMAC-SHA1-96 (RFC 3962)
    /// Strongest widely-deployed encryption, Windows AD preferred
    Aes256CtsHmacSha196 = 18,

    /// AES-128 with CTS mode and HMAC-SHA1-96 (RFC 3962)
    /// Good security, widely supported
    Aes128CtsHmacSha196 = 17,

    /// AES-256 with CTS mode and HMAC-SHA384-192 (RFC 8009)
    /// Newer, stronger variant - requires Windows Server 2019+
    Aes256CtsHmacSha384192 = 20,

    /// AES-128 with CTS mode and HMAC-SHA256-128 (RFC 8009)
    /// Newer variant - requires Windows Server 2019+
    Aes128CtsHmacSha256128 = 19,

    /// Triple-DES with CBC mode and SHA1 (deprecated but still seen)
    /// Only for compatibility with very old systems
    Des3CbcSha1 = 16,

    /// RC4-HMAC (deprecated, requires `allow-weak-crypto` feature)
    ///
    /// # Security Warning
    ///
    /// RC4 is cryptographically weak and should not be used unless absolutely
    /// necessary for legacy system compatibility. Known issues:
    /// - Statistical biases in keystream
    /// - Vulnerable to related-key attacks
    /// - No longer considered secure by NIST, Microsoft, or security researchers
    ///
    /// This encryption type is only available with the `allow-weak-crypto` feature.
    #[cfg(feature = "allow-weak-crypto")]
    Rc4Hmac = 23,
}

impl EncryptionType {
    /// Get the numeric etype value
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Get the human-readable name
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Aes256CtsHmacSha196 => "aes256-cts-hmac-sha1-96",
            Self::Aes128CtsHmacSha196 => "aes128-cts-hmac-sha1-96",
            Self::Aes256CtsHmacSha384192 => "aes256-cts-hmac-sha384-192",
            Self::Aes128CtsHmacSha256128 => "aes128-cts-hmac-sha256-128",
            Self::Des3CbcSha1 => "des3-cbc-sha1",
            #[cfg(feature = "allow-weak-crypto")]
            Self::Rc4Hmac => "rc4-hmac",
        }
    }

    /// Get the default encryption types for Windows AD
    ///
    /// Returns the recommended encryption types in preference order.
    /// AES-256 is preferred, followed by AES-128, then 3DES for compatibility.
    #[must_use]
    pub fn default_etypes() -> Vec<Self> {
        vec![
            Self::Aes256CtsHmacSha196,
            Self::Aes128CtsHmacSha196,
            Self::Aes256CtsHmacSha384192,
            Self::Aes128CtsHmacSha256128,
            Self::Des3CbcSha1,
        ]
    }

    /// Get encryption types for legacy Windows AD environments
    ///
    /// Includes RC4-HMAC for compatibility with older systems.
    /// Only available with the `allow-weak-crypto` feature.
    #[cfg(feature = "allow-weak-crypto")]
    #[must_use]
    pub fn legacy_etypes() -> Vec<Self> {
        vec![
            Self::Aes256CtsHmacSha196,
            Self::Aes128CtsHmacSha196,
            Self::Rc4Hmac,
            Self::Des3CbcSha1,
        ]
    }
}

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
/// use fabi_kerbsec::ServiceClass;
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
    /// Timeout for GSS-API operations
    pub gss_timeout: Duration,
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
    /// If not set, honors `KRB5_CLIENT_KTNAME` or `KRB5_KTNAME` environment variables.
    pub keytab: Option<String>,
    /// Optional channel bindings for enhanced security
    pub channel_bindings: Option<ChannelBindings>,
    /// Enable `GSS_C_DCE_STYLE` flag for DCE/RPC compatibility
    ///
    /// When enabled, this flag:
    /// - Disables GSS sequence number checking (DCE has its own)
    /// - Allows out-of-order message processing
    /// - Prevents GSS replay cache from interfering with DCE/RPC
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
    gss_timeout: Duration,
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
            gss_timeout: Duration::from_secs(30),
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

    /// Set the GSS-API operation timeout
    #[must_use]
    pub const fn gss_timeout(mut self, timeout: Duration) -> Self {
        self.gss_timeout = timeout;
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
    /// use fabi_kerbsec::KerberosConfig;
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
    /// - Disables GSS sequence number checking (DCE has its own)
    /// - Allows out-of-order message processing
    /// - Prevents GSS replay cache from interfering with DCE/RPC
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
        let realm = self
            .realm
            .ok_or_else(|| Error::Config("realm is required".into()))?;
        let target_fqdn = self
            .target_host
            .ok_or_else(|| Error::Config("target_host is required".into()))?;

        // Validate SPN format if provided
        if let Some(ref spn) = self.spn_override {
            validate_spn(spn)?;
        }

        // Check if target is IP and requires override
        if target_fqdn.parse::<std::net::IpAddr>().is_ok() && self.spn_override.is_none() {
            #[cfg(feature = "trace")]
            warn!(target: "kerbsec::config", target = %target_fqdn, "IP target requires SPN override");
            return Err(Error::IpTargetRequiresSpnOverride);
        }

        let config = KerberosConfig {
            realm: realm.clone(),
            target_fqdn: target_fqdn.clone(),
            spn_override: self.spn_override,
            default_auth: self.default_auth,
            dns_timeout: self.dns_timeout,
            gss_timeout: self.gss_timeout,
            kccache: self.kccache.or_else(|| std::env::var("KRB5CCNAME").ok()),
            keytab: self
                .keytab
                .or_else(|| std::env::var("KRB5_CLIENT_KTNAME").ok())
                .or_else(|| std::env::var("KRB5_KTNAME").ok()),
            channel_bindings: self.channel_bindings,
            enable_dce_style: self.enable_dce_style,
            enable_delegation: self.enable_delegation,
            require_mutual_auth: self.require_mutual_auth,
        };

        #[cfg(feature = "trace")]
        debug!(
            target: "kerbsec::config",
            realm = %realm,
            fqdn = %target_fqdn,
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

        let realm = self
            .realm
            .ok_or_else(|| Error::Config("realm is required".into()))?;
        let target_host = self
            .target_host
            .ok_or_else(|| Error::Config("target_host is required".into()))?;

        // Validate SPN format if provided
        if let Some(ref spn) = self.spn_override {
            validate_spn(spn)?;
        }

        // Canonicalize via DNS (CNAME → A/AAAA)
        let target_fqdn = canonicalize_fqdn(&target_host, self.dns_timeout).await?;

        // Check if target is IP and requires override
        if target_fqdn.parse::<std::net::IpAddr>().is_ok() && self.spn_override.is_none() {
            #[cfg(feature = "trace")]
            warn!(target: "kerbsec::config", target = %target_fqdn, "IP target requires SPN override");
            return Err(Error::IpTargetRequiresSpnOverride);
        }

        let config = KerberosConfig {
            realm: realm.clone(),
            target_fqdn: target_fqdn.clone(),
            spn_override: self.spn_override,
            default_auth: self.default_auth,
            dns_timeout: self.dns_timeout,
            gss_timeout: self.gss_timeout,
            kccache: self.kccache.or_else(|| std::env::var("KRB5CCNAME").ok()),
            keytab: self
                .keytab
                .or_else(|| std::env::var("KRB5_CLIENT_KTNAME").ok())
                .or_else(|| std::env::var("KRB5_KTNAME").ok()),
            channel_bindings: self.channel_bindings,
            enable_dce_style: self.enable_dce_style,
            enable_delegation: self.enable_delegation,
            require_mutual_auth: self.require_mutual_auth,
        };

        #[cfg(feature = "trace")]
        debug!(
            target: "kerbsec::config",
            realm = %realm,
            target_host = %target_host,
            canonical_fqdn = %target_fqdn,
            has_spn_override = config.spn_override.is_some(),
            auth_level = ?config.default_auth,
            has_ccache = config.kccache.is_some(),
            has_keytab = config.keytab.is_some(),
            "config built with DNS canonicalization"
        );

        Ok(config)
    }
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
    fn test_encryption_type_values() {
        assert_eq!(EncryptionType::Aes256CtsHmacSha196.as_u16(), 18);
        assert_eq!(EncryptionType::Aes128CtsHmacSha196.as_u16(), 17);
        assert_eq!(EncryptionType::Aes256CtsHmacSha384192.as_u16(), 20);
        assert_eq!(EncryptionType::Aes128CtsHmacSha256128.as_u16(), 19);
        assert_eq!(EncryptionType::Des3CbcSha1.as_u16(), 16);
    }

    #[test]
    fn test_encryption_type_names() {
        assert_eq!(
            EncryptionType::Aes256CtsHmacSha196.name(),
            "aes256-cts-hmac-sha1-96"
        );
        assert_eq!(
            EncryptionType::Aes128CtsHmacSha196.name(),
            "aes128-cts-hmac-sha1-96"
        );
    }

    #[test]
    fn test_default_etypes() {
        let etypes = EncryptionType::default_etypes();
        // AES-256 should be first (preferred)
        assert_eq!(etypes.first(), Some(&EncryptionType::Aes256CtsHmacSha196));
    }

    #[cfg(feature = "allow-weak-crypto")]
    #[test]
    fn test_rc4_available_with_feature() {
        assert_eq!(EncryptionType::Rc4Hmac.as_u16(), 23);
        assert_eq!(EncryptionType::Rc4Hmac.name(), "rc4-hmac");

        let legacy = EncryptionType::legacy_etypes();
        assert!(legacy.contains(&EncryptionType::Rc4Hmac));
    }
}
