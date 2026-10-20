//! kerbsec - Minimal MIT-licensed Kerberos (GSS-API) for DCE/RPC on Unix
//!
//! This crate provides a Kerberos RFC 4121 security context for DCE/RPC transports
//! by leveraging the system GSS-API (MIT Kerberos or Heimdal).
//!
//! Transport-agnostic: users handle RPC framing, kerbsec handles GSS tokens.
//!
//! # Windows Active Directory Compatibility
//!
//! This crate is designed for compatibility with Windows AD environments:
//!
//! - **DCE/RPC Protocol**: Full support via `GSS_C_DCE_STYLE` flag
//! - **Encryption**: AES-256, AES-128 (RC4 available with `allow-weak-crypto` feature)
//! - **SPN Handling**: Helpers for common Windows service classes
//! - **Delegation**: Verified negotiation via `gss_inquire_context`
//!
//! # Security Exclusions
//!
//! The following are **intentionally excluded** for security reasons:
//!
//! ## RC4-HMAC (etype 23)
//!
//! RC4 is disabled by default because:
//! - RC4 has known cryptographic weaknesses (statistical biases in keystream)
//! - Vulnerable to related-key attacks
//! - Microsoft has deprecated RC4 in favor of AES since Windows Server 2008 R2
//! - NIST has removed RC4 from all approved cipher suites
//!
//! If you **must** support legacy systems (pre-Windows Server 2008 R2), enable the
//! `allow-weak-crypto` feature. This is **not recommended** for production.
//!
//! ## DES Encryption (etypes 1, 2, 3)
//!
//! DES encryption types are **not supported at all** because:
//! - 56-bit key size is trivially brute-forceable
//! - Microsoft disabled DES by default in Windows Server 2008 R2
//! - DES was removed from Kerberos standards (RFC 6649)
//!
//! There is no feature flag to enable DES - upgrade your infrastructure instead.
//!
//! ## NTLM Fallback
//!
//! NTLM authentication is **not supported** because:
//! - NTLM is a legacy protocol with multiple security vulnerabilities
//! - Pass-the-hash attacks, relay attacks, and weak challenge-response
//! - Windows has supported Kerberos since Windows 2000
//!
//! Ensure your environment has proper Kerberos infrastructure (DNS, SPNs, etc.)
//!
//! # Example
//!
//! ```no_run
//! use fabi_kerbsec::{Context, KerberosConfig, AuthLevel, ServiceClass};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Build SPN using helper
//! let spn = ServiceClass::Http.spn("web.example.com");
//!
//! let config = KerberosConfig::builder()
//!     .realm("CORP.EXAMPLE.COM")
//!     .target_host("web.example.com")
//!     .spn_override(Some(spn))
//!     .default_auth(AuthLevel::Privacy)
//!     .build_async()
//!     .await?;
//!
//! let mut ctx = Context::new(config)?;
//! let ap_req = ctx.initial_token()?;
//! // Send ap_req to server...
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod context;
pub mod error;

#[cfg(feature = "dns")]
pub mod dns;

#[cfg(all(unix, feature = "iov"))]
pub mod ffi;

#[cfg(feature = "ccache")]
pub mod ccache;

#[cfg(feature = "channel-bindings")]
pub mod channel_bindings;

pub mod security;

// Re-exports
pub use config::{
    AuthLevel, ChannelBindings, EncryptionType, KerberosConfig, KerberosConfigBuilder, ServiceClass,
};
pub use context::Context;
pub use error::{Error, Result};
pub use security::{IovWrap, Oid, KRB5_MECH_OID};
