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
//! - **Encryption**: whatever the system `krb5.conf` permits (AES by default); kerbsec
//!   does not select enctypes itself
//! - **SPN Handling**: Helpers for common Windows service classes
//! - **Delegation**: Verified negotiation via `gss_inquire_context`
//!
//! # Security Exclusions
//!
//! ## Encryption types
//!
//! kerbsec does not choose or restrict Kerberos encryption types: the KDC and the
//! system GSS-API library negotiate them from `krb5.conf` (`permitted_enctypes`,
//! `allow_weak_crypto`, ...). To forbid RC4 or DES, configure that in `krb5.conf`
//! (and on the KDC / service accounts). The resulting protection is enforced
//! at the message level instead: contexts require integrity, and confidentiality
//! when [`AuthLevel::Privacy`] is configured, and fail if the peer does not provide it.
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
//! use kerbsec::{Context, KerberosConfig, AuthLevel, ServiceClass};
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

#[cfg(unix)]
pub mod ffi;

#[cfg(feature = "ccache")]
pub mod ccache;

#[cfg(feature = "channel-bindings")]
pub mod channel_bindings;

pub mod security;

// Re-exports
pub use config::{AuthLevel, ChannelBindings, KerberosConfig, KerberosConfigBuilder, ServiceClass};
pub use context::Context;
pub use error::{Error, Result};
pub use security::{IovWrap, Oid, KRB5_MECH_OID};
