//! Security context abstractions for GSS-API operations
//!
//! This module provides the low-level GSS-API integration for Unix platforms.
//! It includes platform-specific implementations for Linux (with IOV) and
//! macOS (with fallback), handling the differences between MIT Kerberos
//! and Heimdal implementations.
//!
//! The main types are:
//! - [`IovWrap`] for IOV buffer management
//! - [`Oid`] for mechanism identifiers
//! - Platform-specific GSS context wrappers
//!

#[cfg(unix)]
pub mod gss;

#[cfg(unix)]
pub mod gss_iov;

pub mod zeroize;

use bytes::Bytes;

/// IOV wrap result containing header and trailer fragments
#[derive(Debug, Clone)]
pub struct IovWrap {
    /// GSS header fragment (goes before/in RPC verifier)
    pub header: Bytes,
    /// GSS-wrapped payload (plaintext or ciphertext depending on `conf`)
    pub payload: Bytes,
    /// GSS trailer (MIC or encrypted, goes in auth trailer)
    pub trailer: Bytes,
    /// True if Privacy (sealed), false if Integrity (MIC only)
    pub conf: bool,
}

/// Object Identifier for mechanisms
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Oid {
    dotted: &'static str,
    der: &'static [u8],
}

impl Oid {
    /// Create a new OID with dotted notation and DER encoding
    #[must_use]
    pub const fn new(dotted: &'static str, der: &'static [u8]) -> Self {
        Self { dotted, der }
    }

    /// Get the dotted notation string
    #[must_use]
    pub const fn dotted(&self) -> &'static str {
        self.dotted
    }

    /// Get the DER-encoded bytes
    #[must_use]
    pub const fn der(&self) -> &'static [u8] {
        self.der
    }
}

/// Kerberos V5 mechanism OID
pub const KRB5_MECH_OID: Oid = Oid::new(
    "1.2.840.113554.1.2.2",
    &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02,
    ],
);
