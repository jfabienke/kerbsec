//! TLS Channel Bindings support (RFC 5929, RFC 9266)
//!
//! This module provides support for channel bindings, which bind a GSS-API
//! security context to the underlying TLS channel. This prevents credential
//! forwarding attacks by ensuring that the authentication is tied to the
//! specific TLS connection.

use crate::error::Result;
use crate::security::zeroize::SecureBuffer;
use std::net::SocketAddr;

#[cfg(feature = "channel-bindings-rustls")]
pub mod rustls_extract;

/// Channel binding types defined in RFC 5929 and RFC 9266
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelBindingType {
    /// tls-unique: Uses the TLS Finished message (RFC 5929)
    /// Deprecated in TLS 1.3 due to security concerns
    TlsUnique,

    /// tls-server-end-point: Hash of the server's certificate (RFC 5929)
    /// Works with all TLS versions but provides weaker binding
    TlsServerEndPoint,

    /// tls-exporter: Uses the TLS exporter mechanism (RFC 9266)
    /// Recommended for TLS 1.3 and later
    TlsExporter,
}

impl ChannelBindingType {
    /// Get the GSS-API channel binding type identifier
    #[must_use]
    pub const fn gss_type(&self) -> u32 {
        match self {
            Self::TlsUnique => 0,         // GSS_C_CB_TLS_UNIQUE
            Self::TlsServerEndPoint => 1, // GSS_C_CB_TLS_SERVER_END_POINT
            Self::TlsExporter => 2,       // GSS_C_CB_TLS_EXPORTER
        }
    }

    /// Get the string representation for the binding type
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TlsUnique => "tls-unique",
            Self::TlsServerEndPoint => "tls-server-end-point",
            Self::TlsExporter => "tls-exporter",
        }
    }
}

/// Enhanced channel bindings with TLS support
#[derive(Clone, Debug, Default)]
pub struct ChannelBindings {
    /// Type of channel binding
    pub binding_type: Option<ChannelBindingType>,

    /// Address of the context initiator (client)
    pub initiator_addr: Option<SocketAddr>,

    /// Address of the context acceptor (server)
    pub acceptor_addr: Option<SocketAddr>,

    /// Channel binding data (e.g., TLS exporter output)
    /// This is sensitive data and should be zeroized on drop
    pub application_data: Option<SecureBuffer>,
}

impl ChannelBindings {
    /// Create new channel bindings with TLS data
    #[must_use]
    pub fn new_tls(binding_type: ChannelBindingType, binding_data: Vec<u8>) -> Self {
        Self {
            binding_type: Some(binding_type),
            initiator_addr: None,
            acceptor_addr: None,
            application_data: Some(SecureBuffer::from(binding_data)),
        }
    }

    /// Create channel bindings with addresses
    #[must_use]
    pub const fn new_with_addresses(
        initiator: Option<SocketAddr>,
        acceptor: Option<SocketAddr>,
    ) -> Self {
        Self {
            binding_type: None,
            initiator_addr: initiator,
            acceptor_addr: acceptor,
            application_data: None,
        }
    }

    /// Create TLS channel bindings with addresses
    #[must_use]
    pub fn new_full(
        binding_type: ChannelBindingType,
        binding_data: Vec<u8>,
        initiator: Option<SocketAddr>,
        acceptor: Option<SocketAddr>,
    ) -> Self {
        Self {
            binding_type: Some(binding_type),
            initiator_addr: initiator,
            acceptor_addr: acceptor,
            application_data: Some(SecureBuffer::from(binding_data)),
        }
    }

    /// Convert to GSS-API channel bindings structure
    /// Returns (`initiator_addr`, `acceptor_addr`, `application_data`)
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn to_gss_bindings(&self) -> (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>) {
        let initiator = self.initiator_addr.map(|addr| {
            // Format: address type (2 bytes) + address data
            let mut data = Vec::new();
            match addr {
                SocketAddr::V4(v4) => {
                    data.extend_from_slice(&[0x00, 0x02]); // AF_INET
                    data.extend_from_slice(&v4.ip().octets());
                    data.extend_from_slice(&v4.port().to_be_bytes());
                }
                SocketAddr::V6(v6) => {
                    data.extend_from_slice(&[0x00, 0x18]); // AF_INET6
                    data.extend_from_slice(&v6.ip().octets());
                    data.extend_from_slice(&v6.port().to_be_bytes());
                }
            }
            data
        });

        let acceptor = self.acceptor_addr.map(|addr| {
            let mut data = Vec::new();
            match addr {
                SocketAddr::V4(v4) => {
                    data.extend_from_slice(&[0x00, 0x02]); // AF_INET
                    data.extend_from_slice(&v4.ip().octets());
                    data.extend_from_slice(&v4.port().to_be_bytes());
                }
                SocketAddr::V6(v6) => {
                    data.extend_from_slice(&[0x00, 0x18]); // AF_INET6
                    data.extend_from_slice(&v6.ip().octets());
                    data.extend_from_slice(&v6.port().to_be_bytes());
                }
            }
            data
        });

        let app_data = self
            .application_data
            .as_ref()
            .map(|buf| buf.as_bytes().to_vec());

        (initiator, acceptor, app_data)
    }
}

/// Trait for extracting channel binding data from TLS connections
pub trait TlsChannelBindingExtractor {
    /// Extract channel binding data of the specified type
    fn extract_channel_binding(&self, binding_type: ChannelBindingType) -> Result<Vec<u8>>;

    /// Get the recommended channel binding type for this TLS version
    fn recommended_binding_type(&self) -> ChannelBindingType;

    /// Check if a specific binding type is supported
    fn supports_binding_type(&self, binding_type: ChannelBindingType) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_binding_types() {
        assert_eq!(ChannelBindingType::TlsUnique.as_str(), "tls-unique");
        assert_eq!(
            ChannelBindingType::TlsServerEndPoint.as_str(),
            "tls-server-end-point"
        );
        assert_eq!(ChannelBindingType::TlsExporter.as_str(), "tls-exporter");

        assert_eq!(ChannelBindingType::TlsUnique.gss_type(), 0);
        assert_eq!(ChannelBindingType::TlsServerEndPoint.gss_type(), 1);
        assert_eq!(ChannelBindingType::TlsExporter.gss_type(), 2);
    }

    #[test]
    fn test_channel_bindings_creation() {
        let binding_data = vec![0x01, 0x02, 0x03, 0x04];
        let bindings = ChannelBindings::new_tls(ChannelBindingType::TlsExporter, binding_data);

        assert_eq!(bindings.binding_type, Some(ChannelBindingType::TlsExporter));
        assert!(bindings.application_data.is_some());
    }

    #[test]
    fn test_gss_bindings_conversion() {
        use std::net::{Ipv4Addr, SocketAddrV4};

        let initiator = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 8080));
        let acceptor = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), 443));

        let bindings = ChannelBindings::new_with_addresses(Some(initiator), Some(acceptor));
        let (init_data, acc_data, app_data) = bindings.to_gss_bindings();

        assert!(init_data.is_some());
        assert!(acc_data.is_some());
        assert!(app_data.is_none());

        // Check initiator address encoding
        let init = init_data.unwrap();
        assert_eq!(init[0..2], [0x00, 0x02]); // AF_INET
        assert_eq!(init[2..6], [192, 168, 1, 1]); // IP
        assert_eq!(init[6..8], [0x1f, 0x90]); // Port 8080
    }
}
