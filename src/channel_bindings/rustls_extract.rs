//! rustls TLS channel binding extractor
//!
//! This module provides channel binding extraction for rustls connections,
//! implementing RFC 5929 (tls-server-end-point) and RFC 9266 (tls-exporter).

#[cfg(feature = "channel-bindings-rustls")]
use super::{ChannelBindingType, ChannelBindings};
#[cfg(feature = "channel-bindings-rustls")]
use crate::error::Error;

use crate::error::Result;

/// Extract channel bindings from a rustls `ClientConnection`
///
/// # Arguments
///
/// * `conn` - The rustls `ClientConnection`
/// * `binding_type` - The type of channel binding to extract
///
/// # Returns
///
/// Channel bindings containing the requested binding data
///
/// # Example
///
/// ```ignore
/// use rustls::ClientConnection;
/// use fabi_kerbsec::channel_bindings::rustls_extract::extract_rustls_bindings;
/// use fabi_kerbsec::channel_bindings::ChannelBindingType;
///
/// # fn example(conn: &ClientConnection) -> Result<(), Box<dyn std::error::Error>> {
/// let bindings = extract_rustls_bindings(conn, ChannelBindingType::TlsExporter)?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "channel-bindings-rustls")]
pub fn extract_rustls_bindings(
    conn: &rustls::ClientConnection,
    binding_type: ChannelBindingType,
) -> Result<ChannelBindings> {
    match binding_type {
        ChannelBindingType::TlsUnique => {
            // TLS 1.3 doesn't support tls-unique
            if let Some(version) = conn.protocol_version() {
                if version == rustls::ProtocolVersion::TLSv1_3 {
                    return Err(Error::ChannelBinding(
                        "tls-unique not supported in TLS 1.3".into(),
                    ));
                }
            }

            // For TLS 1.2, we would need the Finished message
            // rustls doesn't expose this directly
            Err(Error::ChannelBinding(
                "tls-unique extraction not implemented for rustls".into(),
            ))
        }

        ChannelBindingType::TlsServerEndPoint => {
            // Get the peer certificate
            let cert_chain = conn
                .peer_certificates()
                .ok_or_else(|| Error::ChannelBinding("No peer certificates".into()))?;

            let server_cert = cert_chain
                .first()
                .ok_or_else(|| Error::ChannelBinding("Empty certificate chain".into()))?;

            // Extract the certificate bytes
            let cert_der = server_cert.as_ref();

            // Hash the certificate based on its signature algorithm
            let hash = hash_certificate_for_binding(cert_der)?;

            Ok(ChannelBindings::new_tls(
                ChannelBindingType::TlsServerEndPoint,
                hash,
            ))
        }

        ChannelBindingType::TlsExporter => {
            // Use the RFC 9266 exporter label
            const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";
            const EXPORTER_CONTEXT: &[u8] = b"";
            const EXPORTER_LENGTH: usize = 32; // 256 bits

            // Export keying material
            let mut output = vec![0u8; EXPORTER_LENGTH];
            conn.export_keying_material(
                output.as_mut_slice(),
                EXPORTER_LABEL,
                Some(EXPORTER_CONTEXT),
            )
            .map_err(|e| {
                Error::ChannelBinding(format!("Failed to export keying material: {e:?}"))
            })?;

            Ok(ChannelBindings::new_tls(
                ChannelBindingType::TlsExporter,
                output,
            ))
        }
    }
}

/// Hash a certificate for tls-server-end-point binding
#[allow(dead_code)]
#[allow(clippy::unnecessary_wraps)] // Returns Result for future extensibility (signature algorithm parsing)
fn hash_certificate_for_binding(cert_der: &[u8]) -> Result<Vec<u8>> {
    use ring::digest;

    // Parse the certificate to determine signature algorithm
    // For now, we'll use SHA-256 as a safe default
    // A full implementation would parse the cert to check the signature algorithm

    // RFC 5929 Section 4.1:
    // - If signature uses MD5 or SHA-1, use SHA-256
    // - Otherwise use the hash from the signature algorithm

    let hash = digest::digest(&digest::SHA256, cert_der);
    Ok(hash.as_ref().to_vec())
}

/// Extract channel bindings from a rustls `ServerConnection`
///
/// This is typically used on the server side for mutual authentication
#[cfg(feature = "channel-bindings-rustls")]
pub fn extract_rustls_server_bindings(
    conn: &rustls::ServerConnection,
    binding_type: ChannelBindingType,
) -> Result<ChannelBindings> {
    match binding_type {
        ChannelBindingType::TlsUnique => Err(Error::ChannelBinding(
            "tls-unique not recommended for servers".into(),
        )),

        ChannelBindingType::TlsServerEndPoint => {
            // Server uses its own certificate
            // This would need access to the configured certificate
            Err(Error::ChannelBinding(
                "tls-server-end-point requires server certificate access".into(),
            ))
        }

        ChannelBindingType::TlsExporter => {
            const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";
            const EXPORTER_CONTEXT: &[u8] = b"";
            const EXPORTER_LENGTH: usize = 32;

            let mut output = vec![0u8; EXPORTER_LENGTH];
            conn.export_keying_material(
                output.as_mut_slice(),
                EXPORTER_LABEL,
                Some(EXPORTER_CONTEXT),
            )
            .map_err(|e| {
                Error::ChannelBinding(format!("Failed to export keying material: {e:?}"))
            })?;

            Ok(ChannelBindings::new_tls(
                ChannelBindingType::TlsExporter,
                output,
            ))
        }
    }
}

#[cfg(all(test, feature = "channel-bindings-rustls"))]
mod tests {
    use super::*;

    #[test]
    fn test_binding_type_strings() {
        assert_eq!(ChannelBindingType::TlsUnique.as_str(), "tls-unique");
        assert_eq!(
            ChannelBindingType::TlsServerEndPoint.as_str(),
            "tls-server-end-point"
        );
        assert_eq!(ChannelBindingType::TlsExporter.as_str(), "tls-exporter");
    }

    #[test]
    fn test_binding_type_gss_values() {
        assert_eq!(ChannelBindingType::TlsUnique.gss_type(), 0);
        assert_eq!(ChannelBindingType::TlsServerEndPoint.gss_type(), 1);
        assert_eq!(ChannelBindingType::TlsExporter.gss_type(), 2);
    }
}
