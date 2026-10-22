//! DNS resolver for FQDN canonicalization and KDC discovery

use crate::error::{Error, Result};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use std::time::Duration;
use tokio::time::timeout;

#[cfg(feature = "trace")]
use tracing::{debug, instrument};

/// Canonicalize hostname to FQDN via DNS (CNAME → A/AAAA)
///
/// The resolver follows any CNAME chain itself (including search-domain
/// expansion for short names); the canonical name is the owner name of the first
/// address record in the answer, lowercased and without the trailing dot. A name
/// that resolves but has no address records, or any lookup failure, is an error
/// rather than a silent fallback to the input.
///
/// # Errors
///
/// Returns an error if:
/// - DNS resolution fails
/// - The answer contains no address records
/// - Timeout occurs
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::dns",
    level = "debug",
    skip(dns_timeout),
    fields(host = %host, timeout_secs = ?dns_timeout.as_secs())
))]
pub async fn canonicalize_fqdn(host: &str, dns_timeout: Duration) -> Result<String> {
    // Check if it's already an IP address - no canonicalization needed
    if host.parse::<std::net::IpAddr>().is_ok() {
        #[cfg(feature = "trace")]
        debug!(target: "kerbsec::dns", "host is IP address, no canonicalization needed");
        return Ok(host.to_string());
    }

    #[cfg(feature = "trace")]
    debug!(target: "kerbsec::dns", "canonicalizing hostname");

    let result = timeout(dns_timeout, async {
        // Create resolver using system configuration (/etc/resolv.conf)
        let resolver = Resolver::builder_tokio()
            .map_err(|e| Error::Dns(anyhow::anyhow!("Failed to create resolver builder: {e}")))?
            .build();

        let response = resolver
            .lookup_ip(host)
            .await
            .map_err(|e| Error::CanonicalizationFailed(format!("{host}: {e}")))?;

        let canonical = canonical_owner_name(
            response
                .as_lookup()
                .record_iter()
                .map(|r| (r.record_type(), r.name().to_ascii())),
        )
        .ok_or_else(|| {
            Error::CanonicalizationFailed(format!("{host}: no address records in answer"))
        })?;

        #[cfg(feature = "trace")]
        debug!(target: "kerbsec::dns", canonical = %canonical, "canonicalization complete");

        Ok(canonical)
    })
    .await;

    match result {
        Ok(Ok(canonical)) => Ok(canonical),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::CanonicalizationFailed(format!(
            "DNS timeout for {host}"
        ))),
    }
}

/// Lowercase a DNS name and drop the trailing root dot
fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

/// The canonical name from an answer: the owner of the first A/AAAA record
///
/// After the resolver has followed a CNAME chain, the address records are owned by
/// the chain's final target, so this is the canonical name. CNAME records
/// themselves are owned by the alias and must not be used.
fn canonical_owner_name(records: impl Iterator<Item = (RecordType, String)>) -> Option<String> {
    records
        .filter(|(ty, _)| matches!(ty, RecordType::A | RecordType::AAAA))
        .map(|(_, name)| normalize_name(&name))
        .find(|name| !name.is_empty())
}

/// `host:port` strings from SRV data, ordered per RFC 2782
///
/// Lowest priority first; within a priority, higher weight first (a deterministic
/// stand-in for weighted random selection).
fn order_srv_targets(mut srv: Vec<(u16, u16, String, u16)>) -> Vec<String> {
    srv.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    srv.into_iter()
        .map(|(_, _, host, port)| format!("{}:{port}", normalize_name(&host)))
        .collect()
}

/// Discover KDC via DNS SRV records
///
/// # Errors
///
/// Returns an error if:
/// - DNS SRV lookup fails
/// - No KDCs found
/// - Timeout occurs
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::dns",
    level = "debug",
    skip(dns_timeout),
    fields(realm = %realm, timeout_secs = ?dns_timeout.as_secs())
))]
pub async fn discover_kdc(realm: &str, dns_timeout: Duration) -> Result<Vec<String>> {
    let srv_name = format!("_kerberos._tcp.{}", realm.to_lowercase());
    #[cfg(feature = "trace")]
    debug!(target: "kerbsec::dns", srv = %srv_name, "looking up KDC via SRV record");

    let result = timeout(dns_timeout, async {
        // Create resolver using system configuration
        let resolver = Resolver::builder_tokio()
            .map_err(|e| Error::Dns(anyhow::anyhow!("Failed to create resolver builder: {e}")))?
            .build();

        match resolver.srv_lookup(&srv_name).await {
            Ok(response) => {
                let kdcs = order_srv_targets(
                    response
                        .iter()
                        .map(|srv| {
                            (
                                srv.priority(),
                                srv.weight(),
                                srv.target().to_ascii(),
                                srv.port(),
                            )
                        })
                        .collect(),
                );

                if kdcs.is_empty() {
                    Err(Error::Dns(anyhow::anyhow!(
                        "No KDC found for realm {realm}"
                    )))
                } else {
                    #[cfg(feature = "trace")]
                    debug!(target: "kerbsec::dns", count = kdcs.len(), kdcs = ?kdcs, "discovered KDCs");
                    Ok(kdcs)
                }
            }
            Err(e) => Err(Error::Dns(anyhow::anyhow!("KDC discovery failed: {e}"))),
        }
    })
    .await;

    match result {
        Ok(Ok(kdcs)) => Ok(kdcs),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::Dns(anyhow::anyhow!(
            "DNS timeout discovering KDC for {realm}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_name_is_first_address_owner_not_cname_owner() {
        let answer = vec![
            (RecordType::CNAME, "Alias.Example.COM.".to_string()),
            (RecordType::A, "Host.Corp.Example.Com.".to_string()),
            (RecordType::AAAA, "other.example.com.".to_string()),
        ];
        assert_eq!(
            canonical_owner_name(answer.into_iter()).as_deref(),
            Some("host.corp.example.com")
        );
    }

    #[test]
    fn no_address_records_means_no_canonical_name() {
        let answer = vec![(RecordType::CNAME, "alias.example.com.".to_string())];
        assert_eq!(canonical_owner_name(answer.into_iter()), None);
        assert_eq!(canonical_owner_name(std::iter::empty()), None);
    }

    #[test]
    fn srv_targets_are_ordered_and_have_no_trailing_dot() {
        let srv = vec![
            (20, 100, "kdc3.example.com.".to_string(), 88),
            (10, 10, "KDC2.example.com.".to_string(), 88),
            (10, 50, "kdc1.example.com.".to_string(), 8888),
        ];
        assert_eq!(
            order_srv_targets(srv),
            [
                "kdc1.example.com:8888",
                "kdc2.example.com:88",
                "kdc3.example.com:88"
            ]
        );
    }
}
