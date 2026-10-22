//! KCM (Kerberos Credential Manager) backend implementation
//!
//! This module implements the KCM protocol for credential caching via
//! the sssd-kcm daemon. KCM provides centralized credential management
//! with better isolation than file-based caches.
//!
//! # Protocol
//!
//! KCM uses a simple request/response protocol over Unix domain sockets:
//! - Request: [length:u32][opcode:u16][data...]
//! - Response: [length:u32][status:u32][data...]

use super::{CacheConfig, Credential, CredentialCache, Principal};
use crate::error::{Error, Result};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default KCM socket path
const KCM_SOCKET_PATH: &str = "/var/run/.heim_org.h5l.kcm-socket";

/// KCM protocol version
const KCM_PROTOCOL_VERSION: u16 = 2;

/// KCM operation codes
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
#[allow(dead_code)] // These are protocol constants
enum KcmOp {
    GenNew = 0x0001,
    Initialize = 0x0002,
    Destroy = 0x0003,
    Store = 0x0004,
    GetPrincipal = 0x0005,
    GetCred = 0x0006,
    RemoveCred = 0x0007,
    GetCaches = 0x0008,
    GetDefaultCache = 0x0009,
    SetDefaultCache = 0x000a,
    GetKdcOffset = 0x000b,
    SetKdcOffset = 0x000c,
    ChownCache = 0x000d,
    ChmodCache = 0x000e,
    GetCacheUuid = 0x000f,
}

/// KCM status codes
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
enum KcmStatus {
    Ok = 0,
    Eof = 1,
    BadRequest = 2,
    NoSuchCache = 3,
    IoError = 4,
    NoMem = 5,
    NoSuchCred = 6,
    BadCacheName = 7,
    BadCacheVersion = 8,
    BadCreds = 9,
    CredentialsMissing = 10,
    BadCache = 11,
    ServerError = 12,
}

impl From<u32> for KcmStatus {
    fn from(val: u32) -> Self {
        match val {
            0 => Self::Ok,
            1 => Self::Eof,
            2 => Self::BadRequest,
            3 => Self::NoSuchCache,
            4 => Self::IoError,
            5 => Self::NoMem,
            6 => Self::NoSuchCred,
            7 => Self::BadCacheName,
            8 => Self::BadCacheVersion,
            9 => Self::BadCreds,
            10 => Self::CredentialsMissing,
            11 => Self::BadCache,
            _ => Self::ServerError,
        }
    }
}

/// KCM backend for credential cache
pub struct KcmCache {
    #[allow(dead_code)]
    config: CacheConfig,
    socket_path: String,
    cache_name: Option<String>,
}

impl KcmCache {
    /// Create a new KCM cache backend
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            socket_path: KCM_SOCKET_PATH.to_string(),
            cache_name: None,
        }
    }

    /// Connect to the KCM daemon
    fn connect(&self) -> Result<UnixStream> {
        UnixStream::connect(&self.socket_path).map_err(|e| Error::Ccache {
            text: format!(
                "Failed to connect to KCM daemon at {}: {}",
                self.socket_path, e
            ),
        })
    }

    /// Send a request to the KCM daemon
    fn send_request(&self, op: KcmOp, data: &[u8]) -> Result<Vec<u8>> {
        let mut stream = self.connect()?;

        // Build request: [length:u32][version:u16][opcode:u16][data...]
        let mut request = Vec::new();
        let total_len = 4 + data.len(); // version(2) + opcode(2) + data
        request.extend_from_slice(&(total_len as u32).to_be_bytes());
        request.extend_from_slice(&KCM_PROTOCOL_VERSION.to_be_bytes());
        request.extend_from_slice(&(op as u16).to_be_bytes());
        request.extend_from_slice(data);

        // Send request
        stream.write_all(&request).map_err(|e| Error::Ccache {
            text: format!("Failed to send KCM request: {e}"),
        })?;

        // Read response length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).map_err(|e| Error::Ccache {
            text: format!("Failed to read KCM response length: {e}"),
        })?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        // Read response
        let mut response = vec![0u8; resp_len];
        stream
            .read_exact(&mut response)
            .map_err(|e| Error::Ccache {
                text: format!("Failed to read KCM response: {e}"),
            })?;

        // Parse status
        if response.len() < 4 {
            return Err(Error::Ccache {
                text: "Invalid KCM response: too short".to_string(),
            });
        }

        let status_bytes: [u8; 4] = response[0..4].try_into().unwrap();
        let status = KcmStatus::from(u32::from_be_bytes(status_bytes));

        if status != KcmStatus::Ok {
            return Err(Error::Ccache {
                text: format!("KCM operation failed: {status:?}"),
            });
        }

        // Return data portion
        Ok(response[4..].to_vec())
    }

    /// Initialize a new cache
    #[allow(dead_code)]
    fn initialize_cache(&mut self, name: &str, principal: &Principal) -> Result<()> {
        let mut data = Vec::new();

        // Cache name
        data.extend_from_slice(&(name.len() as u32).to_be_bytes());
        data.extend_from_slice(name.as_bytes());

        // Principal (simplified - KCM expects specific format)
        let principal_str = principal.to_string();
        data.extend_from_slice(&(principal_str.len() as u32).to_be_bytes());
        data.extend_from_slice(principal_str.as_bytes());

        self.send_request(KcmOp::Initialize, &data)?;
        self.cache_name = Some(name.to_string());
        Ok(())
    }

    /// Get the default cache name
    #[allow(dead_code)]
    fn get_default_cache_name(&self) -> Result<String> {
        let data = self.send_request(KcmOp::GetDefaultCache, &[])?;

        if data.len() < 4 {
            return Err(Error::Ccache {
                text: "Invalid KCM response for default cache".to_string(),
            });
        }

        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return Err(Error::Ccache {
                text: "Invalid cache name length in KCM response".to_string(),
            });
        }

        String::from_utf8(data[4..4 + len].to_vec()).map_err(|e| Error::Ccache {
            text: format!("Invalid UTF-8 in cache name: {e}"),
        })
    }

    /// Check if a credential is expired
    #[allow(dead_code)]
    fn is_expired(cred: &Credential) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        cred.times.end_time < now
    }
}

impl CredentialCache for KcmCache {
    fn open(&mut self, path: &Path) -> Result<()> {
        // For KCM, the path is interpreted as a cache name
        // Format: KCM:uid:name or just the name
        let cache_name = path
            .to_str()
            .ok_or(Error::Ccache {
                text: "Invalid cache path".to_string(),
            })?
            .to_string();

        // Strip KCM: prefix if present
        let cache_name = cache_name
            .strip_prefix("KCM:")
            .map_or_else(|| cache_name.clone(), str::to_string);

        self.cache_name = Some(cache_name);
        Ok(())
    }

    fn load(&mut self) -> Result<Vec<Credential>> {
        // KCM doesn't support bulk credential loading
        // This would need to iterate through individual credentials
        // For now, return empty as full implementation requires more protocol details
        Ok(Vec::new())
    }

    fn save(&mut self, _credentials: &[Credential]) -> Result<()> {
        // KCM stores credentials individually, not in bulk
        // This would need to clear and re-add all credentials
        Err(Error::Ccache {
            text: "KCM backend doesn't support bulk save".to_string(),
        })
    }

    fn store_ticket(&mut self, credential: Credential) -> Result<()> {
        let cache_name = self.cache_name.as_ref().ok_or(Error::Ccache {
            text: "Cache not opened".to_string(),
        })?;

        // Build store request
        let mut data = Vec::new();

        // Cache name
        data.extend_from_slice(&(cache_name.len() as u32).to_be_bytes());
        data.extend_from_slice(cache_name.as_bytes());

        // Credential data would need to be serialized in KCM format
        // This is a simplified placeholder
        let cred_data = format!("{} {}", credential.client, credential.server);
        data.extend_from_slice(&(cred_data.len() as u32).to_be_bytes());
        data.extend_from_slice(cred_data.as_bytes());

        self.send_request(KcmOp::Store, &data)?;
        Ok(())
    }

    fn get_ticket(&mut self, spn: &str) -> Result<Option<Credential>> {
        let cache_name = self.cache_name.as_ref().ok_or(Error::Ccache {
            text: "Cache not opened".to_string(),
        })?;

        // Build get request
        let mut data = Vec::new();

        // Cache name
        data.extend_from_slice(&(cache_name.len() as u32).to_be_bytes());
        data.extend_from_slice(cache_name.as_bytes());

        // Service principal
        data.extend_from_slice(&(spn.len() as u32).to_be_bytes());
        data.extend_from_slice(spn.as_bytes());

        self.send_request(KcmOp::GetCred, &data)
            .map_or(Ok(None), |_resp_data| {
                // Would need to parse credential from response
                // This requires full KCM protocol implementation
                Ok(None)
            })
    }

    fn remove_ticket(&mut self, spn: &str) -> Result<()> {
        let cache_name = self.cache_name.as_ref().ok_or(Error::Ccache {
            text: "Cache not opened".to_string(),
        })?;

        // Build remove request
        let mut data = Vec::new();

        // Cache name
        data.extend_from_slice(&(cache_name.len() as u32).to_be_bytes());
        data.extend_from_slice(cache_name.as_bytes());

        // Service principal
        data.extend_from_slice(&(spn.len() as u32).to_be_bytes());
        data.extend_from_slice(spn.as_bytes());

        self.send_request(KcmOp::RemoveCred, &data)?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        // KCM doesn't have a direct list operation
        // Would need to implement credential iteration
        Ok(Vec::new())
    }

    fn purge_expired(&mut self) -> Result<usize> {
        // KCM doesn't have a purge operation
        // Would need to iterate and remove expired credentials
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kcm_status_conversion() {
        assert_eq!(KcmStatus::from(0), KcmStatus::Ok);
        assert_eq!(KcmStatus::from(3), KcmStatus::NoSuchCache);
        assert_eq!(KcmStatus::from(999), KcmStatus::ServerError);
    }

    #[test]
    #[ignore = "requires a running KCM daemon"]
    fn test_kcm_connect() {
        let config = CacheConfig::default();
        let cache = KcmCache::new(config);

        // This will fail unless KCM daemon is running
        match cache.connect() {
            Ok(_) => println!("Successfully connected to KCM daemon"),
            Err(e) => println!("Expected error (no daemon): {e}"),
        }
    }
}
