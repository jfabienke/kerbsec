//! Linux kernel keyring backend implementation
//!
//! This module implements credential caching using the Linux kernel keyring
//! facility. The keyring provides in-kernel secure storage that is automatically
//! cleaned up on logout and is not swapped to disk.
//!
//! # Security
//!
//! - Credentials are stored in kernel memory (not swappable)
//! - Access controlled by kernel security policies
//! - Automatic cleanup on process/session termination
//! - Per-user isolation enforced by the kernel

// Allow unused code - keyring constants and methods are defined for API
// completeness and future use, even if not all are used currently.
#![allow(dead_code)]

use super::format::{FileFormatParser, FileFormatSerializer};
use super::{CacheConfig, Credential, CredentialCache, Principal};
use crate::error::{Error, Result};
use std::ffi::CString;
use std::io::Cursor;
use std::os::raw::{c_char, c_int, c_long};
use std::path::Path;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

// Linux keyring system calls via libc
extern "C" {
    fn syscall(num: c_long, ...) -> c_long;
}

// System call numbers for x86_64
#[cfg(target_arch = "x86_64")]
const SYS_ADD_KEY: c_long = 248;
#[cfg(target_arch = "x86_64")]
const SYS_REQUEST_KEY: c_long = 249;
#[cfg(target_arch = "x86_64")]
const SYS_KEYCTL: c_long = 250;

// System call numbers for aarch64
#[cfg(target_arch = "aarch64")]
const SYS_ADD_KEY: c_long = 217;
#[cfg(target_arch = "aarch64")]
const SYS_REQUEST_KEY: c_long = 218;
#[cfg(target_arch = "aarch64")]
const SYS_KEYCTL: c_long = 219;

// Keyctl commands
const KEYCTL_GET_KEYRING_ID: c_int = 0;
const KEYCTL_UPDATE: c_int = 2;
const KEYCTL_REVOKE: c_int = 3;
const KEYCTL_DESCRIBE: c_int = 6;
const KEYCTL_CLEAR: c_int = 7;
const KEYCTL_LINK: c_int = 8;
const KEYCTL_UNLINK: c_int = 9;
const KEYCTL_READ: c_int = 11;

// Special keyring IDs
const KEY_SPEC_USER_KEYRING: c_int = -4;
const KEY_SPEC_USER_SESSION_KEYRING: c_int = -5;
const KEY_SPEC_SESSION_KEYRING: c_int = -3;

type KeySerial = i32;

/// Linux keyring backend for credential cache
pub struct KeyringCache {
    config: CacheConfig,
    keyring_id: Option<KeySerial>,
    cache_name: Option<String>,
    credentials: Vec<Credential>,
    default_principal: Option<Principal>,
}

impl KeyringCache {
    /// Create a new keyring cache backend
    #[allow(clippy::missing_const_for_fn)] // Can't be const: Vec::new() is not const
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            keyring_id: None,
            cache_name: None,
            credentials: Vec::new(),
            default_principal: None,
        }
    }

    /// Add a key to the keyring
    fn add_key(
        &self,
        key_type: &str,
        description: &str,
        payload: &[u8],
        keyring: KeySerial,
    ) -> Result<KeySerial> {
        let key_type = CString::new(key_type).map_err(|_| Error::Ccache {
            text: "Invalid key type string".to_string(),
        })?;

        let description = CString::new(description).map_err(|_| Error::Ccache {
            text: "Invalid description string".to_string(),
        })?;

        let key_id = unsafe {
            syscall(
                SYS_ADD_KEY,
                key_type.as_ptr(),
                description.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                keyring,
            )
        };

        if key_id < 0 {
            return Err(Error::Ccache {
                text: format!(
                    "Failed to add key to keyring: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        Ok(key_id as KeySerial)
    }

    /// Request a key from the keyring
    fn request_key(
        &self,
        key_type: &str,
        description: &str,
        keyring: KeySerial,
    ) -> Result<KeySerial> {
        let key_type = CString::new(key_type).map_err(|_| Error::Ccache {
            text: "Invalid key type string".to_string(),
        })?;

        let description = CString::new(description).map_err(|_| Error::Ccache {
            text: "Invalid description string".to_string(),
        })?;

        let key_id = unsafe {
            syscall(
                SYS_REQUEST_KEY,
                key_type.as_ptr(),
                description.as_ptr(),
                ptr::null::<c_char>(),
                keyring,
            )
        };

        if key_id < 0 {
            return Err(Error::Ccache {
                text: format!(
                    "Key not found in keyring: {}",
                    description.to_string_lossy()
                ),
            });
        }

        Ok(key_id as KeySerial)
    }

    /// Read a key from the keyring
    fn read_key(&self, key_id: KeySerial) -> Result<Vec<u8>> {
        // First get the size
        let size = unsafe { syscall(SYS_KEYCTL, KEYCTL_READ, key_id, ptr::null_mut::<u8>(), 0) };

        if size < 0 {
            return Err(Error::Ccache {
                text: format!(
                    "Failed to get key size: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        // Now read the data
        let mut buffer = vec![0u8; size as usize];
        let read_size = unsafe {
            syscall(
                SYS_KEYCTL,
                KEYCTL_READ,
                key_id,
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };

        if read_size < 0 {
            return Err(Error::Ccache {
                text: format!(
                    "Failed to read key data: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        buffer.truncate(read_size as usize);
        Ok(buffer)
    }

    /// Update a key in the keyring
    fn update_key(&self, key_id: KeySerial, payload: &[u8]) -> Result<()> {
        let ret = unsafe {
            syscall(
                SYS_KEYCTL,
                KEYCTL_UPDATE,
                key_id,
                payload.as_ptr(),
                payload.len(),
            )
        };

        if ret < 0 {
            return Err(Error::Ccache {
                text: format!("Failed to update key: {}", std::io::Error::last_os_error()),
            });
        }

        Ok(())
    }

    /// Revoke a key
    fn revoke_key(&self, key_id: KeySerial) -> Result<()> {
        let ret = unsafe { syscall(SYS_KEYCTL, KEYCTL_REVOKE, key_id) };

        if ret < 0 {
            return Err(Error::Ccache {
                text: format!("Failed to revoke key: {}", std::io::Error::last_os_error()),
            });
        }

        Ok(())
    }

    /// Get or create a keyring for this cache
    fn get_or_create_keyring(&mut self, name: &str) -> Result<KeySerial> {
        // Try to get existing keyring
        if let Ok(keyring_id) = self.request_key("keyring", name, KEY_SPEC_USER_SESSION_KEYRING) {
            self.keyring_id = Some(keyring_id);
            return Ok(keyring_id);
        }

        // Create new keyring
        let keyring_id = self.add_key("keyring", name, &[], KEY_SPEC_USER_SESSION_KEYRING)?;

        self.keyring_id = Some(keyring_id);
        Ok(keyring_id)
    }

    /// Serialize credentials to binary format
    fn serialize_credentials(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut serializer = FileFormatSerializer::new(&mut buf);

        // Write version
        serializer.write_version()?;

        // Write header terminator
        serializer.write_header_terminator()?;

        // Write default principal
        if let Some(ref principal) = self.default_principal {
            serializer.write_principal(principal)?;
        } else if !self.credentials.is_empty() {
            serializer.write_principal(&self.credentials[0].client)?;
        } else {
            return Err(Error::Ccache {
                text: "No principal to write".to_string(),
            });
        }

        // Write credentials
        for cred in &self.credentials {
            serializer.write_credential(cred)?;
        }

        Ok(buf)
    }

    /// Deserialize credentials from binary format
    fn deserialize_credentials(&mut self, data: &[u8]) -> Result<()> {
        let mut cursor = Cursor::new(data);
        let mut parser = FileFormatParser::new(&mut cursor);

        // Parse version
        let version = parser.parse_version()?;
        if version != super::format::FILE_FORMAT_VERSION {
            return Err(Error::Ccache {
                text: format!("Unsupported format version: 0x{version:04x}"),
            });
        }

        // Parse header
        let _header = parser.parse_header()?;

        // Parse default principal
        self.default_principal = Some(parser.parse_principal()?);

        // Parse credentials
        self.credentials.clear();
        loop {
            match parser.parse_credential() {
                Ok(cred) => self.credentials.push(cred),
                Err(e) => {
                    let error_str = format!("{e}");
                    if error_str.contains("fill whole buffer") || error_str.contains("EOF") {
                        break;
                    }
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Check if a credential is expired
    fn is_expired(cred: &Credential) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        cred.times.end_time < now
    }
}

impl CredentialCache for KeyringCache {
    fn open(&mut self, path: &Path) -> Result<()> {
        // Path is used as the cache name
        let cache_name = path
            .to_str()
            .ok_or(Error::Ccache {
                text: "Invalid cache path".to_string(),
            })?
            .to_string();

        // Strip KEYRING: prefix if present
        let cache_name = if let Some(stripped) = cache_name.strip_prefix("KEYRING:") {
            stripped.to_string()
        } else {
            cache_name
        };

        self.cache_name = Some(cache_name.clone());

        // Get or create keyring
        let keyring_id = self.get_or_create_keyring(&format!("krb5cc_{cache_name}"))?;

        // Try to load existing credentials
        if let Ok(key_id) = self.request_key("user", &cache_name, keyring_id) {
            if let Ok(data) = self.read_key(key_id) {
                let _ = self.deserialize_credentials(&data);
            }
        }

        Ok(())
    }

    fn load(&mut self) -> Result<Vec<Credential>> {
        Ok(self.credentials.clone())
    }

    fn save(&mut self, credentials: &[Credential]) -> Result<()> {
        self.credentials = credentials.to_vec();

        if let Some(ref cache_name) = self.cache_name {
            if let Some(keyring_id) = self.keyring_id {
                let data = self.serialize_credentials()?;

                // Try to update existing key
                if let Ok(key_id) = self.request_key("user", cache_name, keyring_id) {
                    self.update_key(key_id, &data)?;
                } else {
                    // Create new key
                    self.add_key("user", cache_name, &data, keyring_id)?;
                }
            }
        }

        Ok(())
    }

    fn store_ticket(&mut self, credential: Credential) -> Result<()> {
        // Set default principal if not set
        if self.default_principal.is_none() {
            self.default_principal = Some(credential.client.clone());
        }

        // Remove existing ticket for same server
        let server_str = credential.server.to_string();
        self.credentials
            .retain(|c| c.server.to_string() != server_str);

        // Add new ticket
        self.credentials.push(credential);

        // Save to keyring
        self.save(&self.credentials.clone())
    }

    fn get_ticket(&mut self, spn: &str) -> Result<Option<Credential>> {
        Ok(self
            .credentials
            .iter()
            .find(|c| c.server.to_string() == spn && !Self::is_expired(c))
            .cloned())
    }

    fn remove_ticket(&mut self, spn: &str) -> Result<()> {
        let initial_len = self.credentials.len();
        self.credentials.retain(|c| c.server.to_string() != spn);

        if self.credentials.len() < initial_len {
            self.save(&self.credentials.clone())?;
        }

        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self
            .credentials
            .iter()
            .map(|c| c.server.to_string())
            .collect())
    }

    fn purge_expired(&mut self) -> Result<usize> {
        let initial_len = self.credentials.len();
        self.credentials.retain(|c| !Self::is_expired(c));
        let removed = initial_len - self.credentials.len();

        if removed > 0 {
            self.save(&self.credentials.clone())?;
        }

        Ok(removed)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires Linux kernel keyring support"]
    fn test_keyring_basic() {
        let config = CacheConfig::default();
        let mut cache = KeyringCache::new(config);

        // Try to open a cache
        let result = cache.open(Path::new("test_keyring"));

        // This might fail on non-Linux or without proper permissions
        if result.is_err() {
            println!("Expected error (not on Linux or no keyring support): {result:?}");
            return;
        }

        // If we got here, we have keyring support
        assert!(cache.keyring_id.is_some());
    }
}
