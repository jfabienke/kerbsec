//! FILE backend implementation for credential cache
//!
//! This module implements the MIT Kerberos FILE format v5 backend with:
//! - Atomic writes using tempfile + rename
//! - Advisory file locking to prevent concurrent corruption
//! - Proper permission settings (0600 by default)
//! - Full read/write support for credential caching

use super::format::{FileFormatParser, FileFormatSerializer, FILE_FORMAT_VERSION};
use super::{CacheConfig, Credential, CredentialCache, Principal};
use crate::error::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// FILE backend for credential cache
pub struct FileCache {
    config: CacheConfig,
    path: Option<PathBuf>,
    credentials: Vec<Credential>,
    default_principal: Option<Principal>,
}

impl FileCache {
    /// Create a new FILE cache backend
    pub const fn new(config: CacheConfig) -> Self {
        Self {
            config,
            path: None,
            credentials: Vec::new(),
            default_principal: None,
        }
    }

    /// Read credentials from file with locking
    fn read_from_file(&mut self, path: &Path) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| Error::Ccache {
                text: format!("Failed to open cache file: {e}"),
            })?;

        // Acquire shared lock for reading
        #[cfg(unix)]
        if self.config.use_locking {
            Self::acquire_shared_lock(&file)?;
        }

        let mut reader = BufReader::new(file);
        let mut parser = FileFormatParser::new(&mut reader);

        // Parse version
        let version = parser.parse_version()?;

        if version != FILE_FORMAT_VERSION {
            return Err(Error::Ccache {
                text: format!(
                    "Unsupported file format version: 0x{version:04x} (expected 0x{FILE_FORMAT_VERSION:04x})"
                ),
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
                Ok(cred) => {
                    self.credentials.push(cred);
                }
                Err(e) => {
                    // EOF is expected after reading all credentials
                    // The error "failed to fill whole buffer" indicates EOF
                    let error_str = format!("{e}");
                    if error_str.contains("fill whole buffer") || error_str.contains("EOF") {
                        // Normal EOF - we've read all credentials
                        break;
                    }

                    // Real error - propagate it
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Write credentials to file with atomic write and locking
    fn write_to_file(&self, path: &Path) -> Result<()> {
        // If we have no credentials and no default principal, just delete the file
        if self.credentials.is_empty() && self.default_principal.is_none() {
            // Remove the file if it exists
            if path.exists() {
                fs::remove_file(path).map_err(|e| Error::Ccache {
                    text: format!("Failed to remove empty cache file: {e}"),
                })?;
            }
            return Ok(());
        }

        if self.config.atomic_writes {
            self.atomic_write(path)
        } else {
            self.direct_write(path)
        }
    }

    /// Atomic write using tempfile + rename
    fn atomic_write(&self, path: &Path) -> Result<()> {
        let dir = path.parent().unwrap_or_else(|| Path::new("/tmp"));

        // Create temporary file in same directory for atomic rename
        let temp_file = NamedTempFile::new_in(dir).map_err(|e| Error::Ccache {
            text: format!("Failed to create temp file: {e}"),
        })?;

        // Set permissions before writing
        #[cfg(unix)]
        {
            let metadata = temp_file.as_file().metadata().map_err(|e| Error::Ccache {
                text: format!("Failed to get temp file metadata: {e}"),
            })?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(self.config.file_mode);
            fs::set_permissions(temp_file.path(), permissions).map_err(|e| Error::Ccache {
                text: format!("Failed to set temp file permissions: {e}"),
            })?;
        }

        // Write data
        self.write_data(temp_file.as_file())?;

        // Atomic rename
        temp_file.persist(path).map_err(|e| Error::Ccache {
            text: format!("Failed to persist temp file: {e}"),
        })?;

        Ok(())
    }

    /// Direct write (non-atomic)
    fn direct_write(&self, path: &Path) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| Error::Ccache {
                text: format!("Failed to create cache file: {e}"),
            })?;

        // Set permissions
        #[cfg(unix)]
        {
            let metadata = file.metadata().map_err(|e| Error::Ccache {
                text: format!("Failed to get file metadata: {e}"),
            })?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(self.config.file_mode);
            fs::set_permissions(path, permissions).map_err(|e| Error::Ccache {
                text: format!("Failed to set file permissions: {e}"),
            })?;
        }

        // Acquire exclusive lock for writing
        #[cfg(unix)]
        if self.config.use_locking {
            Self::acquire_exclusive_lock(&file)?;
        }

        self.write_data(&file)?;
        Ok(())
    }

    /// Write credential data to file
    fn write_data(&self, file: &File) -> Result<()> {
        use std::io::Write;

        let mut writer = BufWriter::new(file);
        let mut serializer = FileFormatSerializer::new(&mut writer);

        // Write version
        serializer.write_version()?;

        // Write header (empty for now)
        serializer.write_header_terminator()?;

        // Write default principal
        if let Some(ref principal) = self.default_principal {
            serializer.write_principal(principal)?;
        } else if !self.credentials.is_empty() {
            // Use first credential's client as default
            serializer.write_principal(&self.credentials[0].client)?;
        } else {
            // Can't write a file without a principal
            return Err(Error::Ccache {
                text: "Cannot write cache file without a principal".to_string(),
            });
        }

        // Write credentials
        for cred in &self.credentials {
            serializer.write_credential(cred)?;
        }

        // Flush the buffer to ensure all data is written
        writer.flush().map_err(|e| Error::Ccache {
            text: format!("Failed to flush cache data: {e}"),
        })?;

        Ok(())
    }

    /// Acquire shared (read) lock
    #[cfg(unix)]
    fn acquire_shared_lock(file: &File) -> Result<()> {
        use libc::{flock, LOCK_SH};

        let fd = file.as_raw_fd();
        let result = unsafe { flock(fd, LOCK_SH) };

        if result == -1 {
            Err(Error::Ccache {
                text: "Failed to acquire shared lock".to_string(),
            })
        } else {
            Ok(())
        }
    }

    /// Acquire exclusive (write) lock
    #[cfg(unix)]
    fn acquire_exclusive_lock(file: &File) -> Result<()> {
        use libc::{flock, LOCK_EX};

        let fd = file.as_raw_fd();
        let result = unsafe { flock(fd, LOCK_EX) };

        if result == -1 {
            Err(Error::Ccache {
                text: "Failed to acquire exclusive lock".to_string(),
            })
        } else {
            Ok(())
        }
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

impl CredentialCache for FileCache {
    fn open(&mut self, path: &Path) -> Result<()> {
        self.path = Some(path.to_path_buf());

        // Try to read existing cache
        if path.exists() && path.metadata().is_ok_and(|m| m.len() > 0) {
            if matches!(self.read_from_file(path), Ok(())) {
            } else {
                // File exists but couldn't be read - might be corrupted or just created
                // Don't log errors as they may be expected (e.g., new empty file)
                // Clear any partial data but keep the path so load() can retry
                self.credentials.clear();
                self.default_principal = None;
            }
        }

        Ok(())
    }

    fn load(&mut self) -> Result<Vec<Credential>> {
        // If we don't have credentials, try to load from file
        if self.credentials.is_empty() {
            if let Some(path) = self.path.clone() {
                if path.exists() && path.metadata().is_ok_and(|m| m.len() > 0) {
                    // Try to read the file - if it fails, return empty
                    let _ = self.read_from_file(&path);
                }
            }
        }
        Ok(self.credentials.clone())
    }

    fn save(&mut self, credentials: &[Credential]) -> Result<()> {
        let path = self.path.as_ref().ok_or(Error::Ccache {
            text: "Cache path not set".to_string(),
        })?;

        self.credentials = credentials.to_vec();
        self.write_to_file(path)
    }

    fn store_ticket(&mut self, credential: Credential) -> Result<()> {
        // Set default principal if not set
        if self.default_principal.is_none() {
            self.default_principal = Some(credential.client.clone());
        }

        // Remove existing ticket for same server if present
        let server_str = credential.server.to_string();
        self.credentials
            .retain(|c| c.server.to_string() != server_str);

        // Add new ticket
        self.credentials.push(credential);

        // Save to file
        if let Some(ref path) = self.path {
            self.write_to_file(path)?;
        }

        Ok(())
    }

    fn get_ticket(&mut self, spn: &str) -> Result<Option<Credential>> {
        // Don't reload if we already have credentials in memory
        // Only reload if the cache is empty
        if self.credentials.is_empty() {
            if let Some(path) = self.path.clone() {
                if path.exists() {
                    self.read_from_file(&path)?;
                }
            }
        }

        // Find matching non-expired ticket
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
            // Ticket was removed, save changes
            if let Some(ref path) = self.path {
                self.write_to_file(path)?;
            }
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
            // Some tickets were removed, save changes
            if let Some(ref path) = self.path {
                self.write_to_file(path)?;
            }
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccache::format::{KeyBlock, NameType, Times};
    use std::fs;
    use tempfile::tempdir;

    fn create_test_credential() -> Credential {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        Credential {
            client: Principal::new(
                NameType::Principal,
                "TEST.REALM".to_string(),
                vec!["user".to_string()],
            ),
            server: Principal::new(
                NameType::ServiceInstance,
                "TEST.REALM".to_string(),
                vec!["host".to_string(), "server.test.realm".to_string()],
            ),
            key_block: KeyBlock {
                enctype: 18, // AES256
                key_data: vec![0x42; 32],
            },
            times: Times {
                auth_time: now,
                start_time: now,
                end_time: now + 36000,   // 10 hours
                renew_till: now + 86400, // 24 hours
            },
            is_config: 0,
            ticket_flags: 0x40a1_0000,
            addresses: Vec::new(),
            ticket: vec![0xde, 0xad, 0xbe, 0xef], // Dummy ticket
            second_ticket: Vec::new(),
            authdata: Vec::new(),
        }
    }

    #[test]
    fn test_file_cache_basic_operations() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("test.cache");

        let config = CacheConfig::default();
        let mut cache = FileCache::new(config);

        // Open cache
        cache.open(&cache_path).unwrap();

        // Store a ticket
        let cred = create_test_credential();
        cache.store_ticket(cred.clone()).unwrap();

        // Verify file was created with correct permissions
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&cache_path).unwrap();
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o777, 0o600);
        }

        // Get the ticket back
        let retrieved = cache
            .get_ticket("host/server.test.realm@TEST.REALM")
            .unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.server.to_string(), cred.server.to_string());
    }

    #[test]
    fn test_atomic_write() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("atomic.cache");

        let config = CacheConfig {
            atomic_writes: true,
            ..Default::default()
        };

        let mut cache = FileCache::new(config);
        cache.open(&cache_path).unwrap();

        let cred = create_test_credential();
        cache.store_ticket(cred).unwrap();

        // Verify file exists
        assert!(cache_path.exists());

        // Check file size
        let metadata = fs::metadata(&cache_path).unwrap();
        assert!(metadata.len() > 0, "Cache file should not be empty");

        // Reload and verify
        let mut cache2 = FileCache::new(CacheConfig::default());
        cache2.open(&cache_path).unwrap();
        let credentials = cache2.load().unwrap();
        assert_eq!(credentials.len(), 1);
    }

    #[test]
    fn test_purge_expired() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("expire.cache");

        let config = CacheConfig::default();
        let mut cache = FileCache::new(config);
        cache.open(&cache_path).unwrap();

        // Add an expired credential with a unique server
        let mut expired_cred = create_test_credential();
        expired_cred.times.end_time = 1000; // Way in the past
        expired_cred.server = Principal::new(
            NameType::ServiceInstance,
            "TEST.REALM".to_string(),
            vec!["http".to_string(), "expired.test.realm".to_string()],
        );
        cache.store_ticket(expired_cred).unwrap();

        // Add a valid credential with a different server
        let mut valid_cred = create_test_credential();
        valid_cred.server = Principal::new(
            NameType::ServiceInstance,
            "TEST.REALM".to_string(),
            vec!["http".to_string(), "valid.test.realm".to_string()],
        );
        cache.store_ticket(valid_cred).unwrap();

        // Purge expired
        let removed = cache.purge_expired().unwrap();
        assert_eq!(removed, 1);

        // Verify only valid credential remains
        let list = cache.list().unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_remove_ticket() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("remove.cache");

        let config = CacheConfig::default();
        let mut cache = FileCache::new(config);
        cache.open(&cache_path).unwrap();

        // Add multiple credentials
        let cred1 = create_test_credential();
        cache.store_ticket(cred1).unwrap();

        let mut cred2 = create_test_credential();
        cred2.server = Principal::new(
            NameType::ServiceInstance,
            "TEST.REALM".to_string(),
            vec!["http".to_string(), "web.test.realm".to_string()],
        );
        cache.store_ticket(cred2).unwrap();

        assert_eq!(cache.list().unwrap().len(), 2);

        // Remove one
        cache
            .remove_ticket("host/server.test.realm@TEST.REALM")
            .unwrap();

        // Verify only one remains
        let list = cache.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], "http/web.test.realm@TEST.REALM");
    }
}
