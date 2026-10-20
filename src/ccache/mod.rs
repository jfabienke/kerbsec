//! Kerberos credential cache (CCACHE) support
//!
//! This module provides functionality for reading and writing Kerberos credential
//! caches with support for multiple backends including the MIT Kerberos FILE format
//! (version 0x0504), in-memory caching, and platform-specific secure storage.
//!
//! # Overview
//!
//! The credential cache allows storing and retrieving Kerberos tickets for
//! reuse across process boundaries. This implementation provides a pluggable
//! backend system with atomic operations and proper locking.
//!
//! # Security
//!
//! - All sensitive data (keys, tickets) are zeroized on drop
//! - Files are created with 0600 permissions (owner read/write only)
//! - Atomic writes prevent partial cache files
//! - Advisory locking prevents concurrent corruption
//! - No credentials are ever logged

mod file;
pub mod format;
mod memory;

#[cfg(feature = "ccache-kcm")]
mod kcm;

#[cfg(all(target_os = "linux", feature = "ccache-keyring"))]
mod keyring;

// Re-export core types
pub use format::{
    Address, AuthData, Credential, EncType, KeyBlock, NameType, Principal, Times,
    FILE_FORMAT_VERSION,
};

use crate::error::Result;
use std::path::Path;

/// Credential cache trait for backend implementations
pub trait CredentialCache: Send + Sync {
    /// Open or create a credential cache
    fn open(&mut self, path: &Path) -> Result<()>;

    /// Load credentials from the cache
    fn load(&mut self) -> Result<Vec<Credential>>;

    /// Save credentials to the cache
    fn save(&mut self, credentials: &[Credential]) -> Result<()>;

    /// Store a single ticket
    fn store_ticket(&mut self, credential: Credential) -> Result<()>;

    /// Get a ticket for a specific service principal
    fn get_ticket(&mut self, spn: &str) -> Result<Option<Credential>>;

    /// Remove a specific ticket
    fn remove_ticket(&mut self, spn: &str) -> Result<()>;

    /// List all tickets in the cache
    fn list(&self) -> Result<Vec<String>>;

    /// Purge expired tickets
    fn purge_expired(&mut self) -> Result<usize>;
}

/// Credential cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Backend type
    pub backend: CacheBackend,
    /// Enable atomic writes
    pub atomic_writes: bool,
    /// Enable file locking
    pub use_locking: bool,
    /// File permissions (octal, e.g., 0o600)
    pub file_mode: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            backend: CacheBackend::File,
            atomic_writes: true,
            use_locking: true,
            file_mode: 0o600,
        }
    }
}

/// Cache backend type
#[derive(Debug, Clone, Copy)]
pub enum CacheBackend {
    /// MIT Kerberos FILE format v5
    File,
    /// In-memory cache
    Memory,
    /// Linux kernel keyring
    #[cfg(target_os = "linux")]
    Keyring,
    /// KCM daemon via D-Bus
    #[cfg(feature = "ccache-kcm")]
    Kcm,
    /// Windows credential manager
    #[cfg(target_os = "windows")]
    Windows,
}

/// Create a credential cache with the specified backend
pub fn create_cache(config: CacheConfig) -> Result<Box<dyn CredentialCache>> {
    match config.backend {
        CacheBackend::File => Ok(Box::new(file::FileCache::new(config))),
        CacheBackend::Memory => Ok(Box::new(memory::MemoryCache::new())),
        #[cfg(all(target_os = "linux", feature = "ccache-keyring"))]
        CacheBackend::Keyring => Ok(Box::new(keyring::KeyringCache::new(config))),
        #[cfg(all(target_os = "linux", not(feature = "ccache-keyring")))]
        CacheBackend::Keyring => Err(crate::error::Error::Ccache {
            text: "Keyring backend not compiled in (enable ccache-keyring feature)".to_string(),
        }),
        #[cfg(feature = "ccache-kcm")]
        CacheBackend::Kcm => Ok(Box::new(kcm::KcmCache::new(config))),
        #[cfg(target_os = "windows")]
        CacheBackend::Windows => {
            // Windows backend will be implemented in windows.rs
            unimplemented!("Windows backend not yet implemented")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CacheConfig::default();
        assert!(matches!(config.backend, CacheBackend::File));
        assert!(config.atomic_writes);
        assert!(config.use_locking);
        assert_eq!(config.file_mode, 0o600);
    }
}
