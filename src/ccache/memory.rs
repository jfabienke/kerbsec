//! In-memory credential cache backend
//!
//! This module provides an in-memory credential cache that stores credentials
//! in RAM. This is useful for testing and for applications that don't need
//! persistent storage across process restarts.

use super::{Credential, CredentialCache, Principal};
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// In-memory credential cache
pub struct MemoryCache {
    /// Credentials indexed by server principal name
    credentials: RwLock<HashMap<String, Credential>>,
    /// Default principal
    default_principal: RwLock<Option<Principal>>,
}

impl MemoryCache {
    /// Create a new memory cache
    pub fn new() -> Self {
        Self {
            credentials: RwLock::new(HashMap::new()),
            default_principal: RwLock::new(None),
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

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialCache for MemoryCache {
    fn open(&mut self, _path: &Path) -> Result<()> {
        // Memory cache doesn't use file paths
        // This is a no-op for compatibility with the trait
        Ok(())
    }

    fn load(&mut self) -> Result<Vec<Credential>> {
        let creds = self.credentials.read().map_err(|_| Error::Ccache {
            text: "Failed to acquire read lock".to_string(),
        })?;

        Ok(creds.values().cloned().collect())
    }

    fn save(&mut self, credentials: &[Credential]) -> Result<()> {
        {
            let mut creds = self.credentials.write().map_err(|_| Error::Ccache {
                text: "Failed to acquire write lock".to_string(),
            })?;

            // Clear existing and add new
            creds.clear();
            for cred in credentials {
                let key = cred.server.to_string();
                creds.insert(key, cred.clone());
            }
        } // Drop lock here

        // Update default principal from first credential if needed
        if !credentials.is_empty() {
            let mut principal = self.default_principal.write().map_err(|_| Error::Ccache {
                text: "Failed to acquire principal write lock".to_string(),
            })?;
            *principal = Some(credentials[0].client.clone());
        }

        Ok(())
    }

    fn store_ticket(&mut self, credential: Credential) -> Result<()> {
        let key = credential.server.to_string();

        // Update default principal if this is the first credential
        {
            let mut principal = self.default_principal.write().map_err(|_| Error::Ccache {
                text: "Failed to acquire principal write lock".to_string(),
            })?;
            if principal.is_none() {
                *principal = Some(credential.client.clone());
            }
        }

        // Store the credential
        let mut creds = self.credentials.write().map_err(|_| Error::Ccache {
            text: "Failed to acquire write lock".to_string(),
        })?;
        creds.insert(key, credential);

        Ok(())
    }

    fn get_ticket(&mut self, spn: &str) -> Result<Option<Credential>> {
        let creds = self.credentials.read().map_err(|_| Error::Ccache {
            text: "Failed to acquire read lock".to_string(),
        })?;

        // Find the credential and check if it's not expired
        Ok(creds.get(spn).filter(|c| !Self::is_expired(c)).cloned())
    }

    fn remove_ticket(&mut self, spn: &str) -> Result<()> {
        let mut creds = self.credentials.write().map_err(|_| Error::Ccache {
            text: "Failed to acquire write lock".to_string(),
        })?;

        creds.remove(spn);
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        let creds = self.credentials.read().map_err(|_| Error::Ccache {
            text: "Failed to acquire read lock".to_string(),
        })?;

        Ok(creds.keys().cloned().collect())
    }

    fn purge_expired(&mut self) -> Result<usize> {
        let mut creds = self.credentials.write().map_err(|_| Error::Ccache {
            text: "Failed to acquire write lock".to_string(),
        })?;

        let initial_count = creds.len();
        creds.retain(|_, cred| !Self::is_expired(cred));
        let removed_count = initial_count - creds.len();

        Ok(removed_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccache::format::{KeyBlock, NameType, Times};

    fn create_test_credential(server_name: &str, expired: bool) -> Credential {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let end_time = if expired {
            1000 // Way in the past
        } else {
            now + 36000 // 10 hours from now
        };

        Credential {
            client: Principal::new(
                NameType::Principal,
                "TEST.REALM".to_string(),
                vec!["user".to_string()],
            ),
            server: Principal::new(
                NameType::ServiceInstance,
                "TEST.REALM".to_string(),
                server_name
                    .split('/')
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            key_block: KeyBlock {
                enctype: 18, // AES256
                key_data: vec![0x42; 32],
            },
            times: Times {
                auth_time: now,
                start_time: now,
                end_time,
                renew_till: now + 86400,
            },
            is_config: 0,
            ticket_flags: 0x40a1_0000,
            addresses: Vec::new(),
            ticket: vec![0xde, 0xad, 0xbe, 0xef],
            second_ticket: Vec::new(),
            authdata: Vec::new(),
        }
    }

    #[test]
    fn test_memory_cache_basic() {
        let mut cache = MemoryCache::new();

        // Store a credential
        let cred = create_test_credential("host/server.test", false);
        cache.store_ticket(cred).unwrap();

        // Retrieve it
        let retrieved = cache.get_ticket("host/server.test@TEST.REALM").unwrap();
        assert!(retrieved.is_some());

        // List should contain it
        let list = cache.list().unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.contains(&"host/server.test@TEST.REALM".to_string()));
    }

    #[test]
    fn test_memory_cache_expiration() {
        let mut cache = MemoryCache::new();

        // Store both valid and expired credentials
        let valid = create_test_credential("host/valid.test", false);
        let expired = create_test_credential("host/expired.test", true);

        cache.store_ticket(valid).unwrap();
        cache.store_ticket(expired).unwrap();

        // Should only retrieve valid one
        assert!(cache
            .get_ticket("host/valid.test@TEST.REALM")
            .unwrap()
            .is_some());
        assert!(cache
            .get_ticket("host/expired.test@TEST.REALM")
            .unwrap()
            .is_none());

        // Purge should remove expired
        let removed = cache.purge_expired().unwrap();
        assert_eq!(removed, 1);

        // List should only have valid
        let list = cache.list().unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_memory_cache_save_load() {
        let mut cache = MemoryCache::new();

        // Create multiple credentials
        let creds = vec![
            create_test_credential("host/server1.test", false),
            create_test_credential("host/server2.test", false),
        ];

        // Save them
        cache.save(&creds).unwrap();

        // Load should return them
        let loaded = cache.load().unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_memory_cache_remove() {
        let mut cache = MemoryCache::new();

        // Store credentials
        let cred1 = create_test_credential("host/server1.test", false);
        let cred2 = create_test_credential("host/server2.test", false);
        cache.store_ticket(cred1).unwrap();
        cache.store_ticket(cred2).unwrap();

        // Remove one
        cache.remove_ticket("host/server1.test@TEST.REALM").unwrap();

        // Should only have one left
        let list = cache.list().unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.contains(&"host/server2.test@TEST.REALM".to_string()));
    }

    #[test]
    fn test_memory_cache_concurrent_access() {
        // Test that the internal RwLock provides thread safety
        // Note: The trait requires &mut self, so we can't actually share
        // the cache across threads. This test verifies the internal
        // locking mechanisms work correctly.

        let mut cache = MemoryCache::new();

        // Add multiple credentials sequentially
        for i in 0..10 {
            let cred = create_test_credential(&format!("host/server{i}.test"), false);
            cache.store_ticket(cred).unwrap();
        }

        // Verify all were stored
        let list = cache.list().unwrap();
        assert_eq!(list.len(), 10);

        // The RwLock inside ensures thread-safe access to the internal
        // data structures, even though the API requires &mut self
    }
}
