//! Secure memory handling and zeroization utilities
//!
//! This module provides utilities for secure handling of sensitive data
//! in memory, ensuring that secrets are properly zeroed when no longer needed.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure buffer for sensitive data that is automatically zeroed on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create a new secure buffer with the given data
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create an empty secure buffer with the given capacity
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Get a reference to the data
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the data
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length of the buffer
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Extend the buffer with additional data
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }

    /// Clear the buffer (zeros the memory)
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }

    /// Convert to a Vec, consuming self
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        let mut result = Vec::new();
        std::mem::swap(&mut result, &mut self.data);
        result
    }
}

impl From<Vec<u8>> for SecureBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl AsRef<[u8]> for SecureBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBuffer")
            .field("len", &self.data.len())
            .finish()
    }
}

impl From<&[u8]> for SecureBuffer {
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

/// Session key that is automatically zeroed on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey {
    key: Vec<u8>,
    algorithm: String,
}

impl SessionKey {
    /// Create a new session key
    #[must_use]
    pub const fn new(key: Vec<u8>, algorithm: String) -> Self {
        Self { key, algorithm }
    }

    /// Get the key bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Get the algorithm name
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Get the key length in bytes
    #[must_use]
    pub const fn len(&self) -> usize {
        self.key.len()
    }

    /// Check if the key is empty
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.key.is_empty()
    }
}

/// GSS token wrapper that ensures zeroization
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GssToken {
    data: Vec<u8>,
}

impl GssToken {
    /// Create a new GSS token
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the token data
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the token length
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the token is empty
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Convert to Vec, consuming self
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        let mut result = Vec::new();
        std::mem::swap(&mut result, &mut self.data);
        result
    }
}

/// Wrapped message with automatic zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureWrappedMessage {
    header: Vec<u8>,
    data: Vec<u8>,
    trailer: Vec<u8>,
}

impl SecureWrappedMessage {
    /// Create a new wrapped message
    #[must_use]
    pub const fn new(header: Vec<u8>, data: Vec<u8>, trailer: Vec<u8>) -> Self {
        Self {
            header,
            data,
            trailer,
        }
    }

    /// Get the header
    #[must_use]
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// Get the data
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the trailer
    #[must_use]
    pub fn trailer(&self) -> &[u8] {
        &self.trailer
    }

    /// Get the total size
    #[must_use]
    pub const fn total_size(&self) -> usize {
        self.header.len() + self.data.len() + self.trailer.len()
    }
}

/// Utility function to securely compare two byte slices in constant time
#[must_use]
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}

/// Utility to ensure a buffer is zeroed even in the presence of compiler optimizations
pub fn secure_zero(buffer: &mut [u8]) {
    buffer.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer() {
        let data = vec![1, 2, 3, 4, 5];
        let mut buffer = SecureBuffer::new(data.clone());

        assert_eq!(buffer.as_bytes(), &data);
        assert_eq!(buffer.len(), 5);
        assert!(!buffer.is_empty());

        buffer.clear();
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_session_key() {
        let key = SessionKey::new(vec![0x42; 32], "AES256".to_string());

        assert_eq!(key.len(), 32);
        assert_eq!(key.algorithm(), "AES256");
        assert_eq!(key.as_bytes()[0], 0x42);
    }

    #[test]
    fn test_gss_token() {
        let token = GssToken::new(vec![0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(token.len(), 4);
        assert_eq!(token.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_secure_compare() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        let c = vec![1, 2, 3, 5];
        let d = vec![1, 2, 3];

        assert!(secure_compare(&a, &b));
        assert!(!secure_compare(&a, &c));
        assert!(!secure_compare(&a, &d));
    }

    #[test]
    fn test_secure_wrapped_message() {
        let msg = SecureWrappedMessage::new(vec![1, 2], vec![3, 4, 5], vec![6, 7]);

        assert_eq!(msg.header(), &[1, 2]);
        assert_eq!(msg.data(), &[3, 4, 5]);
        assert_eq!(msg.trailer(), &[6, 7]);
        assert_eq!(msg.total_size(), 7);
    }
}
