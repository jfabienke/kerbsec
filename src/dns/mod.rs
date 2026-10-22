//! DNS utilities for FQDN canonicalization and KDC discovery
//!
//! This module provides DNS resolution functionality for proper Kerberos
//! operation, including:
//! - CNAME following for canonical hostname resolution
//! - SRV record lookups for KDC discovery

pub mod resolver;
