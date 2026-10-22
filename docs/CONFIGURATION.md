# Configuration Guide for kerbsec

This guide provides comprehensive documentation for configuring kerbsec in various environments and use cases.

## Table of Contents

- [Basic Configuration](#basic-configuration)
- [GSS Flags Configuration](#gss-flags-configuration)
- [Authentication Levels](#authentication-levels)
- [DNS Configuration](#dns-configuration)
- [Credential Management](#credential-management)
- [Channel Bindings](#channel-bindings)
- [Feature Flags](#feature-flags)
- [Environment Variables](#environment-variables)
- [Common Scenarios](#common-scenarios)

## Basic Configuration

### Minimal Configuration

The minimum required configuration needs only a realm and target host:

```rust
use kerbsec::KerberosConfig;

let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .build()?;
```

### Default Values

When using the builder pattern, the following defaults are applied:

| Setting               | Default Value        | Description                                |
|-----------------------|----------------------|--------------------------------------------|
| `enable_dce_style`    | `true`               | Enable DCE/RPC compatibility mode          |
| `enable_delegation`   | `false`              | Disable credential delegation for security |
| `require_mutual_auth` | `true`               | Require server authentication              |
| `default_auth`        | `AuthLevel::Privacy` | Use encryption by default                  |
| `dns_timeout`         | 5 seconds            | DNS resolution timeout                     |

## GSS Flags Configuration

### DCE-Style Flag (GSS_C_DCE_STYLE)

The DCE-style flag modifies GSS-API behavior for DCE/RPC compatibility:

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .dce_style(true)  // Default: true
    .build()?;
```

**Effects of DCE-style:**
- Selects the DCE/RPC three-leg handshake and relaxed IOV padding/trailer rules
- Does not disable sequence/replay detection
- Modifies replay detection to work with DCE/RPC

**When to use:**
- Always for DCE/RPC protocols (default)
- Windows RPC communications
- SMB protocol implementations

**When to disable:**
- Custom protocols needing GSS sequence protection
- Non-DCE Kerberos applications
- Maximum GSS-API security requirements

### Delegation Flag (GSS_C_DELEG_FLAG)

Credential delegation allows servers to impersonate clients:

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("trusted-server.example.com")
    .delegation(true)  // Default: false - DANGEROUS!
    .build()?;
```

**Security Warning:** Only enable delegation for completely trusted servers!

**Valid use cases:**
- S4U2Self/S4U2Proxy scenarios
- Multi-tier authentication systems
- Trusted internal services only

### Mutual Authentication Flag (GSS_C_MUTUAL_FLAG)

Mutual authentication ensures the server's identity:

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .mutual_auth(true)  // Default: true
    .build()?;
```

**When to disable (NOT recommended):**
- Legacy systems that don't support mutual auth
- Testing environments only
- Performance-critical scenarios with trusted networks

## Authentication Levels

kerbsec supports three authentication levels:

### Privacy (Default)

Full encryption and integrity protection:

```rust
use kerbsec::AuthLevel;

let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .default_auth(AuthLevel::Privacy)
    .build()?;
```

### Integrity

Message integrity without encryption:

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .default_auth(AuthLevel::Integrity)
    .build()?;
```

### None

No protection (authentication only):

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .default_auth(AuthLevel::None)
    .build()?;
```

## DNS Configuration

### Automatic Canonicalization

With the `dns` feature enabled, hostnames are automatically canonicalized:

```rust
#[cfg(feature = "dns")]
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server")  // Will be resolved to FQDN
    .build_async()
    .await?;
```

### Manual FQDN

Provide the full FQDN to skip DNS resolution:

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.corp.example.com")
    .build()?;
```

### IP Address with SPN Override

When using IP addresses, provide an explicit SPN:

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("192.168.1.100")
    .spn_override("HOST/server.corp.example.com")
    .build()?;
```

### DNS Timeout Configuration

Control DNS resolution timeout:

```rust
use std::time::Duration;

let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .dns_timeout(Duration::from_secs(10))
    .build_async()
    .await?;
```

## Credential Management

### Default System Credentials

Use the system's default credential cache:

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .build()?;
```

### Custom Credential Cache

Specify a custom credential cache location:

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .kccache("/tmp/krb5cc_custom")
    .build()?;
```

### Environment Variable

Set via environment variable:

```rust
std::env::set_var("KRB5CCNAME", "FILE:/tmp/krb5cc_myapp");

let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .build()?;
```

## Channel Bindings

Channel bindings tie Kerberos to the transport layer:

```rust
use kerbsec::channel_bindings::{ChannelBindings, ChannelBindingType};

let cb = ChannelBindings {
    initiator_addrtype: 0,
    initiator_address: Vec::new(),
    acceptor_addrtype: 0,
    acceptor_address: Vec::new(),
    application_data: tls_unique_data,  // From TLS connection
    binding_type: Some(ChannelBindingType::TlsUnique),
};

let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .channel_bindings(Some(cb))
    .build()?;
```

## Feature Flags

Configure cargo features in `Cargo.toml`:

```toml
[dependencies]
kerbsec = {
    version = "0.2.0",
    features = [
        "dns",               # DNS canonicalization (default)
        "runtime",           # Async runtime support (default)
        "iov",               # Zero-copy IOV operations (default)
        "ccache",            # Credential cache support
        "trace",             # Structured logging
    ]
}
```

### Feature Combinations

Common feature combinations for different use cases:

**Production DCE/RPC:**
```toml
features = ["dns", "runtime", "iov"]  # Defaults
```

**Debugging:**
```toml
features = ["dns", "runtime", "iov", "trace"]
```

**Minimal Build:**
```toml
default-features = false
features = []  # No DNS, no async, no IOV
```

**With Credential Cache Management:**
```toml
features = ["dns", "runtime", "iov", "ccache"]
```

## Environment Variables

kerbsec respects standard Kerberos environment variables:

| Variable             | Description               | Example                    |
|----------------------|---------------------------|----------------------------|
| `KRB5CCNAME`         | Credential cache location | `FILE:/tmp/krb5cc_1000`    |
| `KRB5_CONFIG`        | Kerberos config file      | `/etc/krb5.conf`           |
| `KRB5_KTNAME`        | Acceptor (server) keytab; not used by kerbsec | `/etc/krb5.keytab` |
| `KRB5_CLIENT_KTNAME` | Client keytab             | `/home/user/client.keytab` |
| `KRB5RCACHETYPE`     | Replay cache type         | `none` (for testing)       |
| `KRB5_TRACE`         | Trace file for debugging  | `/tmp/krb5_trace.log`      |

## Common Scenarios

### Windows Domain Authentication

Standard configuration for Windows Active Directory:

```rust
let config = KerberosConfig::builder()
    .realm("CORP.CONTOSO.COM")
    .target_host("dc01.corp.contoso.com")
    .default_auth(AuthLevel::Privacy)
    .dce_style(true)        // Required for Windows RPC
    .delegation(false)      // Don't delegate unless needed
    .mutual_auth(true)      // Always verify server
    .build_async()
    .await?;
```

### Cross-Realm Trust

Authenticating across trusted realms:

```rust
let config = KerberosConfig::builder()
    .realm("SUBSIDIARY.EXAMPLE.COM")
    .target_host("server.parent.example.com")
    .spn_override("HOST/server.parent.example.com@PARENT.EXAMPLE.COM")
    .build()?;
```

### Load Balancer with SPN Override

Connecting through a load balancer:

```rust
let config = KerberosConfig::builder()
    .realm("EXAMPLE.COM")
    .target_host("lb.example.com")  // Load balancer
    .spn_override("HOST/backend-pool.example.com")  // Actual service SPN
    .build()?;
```

### High-Security Configuration

Maximum security settings:

```rust
let config = KerberosConfig::builder()
    .realm("SECURE.EXAMPLE.COM")
    .target_host("secure-server.example.com")
    .default_auth(AuthLevel::Privacy)
    .dce_style(false)       // Use standard GSS-API
    .delegation(false)      // Never delegate
    .mutual_auth(true)      // Always verify
    .channel_bindings(Some(cb))  // Bind to TLS
    .build()?;
```

### Performance-Optimized

Settings optimized for performance:

```rust
let config = KerberosConfig::builder()
    .realm("EXAMPLE.COM")
    .target_host("fast-server.example.com")
    .default_auth(AuthLevel::Integrity)  // Skip encryption
    .dns_timeout(Duration::from_secs(2))  // Fast DNS timeout
    .build()?;
```

### Testing Configuration

Configuration for development/testing:

```rust
let config = KerberosConfig::builder()
    .realm("TEST.LOCAL")
    .target_host("test-server.local")
    .default_auth(AuthLevel::None)  // No protection for testing
    .dce_style(true)
    .delegation(false)
    .mutual_auth(false)  // Skip mutual auth in test
    .kccache("/tmp/test_krb5cc")
    .build()?;
```

## Configuration Validation

The builder performs validation to ensure configuration consistency:

```rust
// This will fail - incompatible settings
let result = KerberosConfig::builder()
    .realm("")  // Empty realm not allowed
    .target_host("server")
    .build();

assert!(result.is_err());
```

Common validation rules:
- Realm must not be empty
- Target host must be valid
- DNS timeout must be positive
- GSS timeout must be positive
- Channel bindings must have valid structure

## Migration Guide

### From v0.1.x to v0.2.x

The main change is moving from feature-gated to runtime-configurable GSS flags:

**v0.1.x (old):**
```rust
// DCE-style was feature-gated
#[cfg(feature = "dce-style")]
let ctx = Context::new(config)?;
```

**v0.2.x (new):**
```rust
// DCE-style is runtime-configurable
let config = KerberosConfig::builder()
    .dce_style(true)  // Configure at runtime
    .build()?;
let ctx = Context::new(config)?;
```

### Adding Delegation Support

To add delegation to existing code:

```rust
// Before - no delegation
let config = KerberosConfig::builder()
    .realm("EXAMPLE.COM")
    .target_host("server.example.com")
    .build()?;

// After - with delegation (only for trusted servers!)
let config = KerberosConfig::builder()
    .realm("EXAMPLE.COM")
    .target_host("trusted-server.example.com")
    .delegation(true)  // Enable carefully!
    .build()?;

// Check for delegated credentials after authentication
if ctx.has_delegated_credentials() {
    let creds = ctx.export_delegated_credentials()?;
    // Use delegated credentials carefully
}
```

## Troubleshooting

### Common Configuration Issues

**Issue: "Target host not found"**
- Ensure DNS is working: `nslookup server.example.com`
- Try using FQDN directly
- Check firewall rules

**Issue: "Realm not found"**
- Verify krb5.conf has realm configuration
- Check KDC is reachable: `ping kdc.example.com`
- Ensure realm is uppercase

**Issue: "Clock skew too great"**
- Synchronize system time with NTP
- Default allowed skew is 5 minutes
- Check timezone settings

**Issue: "Credential cache not found"**
- Run `kinit` to obtain tickets
- Check KRB5CCNAME environment variable
- Verify cache file permissions

### Debug Logging

Enable trace logging to debug configuration issues:

```rust
#[cfg(feature = "trace")]
tracing_subscriber::fmt()
    .with_env_filter("kerbsec=debug")
    .init();
```

Then run with:
```bash
RUST_LOG=kerbsec=debug cargo run
```

---

*Configuration guide for kerbsec v0.2.0*
