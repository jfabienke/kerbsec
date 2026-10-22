# kerbsec Usage Guide

## Table of Contents

- [GSS Flags Configuration](#gss-flags-configuration)
- [Logging Configuration](#logging-configuration)
- [Credential Cache](#credential-cache-krb5ccname)
- [Mechanism OID](#mechanism-oid)
- [GSS Wrap Size Limits](#gss-wrap-size-limits)
- [Platform Differences](#platform-differences)
- [MIT vs Heimdal Version Matrix](#mit-vs-heimdal-version-matrix)
- [Environment Variables](#environment-variables)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## GSS Flags Configuration

kerbsec provides runtime configuration for critical GSS-API flags that control authentication behavior:

### DCE-Style Flag (GSS_C_DCE_STYLE)

The DCE-style flag (0x1000) modifies GSS-API behavior for DCE/RPC compatibility:

```rust
let config = KerberosConfig::builder()
    .dce_style(true)  // Default: true
    .build()?;
```

**When enabled (default):**
- Selects the DCE/RPC three-leg handshake and relaxed IOV padding/trailer rules
- Does not disable sequence/replay detection

**When to disable:**
- Non-DCE/RPC Kerberos applications
- Standard GSS-API usage without RPC framing

### Credential Delegation (GSS_C_DELEG_FLAG)

Allows the server to impersonate the client:

```rust
let config = KerberosConfig::builder()
    .delegation(true)  // Default: false
    .build()?;

// After authentication
if ctx.has_delegated_credentials() {
    match ctx.export_delegated_credentials() {
        Ok(creds) => {
            // Use for S4U2Self/S4U2Proxy
            println!("Got {} bytes of delegated credentials", creds.len());
        }
        Err(e) => {
            println!("Delegation not available: {}", e);
        }
    }
}
```

**Use cases:**
- Multi-tier architectures where middle tier needs client's identity
- Services that access resources on behalf of users
- S4U2Self and S4U2Proxy scenarios

**Security considerations:**
- Only enable for completely trusted servers
- Server can impersonate client to any service
- Monitor delegation usage in audit logs

### Mutual Authentication (GSS_C_MUTUAL_FLAG)

Ensures server authenticates to client:

```rust
let config = KerberosConfig::builder()
    .mutual_auth(true)  // Default: true
    .build()?;
```

**When enabled (default):**
- Server must prove its identity
- Prevents man-in-the-middle attacks
- Required for secure channel establishment

**When to disable (not recommended):**
- Legacy systems that don't support mutual auth
- Testing/debugging scenarios only

### Configuration Examples

#### Standard DCE/RPC (defaults)
```rust
// All defaults are optimized for DCE/RPC
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .build()?;
// Results in: DCE-style=true, delegation=false, mutual=true
```

#### Delegation for Trusted Server
```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("trusted-app-tier.example.com")
    .delegation(true)  // Enable delegation
    .build()?;
```

#### Non-DCE Kerberos Application
```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("legacy.example.com")
    .dce_style(false)  // Disable DCE-style
    .build()?;
```

## Logging Configuration

kerbsec provides structured logging via the `trace` feature flag:

### Enabling Logging

```rust
// Initialize tracing subscriber
#[cfg(feature = "trace")]
tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .init();
```

### Available Log Targets

| Target            | Description        | Example Usage                   |
|-------------------|--------------------|---------------------------------|
| `kerbsec::ctx`    | Context lifecycle  | `RUST_LOG=kerbsec::ctx=debug`   |
| `kerbsec::gss`    | GSS-API operations | `RUST_LOG=kerbsec::gss=trace`   |
| `kerbsec::dns`    | DNS resolution     | `RUST_LOG=kerbsec::dns=info`    |
| `kerbsec::iov`    | IOV wrap/unwrap    | `RUST_LOG=kerbsec::iov=debug`   |
| `kerbsec::config` | Configuration      | `RUST_LOG=kerbsec::config=warn` |

### Examples

```bash
# Enable all kerbsec logging
RUST_LOG=kerbsec=debug cargo run

# Debug GSS errors specifically
RUST_LOG=kerbsec::gss=trace cargo run

# Mixed levels for different modules
RUST_LOG=kerbsec::ctx=info,kerbsec::iov=debug,kerbsec::gss=trace cargo run
```

See [docs/LOGGING.md](LOGGING.md) for comprehensive logging documentation.

## Credential Cache (KRB5CCNAME)

The Kerberos credential cache stores your tickets after authentication. kerbsec respects the standard `KRB5CCNAME` environment variable:

```bash
# Use default cache location
kinit user@REALM.COM

# Use custom cache location
export KRB5CCNAME=/tmp/krb5cc_custom
kinit user@REALM.COM

# Use memory cache (Linux)
export KRB5CCNAME=MEMORY:myapp
kinit user@REALM.COM

# Use API cache (macOS)
export KRB5CCNAME=API:
kinit user@REALM.COM

# Use KCM daemon cache (systemd systems)
export KRB5CCNAME=KCM:
kinit user@REALM.COM
```

### Programmatic Cache Selection

```rust
use kerbsec::KerberosConfig;

// Use environment variable (default)
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .build()?;

// Override with specific cache
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.example.com")
    .kccache(Some("/tmp/krb5cc_myapp".to_string()))
    .build()?;

// Use in-memory cache for testing
let config = KerberosConfig::builder()
    .realm("TEST.REALM")
    .target_host("test.server")
    .kccache(Some("MEMORY:test".to_string()))
    .build()?;
```

## Mechanism OID

kerbsec uses the Kerberos V5 mechanism OID as defined in RFC 1964:

```rust
use kerbsec::{Context, KRB5_MECH_OID};

let ctx = Context::new(config)?;

// Get the mechanism OID for SPNEGO negotiation
let oid = ctx.mech_oid();
assert_eq!(oid, &KRB5_MECH_OID);

// OID in dotted notation: 1.2.840.113554.1.2.2
println!("Mech OID: {}", oid.dotted());

// OID in DER encoding for ASN.1
let der_bytes = oid.der();
// [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]
```

### Common OIDs

| Mechanism   | OID                    | Description                      |
|-------------|------------------------|----------------------------------|
| Kerberos V5 | 1.2.840.113554.1.2.2   | Native Kerberos (RFC 1964)       |
| SPNEGO      | 1.3.6.1.5.5.2          | Negotiation mechanism (RFC 4178) |
| NTLM        | 1.3.6.1.4.1.311.2.2.10 | Legacy Windows auth              |
| MS-KRB5     | 1.2.840.48018.1.2.2    | Microsoft Kerberos variant       |

## GSS Wrap Size Limits

The GSS-API `gss_wrap_size_limit` function determines the maximum message size that can be wrapped without exceeding token size limits:

```rust
// Maximum sizes for DCE/RPC with default 4KB fragment size
const MAX_RPC_FRAGMENT: usize = 4096;
const GSS_OVERHEAD_PRIVACY: usize = 60;  // Typical: 32 header + 16 padding + 12 trailer
const GSS_OVERHEAD_INTEGRITY: usize = 28; // Typical: 16 header + 12 trailer

// Calculate maximum payload size
fn max_payload_size(auth_level: AuthLevel, fragment_size: usize) -> usize {
    let overhead = match auth_level {
        AuthLevel::Privacy => GSS_OVERHEAD_PRIVACY,
        AuthLevel::Integrity => GSS_OVERHEAD_INTEGRITY,
    };

    fragment_size.saturating_sub(overhead)
}

// Example: 4KB fragment with Privacy
let max_payload = max_payload_size(AuthLevel::Privacy, 4096);
assert!(max_payload <= 4036); // ~4KB - 60 bytes overhead
```

### IOV Overhead Breakdown

| Component  | Integrity | Privacy     | Description             |
|------------|-----------|-------------|-------------------------|
| GSS Header | 16 bytes  | 16-32 bytes | Token header with flags |
| Sequence   | 4 bytes   | 4 bytes     | Anti-replay counter     |
| Padding    | 0 bytes   | 0-16 bytes  | Block cipher alignment  |
| MIC/MAC    | 12 bytes  | 12-16 bytes | Message auth code       |
| **Total**  | ~28 bytes | ~60 bytes   | Typical overhead        |

## MIT vs Heimdal Version Matrix

kerbsec is tested against multiple Kerberos implementations:

| Platform     | Implementation | Versions Tested | Notes             |
|--------------|----------------|-----------------|-------------------|
| Ubuntu 20.04 | MIT Kerberos   | 1.17            | LTS baseline      |
| Ubuntu 22.04 | MIT Kerberos   | 1.19.2          | Current LTS       |
| Ubuntu 24.04 | MIT Kerberos   | 1.20+           | Latest features   |
| macOS 12+    | Heimdal        | 7.7.0           | System default    |
| macOS (brew) | MIT Kerberos   | 1.20+           | Optional install  |
| RHEL 8       | MIT Kerberos   | 1.18            | Enterprise        |
| RHEL 9       | MIT Kerberos   | 1.19+           | Enterprise latest |

### Feature Compatibility

| Feature          | MIT 1.17+ | Heimdal 7.7+ | Notes                     |
|------------------|-----------|--------------|---------------------------|
| Basic GSS-API    | ✅        | ✅           | Core functionality        |
| IOV Extensions   | ✅        | ⚠️           | Heimdal has different API |
| Channel Bindings | ✅        | ✅           | TLS integration           |
| S4U Extensions   | ✅        | ✅           | Delegation                |
| Anonymous PKINIT | ✅        | ⚠️           | Limited Heimdal support   |
| OTP Support      | ✅        |  ❌           | MIT only                  |
| FAST             | ✅        | ⚠️           | Heimdal partial           |

### Configuration Differences

#### MIT Kerberos (/etc/krb5.conf)
```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

    # MIT-specific
    allow_weak_crypto = false  # RC4 disabled
    preferred_preauth_types = 17,16,15,14
```

#### Heimdal (/etc/krb5.conf)
```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = no
    dns_lookup_kdc = yes
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = yes

    # Heimdal-specific
    allow_weak_crypto = no
    default_etypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
```

## Environment Variables

kerbsec respects standard Kerberos environment variables:

| Variable        | Description               | Example               |
|-----------------|---------------------------|-----------------------|
| `KRB5CCNAME`    | Credential cache location | `/tmp/krb5cc_1000`    |
| `KRB5_CONFIG`   | Config file path          | `/etc/krb5.conf`      |
| `KRB5_CLIENT_KTNAME` | Client keytab (service accounts) | `/etc/krb5.keytab` |
| `KRB5_KTNAME`   | Acceptor (server) keytab; not used by kerbsec | `/etc/krb5.keytab` |
| `KRB5RCACHEDIR` | Replay cache directory    | `/var/tmp`            |
| `KRB5_TRACE`    | Debug trace file          | `/tmp/krb5_trace.log` |
| `GSS_USE_IOV`   | Force IOV usage           | `1`                   |

### Debug Tracing

Enable detailed Kerberos tracing for troubleshooting:

```bash
# MIT Kerberos trace
export KRB5_TRACE=/tmp/krb5_trace.log
cargo run --example wmi_client

# GSS-API debug (MIT)
export GSSAPI_TRACE=/tmp/gss_trace.log

# Heimdal debug
export KRB5_TRACE_LEVEL=5
```

## Security Considerations

### Encryption types come from krb5.conf

kerbsec does not select encryption types; the KDC and system GSS-API library negotiate
them. RC4-HMAC (arcfour-hmac) is weak, so keep `allow_weak_crypto = false` (see the
`krb5.conf` examples above) and restrict `permitted_enctypes`.

### Supported Encryption Types

Strength guide only; the negotiated type is governed by `krb5.conf`.

| Type                       | Security | Default | Notes            |
|----------------------------|----------|---------|------------------|
| aes256-cts-hmac-sha1-96    | Strong   | ✅      | Recommended      |
| aes128-cts-hmac-sha1-96    | Strong   | ✅      | Good performance |
| aes256-cts-hmac-sha384-192 | Strong   | ✅      | RFC 8009         |
| aes128-cts-hmac-sha256-128 | Strong   | ✅      | RFC 8009         |
| des3-cbc-sha1              | Weak     | ⚠️      | Legacy only      |
| arcfour-hmac (RC4)         | Broken   | ❌       | Disabled         |
| des-cbc-crc                | Broken   | ❌       | Never use        |

### Replay Protection

kerbsec enforces replay protection through:

1. **Sequence Numbers**: Monotonically increasing per-context
2. **Timestamps**: 5-minute default clock skew tolerance
3. **Replay Cache**: System-level duplicate detection

```rust
// Configure clock skew tolerance
let config = KerberosConfig::builder()
    .realm("SECURE.CORP")
    .target_host("server")
    .clock_skew(Duration::from_secs(120)) // 2 minutes
    .build()?;
```

## Platform Differences

### IOV Support

IOV (Input/Output Vector) operations provide zero-copy message protection but availability varies by platform:

| Platform         | IOV Support      | Implementation        | Performance |
|------------------|------------------|-----------------------|-------------|
| Linux (MIT)      | ✅ Full          | Native `gss_wrap_iov` | Optimal     |
| Linux (Heimdal)  | ⚠️ Different API | Not supported         | Falls back  |
| macOS (Heimdal)  | ❌ None           | Regular wrap/unwrap   | Good        |
| macOS (MIT brew) | ✅ Full          | Native `gss_wrap_iov` | Optimal     |

### Detecting IOV Support

```rust
use kerbsec::ffi;

if ffi::has_iov_support() {
    println!("Platform has native IOV support");
} else {
    println!("Using fallback implementation");
}
```

### Performance Impact

```rust
// With IOV (Linux): Zero-copy, optimal performance
// Header and trailer are separate buffers
let wrap = ctx.wrap_iov(&pdu)?;
send_header(wrap.header);
send_data(&pdu);
send_trailer(wrap.trailer);

// Without IOV (macOS): One allocation, good performance
// Complete wrapped token returned
let wrap = ctx.wrap_iov(&pdu)?;
send_token(wrap.header); // Contains complete wrapped message
```

## Troubleshooting

### IOV-Specific Issues

| Issue                       | Symptom         | Solution                                |
|-----------------------------|-----------------|-----------------------------------------|
| IOV not available           | Warning in logs | Normal on macOS, performance still good |
| Header/trailer sizes differ | Interop issues  | Platform difference, both are valid     |
| `GSS_C_DCE_STYLE` missing   | Sequence errors | Manually applied, should work           |

### Common Issues

| Error                         | Cause           | Solution                |
|-------------------------------|-----------------|-------------------------|
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | User not in KDC | Verify principal exists |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | Invalid SPN     | Check service principal |
| `KRB_AP_ERR_MODIFIED`         | Token tampered  | Check network integrity |
| `KRB_AP_ERR_REPEAT`           | Replay detected | Check time sync         |
| `KRB_AP_ERR_SKEW`             | Clock skew      | Sync with NTP           |
| `GSS_S_NO_CRED`               | No ticket       | Run `kinit`             |
| `GSS_S_FAILURE`               | Generic error   | Check KRB5_TRACE        |

### Diagnostic Commands

```bash
# List cached tickets
klist -v

# Test Kerberos connectivity
kvno host/server.example.com@REALM.COM

# Renew tickets
kinit -R

# Destroy tickets
kdestroy

# Test DNS SRV records
dig _kerberos._tcp.example.com SRV

# Check time sync
ntpdate -q ntp.example.com

# Enable kerbsec trace logging
RUST_LOG=kerbsec=trace cargo run 2>&1 | tee debug.log

# Enable MIT Kerberos tracing
KRB5_TRACE=/tmp/krb5.log cargo run

# Check IOV support
cargo test --features iov -- --nocapture | grep IOV
```

### Performance Tuning

For production DCE/RPC workloads:

```rust
// Use appropriate fragment sizes
const OPTIMAL_FRAGMENT_SIZE: usize = 16384; // 16KB for LAN
const WAN_FRAGMENT_SIZE: usize = 4096;      // 4KB for WAN

// Pre-allocate buffers for hot paths
let mut buffer = Vec::with_capacity(OPTIMAL_FRAGMENT_SIZE);

// Reuse contexts for multiple operations
let ctx = Context::new(config)?;
for request in requests {
    let wrapped = ctx.wrap_iov(&request)?;
    // Process...
}
```
