# kerbsec

Internal Kerberos (GSS-API) library for DCE/RPC on Unix

## Overview

`kerbsec` provides a lightweight Kerberos security context for DCE/RPC transports by leveraging the system GSS-API (MIT Kerberos or Heimdal). Designed specifically for DCE/RPC authentication and protection, it offers a focused (~9,000 LOC) implementation that is transport-agnostic.

## Features

- **MIT Licensed**: Commercial-friendly open source license
- **Unix-focused**: Leverages system GSS-API (MIT Kerberos/Heimdal)
- **DCE/RPC optimized**: Implements 3-leg handshake with IOV-like wrap/unwrap
- **Windows AD compatible**: Full compatibility with Active Directory environments
- **Runtime-configurable GSS flags**: DCE-style, delegation, and mutual auth
- **Transport-agnostic**: Users handle RPC framing, kerbsec handles GSS tokens
- **DNS canonicalization**: Automatic FQDN resolution for proper SPN construction
- **Flexible auth levels**: Support for Integrity (MIC) and Privacy (seal+MIC)
- **Credential delegation**: Support for S4U2Self/S4U2Proxy scenarios
- **Channel bindings**: TLS channel bindings support (RFC 5929)
- **Zero-copy IOV**: Native IOV operations on Linux for maximum performance
- **Structured logging**: Feature-gated tracing with module-specific targets
- **Mock testing**: Built-in mock GSS-API for unit testing without a KDC
- **Feature-gated**: Optional DNS, async runtime, IOV, ccache, and tracing support

### Feature Flags

| Feature                   | Description                            | Default |
|---------------------------|----------------------------------------|---------|
| `dns`                     | DNS canonicalization and KDC discovery | ✅      |
| `runtime`                 | Async runtime support (tokio)          | ✅      |
| `iov`                     | GSS IOV operations for zero-copy       | ✅      |
| `ccache`                  | Credential cache support               | ❌      |
| `channel-bindings`        | TLS channel bindings (RFC 5929)        | ❌      |
| `channel-bindings-rustls` | Channel bindings with rustls           | ❌      |
| `trace`                   | Structured logging via tracing         | ❌      |

## Installation

This is an internal library. Add to your `Cargo.toml`:

```toml
[dependencies]
kerbsec = { path = "../kerbsec", features = ["dns", "runtime", "ccache"] }
```

### Prerequisites

- **Ubuntu/Debian**: `sudo apt-get install libkrb5-dev libgssapi-krb5-2`
- **macOS**: System Kerberos (Heimdal) included, or `brew install krb5` for MIT
- **RHEL/Fedora**: `sudo dnf install krb5-devel`

## Usage

### Basic DCE/RPC Authentication

```rust
use kerbsec::{Context, KerberosConfig, AuthLevel};

// Configure with DNS canonicalization and DCE-style (default)
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.corp.example.com")
    .default_auth(AuthLevel::Privacy)
    .dce_style(true)        // Default: true for DCE/RPC
    .delegation(false)      // Default: false for security
    .mutual_auth(true)      // Default: true for security
    .build_async()
    .await?;

// Create context
let mut ctx = Context::new(config)?;

// Generate AP-REQ for RPC bind
let ap_req = ctx.initial_token()?;
// → Send in RPC bind PDU auth trailer

// Process AP-REP from bind_ack
let third_leg = ctx.accept_ap_rep(&ap_rep)?;
// → Send third leg in alter_context (even if empty)

// Check for delegated credentials (if delegation was enabled)
if ctx.has_delegated_credentials() {
    let creds = ctx.export_delegated_credentials()?;
    // → Use for S4U2Self/S4U2Proxy operations
}

// Protect RPC requests
let wrapped = ctx.wrap_iov(&request_pdu)?;
// → Append wrapped.header and wrapped.trailer to PDU
```

### Logging and Debugging

Enable structured logging with the `trace` feature:

```rust
// Initialize logging
#[cfg(feature = "trace")]
tracing_subscriber::fmt()
    .with_env_filter("kerbsec=debug")
    .init();

// Available log targets:
// - kerbsec::ctx - Context operations
// - kerbsec::gss - GSS-API calls
// - kerbsec::dns - DNS resolution
// - kerbsec::iov - IOV wrap/unwrap
// - kerbsec::config - Configuration
```

See [docs/LOGGING.md](docs/LOGGING.md) for detailed logging guide.

### IP Address Targets

For IP addresses, override the SPN:

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("192.168.1.100")
    .spn_override("HOST/server.corp.example.com")
    .build()?;
```

### Custom Credential Cache

```rust
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("server.corp.example.com")
    .kccache("/tmp/krb5cc_custom")
    .build()?;
```

## Architecture

kerbsec is designed as a thin wrapper around the system GSS-API:

```
Application (e.g., linux-wmi)
    ↓
kerbsec::Context (Rust API)
    ↓
libgssapi (Rust bindings)
    ↓
System GSS-API (MIT Kerberos/Heimdal)
```

The library handles:
- GSS token generation and processing
- IOV-based wrap/unwrap for efficiency
- DCE-style 3-leg handshake semantics
- DNS canonicalization for FQDN resolution

Users are responsible for:
- RPC PDU framing and transport
- Kerberos ticket acquisition (kinit)
- Network connection management

## Reference Documentation

The implementation follows these standards and specifications, available in `docs/refs/`:

### Core Kerberos
- **RFC 4120**: The Kerberos Network Authentication Service (V5)
- **RFC 4121**: Kerberos Version 5 GSS-API Mechanism (Updated)
- **RFC 1964**: The Kerberos Version 5 GSS-API Mechanism (Legacy)

### GSS-API
- **RFC 2743**: Generic Security Service API Version 2
- **RFC 2744**: Generic Security Service API Version 2: C-bindings
- **GSSAPI-IOV.pdf**: IOV extensions for efficient wrapping

### Microsoft Extensions
- **MS-KILE**: Kerberos Protocol Extensions
- **MS-RPCE**: Remote Procedure Call Protocol Extensions
- **MS-SPNG**: Simple and Protected GSS-API Negotiation Mechanism
- **MS-ADTS**: Active Directory Technical Specification

### Supporting Standards
- **RFC 2782**: DNS SRV Records for service discovery
- **RFC 4178**: GSS-API Negotiation Mechanism (SPNEGO)
- **RFC 5929**: Channel Bindings for TLS
- **CCACHE.pdf**: Credential cache format specification
- **CCACHE-FS.pdf**: File-based credential cache implementation

## Known Limitations

### IOV Implementation

**Linux**: Full native IOV support using custom FFI bindings to `gss_wrap_iov`/`gss_unwrap_iov`. This provides zero-copy operations and optimal performance for DCE/RPC workloads. This is tested with MIT Kerberos. With Heimdal on Linux, build without the `iov` feature: in DCE style Heimdal rejects the IOV buffer layout kerbsec uses.

**macOS** (and Linux without the `iov` feature): uses single-token `gss_wrap`/`gss_unwrap`. `IovWrap::header` holds the whole wrapped token and `payload`/`trailer` are empty, so the caller sends the header as one blob. Confidentiality and flag checks are the same as on Linux.

The implementation automatically detects the platform and uses the best available method

### GSS_C_DCE_STYLE Flag
The GSS_C_DCE_STYLE flag (0x1000) is runtime-configurable via the `enable_dce_style` configuration option (defaults to true). Since libgssapi 0.9.1 doesn't expose it in CtxFlags, we manually apply it using bitwise operations. This flag is critical for:
- The DCE/RPC three-leg handshake
- Relaxed IOV padding/trailer rules for DCE/RPC PDU framing

It does not disable sequence or replay detection; those are still requested.

```rust
// Enable DCE-style (default for DCE/RPC compatibility)
let config = KerberosConfig::builder()
    .dce_style(true)  // Default: true
    .build()?;
```

### Credential Delegation (GSS_C_DELEG_FLAG)
Credential delegation allows the server to impersonate the client for accessing other services (S4U2Self/S4U2Proxy). This is disabled by default for security:

```rust
// Enable delegation only for trusted servers
let config = KerberosConfig::builder()
    .delegation(true)  // Default: false
    .build()?;

// After authentication, check for delegated credentials
if ctx.has_delegated_credentials() {
    let creds = ctx.export_delegated_credentials()?;
    // Use credentials for impersonation
}
```

**Security Warning**: Only enable delegation when you completely trust the server, as it allows the server to act on your behalf.

### DNS Canonicalization
DNS canonicalization now properly:
- Chases CNAME records to find canonical names
- Lowercases all FQDNs for consistent SPN construction
- Honors system resolver configuration (/etc/resolv.conf)
- Supports configurable timeouts

## Testing

### Unit Tests

```bash
# Run all tests
cargo test --all-features

# Test with tracing enabled
RUST_LOG=kerbsec=debug cargo test --features trace

# Test specific log targets
RUST_LOG=kerbsec::gss=trace,kerbsec::iov=debug cargo test

# Platform-specific testing
cargo test --features iov  # Tests IOV on Linux, fallback on macOS
```

### End-to-end tests (throwaway KDC)

`scripts/e2e-kdc.sh` starts a temporary MIT KDC on localhost (needs `krb5-kdc`,
`krb5-admin-server` and `krb5-user`), performs the real 3-leg handshake against an
acceptor, and runs `tests/e2e_kdc.rs`:

```bash
./scripts/e2e-kdc.sh
```

CI runs the same script in the `e2e` job (Linux, MIT) and the `macos` job (Apple GSS.framework,
with the KDC and `kinit` from Homebrew's `krb5`).

## Performance

kerbsec is optimized for DCE/RPC workloads with the following performance targets:

### Wrap/Unwrap Throughput (64KB payload)

| Operation  | Auth Level | Target    | Actual | Hardware |
|------------|------------|-----------|--------|----------|
| wrap_iov   | Integrity  | >500 MB/s | TBD    | M1 Pro   |
| wrap_iov   | Privacy    | >300 MB/s | TBD    | M1 Pro   |
| unwrap_iov | Integrity  | >600 MB/s | TBD    | M1 Pro   |
| unwrap_iov | Privacy    | >350 MB/s | TBD    | M1 Pro   |

### Overhead per Operation

| Payload Size | Integrity Overhead | Privacy Overhead  |
|--------------|--------------------|-------------------|
| 256 bytes    | ~28 bytes (11%)    | ~60 bytes (23%)   |
| 4 KB         | ~28 bytes (0.7%)   | ~60 bytes (1.5%)  |
| 64 KB        | ~28 bytes (0.04%)  | ~76 bytes (0.12%) |

### Latency Targets

| Operation       | Target p99 | Notes                   |
|-----------------|------------|-------------------------|
| initial_token() | <10ms      | First AP-REQ generation |
| accept_ap_rep() | <5ms       | AP-REP processing       |
| wrap_iov(4KB)   | <100μs     | Typical RPC request     |
| unwrap_iov(4KB) | <100μs     | Typical RPC response    |

## Examples

See the `examples/` directory for complete examples:

- `wmi_client.rs`: Windows WMI query via DCE/RPC with Kerberos
- `ccache_demo.rs`: Credential cache operations demo
- `dce_style_delegation.rs`: DCE-style authentication with delegation

Run with logging:
```bash
RUST_LOG=kerbsec=debug cargo run --example wmi_client --features trace,dns,runtime
```

## Contributing

Contributions are welcome! Please ensure:

1. Tests pass on both Ubuntu (with IOV) and macOS (with fallback)
2. Code follows Rust conventions and passes `cargo clippy`
3. DCE/RPC semantics are preserved
4. No secrets are logged (even with trace enabled)
5. Unsafe code is documented with safety comments
6. MIT license compatibility

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design details.

## License

MIT License - See LICENSE file for details

## Acknowledgments

This project builds upon:
- MIT Kerberos and Heimdal implementations
- The `libgssapi` Rust bindings
- Microsoft's DCE/RPC and Kerberos documentation
- The broader Kerberos and RPC communities
