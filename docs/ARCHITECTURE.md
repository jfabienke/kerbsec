# kerbsec Architecture

## Overview

kerbsec is a lightweight Kerberos security context library designed specifically for DCE/RPC authentication on Unix platforms. It acts as a thin wrapper around the system's GSS-API implementation while providing DCE/RPC-specific semantics.

## System Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Application Layer                  │
│              (e.g., linux-wmi, SMB client)          │
└─────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│                    kerbsec API                      │
│                  Context, Config                    │
└─────────────────────────────────────────────────────┘
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
  ┌──────────────────────┐  ┌──────────────────────┐
  │   Platform Layer     │  │    Optional Features │
  │  ┌────────────────┐  │  │  ┌────────────────┐  │
  │  │  Unix (GSS)    │  │  │  │      DNS       │  │
  │  └────────────────┘  │  │  └────────────────┘  │
  │  ┌────────────────┐  │  │  ┌────────────────┐  │
  │  │   IOV (FFI)    │  │  │  │    Logging     │  │
  │  └────────────────┘  │  │  └────────────────┘  │
  └──────────────────────┘  └──────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────┐
│                System GSS-API Layer                 │
│              (MIT Kerberos or Heimdal)              │
└─────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────┐
│                   KDC (Kerberos)                    │
│              Active Directory / MIT KDC             │
└─────────────────────────────────────────────────────┘
```

## Component Architecture

### Core Components

#### 1. Context (`src/context.rs`)
- **Purpose**: Main API entry point for security context management
- **Responsibilities**:
  - Context lifecycle (creation, establishment, destruction)
  - Token generation and processing
  - Message protection (wrap/unwrap)
- **Thread Safety**: Send but not Sync (movable, not shareable)

#### 2. Configuration (`src/config.rs`)
- **Purpose**: Fluent configuration builder
- **Responsibilities**:
  - Parameter validation
  - Default value management
  - DNS canonicalization triggers
  - GSS flag configuration
- **Key Types**:
  - `KerberosConfig`: Immutable configuration
  - `KerberosConfigBuilder`: Fluent builder pattern
  - `AuthLevel`: Integrity vs Privacy selection
- **Runtime Flags** (v0.2.0+):
  - `enable_dce_style`: DCE/RPC compatibility mode
  - `enable_delegation`: Credential delegation support
  - `require_mutual_auth`: Server authentication requirement

#### 3. Security Layer (`src/security/`)
- **Purpose**: Platform abstraction for GSS-API
- **Components**:
  - `gss.rs`: Unix GSS-API wrapper
  - `gss_iov.rs`: IOV operations (Linux-specific)
  - `mod.rs`: Common types (IovWrap, Oid)

#### 4. FFI Layer (`src/ffi/`)
- **Purpose**: Hand-written bindings for `gss_wrap`/`gss_unwrap`, the IOV calls and
  `gss_wrap_size_limit`
- **Why Custom**: libgssapi's wrappers discard `conf_state`, which kerbsec checks to
  reject Privacy downgrades; `tests/ffi_abi.rs` checks the bindings against the headers
- **Safety**: All unsafe code isolated here

### Optional Components

#### DNS Module (`src/dns/`)
- **Feature**: `dns`
- **Purpose**: FQDN canonicalization and KDC discovery
- **Components**:
  - `resolver.rs`: CNAME following, SRV lookups
  - `spn.rs`: SPN construction and validation

#### Error Handling (`src/error.rs`)
- **Purpose**: Structured error types with context
- **Design**: Uses `thiserror` for ergonomic error handling
- **Categories**:
  - GSS errors (with major/minor codes)
  - DNS errors
  - Configuration errors
  - IOV errors

## Data Flow

### 1. Authentication Handshake (DCE/RPC 3-leg)

```
Client (kerbsec)                    Server
       │                               │
       ├──────── AP-REQ ──────────────►│
       │      (initial_token)          │
       │    [GSS flags applied:        │
       │     DCE_STYLE, MUTUAL,        │
       │     DELEG (if enabled)]       │
       │                               │
       │◄──────── AP-REP ──────────────┤
       │      (accept_ap_rep)          │
       │    [Delegated creds           │
       │     if DELEG negotiated]      │
       │                               │
       ├──────── Third Leg ───────────►│
       │   (alter_context, may be      │
       │    empty for DCE-style)       │
       │                               │
       └─── Context Established ───────┘
```

### 2. Message Protection Flow

```
Application Data
       │
       ▼
┌──────────────┐
│  wrap_iov()  │
└──────────────┘
       │
       ├────► Header (16-32 bytes)
       ├────► Data (unchanged if integrity-only)
       └────► Trailer (12-16 bytes)

Network Transport
       │
       ▼
┌──────────────┐
│ unwrap_iov() │
└──────────────┘
       │
       ▼
Application Data
```

## Platform Abstraction

### Linux (MIT Kerberos)

```rust
#[cfg(all(target_os = "linux", feature = "iov"))]
impl GssContext {
    fn wrap_iov(&mut self, data: &[u8]) -> Result<IovWrap> {
        // Direct FFI to gss_wrap_iov
        unsafe { ffi::gss_wrap_iov(...) }
    }
}
```

### macOS (Heimdal)

```rust
#[cfg(not(all(target_os = "linux", feature = "iov")))]
impl GssContext {
    fn wrap_iov(&mut self, data: &[u8]) -> Result<IovWrap> {
        // Fallback to regular wrap
        let wrapped = self.wrap(data)?;
        // Estimate header/trailer split
        split_wrapped_token(wrapped)
    }
}
```

## Memory Management

### Zero-Copy Operations (Linux IOV)

```
┌─────────────────────────────────────┐
│         Application Buffer          │
│              (PDU data)             │
└─────────────────────────────────────┘
                   │
                   ▼ (no copy)
┌──────────┬──────────────┬───────────┐
│  Header  │     Data     │  Trailer  │
│  Buffer  │  (original)  │  Buffer   │
└──────────┴──────────────┴───────────┘
```

### Fallback Mode (macOS)

```
┌─────────────────────────────────────┐
│         Application Buffer          │
│             (PDU data)              │
└─────────────────────────────────────┘
                   │
                   ▼ (one copy)
┌─────────────────────────────────────┐
│         Wrapped Token Buffer        │
│      (header + data + trailer)      │
└─────────────────────────────────────┘
```

## Security Boundaries

### Trust Boundaries

1. **User Space ↔ Kernel**: GSS-API calls cross this boundary
2. **Application ↔ kerbsec**: API boundary with validated inputs
3. **kerbsec ↔ Network**: Protected by Kerberos cryptography

### Threat Model

```
┌───────────────────────────────────┐
│          Untrusted Network        │
│  ┌─────────────────────────────┐  │
│  │   Attacker can:             │  │
│  │   - Intercept messages      │  │
│  │   - Replay old messages     │  │
│  │   - Modify in transit       │  │
│  │   - Steal delegated creds   │  │
│  └─────────────────────────────┘  │
└───────────────────────────────────┘
           │
           ▼ Protected by
┌───────────────────────────────────┐
│         Kerberos Provides:        │
│   - Mutual authentication         │
│   - Message integrity (MIC)       │
│   - Confidentiality (encryption)  │
│   - Replay protection             │
│   - Sequence detection            │
│                                   │
│   DCE-Style (when enabled):       │
│   - Modified replay handling      │
│   - Out-of-order message support  │
│                                   │
│   Delegation (when enabled):      │
│   - Controlled impersonation      │
│   - S4U2Self/S4U2Proxy support    │
└───────────────────────────────────┘
```

## Concurrency Model

### Context Lifecycle

```rust
// Context is Send but not Sync
impl Send for Context {}
// impl Sync for Context {} // NOT implemented

// Can move between threads
let ctx = Context::new(config)?;
thread::spawn(move || {
    ctx.initial_token()?;
});

// Cannot share between threads without Mutex
let ctx = Arc::new(Mutex::new(Context::new(config)?));
```

### Why Not Sync?

GSS contexts maintain internal state:
- Sequence numbers (must be monotonic)
- Replay cache (must be consistent)
- Cryptographic state (not thread-safe)

## Feature Architecture

### Feature Dependencies

```
kerbsec
├── default = ["dns", "runtime", "iov"]
├── dns ──────► hickory-resolver
├── runtime ──► tokio
├── iov ──────► (enables IOV code paths)
├── trace ────► tracing, tracing-subscriber
└── ccache ───► credential cache management

 Runtime Configuration (v0.2.0+):
 ├── DCE-style flag (configurable)
 ├── Delegation flag (configurable)
 └── Mutual auth flag (configurable)
```

### Conditional Compilation

```rust
#[cfg(feature = "dns")]
pub mod dns;

#[cfg(all(unix, feature = "iov"))]
pub mod ffi;

#[cfg(feature = "trace")]
use tracing::{debug, instrument};
```

## Performance Characteristics

### Hot Paths

1. **wrap_iov/unwrap_iov**: Called for every RPC message
   - Linux: Zero-copy, ~100μs for 4KB
   - macOS: One allocation, ~150μs for 4KB

2. **Token processing**: Called during handshake
   - initial_token: ~5ms (includes KDC round-trip)
   - accept_ap_rep: ~1ms (local processing)

### Memory Usage

| Component       | Typical Size | Lifetime            |
|-----------------|--------------|---------------------|
| Context         | ~1KB         | Connection duration |
| Config          | ~200B        | Context creation    |
| Wrapped header  | 16-32B       | Per message         |
| Wrapped trailer | 12-16B       | Per message         |
| Token buffers   | 1-4KB        | Handshake only      |

## Extension Points

### Adding New Platforms

1. Implement platform module in `src/security/`:
```rust
#[cfg(windows)]
pub mod sspi;
```

2. Add platform-specific context:
```rust
#[cfg(windows)]
pub struct SspiContext { ... }
```

3. Implement common traits:
```rust
impl SecurityContext for SspiContext { ... }
```

### Adding New Mechanisms

1. Define OID in `src/security/mod.rs`:
```rust
pub const NTLM_MECH_OID: Oid = Oid::new(
    "1.3.6.1.4.1.311.2.2.10",
    &[0x2b, 0x06, 0x01, 0x04, ...],
);
```

2. Add mechanism-specific logic in context

### GSS Flag Management (v0.2.0+)

GSS flags are now runtime-configurable rather than compile-time:

```rust
// Configuration layer
struct KerberosConfig {
    enable_dce_style: bool,    // GSS_C_DCE_STYLE (0x1000)
    enable_delegation: bool,   // GSS_C_DELEG_FLAG (0x01)
    require_mutual_auth: bool, // GSS_C_MUTUAL_FLAG
}

// GSS layer applies flags
if config.enable_dce_style {
    flags |= GSS_C_DCE_STYLE;  // Using from_bits_retain()
}
```

This design allows applications to choose security/compatibility trade-offs at runtime without recompilation.

## Testing Architecture

### Test Layers

1. **Unit Tests**: Test individual components
2. **Integration Tests**: Test with mock KDC
3. **Platform Tests**: Platform-specific behavior
4. **Benchmarks**: Performance regression detection

### Test Matrix

```
        Linux    macOS    Windows
        ─────    ─────    ───────
MIT     ✓        ✓        Future
Heimdal N/A      ✓        N/A
IOV     ✓        Fallback N/A
```

## Build Architecture

### Build Features

- **Minimal**: Core functionality only (~1000 LOC)
- **Default**: DNS + runtime + IOV (~1500 LOC)
- **Full**: All features including trace (~1700 LOC)

### Platform Detection

```rust
#[cfg(target_os = "linux")]
const HAS_IOV: bool = true;

#[cfg(not(target_os = "linux"))]
const HAS_IOV: bool = false;
```

---

*Last updated: January 2025*
