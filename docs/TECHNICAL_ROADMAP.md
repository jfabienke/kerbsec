# Technical Roadmap for kerbsec

## Overview

This document details the technical implementation decisions, platform-specific considerations, and future migration plans for kerbsec.

## Current Implementation Status

### IOV Operations (v0.1.0) ✅

#### Platform Support Matrix

| Platform             | Implementation                | Status      | Performance           |
|----------------------|-------------------------------|-------------|-----------------------|
| Linux + MIT Kerberos | Custom FFI to `gss_wrap_iov`  | ✅ Full     | Optimal (zero-copy)   |
| Linux + Heimdal      | Different API, not compatible | ⚠️ Fallback | Good (one allocation) |
| macOS + Heimdal      | No IOV in GSS.framework       | ⚠️ Fallback | Good (one allocation) |
| macOS + MIT (brew)   | Custom FFI to `gss_wrap_iov`  | ✅ Full     | Optimal (zero-copy)   |

#### Implementation Details

```rust
// Platform detection at compile time
#[cfg(target_os = "linux")]
unsafe fn wrap_iov_real(...) {
    // Direct FFI to gss_wrap_iov
    // Zero-copy operation
}

#[cfg(not(target_os = "linux"))]
fn wrap_iov_fallback(...) {
    // Use regular gss_wrap
    // Estimate header/trailer split
}
```

#### Why Custom FFI?

1. **libgssapi 0.9.1 limitations**:
   - Doesn't expose IOV functions
   - Missing GSS_C_DCE_STYLE flag
   - No wrap_size_limit binding

2. **Benefits of custom FFI**:
   - Zero-copy on supported platforms
   - Proper DCE/RPC semantics
   - Direct control over buffer management

### GSS_C_DCE_STYLE Flag (0x1000) ✅

Critical for DCE/RPC:
- Selects the DCE/RPC three-leg handshake and relaxed IOV padding/trailer rules
- Does not disable sequence/replay detection
- Prevents replay cache interference

```rust
// Manual flag application
let flags = CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_INTEG_FLAG;
let flags_with_dce = flags.bits() | 0x1000; // Add DCE_STYLE
flags = CtxFlags::from_bits_retain(flags_with_dce);
```

### Structured Logging ✅

Module-targeted logging following linux-wmi patterns:

```rust
// Feature-gated, zero-cost when disabled
#[cfg(feature = "trace")]
debug!(
    target: "kerbsec::iov",
    conf = conf_req,
    pdu_len = pdu.len(),
    header_len = header.len(),
    trailer_len = trailer.len(),
    "wrap_iov completed"
);
```

## Migration Plans

### libgssapi 0.10+ Migration (Future)

When libgssapi exposes IOV:

1. **Phase 1**: Feature flag for new API
   ```toml
   [features]
   libgssapi-iov = ["libgssapi/iov"]
   ```

2. **Phase 2**: Conditional compilation
   ```rust
   #[cfg(feature = "libgssapi-iov")]
   use libgssapi::iov::{wrap_iov, unwrap_iov};

   #[cfg(not(feature = "libgssapi-iov"))]
   use crate::ffi::{gss_wrap_iov, gss_unwrap_iov};
   ```

3. **Phase 3**: Deprecate custom FFI
   - Maintain for 2 minor versions
   - Remove in next major version

### Windows SSPI Support (v0.3.0)

Architecture for cross-platform abstraction:

```rust
trait SecurityContext: Send {
    fn initial_token(&mut self) -> Result<Vec<u8>>;
    fn accept_token(&mut self, token: &[u8]) -> Result<Option<Vec<u8>>>;
    fn wrap_iov(&mut self, data: &[u8]) -> Result<IovWrap>;
    fn unwrap_iov(&mut self, token: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(unix)]
impl SecurityContext for GssContext { ... }

#[cfg(windows)]
impl SecurityContext for SspiContext { ... }
```

## Performance Considerations

### Current Bottlenecks

1. **macOS fallback**: One extra allocation per wrap
2. **Header/trailer estimation**: Inexact on fallback platforms
3. **No buffer reuse**: Each operation allocates

### Optimization Opportunities

1. **Buffer pooling**:
   ```rust
   thread_local! {
       static BUFFER_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
   }
   ```

2. **Predictive sizing**:
   ```rust
   // Learn typical sizes per context
   struct SizePredictor {
       integrity_overhead: usize,
       privacy_overhead: usize,
   }
   ```

3. **SIMD for MIC verification** (future):
   - Use AVX2/NEON for constant-time comparison
   - Parallel MAC computation

## Security Hardening

### Memory Zeroization (v0.2.0)

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
struct SessionKey {
    #[zeroize(skip)] // Public data
    algorithm: Algorithm,
    key_material: Vec<u8>, // Auto-zeroized
}
```

### Constant-Time Operations

```rust
// Prevent timing attacks
fn verify_mic(expected: &[u8], actual: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    expected.ct_eq(actual).unwrap_u8() == 1
}
```

## Testing Strategy

### Platform Coverage

| Test Type   | Linux  | macOS    | Windows |
|-------------|--------|----------|---------|
| Unit tests  | CI     | CI       | Future  |
| IOV tests   | Full   | Fallback | N/A     |
| Integration | Docker | Local    | Future  |
| Benchmarks  | Yes    | Yes      | Future  |

### Fuzzing Targets

1. **Token parsing**: AP-REQ, AP-REP formats
2. **IOV buffer boundaries**: Edge cases in header/trailer split
3. **Sequence number overflow**: Wraparound handling

## Dependencies Management

### Current Dependencies

```toml
[dependencies]
# Core - minimal and stable
thiserror = "2"       # Error handling
anyhow = "1"          # Error context
bytes = "1"           # Zero-copy buffers

# Platform-specific
[target.'cfg(unix)'.dependencies]
libgssapi = "=0.9.1"  # Exact version for stability
libc = "0.2"          # System calls

# Optional features
tokio = { version = "1.47", optional = true }
hickory-resolver = { version = "0.25", optional = true }
tracing = { version = "0.1", optional = true }
```

### Dependency Policies

1. **Exact versions** for security-critical deps
2. **Minimal dependencies** for core functionality
3. **Feature-gate** all optional functionality
4. **No unsafe** in user-facing code (only FFI)

## Compatibility Commitments

### Supported Versions

| Component    | Minimum | Recommended | Notes                 |
|--------------|---------|-------------|-----------------------|
| Rust         | 1.70    | Stable      | MSRV policy           |
| MIT Kerberos | 1.17    | 1.20+       | Ubuntu 20.04 baseline |
| Heimdal      | 7.7     | 8.0+        | macOS default         |
| glibc        | 2.31    | 2.35+       | Ubuntu 20.04 baseline |

### Breaking Change Policy

1. **Never break** in patch releases (x.y.Z)
2. **Deprecate first** in minor releases (x.Y.z)
3. **Remove after** 2 minor versions or 1 major
4. **Document all** breaking changes in CHANGELOG

## Future Research

### Post-Quantum Cryptography

Monitor IETF drafts:
- Kyber for key exchange
- Dilithium for signatures
- SPHINCS+ as backup

### QUIC Transport

Benefits for Kerberos:
- 0-RTT for cached tickets
- Connection migration
- Built-in encryption

### WebAssembly Support

Challenges:
- No system GSS-API
- Browser sandboxing
- Credential management

Potential solution: Pure Rust Kerberos implementation for WASM target.

## Maintenance Schedule

### Regular Tasks

| Task                   | Frequency | Owner         |
|------------------------|-----------|---------------|
| Dependency updates     | Weekly    | Dependabot    |
| Security audit         | Quarterly | Security team |
| Performance regression | Per PR    | CI            |
| Documentation review   | Monthly   | Maintainers   |

### Version Support

| Version | Status     | EOL              |
|---------|------------|------------------|
| 0.1.x   | Current    | When 0.3.0 ships |
| 0.2.x   | Planned    | When 0.4.0 ships |
| 0.3.x   | Future     | When 1.0.0 ships |
| 1.x.x   | Future LTS | 2027             |

## Contact

Technical questions: Create an issue with the `technical` label.

---

*Last updated: January 2025*
