# Security Documentation for kerbsec

## Overview

This document outlines the security design, threat model, and audit findings for kerbsec. The library prioritizes security by delegating cryptographic operations to the system's GSS-API implementation and following defense-in-depth principles.

## Threat Model

### In Scope Threats

1. **Network Attacks**
   - Man-in-the-middle (MITM)
   - Replay attacks
   - Token tampering
   - Downgrade attacks

2. **Authentication Attacks**
   - Credential theft
   - Brute force
   - Pass-the-hash/ticket

3. **Memory Attacks**
   - Memory dumps
   - Side-channel leaks
   - Timing attacks

### Out of Scope

1. **System Compromise**: If the OS is compromised, Kerberos tickets are accessible
2. **KDC Compromise**: Requires infrastructure security beyond this library
3. **Physical Access**: Requires OS-level protections
4. **Cryptographic Breaks**: Relies on system GSS-API implementation

## Security Architecture

### Defense Layers

```
┌───────────────────────────┐
│     Application Layer     │ ← Input validation
├───────────────────────────┤
│     kerbsec Library       │ ← Safe abstractions
├───────────────────────────┤
│     GSS-API (System)      │ ← Cryptography
├───────────────────────────┤
│     Kerberos Protocol     │ ← Authentication
├───────────────────────────┤
│     Network Transport     │ ← TLS (optional)
└───────────────────────────┘
```

### Security Boundaries

- **API Boundary**: All inputs validated before GSS-API calls
- **FFI Boundary**: Unsafe code isolated in `src/ffi/`
- **Platform Boundary**: Platform-specific code in `cfg` blocks
- **Feature Boundary**: Security features cannot be disabled without explicit opt-in

## Logging Security

### Safe Logging Policy

The `trace` feature implements structured logging with strict security policies:

#### Never Logged ❌
- Passwords or passphrases
- Kerberos tickets (TGT, service tickets)
- Session keys or key material
- Full token contents (AP-REQ, AP-REP)
- Wrapped/unwrapped message data
- Credential cache contents

#### Safe to Log ✅
- Token sizes (not contents)
- Operation success/failure status
- Realm and principal names
- FQDNs and SPNs
- Error codes (major/minor)
- Configuration flags
- Message metadata

### Example Safe Logging

```rust
// GOOD: Log metadata only
debug!(
    target: "kerbsec::iov",
    token_size = token.len(),
    encrypted = conf_req,
    "wrapped message"
);

// BAD: Never log sensitive data
// debug!("session_key = {:?}", key); // NEVER DO THIS
```

# Security Audit Checklist

## Secrets and Sensitive Data

### ✅ No Hardcoded Secrets
- [x] No hardcoded passwords, keys, or tokens in source
- [x] No test credentials in examples
- [x] Environment variables used for KRB5CCNAME

### ✅ No Secret Logging
```bash
# Audit for potential secret logging
rg -i "password|secret|key|token" --type rust | grep -v "session_key\|keytab"
```
- [x] No credentials logged at any level
- [x] Session keys never logged
- [x] GSS tokens not logged in full

### ⚠️ Memory Zeroization (TODO)
- [ ] Session keys should be zeroized after use
- [ ] GSS tokens should be cleared from memory
- [ ] Consider using `zeroize` crate for sensitive buffers

```rust
// Recommendation: Add to Cargo.toml
zeroize = { version = "1.7", features = ["derive"] }

// Example usage:
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SessionKey {
    #[zeroize(skip)]
    id: u32,
    key: Vec<u8>,
}
```

## Authentication Security

### ✅ Replay Protection
- [x] Sequence numbers enforced
- [x] Timestamp validation (5 min skew)
- [x] Tests for replay detection

### ✅ Downgrade Prevention
- [x] Auth level cannot be downgraded
- [x] Tests for downgrade scenarios

### ✅ Weak Cipher Control
- [x] Enctype selection is left to `krb5.conf` / the KDC; kerbsec has no switch for it
- [x] To forbid RC4/DES set `permitted_enctypes` (and `allow_weak_crypto = false`) in `krb5.conf`
- [x] Message protection is verified per message: integrity always, confidentiality when
      `AuthLevel::Privacy` (a token that is not encrypted is rejected with
      `ConfidentialityNotProvided`)

## Input Validation

### ✅ SPN Validation
- [x] IP addresses require SPN override
- [x] Invalid SPNs handled gracefully
- [x] Tests for edge cases

### ✅ PDU Parsing
- [x] Length checks before parsing
- [x] Bounds checking on all reads
- [x] No unsafe buffer operations

## Error Handling

### ✅ No Information Leakage
- [x] Generic error messages for auth failures
- [x] No stack traces in production
- [x] No internal paths exposed

### ✅ Fail Secure
- [x] Default to most secure options
- [x] Explicit opt-in for weaker security
- [x] Context not established on any error

## Dependencies

### ✅ Minimal Dependencies
- [x] Only essential crates used
- [x] No unmaintained dependencies
- [x] libgssapi pinned to stable version

### ✅ Supply Chain
```bash
# Check for known vulnerabilities
cargo audit

# Review dependency tree
cargo tree

# Check licenses
cargo license
```

## Platform Security

### ✅ Unix Permissions
- [x] Respects system Kerberos config
- [x] Uses system credential cache
- [x] No custom file permissions set

### ✅ Network Security
- [x] No custom crypto implementation
- [x] Delegates to system GSS-API
- [x] Transport security handled by caller

## Recommendations

### High Priority
1. **Add memory zeroization** for sensitive data
   - Session keys
   - GSS tokens
   - Credential cache data

2. **Add rate limiting** for auth attempts
   - Prevent brute force
   - Log excessive failures

3. **Add audit logging**
   - Authentication events
   - Authorization failures
   - Suspicious patterns

### Medium Priority
1. **Fuzz testing** for PDU parsing
2. **Constant-time comparisons** for MACs
3. **Certificate pinning** support for channel bindings

### Low Priority
1. **FIPS mode** support
2. **HSM integration** for keys
3. **Threat model** documentation

## Security Contacts

Report security vulnerabilities to:
- Private: security@example.com
- Public: GitHub Security Advisories

## Compliance

- **MIT License**: No warranty, use at own risk
- **Export Control**: May be subject to export restrictions
- **No Cryptographic Code**: Uses system GSS-API only

## IOV Security Considerations

### Platform-Specific Security

| Platform    | IOV Support | Security Impact                           |
|-------------|-------------|-------------------------------------------|
| Linux + MIT | Native IOV  | Optimal: Zero-copy reduces attack surface |
| macOS       | Fallback    | Good: One extra copy, still secure        |
| Windows     | Future      | Will use SSPI native functions            |

### FFI Safety

```rust
// All unsafe operations isolated
#[cfg(target_os = "linux")]
unsafe fn wrap_iov_real(...) {
    // Validated inputs
    // Bounded operations
    // Error propagation
}
```

## Cryptographic Security

### Supported Algorithms

kerbsec does not choose encryption types: the KDC and system GSS-API library negotiate
them from `krb5.conf`. The table describes algorithm strength, not a kerbsec setting.

| Algorithm           | Status     | Notes                 |
|---------------------|------------|-----------------------|
| AES256-CTS-SHA1     | ✅ Default | Recommended           |
| AES128-CTS-SHA1     | ✅ Enabled | Good performance      |
| AES-SHA2 (RFC 8009) | ✅ Enabled | Modern standard       |
| 3DES                | ⚠️ Weak    | Legacy only; krb5.conf |
| RC4                 | ❌ Weak    | Disable in krb5.conf   |
| DES                 | ❌ Broken  | Disabled by modern MIT |

### Weak Crypto Prevention

Configure the Kerberos library, not kerbsec:

```ini
[libdefaults]
    allow_weak_crypto = false
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
```

kerbsec then refuses to run with weaker *message* protection than configured:

```rust
// Privacy contexts reject integrity-only tokens
match ctx.unwrap_iov(&token) {
    Err(Error::ConfidentialityNotProvided(_)) => { /* downgrade attempt */ }
    _ => {}
}
```

## Credential Delegation Security

### GSS_C_DELEG_FLAG Considerations

Credential delegation (GSS_C_DELEG_FLAG) is a powerful but dangerous feature that allows the server to impersonate the client. This is **disabled by default** for security reasons.

#### Security Risks

1. **Complete Impersonation**: The server can act as the client to any service
2. **Credential Theft**: Compromised servers can steal delegated credentials
3. **Lateral Movement**: Attackers can use delegated credentials to move through the network
4. **Audit Trail Loss**: Actions performed with delegated credentials appear to come from the original client

#### When to Enable Delegation

Only enable delegation when ALL of these conditions are met:
- The server is fully trusted and under your control
- The server needs to access resources on behalf of the client
- No alternative architecture (like token-based authorization) is feasible
- Strong audit logging is in place
- The delegation is time-limited

#### Safe Usage Example

```rust
// Only enable for trusted servers
let config = KerberosConfig::builder()
    .realm("CORP.EXAMPLE.COM")
    .target_host("trusted-internal-server.corp.example.com")
    .delegation(true)  // DANGEROUS: Only for trusted servers
    .build()?;

// After authentication, handle delegated credentials carefully
if ctx.has_delegated_credentials() {
    // Log the delegation event with full context
    audit_log!("DELEGATION_GRANTED", client = principal, server = spn);

    // Export credentials with care
    let creds = ctx.export_delegated_credentials()?;

    // Use credentials with time limits and scope restrictions
    // Never store delegated credentials persistently
}
```

#### Delegation Mitigation Strategies

1. **Constrained Delegation**: Use S4U2Proxy to limit which services can be accessed
2. **Time Limits**: Set short credential lifetimes
3. **Audit Everything**: Log all delegation requests and usage
4. **Network Segmentation**: Isolate servers that require delegation
5. **Regular Rotation**: Rotate service accounts frequently

### DCE-Style Security (GSS_C_DCE_STYLE)

The GSS_C_DCE_STYLE flag (0x1000) is **enabled by default** for DCE/RPC compatibility. This flag modifies GSS-API behavior:

#### Security Implications

1. **Sequence Checking**: GSS sequence number checking is disabled (DCE/RPC has its own)
2. **Out-of-Order Messages**: Allows messages to be processed out of order
3. **Replay Cache**: GSS replay detection is modified to work with DCE/RPC semantics

#### When to Disable DCE-Style

Consider disabling DCE-style only when:
- Not using DCE/RPC protocols
- Implementing a custom protocol that needs GSS sequence protection
- Maximum GSS-API security is required regardless of compatibility

```rust
// Disable DCE-style for non-DCE protocols
let config = KerberosConfig::builder()
    .realm("EXAMPLE.COM")
    .target_host("server.example.com")
    .dce_style(false)  // Use standard GSS-API semantics
    .build()?;
```

## Channel Bindings

### TLS Integration

Channel bindings tie the Kerberos authentication to the underlying transport, preventing token forwarding attacks:

```rust
use kerbsec::channel_bindings::{ChannelBindings, ChannelBindingType};

// Create TLS channel bindings
let cb = ChannelBindings {
    initiator_addrtype: 0,
    initiator_address: Vec::new(),
    acceptor_addrtype: 0,
    acceptor_address: Vec::new(),
    application_data: tls_exporter_material,  // From RFC 5929
    binding_type: Some(ChannelBindingType::TlsServerEndPoint),
};

let config = KerberosConfig::builder()
    .realm("EXAMPLE.COM")
    .target_host("server.example.com")
    .channel_bindings(Some(cb))
    .build()?;
```

Benefits:
- Prevents token forwarding
- Binds Kerberos to TLS session
- Mitigates MITM attacks
- Required by some compliance standards

## Security Testing

### Current Test Coverage

- ✅ Replay attack detection
- ✅ Sequence number validation
- ✅ Downgrade prevention
- ✅ Weak cipher rejection
- ✅ SPN validation
- ✅ Clock skew handling

### Future Testing

- [ ] Fuzzing with AFL/LibFuzzer
- [ ] Property-based testing
- [ ] Timing attack analysis
- [ ] Memory safety with Miri

## Incident Response

### Security Issue Handling

1. **Report**: Send to security contact
2. **Triage**: Assess severity (CVSS)
3. **Fix**: Develop patch in private
4. **Disclose**: Coordinate disclosure
5. **Release**: Publish fix with advisory

### Severity Levels

| Level    | Response Time | Example                |
|----------|---------------|-----------------------||
| Critical | 24 hours      | RCE, auth bypass       |
| High     | 7 days        | Privilege escalation   |
| Medium   | 30 days       | Information disclosure |
| Low      | Next release  | Theoretical issues     |

## Audit History

| Date       | Version   | Auditor          | Result                    |
|------------|-----------|------------------|---------------------------|
| 2025-01-21 | 0.1.0     | Self + Community | Pass with recommendations |
| 2024-01-20 | 0.1.0-pre | Self             | Initial review            |

## Security Tools and Commands

### Static Analysis

```bash
# Rust security lints
cargo clippy --all-features -- -D warnings

# Security audit for dependencies
cargo audit

# Check for unsafe code
grep -r "unsafe" src/ --include="*.rs"

# Memory safety with Miri (nightly)
cargo +nightly miri test
```

### Dynamic Analysis

```bash
# Memory leaks
valgrind --leak-check=full cargo test

# Address sanitizer (Linux)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test

# Thread sanitizer
RUSTFLAGS="-Z sanitizer=thread" cargo +nightly test
```

### Fuzzing (Future)

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzzer
cargo fuzz run token_parser

# With AFL
cargo afl build
cargo afl fuzz -i in -o out target/debug/fuzz_target
```

### Coverage Analysis

```bash
# Generate coverage report
cargo tarpaulin --all-features --out Html

# With llvm-cov
cargo llvm-cov --html --all-features
```

## Security Checklist for Contributors

### Before Submitting PR

- [ ] No new `unsafe` code without justification
- [ ] No logging of sensitive data
- [ ] Input validation for all public APIs
- [ ] Error messages don't leak information
- [ ] Tests for security-relevant changes
- [ ] Documentation for security implications

### Review Checklist

- [ ] Check for timing vulnerabilities
- [ ] Verify error handling
- [ ] Audit dependencies added
- [ ] Review unsafe blocks
- [ ] Check for panics in hot paths

---

*Last updated: January 2025*
