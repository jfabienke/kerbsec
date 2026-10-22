# Changelog

All notable changes to kerbsec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Security
- Unwrap on a Privacy context rejects tokens that were not encrypted
  (`Error::ConfidentialityNotProvided`); previously a signed-only token was accepted.
- Wrap reports confidentiality from the mechanism's `conf_state` and fails if Privacy
  was requested but not applied; previously it echoed the request.
- Negotiated flags are verified after the handshake (integrity always; mutual auth,
  confidentiality and DCE style when configured) - `Error::FlagNotNegotiated`. A failed
  flag inquiry is an error instead of assuming the requested flags.
- No longer reads libgssapi's private `ClientCtx` layout; libgssapi 0.9.1 is vendored
  with one accessor, `ClientCtx::raw_ctx()`.
- A credential cache or keytab that conflicts with the process-wide one is an error
  instead of being silently ignored. `KRB5_KTNAME` is no longer used as a client keytab.
- Credential delegation disabled by default for security
- DCE-style enabled by default for DCE/RPC compatibility
- Mutual authentication required by default
- Comprehensive security warnings added for delegation usage

### Added
- **Runtime-Configurable GSS Flags** - Security and compatibility flags are now runtime-configurable:
  - GSS_C_DCE_STYLE (0x1000): DCE/RPC compatibility mode (default: enabled)
  - GSS_C_DELEG_FLAG (0x01): Credential delegation support (default: disabled)
  - GSS_C_MUTUAL_FLAG: Server authentication requirement (default: enabled)
- **Delegation Support** - Complete implementation of credential delegation:
  - `has_delegated_credentials()` method to check for delegated creds
  - `export_delegated_credentials()` method for S4U2Self/S4U2Proxy scenarios
  - Security warnings and best practices documented
- **Enhanced Configuration API** - New builder methods for runtime configuration:
  - `.dce_style(bool)` - Control DCE/RPC compatibility
  - `.delegation(bool)` - Enable/disable credential delegation
  - `.mutual_auth(bool)` - Control mutual authentication requirement

### Fixed
- Target principal: `HOST/fqdn` was imported as a host-based service name, so the KDC
  was asked for the wrong principal. It is now imported as `spn@realm`.
- Handshake ordering is enforced (`Error::HandshakeState`); an AP-REP that leaves the
  context incomplete is an error instead of being reported as established.
- DNS canonicalization returns the name owning the address records and reports lookup
  errors; KDC discovery strips the trailing dot and orders by SRV priority/weight.
- `wrap_size_limit` uses `gss_wrap_size_limit` once established.
- IOV padding is rejected instead of being dropped; plaintext is wiped on failure.
- Address-only channel bindings, or bindings set after the first leg, are errors.
- `Context` is now actually `!Sync`, as documented.
- GSS error text includes every status message, not only the first.
- `--no-default-features` and `--features ccache` build again.
- GSS error text kept only the supplementary condition on Heimdal and Apple's
  GSS.framework (e.g. "duplicate token" but not "invalid MIC"); the error and
  supplementary bits are now displayed separately.

### Changed
- GSS_C_DCE_STYLE flag moved from compile-time feature to runtime configuration
- Configuration defaults documented and standardized across the codebase
- Security documentation expanded with delegation risks and mitigation strategies
- **Breaking:** `Context::set_channel_bindings` returns `Result<()>`.
- **Breaking:** The configured realm is appended to SPN overrides that do not name one.
- **Breaking:** Config `build()`/`build_async()` reject an empty realm or host and normalize hosts.
- **Breaking:** `Context` is no longer `Sync` (it was documented as `!Sync` but was `Sync`).
- **Breaking:** New `Error` variants: `ConfidentialityNotProvided`, `HandshakeState`,
  `FlagNotNegotiated`.

### Removed (breaking)
- `EncryptionType` and the `allow-weak-crypto` feature (they never affected
  negotiation; encryption types come from `krb5.conf`).
- Error variants that were never produced: `ClockSkew`, `SpnNotFound`,
  `EncryptionTypeMismatch`, `DelegationDenied`, `PreAuthFailed`, `TicketExpired`,
  `KdcUnreachable`.
- `security::traits` mocks and the `mock` / `integration-tests` features; `dns::spn`;
  the unused `gss_timeout` setting; `build.rs`; the mock benchmark.

### Testing
- `scripts/e2e-kdc.sh` and `tests/e2e_kdc.rs`: real 3-leg handshake against a
  throwaway MIT KDC, run in CI.
- `tests/ffi_abi.rs` checks the hand-written FFI against the system headers.
- CI `macos` job: clippy, tests and the e2e handshake against Apple's GSS.framework.
- Known issue: Heimdal on Linux with the `iov` feature fails Privacy and Integrity
  wraps (DCE-style IOV layout); use it without `iov`.
- Removed tests that could not fail.

## [0.2.0] - 2025-01-21

### Added
- **Credential Cache Support** - Complete implementation of multiple backend storage systems:
  - FILE backend: MIT Kerberos ccache v5 format (0x0504) with full binary parsing/serialization
  - Memory backend: Thread-safe in-memory storage with RwLock protection
  - KCM backend: Kerberos Credential Manager daemon protocol over Unix sockets
  - Linux Keyring backend: Kernel keyring integration via system calls
- **TLS Channel Bindings** (RFC 5929, RFC 9266) - Prevent credential forwarding attacks:
  - rustls integration for TLS channel binding extraction
  - Support for tls-unique, tls-server-end-point, and tls-exporter binding types
  - Full GSS-API channel binding structure support
- **Memory Zeroization** - Secure handling of sensitive data:
  - Integration with `zeroize` crate for automatic memory clearing
  - SecureBuffer wrapper for sensitive byte arrays
  - Automatic zeroization of keys, tickets, and authentication data on drop
- Native IOV operations with custom FFI bindings for `gss_wrap_iov`/`gss_unwrap_iov`
- Structured logging via `tracing` with module-specific targets
- Platform detection for automatic Linux vs macOS handling
- GSS_C_DCE_STYLE flag (0x1000) properly applied for DCE/RPC semantics
- Comprehensive documentation overhaul including architecture and security guides
- CI test job for trace feature validation
- Feature flags table in README
- Platform differences documentation in USAGE.md
- Technical roadmap with migration plans
- Integration guide for DCE/RPC, SMB, and WMI

### Changed
- IOV operations now use zero-copy on Linux with MIT Kerberos
- macOS gracefully falls back to regular wrap/unwrap
- All FFI types now have proper documentation
- Module-level documentation added to all components
- Credential cache operations are now feature-gated (`ccache` feature)
- Channel bindings are feature-gated (`channel-bindings` and `channel-bindings-rustls` features)
- ROADMAP.md updated with completed items
- IMPROVEMENTS.md updated with recent enhancements
- SECURITY.md expanded with threat model and logging security

### Fixed
- FILE cache header parsing bug where null terminator wasn't consuming length field
- FFI type documentation warnings resolved
- Platform-specific linking errors prevented with compile-time guards
- GSS_C_DCE_STYLE flag now properly set for DCE/RPC
- All Clippy warnings addressed (reduced from 206 to 73)
- rustls version comparison using correct protocol version API

### Security
- Automatic memory zeroization for all sensitive data structures
- Secure credential storage with multiple backend options
- TLS channel binding support to prevent relay attacks
- Safe logging policy implemented - no secrets ever logged
- All unsafe code isolated in `src/ffi/` module
- Platform guards prevent unsafe operations

### Testing
- Comprehensive test suite for all credential cache backends
- Tests for atomic write operations in FILE cache
- Tests for expired credential purging
- Tests for thread-safety in Memory cache
- Channel binding extraction tests
- All 64 tests passing across all features

## [0.1.0] - 2024-01-20

### Added
- Initial release with core DCE/RPC Kerberos functionality
- DCE/RPC 3-leg handshake implementation
- Simplified IOV wrap/unwrap operations
- MIT Kerberos and Heimdal compatibility
- DNS canonicalization with CNAME following
- Flexible authentication levels (Integrity/Privacy)
- Comprehensive test suite
- Performance benchmarks
- Example WMI client

### Security
- RC4 disabled by default
- Replay protection via sequence numbers
- Clock skew tolerance (5 minutes default)
- Auth level downgrade prevention
- IP address SPN validation

## [0.0.1] - 2024-01-01

### Added
- Project initialization
- Basic GSS-API wrapper
- MIT license
- Initial documentation structure

---

## Version Guidelines

### Versioning Scheme

- **MAJOR.MINOR.PATCH**
  - **MAJOR**: Breaking API changes
  - **MINOR**: New features, backwards compatible
  - **PATCH**: Bug fixes, backwards compatible

### Pre-1.0 Stability

While in 0.x versions:
- API may change between minor versions
- Best effort to minimize breaking changes
- Clear migration guides provided

### 1.0 Stability Promise

From version 1.0.0:
- No breaking changes without major version bump
- Deprecation warnings for 2 minor versions minimum
- Security fixes backported to supported versions

## Release Process

1. Update version in `Cargo.toml`
2. Update this CHANGELOG.md
3. Tag release: `git tag -s v0.1.0 -m "Release version 0.1.0"`
4. Build and test: `cargo test --all-features`
5. Publish docs: `cargo doc --all-features`

## Support

| Version | Status     | End of Support   |
|---------|------------|------------------|
| 0.2.x   | Current    | When 0.4.0 ships |
| 0.1.x   | Supported  | When 0.3.0 ships |
| 0.0.x   | Deprecated | 2024-02-01       |

## Security Reporting

Security vulnerabilities should be reported via:
- Email: security@example.com
- GitHub Security Advisories

## Links

- [Documentation](https://internal.docs/kerbsec)
- [Issue Tracker](https://github.com/internal/kerbsec/issues)
- [Security Policy](docs/SECURITY.md)

[0.3.0]: https://github.com/internal/kerbsec/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/internal/kerbsec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/internal/kerbsec/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/internal/kerbsec/releases/tag/v0.0.1
