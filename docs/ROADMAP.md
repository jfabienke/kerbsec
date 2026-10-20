# kerbsec Roadmap

## v0.1.0 (Released) ✅

**Focus**: Core DCE/RPC Kerberos functionality for Unix/Linux

- ✅ DCE/RPC 3-leg handshake with GSS_C_DCE_STYLE
- ✅ IOV wrap/unwrap (native on Linux, fallback on macOS)
- ✅ MIT/Heimdal compatibility
- ✅ Comprehensive test suite
- ✅ MIT license
- ✅ Structured logging with tracing
- ✅ DNS canonicalization with CNAME following
- ✅ Custom FFI bindings for IOV operations
- ✅ ~1,500 lines of code

## v0.2.0 (Q2 2024) 🚧

**Focus**: Security hardening and TLS integration

### High Priority 🔴
- [ ] **Memory Zeroization** ([#issue-001](.github/ISSUES/v0.2.0-zeroize.md))
  - Zeroize session keys on drop
  - Clear GSS tokens from memory
  - Secure credential handling

### Medium Priority 🟡
- [ ] **TLS Channel Bindings** ([#issue-002](.github/ISSUES/v0.2.0-channel-bindings.md))
  - RFC 5929 implementation
  - rustls integration
  - native-tls support

### Low Priority 🟢
- ✅ **Native GSS IOV** (Completed in v0.1.0)
  - Custom FFI bindings for gss_wrap_iov/gss_unwrap_iov
  - Zero-copy operations on Linux
  - Automatic platform detection and fallback

### Other Improvements
- ✅ Structured logging with module targets (v0.1.0)
- [ ] Fuzzing for PDU parsing
- [ ] Audit logging hooks
- [ ] Rate limiting support
- [ ] Constant-time MAC comparison

**Target**: ~1,000 lines of code

## v0.3.0 (Q3 2024) 🔮

**Focus**: Cross-platform support

- [ ] **Windows SSPI Backend** ([#issue-003](.github/ISSUES/v0.3.0-windows-sspi.md))
  - Native Windows support
  - SSPI abstraction layer
  - Credential Guard integration

- [ ] **macOS Enhancements**
  - Keychain integration
  - Native Security.framework usage

- [ ] **Advanced Kerberos**
  - S4U2Self/S4U2Proxy (delegation)
  - PKINIT support
  - Anonymous authentication

**Target**: ~1,500 lines of code

## v0.4.0 (Q4 2024) 🌟

**Focus**: Enterprise features

- [ ] **Observability**
  - OpenTelemetry integration
  - Metrics and tracing
  - ✅ Structured logging (Completed in v0.1.0)

- [ ] **High Availability**
  - KDC failover
  - Connection pooling
  - Retry strategies

- [ ] **Cloud Integration**
  - Azure AD support
  - AWS IAM Kerberos
  - Kubernetes service accounts

**Target**: ~2,000 lines of code

## v1.0.0 (2025) 🎯

**Focus**: Production maturity

### Requirements for 1.0

- ✅ Stable API (no breaking changes)
- ✅ Comprehensive documentation
- ✅ 90%+ test coverage
- ✅ Security audit passed
- ✅ Performance benchmarks met
- ✅ Used in production by 3+ organizations
- ✅ Windows, Linux, macOS support

### API Stability Promise

From v1.0.0:
- No breaking changes without major version bump
- Deprecation warnings for 2 minor versions
- Security fixes backported to v1.x

## Long-term Vision

### Beyond 1.0

- **QUIC Support**: Kerberos over QUIC for modern transports
- **WebAssembly**: Browser-based Kerberos (experimental)
- **Async/Await**: Full async API option
- **Hardware Security**: TPM/HSM integration
- **Post-Quantum**: Quantum-resistant algorithms when standardized

### Community Goals

- 100+ GitHub stars ⭐
- 10+ contributors 👥
- 1,000+ downloads/month 📦
- Enterprise adoption 🏢
- Security bug bounty program 🐛

## Contributing

We welcome contributions! Priority areas:

1. **Testing**: Real-world AD environments
2. **Documentation**: Usage examples and guides
3. **Security**: Fuzzing and auditing
4. **Platforms**: Windows and macOS testing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Release Cadence

- **Patch releases**: As needed for security/critical bugs
- **Minor releases**: Quarterly with new features
- **Major releases**: Yearly with breaking changes (if needed)

## Support Matrix

| Version | Status  | Support Until  |
|---------|---------|----------------|
| 0.1.x   | Current | v0.3.0 release |
| 0.2.x   | Planned | v0.4.0 release |
| 0.3.x   | Future  | v1.0.0 release |
| 1.0.x   | Future  | 2027 (LTS)     |

## Metrics

### Current Status (v0.1.0)

- **Performance**: ~5ms handshake (LAN), TBD throughput
- **Size**: ~1,500 lines of code
- **Dependencies**: 6 direct dependencies
- **Security**: 0 known CVEs
- **Compatibility**: MIT 1.17+, Heimdal 7.7+
- **Platform Support**: Linux (full IOV), macOS (fallback)

### Success Metrics for v1.0

- **Performance**: <10ms handshake, >500MB/s throughput
- **Size**: <2,000 lines of code
- **Dependencies**: <10 direct dependencies
- **Security**: 0 known CVEs
- **Compatibility**: 3 major Kerberos implementations
- **Adoption**: 100+ production deployments

## Contact

- Issues: [GitHub Issues](https://github.com/jfabienke/kerbsec/issues)
- Security: security@example.com
- Discord: [Join our server](https://discord.gg/example)

---

*Last updated: January 2025*

## Recent Updates

### v0.1.0 Enhancements (January 2025)
- ✅ Implemented native IOV operations with custom FFI
- ✅ Added structured logging with tracing feature
- ✅ Platform-specific optimizations (Linux vs macOS)
- ✅ GSS_C_DCE_STYLE flag properly applied
- ✅ Comprehensive documentation updates
