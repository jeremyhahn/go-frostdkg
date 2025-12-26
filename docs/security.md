# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | Yes       |

## Reporting a Vulnerability

Please report security vulnerabilities by:

1. **GitHub Security Advisories**: Open a private security advisory at https://github.com/jeremyhahn/go-frostdkg/security/advisories
2. **Email**: Contact the maintainers directly
3. **GitHub Issues**: For non-sensitive issues, open a public GitHub issue

We aim to respond to security reports within 48 hours and provide fixes for critical vulnerabilities promptly.

## Security Practices

### Code Quality

- All code passes `gosec` security scanning
- Static analysis with `golangci-lint`
- Vulnerability scanning with `govulncheck`
- Race condition detection enabled in tests
- 90%+ code coverage with unit and integration tests

### Cryptographic Security

- TLS 1.3 minimum version enforced
- Strong cipher suites only (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305)
- ECDSA P-256 and Ed25519 key types supported
- Secure random number generation via `crypto/rand`
- Memory zeroization for sensitive key material

### File Security

- Key share files created with `0600` permissions (owner read/write only)
- Directory permissions set to `0750`
- File path sanitization to prevent directory traversal

## Known Vulnerabilities

### GO-2024-3218: Content Censorship via Kademlia DHT

**Status:** No fix available (as of 2025-01)

**Affected Package:** `github.com/libp2p/go-libp2p-kad-dht@v0.36.0`

**Description:** Content Censorship in the InterPlanetary File System (IPFS) via Kademlia DHT abuse.

**Impact:** This vulnerability affects the DHT-based peer discovery functionality in the libp2p transport layer. The core DKG cryptographic operations are not affected.

**Mitigation:**
- Use direct peer connections instead of DHT discovery for production deployments
- Configure bootstrap peers explicitly rather than relying on DHT peer discovery
- Use alternative transport protocols (gRPC, HTTP, QUIC) that don't rely on DHT

**Tracking:** https://pkg.go.dev/vuln/GO-2024-3218

This document will be updated when a fix becomes available.

## Best Practices for Production

### Transport Security

1. **Always use TLS** for network transports (gRPC, HTTP, QUIC)
2. **Use mTLS** for mutual authentication when possible
3. **Avoid `--insecure` flag** in production - it disables certificate verification
4. **Use trusted CA certificates** instead of self-signed certificates

### Key Management

1. **Protect secret shares** - never transmit over insecure channels
2. **Secure storage** - use encrypted filesystems or HSMs
3. **Backup procedures** - implement secure backup for key shares
4. **Access control** - restrict file permissions to authorized users only

### Network Security

1. **Firewall configuration** - restrict coordinator access to authorized participants
2. **Rate limiting** - prevent DoS attacks on coordinator endpoints
3. **Monitoring** - log and monitor DKG session activity
4. **Session isolation** - use unique session IDs to prevent cross-session interference

## Dependency Security

Dependencies are regularly audited using:

```bash
# Check for known vulnerabilities
make vulncheck

# Run security scan
make security
```

## Changelog

- **2025-01**: Initial security policy, documented GO-2024-3218
