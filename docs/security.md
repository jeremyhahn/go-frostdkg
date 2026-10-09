# Security Policy

> **Status: NORMATIVE** · Scope: go-frostdkg · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.

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

### Cryptographic Security

- TLS 1.3 minimum version enforced
- Strong cipher suites only (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305)
- ECDSA P-256 and Ed25519 key types supported
- Secure random number generation via `crypto/rand`
- Memory zeroization for sensitive key material
- Application-level share encryption via ECDH (see [encryption.md](encryption.md))

### File Security

- Key share files created with `0600` permissions (owner read/write only)
- Directory permissions set to `0750`
- `verify --share` cleans the share path with `filepath.Clean`

## Known Vulnerabilities

### GO-2024-3218: Content Censorship via Kademlia DHT

**Status:** No fix available (as of 2025-01)

**Affected Package:** `github.com/libp2p/go-libp2p-kad-dht` (go.mod pins v0.38.0)

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

## Encrypted DKG Security

go-frostdkg supports application-level encryption of secret shares using ECDH key agreement. See [encryption.md](encryption.md) for full documentation.

### Security Properties

**Confidentiality**: Secret shares are encrypted using ECDH-derived keys before transmission. Even if an attacker captures network traffic, shares remain protected.

**Forward Secrecy (per-session)**: Ephemeral nonces are generated for each DKG session. Compromising a host key does not reveal shares from past sessions.

**Defense in Depth**: Encrypted DKG provides protection independent of transport security. Use both TLS and encrypted DKG for maximum security.

**Replay Protection**: CertEq signatures include session context binding (threshold, participant count, all host public keys) preventing cross-session replay attacks.

### When to Use Encrypted DKG

| Threat Model | Recommendation |
|--------------|---------------|
| Passive network attacker | TLS sufficient |
| Active MITM attacker | TLS with certificate pinning |
| Compromised transport | Encrypted DKG required |
| Untrusted coordinator | Encrypted DKG required |
| Hardware key storage | Encrypted DKG with HostKey interface |
| Regulatory compliance | Encrypted DKG + HSM |

### HostKey Security

The HostKey interface enables hardware-backed keys:

1. **TPM Integration**: Private keys never leave the TPM
2. **HSM Support**: PKCS#11 or vendor APIs for ECDH/signing
3. **Key Attestation**: Verify keys are hardware-protected

Implementation requirements:
- ECDH must compute raw shared point (no hashing)
- Signatures must follow the scheme `SoftwareHostKey` uses (ECDSA for P-256, Schnorr otherwise)
- Public key serialization must match ciphersuite expectations

### Cryptographic Details

**ECDH Pad Derivation**:
```
pad = hashToBytes(cs, "ecdh pad", nonce_order || shared_point)
```

**Share Encryption**:
```
encrypted_share = share XOR pad[:share_length]
```

**CertEq Message Format**:
```
message = "FROST-DKG/certeq" || index || threshold || n || hostpubkeys || transcript
```

### Zeroization

Always zeroize sensitive data after use:

```go
defer state.Zeroize()
defer output.ZeroizeWithGroup(cs.Group())
dkg.ZeroBytes(secretKey)
```

### Secrets live in enclaves, not in `[]byte`

These are sealed in a `secmem.SecretBytes` — encrypted at rest with memguard's
Enclave, decrypted into `mlock`'d memory only for the moment an operation needs
them:

| Secret | Where |
|---|---|
| Host secret key | `SoftwareHostKey` (unexported), `DKGParams.HostSeckey` |
| Session randomness | `DKGParams.Random` |
| Participant session seed | `FROSTDKGParticipantState.Seed` |
| Host key held by DKG state | `FROSTDKGEncParticipantState.HostSeckey`, `FROSTDKGFullParticipantState1.HostSeckey` |
| Resulting secret share | `DKGResult.SecretShare` |

A plain `[]byte` field would sit on the swappable heap for the whole life of the
key, which is what a `ZeroBytes` at the end cannot undo.

`DKGParams.Random` is on that list because it is a **secret, not a nonce**:
combined with the host key it derives the participant seed, so anyone holding
both can reproduce the share.

Reading one is a borrow window, and the bytes must not outlive it:

```go
if err := secmem.WithSecret(result.SecretShare, func(share []byte) error {
    return persist(share) // do not retain `share` past this callback
}); err != nil { /* ... */ }
```

Build one with `transport.SealSecret` (or `dkg`'s internal `sealCopy`), which
copies before sealing. `secmem.NewSecretBytes` zeroes the slice it is handed —
use it directly only when destroying your source buffer is what you want.

Releasing a secret **destroys** the enclave rather than zeroing a slice that
still exists: `DKGParams.Zeroize`, `DKGResult.Zeroize`, and the DKG state
`Zeroize` methods all do this for the secrets they own.

#### What is deliberately NOT in an enclave

Stated so the list above can be audited rather than assumed:

- **`FROSTDKGOutput.SecretShare`** is a `group.Scalar`. `secmem`'s own package
  documentation excludes scalars — they are managed by external crypto
  libraries and cannot be wrapped. It is zeroized through the group API
  instead.
- **`SoftwareHostKey.SecretKey()`** returns a plain `[]byte` on purpose, because
  `HostKeyGenerator.LoadHostKey` defines software keys as exportable and
  persisting a key needs it. It is the one documented way out of protected
  memory: the caller owns that exposure and must `ZeroBytes` the result as soon
  as it is consumed. Whether the export should exist at all is an open
  question.
- **`SecretPackage` and `SecureScalar`** (`pkg/dkg/zeroize.go`) still hold
  plain `[]byte`. They are exported but unused — no caller anywhere in this
  repository — and removing exported symbols is not a change to make in
  passing. Tracked as issue #25.
- **Hex-encoded key material in the CLI's output file** is a `string` on its way
  to disk. Strings cannot be scrubbed soundly, so the exposure is the file's
  `0600` mode, not the in-memory copy.

Anything not on either list is public: host public keys, the threshold public
key, public shares, and `DKGResult.RecoveryData`.

**A borrower never wipes what it borrowed.** A `HostKey` passed into any of
the `*WithHostKey` entry points stays owned by the caller: the DKG state holds
a reference for the ceremony and its `Zeroize()` only drops that reference.
Zeroizing the key is the caller's job, and only once the key itself is
finished — not once a session is. A host key is a long-lived identity key that
signs both steps of a ceremony and usually outlives many ceremonies.

```go
hostKey, err := dkg.GenerateSoftwareHostKey(cs)
if err != nil { /* ... */ }
defer hostKey.Zeroize() // the owner zeroizes; the DKG state never does

state1, msg1, err := dkg.FROSTDKGFullParticipantStep1WithHostKey(cs, hostKey, /* ... */)
```

## Dependency Security

Dependencies are regularly audited using:

```bash
# Check for known vulnerabilities
make vulncheck

# Run security scan
make security
```

## Changelog

- 2025-01: Initial security policy, documented GO-2024-3218
- 2025-01: Added Encrypted DKG security section, HostKey documentation
