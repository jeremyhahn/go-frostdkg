# Architecture Overview

go-frostdkg is a Go implementation of the FROST Distributed Key Generation protocol for threshold signatures, inspired by [ChillDKG](https://github.com/BlockstreamResearch/bip-frost-dkg). The system provides a modular architecture with pluggable transport layers and support for multiple FROST ciphersuites.

## System Architecture

```
┌─────────────────────────────────────────────────┐
│                 CLI Application                 │
│                 (cmd/frostdkg)                  │
└────────────────────────┬────────────────────────┘
                         │
            ┌────────────┴────────────┐
            │                         │
            ▼                         ▼
     ┌─────────────┐           ┌─────────────┐
     │ Coordinator │◄─────────►│ Participant │
     │   (Relay)   │           │    (DKG)    │
     └──────┬──────┘           └──────┬──────┘
            │                         │
            └────────────┬────────────┘
                         │
     ┌───────────────────┴───────────────────┐
     │           Transport Layer             │
     │           (pkg/transport)             │
     │                                       │
     │  • gRPC (TCP/Unix)  • libp2p (P2P)    │
     │  • HTTP/REST        • MCP (JSON-RPC)  │
     │  • QUIC (UDP)       • Memory (test)   │
     └───────────────────┬───────────────────┘
                         │
     ┌───────────────────┴───────────────────┐
     │          DKG Protocol Layer           │
     │             (pkg/dkg)                 │
     │                                       │
     │  • EncPedPop (main protocol)          │
     │  • SimplPedPop (base)                 │
     │  • VSS (secret sharing)               │
     │  • CertEq (equality proof)            │
     │  • Schnorr (signatures)               │
     └───────────────────────────────────────┘
```

## Package Structure

### Core Packages

- **cmd/frostdkg** - CLI application providing coordinator and participant commands
- **pkg/dkg** - FROST DKG protocol implementation (EncPedPop, SimplPedPop, VSS, CertEq)
- **pkg/transport** - Transport layer abstraction and common interfaces

### Transport Implementations

- **pkg/transport/grpc** - gRPC over TCP and Unix domain sockets
- **pkg/transport/http** - HTTP/REST with JSON
- **pkg/transport/quic** - QUIC protocol (UDP-based)
- **pkg/transport/libp2p** - libp2p peer-to-peer networking
- **pkg/transport/mcp** - Model Context Protocol (JSON-RPC)
- **pkg/transport/memory** - In-memory transport for testing
- **pkg/transport/tls** - TLS 1.3 configuration utilities

## DKG Protocol Flow

FROST DKG executes in two rounds plus verification:

1. **Setup**
   - Coordinator starts and waits for participants
   - Participants generate host keys and connect
   - Participants send join messages with participant IDs

2. **Round 1: EncPedPop Participant Messages**
   - Generate VSS polynomial commitments
   - Create Schnorr proof of possession (PoP)
   - Generate encryption nonces
   - Encrypt secret shares for each participant
   - Send message to coordinator

3. **Round 2: Share Distribution**
   - Coordinator aggregates and broadcasts Round 1 messages
   - Participants decrypt received shares
   - Verify shares against VSS commitments
   - Compute secret share sum

4. **CertEq: Certificate Equality Verification**
   - All participants prove they derived the same group public key
   - Uses non-interactive zero-knowledge proof
   - Ensures protocol correctness without trusted coordinator

5. **Result**
   - Each participant receives their threshold secret share
   - All participants have the same threshold public key
   - Output is compatible with go-frost signing

## Supported Ciphersuites

All RFC 9591 FROST ciphersuites are supported:

| Ciphersuite | Curve | Hash | Security | Status |
|-------------|-------|------|----------|--------|
| FROST-ED25519-SHA512-v1 | Ed25519 | SHA-512 | 128-bit | Default |
| FROST-RISTRETTO255-SHA512-v1 | ristretto255 | SHA-512 | 128-bit | Supported |
| FROST-P256-SHA256-v1 | P-256 | SHA-256 | 128-bit | Supported |
| FROST-ED448-SHAKE256-v1 | Ed448 | SHAKE256 | 224-bit | Supported |
| FROST-secp256k1-SHA256-v1 | secp256k1 | SHA-256 | 128-bit | Supported |

## Transport Layer Design

All transport implementations provide the same interface:

### Coordinator Interface
```go
type Coordinator interface {
    Start(ctx context.Context) error
    WaitForParticipants(ctx context.Context, n int) error
    BroadcastMessage(ctx context.Context, msg Message) error
    ReceiveMessages(ctx context.Context) ([]Message, error)
    Close() error
}
```

### Participant Interface
```go
type Participant interface {
    Connect(ctx context.Context) error
    SendMessage(ctx context.Context, msg Message) error
    ReceiveMessage(ctx context.Context) (Message, error)
    Close() error
}
```

### Message Serialization

Supports multiple codecs:
- **JSON** - Human-readable, default
- **CBOR** - Compact binary encoding
- **MessagePack** - Efficient binary format

## Security Architecture

### Transport Security
- **TLS 1.3** required for production deployments
- **mTLS** optional for mutual authentication
- **Protocol-specific security**:
  - gRPC: TLS with certificate verification
  - HTTP: HTTPS with optional client certificates
  - QUIC: Native TLS 1.3 integration
  - libp2p: Noise protocol or TLS
  - Unix sockets: Filesystem permissions

### Cryptographic Security
- **Untrusted Coordinator** - Relay only, no cryptographic role
- **Host Keys** - Each participant generates Ed25519 key pair
- **CertEq Verification** - Ensures all participants agree on result
- **VSS Commitments** - Verifiable secret sharing prevents cheating
- **Proof of Possession** - Prevents rogue key attacks

## Error Handling

All packages define typed errors:
- Transport errors: `pkg/transport/errors.go`
- DKG errors: `pkg/dkg/errors.go`
- TLS errors: `pkg/transport/tls/errors.go`

Critical invariants:
- No error ignored (no `_` usage)
- All errors propagated with context
- Graceful degradation on non-critical failures

## Integration Points

### go-frost Integration
Output from FROST DKG is directly compatible with go-frost:
- `DKGOutput.SecretShare` → FROST signing share
- `DKGOutput.ThresholdPubkey` → FROST group public key
- `DKGOutput.PublicShares` → FROST verification keys

### CLI Usage
```bash
# Start coordinator
frostdkg coordinator --transport grpc --address localhost:9000

# Run participant
frostdkg participant --coordinator localhost:9000 --threshold 2 --total 3
```

## Design Principles

- **Modularity** - Pluggable transports, ciphersuites
- **Simplicity** - Clean abstractions, minimal dependencies
- **Performance** - Lock-free algorithms, efficient serialization
- **Security** - Defense in depth, typed errors, zero trust
- **Testing** - 90%+ code coverage, integration tests, benchmarks
- **Standards** - RFC 9591 compliance
