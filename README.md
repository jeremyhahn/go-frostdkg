# go-frostdkg

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![Coverage](https://img.shields.io/badge/coverage-60%25-yellow.svg)](https://github.com/jeremyhahn/go-frostdkg)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE.md)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://github.com/jeremyhahn/go-frostdkg)

A Go implementation of the FROST Distributed Key Generation protocol for threshold signatures, based on [ChillDKG](https://github.com/BlockstreamResearch/bip-frost-dkg).

## Overview

go-frostdkg implements a distributed key generation protocol designed to work with [go-frost](https://github.com/jeremyhahn/go-frost) for complete threshold signature solutions. The implementation provides pluggable transport layers via gRPC, REST, QUIC, libp2p, and Unix sockets.

### Inspiration & Attribution

This implementation draws inspiration from the ChillDKG specification and reference implementation by Tim Ruffing and Jonas Nick at Blockstream Research:

- **Original Specification**: [BIP-FROST-DKG](https://github.com/BlockstreamResearch/bip-frost-dkg)
- **Authors**: Tim Ruffing ([@real_or_random](https://github.com/real-or-random)), Jonas Nick ([@jonasnick](https://github.com/jonasnick))

While ChillDKG was designed specifically for Bitcoin, go-frostdkg has evolved into its own FROST DKG solution with broader applicability and extended transport options.

## Supported Ciphersuites

| Ciphersuite | Curve | Hash |
|-------------|-------|------|
| FROST-ED25519-SHA512-v1 | Ed25519 | SHA-512 |
| FROST-RISTRETTO255-SHA512-v1 | ristretto255 | SHA-512 |
| FROST-ED448-SHAKE256-v1 | Ed448 | SHAKE256 |
| FROST-P256-SHA256-v1 | P-256 | SHA-256 |
| FROST-secp256k1-SHA256-v1 | secp256k1 | SHA-256 |

## Installation

### Library

```bash
go get github.com/jeremyhahn/go-frostdkg
```

### CLI

```bash
# Install from source
git clone https://github.com/jeremyhahn/go-frostdkg.git
cd go-frostdkg
make install

# Or build locally
make build-cli
./bin/frostdkg --help
```

## Quick Start (CLI)

The fastest way to run a DKG session is using the CLI.

### 1. Start a Coordinator

```bash
# Start a 2-of-3 threshold DKG coordinator
frostdkg coordinator --protocol grpc --listen 0.0.0.0:9000 \
  --threshold 2 --participants 3 --verbose
```

### 2. Join as Participants (in separate terminals)

Terminal 1:
```bash
frostdkg participant --coordinator localhost:9000 --id 0 \
  --threshold 2 --output participant0.json --verbose
```

Terminal 2:
```bash
frostdkg participant --coordinator localhost:9000 --id 1 \
  --threshold 2 --output participant1.json --verbose
```

Terminal 3:
```bash
frostdkg participant --coordinator localhost:9000 --id 2 \
  --threshold 2 --output participant2.json --verbose
```

### 3. Verify Key Shares

```bash
# All participants should have the same group public key
frostdkg verify --share participant0.json
frostdkg verify --share participant1.json
frostdkg verify --share participant2.json
```

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `coordinator` | Start a DKG coordinator server |
| `participant` | Join a DKG session as participant |
| `certgen` | Generate TLS certificates |
| `verify` | Verify key share files |
| `config` | Manage configuration |

### Transport Protocols

| Protocol | Flag | Description |
|----------|------|-------------|
| gRPC | `--protocol grpc` | Default, HTTP/2-based RPC |
| HTTP | `--protocol http` | REST/JSON over HTTP |
| QUIC | `--protocol quic` | UDP-based with built-in TLS |
| libp2p | `--protocol libp2p` | P2P with Noise encryption |
| MCP | `--protocol mcp` | Model Context Protocol for AI integration |
| Unix | `--protocol unix` | Unix domain sockets |

### Example with TLS

```bash
# Generate certificates
frostdkg certgen --type ecdsa --output ./certs --name server

# Start coordinator with TLS
frostdkg coordinator --protocol grpc --listen 0.0.0.0:9000 \
  --tls-cert ./certs/server.crt --tls-key ./certs/server.key \
  --threshold 2 --participants 3

# Join with TLS
frostdkg participant --coordinator localhost:9000 --id 0 \
  --tls-ca ./certs/server.crt \
  --threshold 2 --output participant0.json
```

See [CLI Documentation](cmd/frostdkg/README.md) for complete details.

## Library Usage

### Using the Transport Layer

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-frostdkg/pkg/transport"
    "github.com/jeremyhahn/go-frostdkg/pkg/transport/grpc"
)

func main() {
    ctx := context.Background()

    // Create transport config
    config := &transport.Config{
        Protocol: transport.ProtocolGRPC,
        Address:  "localhost:9000",
    }

    // Create session config
    sessionCfg := &transport.SessionConfig{
        Threshold:       2,
        NumParticipants: 3,
        Ciphersuite:     "FROST-ED25519-SHA512-v1",
    }

    // Create and start coordinator
    server, err := grpc.NewGRPCServer(config, sessionCfg)
    if err != nil {
        log.Fatal(err)
    }

    if err := server.Start(ctx); err != nil {
        log.Fatal(err)
    }
    defer server.Stop(ctx)

    // Wait for participants
    if err := server.WaitForParticipants(ctx, 3); err != nil {
        log.Fatal(err)
    }

    log.Println("DKG completed successfully")
}
```

### Participant Example

```go
package main

import (
    "context"
    "crypto/rand"
    "log"

    "github.com/jeremyhahn/go-frostdkg/pkg/transport"
    "github.com/jeremyhahn/go-frostdkg/pkg/transport/grpc"
)

func main() {
    ctx := context.Background()

    // Create client
    config := &transport.Config{
        Protocol: transport.ProtocolGRPC,
    }

    client, err := grpc.NewGRPCClient(config)
    if err != nil {
        log.Fatal(err)
    }

    // Connect to coordinator
    if err := client.Connect(ctx, "localhost:9000"); err != nil {
        log.Fatal(err)
    }
    defer client.Disconnect()

    // Generate host key (32 bytes)
    hostSeckey := make([]byte, 32)
    rand.Read(hostSeckey)

    // Generate randomness for DKG
    random := make([]byte, 32)
    rand.Read(random)

    // DKG parameters
    params := &transport.DKGParams{
        HostSeckey:     hostSeckey,
        HostPubkeys:    nil, // Auto-discovered from coordinator
        Threshold:      2,
        ParticipantIdx: 0,
        Random:         random,
    }

    // Run DKG protocol
    result, err := client.RunDKG(ctx, params)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("DKG Complete!")
    log.Printf("Secret Share: %x", result.SecretShare)
    log.Printf("Threshold Pubkey: %x", result.ThresholdPubkey)
}
```

## Architecture

```
go-frostdkg/
├── cmd/frostdkg/         # CLI application
│   ├── coordinator.go    # Coordinator command
│   ├── participant.go    # Participant command
│   ├── certgen.go        # Certificate generation
│   ├── verify.go         # Key share verification
│   └── config.go         # Configuration management
├── pkg/
│   ├── dkg/              # DKG protocol implementation
│   │   ├── frostdkg.go   # Main DKG protocol
│   │   ├── certeq.go     # Certificate equality
│   │   ├── vss.go        # Verifiable secret sharing
│   │   ├── polynomial.go # Polynomial operations
│   │   └── signer.go     # Ciphersuite support
│   └── transport/        # Transport layer
│       ├── grpc/         # gRPC transport
│       ├── http/         # HTTP/REST transport
│       ├── quic/         # QUIC transport
│       ├── libp2p/       # libp2p P2P transport
│       ├── mcp/          # Model Context Protocol
│       ├── memory/       # In-memory (testing)
│       └── tls/          # TLS configuration
├── test/
│   ├── integration/      # Integration tests
│   └── testvectors/      # RFC 9591 test vectors
└── docs/                 # Documentation
```

## Protocol Layers

FROST DKG is built from composable layers:

```
┌─────────────────────────────────────────────────┐
│                  FROST DKG                      │
│  Complete standalone DKG protocol               │
├─────────────────────────────────────────────────┤
│                  CertEq                         │
│  Certificate equality (consensus)               │
├─────────────────────────────────────────────────┤
│                 EncPedPop                       │
│  Encrypted channels via ECDH                    │
├─────────────────────────────────────────────────┤
│                SimplPedPop                      │
│  Core DKG: polynomials, VSS, commitments        │
└─────────────────────────────────────────────────┘
```

## Key Share Output

DKG produces key shares in JSON format:

```json
{
  "participant_index": 0,
  "secret_share": "hex-encoded 32 bytes",
  "threshold_pubkey": "hex-encoded 33 bytes",
  "public_shares": ["hex 33 bytes", "hex 33 bytes", "hex 33 bytes"],
  "session_id": "unique-session-id",
  "recovery_data": "hex-encoded recovery data"
}
```

## Testing

```bash
make test              # Run all unit tests
make integration-test  # Run integration tests (Docker)
make coverage          # Generate coverage report
make bench             # Run benchmarks
make lint              # Run linters
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [CLI Reference](cmd/frostdkg/README.md)
- [Architecture](docs/architecture.md)
- [Transport Layer](docs/transport.md)
- [CertEq Protocol](docs/certeq.md)
- [DHT Discovery](docs/dht.md)
- [Security Policy](docs/security.md)
- [RFC 9591 - FROST](https://www.rfc-editor.org/rfc/rfc9591.html)

## Related Projects

- [go-frost](https://github.com/jeremyhahn/go-frost) - FROST threshold signing
- [go-keychain](https://github.com/jeremyhahn/go-keychain) - Key management
- [go-trusted-ca](https://github.com/jeremyhahn/go-trusted-ca) - Certificate Authority
- [go-trusted-platform](https://github.com/jeremyhahn/go-trusted-platform) - Trusted Computing Platform

## Acknowledgments

This project draws inspiration from the excellent work of the Blockstream Research team:

- **[ChillDKG BIP](https://github.com/BlockstreamResearch/bip-frost-dkg)** - The original ChillDKG specification and Python reference implementation
- **Tim Ruffing** ([@real_or_random](https://github.com/real-or-random)) - Co-author of ChillDKG, FROST, MuSig2
- **Jonas Nick** ([@jonasnick](https://github.com/jonasnick)) - Co-author of ChillDKG

The FROST DKG protocol builds on foundational cryptographic research:

- [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852) (Komlo & Goldberg)
- [RFC 9591: FROST Threshold Signatures](https://www.rfc-editor.org/rfc/rfc9591.html)

## License

Apache 2.0 - see [LICENSE.md](LICENSE.md)
