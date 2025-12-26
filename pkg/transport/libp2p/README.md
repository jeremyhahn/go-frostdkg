# libp2p Transport for FROST-DKG

This package implements a libp2p-based transport layer for the FROST distributed key generation protocol with optional TLS support.

## Overview

The libp2p transport provides peer-to-peer communication for DKG sessions using the [libp2p](https://libp2p.io/) networking stack. Unlike client-server transports, libp2p enables fully decentralized DKG where any peer can act as a coordinator.

## Features

- **Peer-to-peer Architecture**: No centralized server required
- **Built-in Encryption**: Noise protocol and TLS 1.3 for secure communication
- **Optional Certificate-based TLS**: Additional X.509 certificate authentication
- **Multiaddr Addressing**: Flexible addressing using libp2p multiaddrs
- **Protocol Negotiation**: Automatic protocol version negotiation
- **Stream Multiplexing**: Efficient bidirectional stream management
- **NAT Traversal**: Optional relay support for NAT/firewall traversal
- **Backward Compatible**: TLS is optional and doesn't break existing code

## Security

### Transport Security (Always Enabled)

The libp2p transport uses industry-standard security protocols that are **always active**:

- **Noise Protocol**: Modern cryptographic protocol with forward secrecy
- **TLS 1.3**: Standard TLS with perfect forward secrecy
- **Protocol Negotiation**: Automatic selection of best available security

All peer connections are encrypted and authenticated by default.

### Optional Certificate-based TLS (New)

Additional application-level TLS can be configured for environments requiring X.509 certificate validation:

- **Server-side TLS**: Certificate and key authentication
- **Mutual TLS (mTLS)**: Client certificate verification
- **Custom CA Support**: Integration with existing PKI infrastructure

This feature is **optional** and provides an additional layer of authentication on top of libp2p's built-in security.

#### Basic TLS Configuration

```go
cfg := libp2p.DefaultHostConfig()
cfg.TLSCertFile = "/path/to/server.crt"
cfg.TLSKeyFile = "/path/to/server.key"

host, err := libp2p.NewHost(ctx, cfg)
if err != nil {
    log.Fatal(err)
}
defer host.Close()
```

#### Mutual TLS (mTLS) Configuration

```go
cfg := libp2p.DefaultHostConfig()
cfg.TLSCertFile = "/path/to/server.crt"
cfg.TLSKeyFile = "/path/to/server.key"
cfg.TLSCAFile = "/path/to/ca.crt"  // For client cert verification

host, err := libp2p.NewHost(ctx, cfg)
if err != nil {
    log.Fatal(err)
}
defer host.Close()
```

#### Using transport.Config

For consistency with other transports:

```go
cfg := transport.NewTLSConfig(
    transport.ProtocolLibp2p,
    "/ip4/0.0.0.0/tcp/9000",
    "server.crt",
    "server.key",
    "ca.crt",
)

host, err := libp2p.NewHostFromTransportConfig(ctx, cfg)
if err != nil {
    log.Fatal(err)
}
defer host.Close()
```

## Components

### DKGHost (`host.go`)

Wraps a libp2p host with DKG-specific functionality:

```go
cfg := libp2p.DefaultHostConfig()
cfg.ListenAddrs = []string{"/ip4/0.0.0.0/tcp/4001"}

// Optional: Add TLS configuration
cfg.TLSCertFile = "server.crt"
cfg.TLSKeyFile = "server.key"

host, err := libp2p.NewHost(ctx, cfg)
if err != nil {
    log.Fatal(err)
}
defer host.Close()

// Check if TLS is configured
if host.HasTLS() {
    log.Println("TLS is enabled")
}
```

**Key Features:**
- Configurable listen addresses
- Identity key management (Ed25519)
- Security protocols (Noise, TLS)
- Optional certificate-based TLS
- Optional relay support

### Protocol (`protocol.go`)

Defines the DKG protocol over libp2p streams:

- **Protocol ID**: `/frost-dkg/1.0.0`
- **Message Framing**: Length-prefixed (4-byte big-endian)
- **Max Message Size**: 10MB

**Message Format:**
```
[4-byte length][message data]
```

### P2PCoordinator (`coordinator.go`)

Implements the `transport.Coordinator` interface for libp2p with TLS support:

```go
config := &transport.SessionConfig{
    Threshold:       2,
    NumParticipants: 3,
    Ciphersuite:     "FROST-ED25519-SHA512-v1",
}

// Using HostConfig
hostCfg := libp2p.DefaultHostConfig()
hostCfg.TLSCertFile = "server.crt"
hostCfg.TLSKeyFile = "server.key"
coordinator, err := libp2p.NewP2PCoordinator("session-123", config, hostCfg)

// OR using transport.Config
transportCfg := transport.NewTLSConfig(
    transport.ProtocolLibp2p,
    "/ip4/0.0.0.0/tcp/9000",
    "server.crt",
    "server.key",
    "",
)
coordinator, err := libp2p.NewP2PCoordinatorFromTransportConfig(
    "session-123",
    transportCfg,
    config,
)

// Start coordinator
ctx := context.Background()
if err := coordinator.Start(ctx); err != nil {
    log.Fatal(err)
}
defer coordinator.Stop(ctx)

// Check TLS status
if coordinator.TLSEnabled() {
    log.Println("Coordinator using TLS")
}

// Get coordinator address
addr := coordinator.Address()
fmt.Printf("Coordinator listening on: %s\n", addr)

// Wait for participants
if err := coordinator.WaitForParticipants(ctx, 3); err != nil {
    log.Fatal(err)
}
```

**Responsibilities:**
- Accept participant connections
- Relay messages between participants
- Manage session lifecycle
- Handle peer disconnections
- Optional TLS certificate validation

### P2PParticipant (`participant.go`)

Implements the `transport.Participant` interface for libp2p with TLS support:

```go
// Using HostConfig
hostCfg := libp2p.DefaultHostConfig()
hostCfg.TLSCertFile = "client.crt"  // For mTLS
hostCfg.TLSKeyFile = "client.key"
hostCfg.TLSCAFile = "ca.crt"
participant, err := libp2p.NewP2PParticipant(hostCfg)

// OR using transport.Config
cfg := transport.NewTLSConfig(
    transport.ProtocolLibp2p,
    "",
    "client.crt",
    "client.key",
    "ca.crt",
)
participant, err := libp2p.NewP2PParticipantFromTransportConfig(cfg)

defer participant.Disconnect()

// Connect to coordinator
ctx := context.Background()
coordAddr := "/ip4/127.0.0.1/tcp/4001/p2p/QmXyz..."
if err := participant.Connect(ctx, coordAddr); err != nil {
    log.Fatal(err)
}

// Run DKG
params := &transport.DKGParams{
    HostSeckey:     hostSeckey,      // 32 bytes
    HostPubkeys:    hostPubkeys,     // All participant public keys
    Threshold:      2,
    ParticipantIdx: 0,
    Random:         random,          // 32 bytes CSPRNG
}

result, err := participant.RunDKG(ctx, params)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("DKG Complete! Threshold Pubkey: %x\n", result.ThresholdPubkey)
```

**Responsibilities:**
- Connect to coordinator
- Execute DKG protocol rounds
- Validate DKG parameters
- Manage local state
- Optional TLS client authentication

## TLS Certificate Management

### Generate Self-Signed Certificates (Testing Only)

```go
import tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"

certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
    []string{"localhost", "127.0.0.1"},
    365*24*time.Hour,
)
if err != nil {
    log.Fatal(err)
}

os.WriteFile("server.crt", certPEM, 0600)
os.WriteFile("server.key", keyPEM, 0600)
```

### Production Certificates

For production, use proper certificates from a trusted CA:

```bash
# Example using Let's Encrypt
certbot certonly --standalone -d dkg.example.com

# Use generated certificates
TLS_CERT=/etc/letsencrypt/live/dkg.example.com/fullchain.pem
TLS_KEY=/etc/letsencrypt/live/dkg.example.com/privkey.pem
```

## Identity

Each peer has a persistent identity derived from an Ed25519 keypair:

```go
privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
if err != nil {
    log.Fatal(err)
}

cfg := &HostConfig{
    PrivateKey: privKey,
}
host, err := NewHost(ctx, cfg)
```

The peer ID is deterministically derived from the public key.

## Addressing

libp2p uses [multiaddr](https://github.com/multiformats/multiaddr) for flexible addressing:

```
/ip4/127.0.0.1/tcp/4001/p2p/QmXyz...
/ip6/::1/tcp/4001/p2p/QmXyz...
/dns4/example.com/tcp/4001/p2p/QmXyz...
```

Components:
- Network protocol (`/ip4`, `/ip6`, `/dns4`)
- Transport (`/tcp`, `/udp`)
- Peer ID (`/p2p/<peer-id>`)

## Testing

Run tests:
```bash
go test ./pkg/transport/libp2p/...
```

Run TLS-specific tests:
```bash
go test ./pkg/transport/libp2p/... -run TLS
```

Run with coverage:
```bash
go test ./pkg/transport/libp2p/... -cover
```

Run benchmarks:
```bash
go test ./pkg/transport/libp2p/... -bench=. -benchmem
```

## Examples

See `example_tls_test.go` for complete working examples:

```bash
go test ./pkg/transport/libp2p/... -run Example -v
```

### Simple 2-of-3 DKG Session

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-frostdkg/pkg/transport"
    "github.com/jeremyhahn/go-frostdkg/pkg/transport/libp2p"
)

func runCoordinator() {
    config := &transport.SessionConfig{
        Threshold:       2,
        NumParticipants: 3,
        Ciphersuite:     "FROST-ED25519-SHA512-v1",
    }

    hostCfg := libp2p.DefaultHostConfig()
    hostCfg.ListenAddrs = []string{"/ip4/0.0.0.0/tcp/4001"}

    // Optional: Add TLS
    hostCfg.TLSCertFile = "server.crt"
    hostCfg.TLSKeyFile = "server.key"

    coordinator, err := libp2p.NewP2PCoordinator("dkg-session", config, hostCfg)
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    if err := coordinator.Start(ctx); err != nil {
        log.Fatal(err)
    }
    defer coordinator.Stop(ctx)

    log.Printf("Coordinator: %s\n", coordinator.Address())

    if err := coordinator.WaitForParticipants(ctx, 3); err != nil {
        log.Fatal(err)
    }

    log.Println("All participants connected!")
}

func runParticipant(coordAddr string, index int) {
    hostCfg := libp2p.DefaultHostConfig()

    // Optional: Add TLS client certificate
    hostCfg.TLSCertFile = "client.crt"
    hostCfg.TLSKeyFile = "client.key"
    hostCfg.TLSCAFile = "ca.crt"

    participant, err := libp2p.NewP2PParticipant(hostCfg)
    if err != nil {
        log.Fatal(err)
    }
    defer participant.Disconnect()

    ctx := context.Background()
    if err := participant.Connect(ctx, coordAddr); err != nil {
        log.Fatal(err)
    }

    // Generate DKG parameters
    params := generateDKGParams(index)

    result, err := participant.RunDKG(ctx, params)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Participant %d complete! Pubkey: %x\n", index, result.ThresholdPubkey)
}
```

## Performance

Benchmark results (typical):

```
BenchmarkHostCreation-96           11.8ms/op
BenchmarkMessageFraming-96         20.7μs/op
BenchmarkHostCreationWithTLS-96    11.8ms/op
BenchmarkHostCreationNoTLS-96      12.0ms/op
```

**Key findings:**
- TLS configuration adds <1% overhead
- Message framing is highly efficient (~20μs)
- Host creation is fast (~12ms)

## Best Practices

1. **Always use TLS in production**
   ```go
   cfg.TLSCertFile = "/etc/dkg/certs/server.crt"
   cfg.TLSKeyFile = "/etc/dkg/certs/server.key"
   ```

2. **Use mTLS for client authentication**
   ```go
   cfg.TLSCAFile = "/etc/dkg/certs/ca.crt"
   ```

3. **Protect private keys**
   ```bash
   chmod 600 /etc/dkg/certs/server.key
   ```

4. **Handle errors appropriately**
   ```go
   if err := coordinator.Start(ctx); err != nil {
       log.Fatalf("failed to start: %v", err)
   }
   ```

5. **Always close resources**
   ```go
   defer host.Close()
   defer coordinator.Stop(ctx)
   defer participant.Disconnect()
   ```

## Limitations

- **NAT Traversal**: Requires relay or manual port forwarding for complex NAT scenarios
- **Discovery**: Basic mDNS discovery for local networks (DHT for global discovery requires additional setup)
- **Message Size**: 10MB maximum message size
- **Connection Limits**: Subject to libp2p host connection limits

## Implemented Enhancements

All previously planned enhancements have been implemented:

- [x] **Pubsub-based broadcast** (`pubsub.go`) - GossipSub-based session messaging with acknowledgments
- [x] **DHT integration for peer discovery** (`discovery.go`) - Kademlia DHT with rendezvous-based discovery
- [x] **Connection pooling and multiplexing optimization** (`connpool.go`) - Adaptive connection management with priority tagging
- [x] **Bandwidth limiting and QoS** (`qos.go`) - Token-bucket rate limiting with priority queuing
- [x] **Prometheus metrics integration** (`metrics.go`) - Comprehensive metrics with HTTP endpoint
- [x] **Circuit relay v2 support** (`relay.go`) - NAT traversal with reservation management

### Feature Configuration Examples

#### PubSub Broadcasting
```go
cfg := DefaultHostConfig()
cfg.EnablePubSub = true
cfg.PubSubConfig = DefaultPubSubConfig()

host, _ := NewHost(ctx, cfg)
psm := host.PubSubManager()
psm.JoinSession(ctx, "session-123")
psm.Publish(ctx, "session-123", data)
```

#### DHT Discovery
```go
cfg := DefaultDiscoveryConfig()
cfg.Mode = DHTModeServer
cfg.BootstrapPeers = bootstrapPeers

discovery, _ := NewDiscoveryService(host, cfg)
discovery.Start(ctx)
discovery.AdvertiseSession(ctx, "session-123", 10*time.Minute)
peers, _ := discovery.FindSessionPeers(ctx, "session-123", 10, 30*time.Second)
```

#### Connection Pooling
```go
cfg := DefaultPoolConfig()
cfg.LowWatermark = 64
cfg.HighWatermark = 128
cfg.MaxConnectionsPerPeer = 4

pool, _ := NewConnectionPool(cfg)
pool.TagSession(peerID, "session-123", SessionPriorityHigh)
```

#### QoS Management
```go
cfg := DefaultQoSConfig()
cfg.MaxBandwidthIn = 100 * 1024 * 1024  // 100 MB/s
cfg.MaxBandwidthOut = 100 * 1024 * 1024
cfg.EnablePrioritization = true

qos, _ := NewQoSManager(cfg)
qos.WaitOutgoing(ctx, peerID, messageSize)
```

#### Prometheus Metrics
```go
cfg := DefaultMetricsConfig()
cfg.HTTPEnabled = true
cfg.HTTPAddr = ":9090"

mc, _ := NewMetricsCollector(cfg)
mc.StartHTTPServer(ctx)
mc.RecordMessageSent("commitment", 1024)
// Metrics available at http://localhost:9090/metrics
```

#### Circuit Relay v2
```go
cfg := DefaultRelayConfig()
cfg.EnableRelay = true
cfg.EnableAutoRelay = true
cfg.StaticRelays = []string{"/ip4/relay.example.com/tcp/4001/p2p/QmRelay..."}

rm, _ := NewRelayManager(host, cfg)
rm.Start(ctx)
relayAddrs := rm.GetRelayAddresses()
```

## References

- [libp2p Specifications](https://github.com/libp2p/specs)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [Multiaddr Specification](https://github.com/multiformats/multiaddr)
- [FROST DKG Paper](https://eprint.iacr.org/2020/852)
- [TLS Package Documentation](../tls/)
