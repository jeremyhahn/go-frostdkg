# Transport Layer

The transport layer provides flexible network communication for FROST DKG sessions. It abstracts protocol-specific details behind a unified interface, allowing participants to connect via multiple transport protocols with pluggable serialization and TLS security.

## Architecture

The transport layer consists of two primary interfaces:

- **Coordinator**: Message relay server with no cryptographic role
- **Participant**: DKG client that connects to coordinator and executes protocol

## Supported Protocols

### gRPC (Default)
High-performance RPC with HTTP/2 streaming and protobuf serialization.

**Best for**: Production servers, high-throughput applications
**Latency**: Low
**Firewall**: Requires port configuration
**P2P**: No

```go
cfg := transport.NewGRPCConfig("localhost:9000")
cfg.CodecType = "json"
cfg.Timeout = 30 * time.Second
```

### HTTP
REST-based transport with standard HTTP/1.1 or HTTP/2.

**Best for**: Web integration, proxy-friendly environments
**Latency**: Medium
**Firewall**: Friendly (port 80/443)
**P2P**: No

```go
cfg := transport.NewHTTPConfig("localhost:8080")
cfg.TLSCertFile = "/path/to/cert.pem"
cfg.TLSKeyFile = "/path/to/key.pem"
```

### QUIC
UDP-based transport with built-in TLS 1.3 and connection migration.

**Best for**: Mobile networks, unreliable connections
**Latency**: Low
**Firewall**: Requires UDP
**P2P**: No

```go
cfg := transport.NewQUICConfig("0.0.0.0:9001")
cfg.TLSCertFile = "/path/to/cert.pem" // Required
cfg.TLSKeyFile = "/path/to/key.pem"   // Required
```

### Unix Sockets
Local IPC via Unix domain sockets, no network overhead.

**Best for**: Same-machine processes, testing
**Latency**: Lowest
**Firewall**: N/A
**P2P**: No

```go
cfg := transport.NewUnixConfig("/tmp/frostdkg.sock")
```

### libp2p
Peer-to-peer networking with NAT traversal and peer discovery.

**Best for**: Decentralized applications
**Latency**: Variable
**Firewall**: NAT traversal built-in
**P2P**: Yes

```go
cfg := &transport.Config{
    Protocol: transport.ProtocolLibp2p,
    Address:  "/ip4/0.0.0.0/tcp/9000",
}
```

### MCP (Model Context Protocol)
JSON-RPC 2.0 based transport designed for AI agent integration.

**Best for**: AI assistants, LLM tool integration, automation
**Latency**: Low
**Firewall**: HTTP-friendly (stdio also supported)
**P2P**: No

Supports two transport modes:
- **stdio**: JSON-RPC over stdin/stdout for subprocess communication
- **http**: JSON-RPC over HTTP for network access

```go
// HTTP mode
server, err := mcp.NewMCPServer(sessionID, sessionCfg, mcp.TransportHTTP, "localhost:8080")

// stdio mode
server, err := mcp.NewMCPServer(sessionID, sessionCfg, mcp.TransportStdio, "")
```

Available tools:
- `dkg_create_session` - Create new DKG session
- `dkg_join_session` - Join existing session
- `dkg_get_session` - Get session status
- `dkg_submit_round1` - Submit Round1 message
- `dkg_submit_round2` - Submit Round2 message
- `dkg_submit_certeq` - Submit CertEq signature
- `dkg_get_result` - Get DKG result
- `dkg_list_sessions` - List active sessions

See [MCP Transport Details](../pkg/transport/mcp/README.md) for comprehensive API documentation, error codes, and integration examples.

### Memory (Testing Only)
In-process communication for unit tests.

```go
cfg := transport.NewMemoryConfig("test-session")
```

## Configuration

### Basic Config
```go
type Config struct {
    Protocol          Protocol      // Transport protocol
    Address           string        // Network address
    TLSCertFile       string        // TLS certificate (PEM)
    TLSKeyFile        string        // TLS private key (PEM)
    TLSCAFile         string        // CA cert for mTLS (PEM)
    CodecType         string        // json, msgpack, cbor
    Timeout           time.Duration // Operation timeout
    MaxMessageSize    int           // Max message bytes
    KeepAlive         bool          // TCP keepalive
    KeepAliveInterval time.Duration // Keepalive interval
}
```

### Session Config
```go
type SessionConfig struct {
    SessionID            string        // Unique session ID
    Threshold            int           // t-of-n threshold
    NumParticipants      int           // Total participants
    Ciphersuite          string        // FROST ciphersuite
    Timeout              time.Duration // Session timeout
    AllowPartialSessions bool          // Allow <n participants
}
```

## Serialization Formats

### JSON (Default)
Human-readable, debugging-friendly, widely supported.

```go
cfg.CodecType = "json"
```

### MessagePack
Binary format, compact representation, fast encoding/decoding.

```go
cfg.CodecType = "msgpack"
```

### CBOR
Binary format, RFC 8949 compliant, self-describing.

```go
cfg.CodecType = "cbor"
```

## TLS Configuration

### Server TLS
```go
cfg := transport.NewTLSConfig(
    transport.ProtocolGRPC,
    "localhost:9000",
    "/path/to/server.crt",
    "/path/to/server.key",
    "", // No CA = server-only TLS
)
```

### Mutual TLS (mTLS)
```go
cfg := transport.NewTLSConfig(
    transport.ProtocolGRPC,
    "localhost:9000",
    "/path/to/server.crt",
    "/path/to/server.key",
    "/path/to/ca.crt", // CA enables mTLS
)
```

**TLS Requirements**:
- Minimum version: TLS 1.3
- Certificate format: PEM
- QUIC protocol requires TLS

## Security Requirements

The FROST DKG protocol has specific security requirements for transport layer confidentiality and authentication. This section documents the requirements aligned with Zcash FROST and RFC 9591.

### Protocol Round Security Model

**Round 1 Messages (Public)**:
- VSS commitments (public polynomial coefficients)
- Proof of possession (Schnorr signature)
- Encrypted shares (when using encrypted DKG variant)

Round 1 messages require **integrity and authentication** but NOT confidentiality. All data is either public or already encrypted.

**Round 2 Messages (Confidential)**:
- Secret shares (from coordinator to participants)

Round 2 messages MUST be sent over a **confidential and authenticated channel**. Secret shares must never be transmitted in plaintext.

### Transport Security Options

#### Option 1: TLS/mTLS (Recommended)
Use TLS 1.3 for all communications. This provides:
- Confidentiality for Round 2 shares
- Authentication of participants
- Integrity protection

```go
cfg := transport.NewTLSConfig(
    transport.ProtocolGRPC,
    "localhost:9000",
    "/path/to/server.crt",
    "/path/to/server.key",
    "/path/to/ca.crt", // mTLS for participant authentication
)
```

#### Option 2: Encrypted DKG (Application-Level)
The encrypted DKG variant (`FROSTDKGEncParticipantRound1`, etc.) provides application-level encryption using ECDH key agreement. This allows secure DKG over untrusted transports.

**Encryption scheme**:
1. Each participant generates an ephemeral nonce
2. ECDH shared secret: `sender_hostSecret × receiver_hostPubkey`
3. Pad derivation: `H("ecdh pad" || nonce || shared_secret)`
4. XOR encryption of secret shares

```go
// Participants exchange host public keys out-of-band
state, msg, err := FROSTDKGEncParticipantRound1(
    cs, seed, hostSeckey, hostPubkeys, threshold, index, random,
)
```

#### Option 3: External Channel (Out-of-Band)
In some deployments, Round 2 shares can be distributed via an external secure channel (e.g., Signal, encrypted email). The transport layer only handles Round 1 messages.

### Authentication Requirements

Participants MUST be authenticated. Options:

1. **mTLS**: Client certificates for each participant
2. **Host Key Binding**: Host public keys pre-shared and verified
3. **Proof of Possession**: Schnorr signatures included in Round 1

### Security Guarantees

When using TLS/mTLS or encrypted DKG:

| Property | Round 1 | Round 2 |
|----------|---------|---------|
| Confidentiality | Optional | Required |
| Integrity | Required | Required |
| Authentication | Required | Required |
| Replay Protection | Required | Required |

### Malicious Participant Detection

The protocol detects malicious behavior through:

1. **Invalid POP**: `ErrFROSTDKGInvalidPOP` - participant's Schnorr signature verification failed
2. **Invalid Share**: `ErrInvalidShare` - share doesn't match VSS commitment
3. **Commitment Mismatch**: `ErrFROSTDKGCommitmentMismatch` - coordinator modified commitments

Investigation data is provided via `UnknownFaultyPartyError` when the faulty party cannot be immediately identified.

## Usage Example

### Coordinator
```go
cfg := transport.NewGRPCConfig("localhost:9000")
sessionCfg := transport.NewSessionConfig(2, 3, "FROST-ED25519-SHA512-v1")

coord, err := grpc.NewGRPCServer(cfg, sessionCfg)
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()
if err := coord.Start(ctx); err != nil {
    log.Fatal(err)
}
defer coord.Stop(ctx)

// Wait for 3 participants
if err := coord.WaitForParticipants(ctx, 3); err != nil {
    log.Fatal(err)
}
```

### Participant
```go
cfg := transport.NewGRPCConfig("")
client, err := grpc.NewGRPCClient(cfg)
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()
if err := client.Connect(ctx, "localhost:9000"); err != nil {
    log.Fatal(err)
}
defer client.Disconnect()

params := &transport.DKGParams{
    HostSeckey:     hostSeckey,     // 32 bytes
    HostPubkeys:    hostPubkeys,    // n x 32 bytes
    Threshold:      2,
    ParticipantIdx: 0,
    Random:         randomness,     // 32 bytes
}

result, err := client.RunDKG(ctx, params)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Threshold Key: %x\n", result.ThresholdPubkey)
```
