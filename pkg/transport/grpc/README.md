# gRPC Transport for FROST DKG

This package provides gRPC transport implementation for the FROST DKG protocol.

## Features

- **Bidirectional Streaming**: Efficient real-time message exchange using gRPC bidirectional streams
- **TLS 1.3 Security**: Required for TCP connections with support for mutual TLS (mTLS)
- **Unix Socket Support**: Local-only communication via Unix domain sockets (no TLS needed)
- **Session Management**: Coordinator manages multiple concurrent DKG sessions
- **Graceful Shutdown**: Proper cleanup and resource management
- **Configurable**: Message size limits, keepalive, timeouts

## Components

### Protocol Buffers

- `proto/dkg.proto` - Service and message definitions
- `proto/dkg.pb.go` - Generated Go protobuf code
- `proto/dkg_grpc.pb.go` - Generated gRPC service code

### Server Implementation

- `server.go` - TCP gRPC server with TLS 1.3 support
  - Implements `transport.Coordinator` interface
  - Handles participant registration and message relay
  - Thread-safe session management

### Client Implementation

- `client.go` - TCP gRPC client with TLS 1.3 support
  - Implements `transport.Participant` interface
  - Connection management with reconnection logic
  - Stream-based message sending/receiving

### Unix Socket Support

- `unix.go` - Unix domain socket server and client
  - Local-only communication
  - No TLS needed
  - Same interface as TCP implementation

## Usage

### Server (Coordinator)

```go
import (
    "context"
    "github.com/jeremyhahn/go-frostdkg/pkg/transport"
    "github.com/jeremyhahn/go-frostdkg/pkg/transport/grpc"
)

// Create server config
config := &transport.Config{
    Protocol:    transport.ProtocolGRPC,
    Address:     "localhost:9000",
    TLSCertFile: "server.crt",
    TLSKeyFile:  "server.key",
}

sessionCfg := &transport.SessionConfig{
    Threshold:       2,
    NumParticipants: 3,
    Ciphersuite:     "FROST-ED25519-SHA512-v1",
}

// Create and start server
server, err := grpc.NewGRPCServer(config, sessionCfg)
if err != nil {
    panic(err)
}

ctx := context.Background()
if err := server.Start(ctx); err != nil {
    panic(err)
}
defer server.Stop(context.Background())

// Wait for participants
if err := server.WaitForParticipants(ctx, 3); err != nil {
    panic(err)
}
```

### Client (Participant)

```go
// Create client config
config := &transport.Config{
    Protocol:  transport.ProtocolGRPC,
    CodecType: "json",
}

// Create and connect client
client, err := grpc.NewGRPCClient(config)
if err != nil {
    panic(err)
}

ctx := context.Background()
if err := client.Connect(ctx, "localhost:9000"); err != nil {
    panic(err)
}
defer client.Disconnect()

// Run DKG
params := &transport.DKGParams{
    HostSeckey:     hostSeckey,
    HostPubkeys:    hostPubkeys,
    Threshold:      2,
    ParticipantIdx: 0,
    Random:         random,
}

result, err := client.RunDKG(ctx, params)
if err != nil {
    panic(err)
}
```

### Unix Socket

```go
// Server
config := &transport.Config{
    Protocol: transport.ProtocolUnix,
    Address:  "/tmp/dkg.sock",
}

server, err := grpc.NewUnixServer(config, sessionCfg)
// ... same as TCP server

// Client
client, err := grpc.NewUnixClient(config)
// ... same as TCP client
```

## Testing

Run tests:
```bash
go test ./pkg/transport/grpc/...
```

Run with coverage:
```bash
go test ./pkg/transport/grpc/... -cover
```

Run benchmarks:
```bash
go test -bench=. ./pkg/transport/grpc/...
```

## Architecture

### Message Flow

1. **Join Phase**
   - Participant connects and sends `MSG_TYPE_JOIN`
   - Coordinator assigns index and sends `MSG_TYPE_SESSION_INFO`

2. **DKG Rounds**
   - Round 1: VSS commitments and proofs (`MSG_TYPE_ROUND1`)
   - Round 2: Encrypted shares (`MSG_TYPE_ROUND2`)
   - Certificate: Final DKG certificate (`MSG_TYPE_CERTIFICATE`)

3. **Completion**
   - Participants receive `MSG_TYPE_COMPLETE`
   - DKG result returned with threshold key and shares

### Security

- **TLS 1.3 Required**: All TCP connections must use TLS 1.3
- **mTLS Support**: Optional client certificate verification
- **Unix Socket**: Local-only, no TLS needed
- **Message Validation**: All messages validated before processing

### Concurrency

- **Thread-Safe**: All operations are thread-safe using atomic operations and mutexes
- **Lock-Free Where Possible**: Atomic operations preferred over mutexes
- **Graceful Shutdown**: Proper cleanup of goroutines and resources
- **Context Propagation**: All operations support context cancellation

## Performance

Typical benchmarks on modern hardware:

- Server start/stop: ~90μs per operation
- Client connect: ~760μs per operation
- Message throughput: Thousands of messages per second
- Concurrent participants: Tested with 5+ simultaneous participants

## Dependencies

- `google.golang.org/grpc` - gRPC framework
- `google.golang.org/protobuf` - Protocol Buffers
- `github.com/jeremyhahn/go-frostdkg/pkg/transport` - Transport interfaces
- `github.com/jeremyhahn/go-frostdkg/pkg/transport/tls` - TLS configuration utilities
