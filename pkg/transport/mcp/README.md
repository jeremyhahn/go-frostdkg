# MCP Transport for go-frostdkg

This package implements the Model Context Protocol (MCP) transport layer for the go-frostdkg FROST-DKG library. MCP enables AI models like Claude to participate in distributed key generation sessions through a standardized JSON-RPC 2.0 interface.

## Overview

The MCP transport provides a way for AI agents and automated systems to interact with DKG sessions using well-defined tools and JSON-RPC calls. It supports both stdio (for CLI integration) and HTTP/SSE (for web services) transport mechanisms.

## Architecture

The implementation consists of four main components:

### 1. JSON-RPC Protocol (`jsonrpc.go`)

Implements the JSON-RPC 2.0 protocol with:
- Request/response handling
- Error reporting
- Notification support
- Full validation

### 2. Tool Definitions (`tools.go`)

Defines 8 MCP tools for DKG operations:

| Tool Name | Description |
|-----------|-------------|
| `dkg_create_session` | Create a new DKG session with specified parameters |
| `dkg_join_session` | Join an existing session as a participant |
| `dkg_get_session` | Retrieve session information and status |
| `dkg_submit_round1` | Submit Round1 message (VSS commitments, PoP) |
| `dkg_submit_round2` | Submit Round2 message (encrypted shares) |
| `dkg_submit_certeq` | Submit CertEq signature |
| `dkg_get_result` | Retrieve DKG session results |
| `dkg_list_sessions` | List all active sessions |

Each tool has complete JSON Schema definitions for parameters and results.

### 3. MCP Server (`server.go`)

Implements the `transport.Coordinator` interface:
- Manages multiple concurrent DKG sessions
- Routes messages between participants
- Tracks session state (Created → Round1 → Round2 → CertEq → Completed)
- Supports both stdio and HTTP transports
- Thread-safe session management

Session States:
```
Created → WaitingParticipants → Round1 → Round2 → CertEq → Completed/Failed
```

### 4. MCP Client (`client.go`)

Implements the `transport.Participant` interface:
- Connects to MCP servers via stdio or HTTP
- Executes DKG protocol rounds
- Submits messages and retrieves results
- Full parameter validation

## Usage Examples

### Creating an MCP Server (Coordinator)

```go
import (
    "context"
    "github.com/jeremyhahn/go-frostdkg/pkg/transport"
    "github.com/jeremyhahn/go-frostdkg/pkg/transport/mcp"
)

// Configure session
config := &transport.SessionConfig{
    Threshold:       2,
    NumParticipants: 3,
    Ciphersuite:     "FROST-ED25519-SHA512-v1",
    Timeout:         5 * time.Minute,
}

// Create HTTP server
server, err := mcp.NewMCPServer(
    "my-session-id",
    config,
    mcp.TransportHTTP,
    "localhost:8080",
)
if err != nil {
    log.Fatal(err)
}

// Start server
ctx := context.Background()
if err := server.Start(ctx); err != nil {
    log.Fatal(err)
}
defer server.Stop(ctx)

// Wait for participants
if err := server.WaitForParticipants(ctx, 3); err != nil {
    log.Fatal(err)
}
```

### Creating an MCP Client (Participant)

```go
// Create HTTP client
client, err := mcp.NewMCPClient("participant-1", mcp.TransportHTTP)
if err != nil {
    log.Fatal(err)
}

// Connect to server
ctx := context.Background()
if err := client.Connect(ctx, "http://localhost:8080"); err != nil {
    log.Fatal(err)
}
defer client.Disconnect()

// Run DKG
params := &transport.DKGParams{
    HostSeckey:     mySecretKey,     // 32 bytes
    HostPubkeys:    allPublicKeys,   // [][]byte, each 33 bytes
    Threshold:      2,
    ParticipantIdx: 0,
    Random:         randomness,      // 32 bytes CSPRNG
}

result, err := client.RunDKG(ctx, params)
if err != nil {
    log.Fatal(err)
}

// Use the result
fmt.Printf("Secret Share: %x\n", result.SecretShare)
fmt.Printf("Threshold Pubkey: %x\n", result.ThresholdPubkey)
```

### Using MCP Tools Directly

For AI agents or custom integrations, you can call tools directly via JSON-RPC:

```bash
# Create a session
curl -X POST http://localhost:8080/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "dkg_create_session",
    "params": {
      "session_id": "my-session",
      "threshold": 2,
      "num_participants": 3,
      "ciphersuite": "FROST-ED25519-SHA512-v1"
    },
    "id": 1
  }'

# Join a session
curl -X POST http://localhost:8080/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "dkg_join_session",
    "params": {
      "session_id": "my-session",
      "host_pubkey": "02abc123..."
    },
    "id": 2
  }'

# Get session info
curl -X POST http://localhost:8080/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "dkg_get_session",
    "params": {
      "session_id": "my-session"
    },
    "id": 3
  }'
```

### Stdio Transport for CLI

```go
// Server with stdio
server, _ := mcp.NewMCPServer("session", config, mcp.TransportStdio, "")
server.SetStdio(os.Stdin, os.Stdout)
server.Start(context.Background())

// Client with stdio
client, _ := mcp.NewMCPClient("participant", mcp.TransportStdio)
client.SetStdio(os.Stdin, os.Stdout)
client.Connect(context.Background(), "session-id")
```

## Transport Types

### Stdio Transport
- Uses stdin/stdout for JSON-RPC communication
- Ideal for CLI tools and piped workflows
- One request/response per line
- No authentication/encryption (relies on OS security)

### HTTP Transport
- RESTful HTTP endpoint at `/jsonrpc`
- Tools list endpoint at `/tools`
- Supports concurrent connections
- Can be secured with TLS
- Suitable for web services and remote access

## Session State Management

The MCP server tracks session state through the DKG protocol:

1. **Created**: Session initialized, no participants yet
2. **WaitingParticipants**: Waiting for all participants to join
3. **Round1**: Collecting Round1 messages (VSS commitments, PoP)
4. **Round2**: Collecting Round2 messages (encrypted shares)
5. **CertEq**: Collecting CertEq signatures
6. **Completed**: DKG successfully completed
7. **Failed**: DKG failed (error occurred)

State transitions are automatic based on message submissions.

## Error Handling

All errors follow the JSON-RPC 2.0 error format:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32600,
    "message": "Invalid request"
  },
  "id": 1
}
```

Custom error codes:
- `1000`: Invalid parameters
- `1001`: Session not found
- `1002`: Session already exists
- `1003`: Session full
- `1004`: Invalid state for operation
- `1005`: Operation timeout
- `1006`: Internal server error

## Thread Safety

All components are thread-safe:
- Server uses `sync.RWMutex` for session management
- Client uses `sync.RWMutex` for connection state
- Atomic operations for connection status
- Safe concurrent tool calls

## Testing

Comprehensive test suite with 92.7% code coverage:

```bash
# Run all tests
go test ./pkg/transport/mcp/...

# Run with coverage
go test -cover ./pkg/transport/mcp/...

# Generate coverage report
go test -coverprofile=coverage.out ./pkg/transport/mcp/...
go tool cover -html=coverage.out
```

Test categories:
- Unit tests for all components
- Integration tests for client-server interaction
- Error handling tests
- Edge case validation
- Concurrent operation tests

## Performance Considerations

- **Async Operations**: Server uses goroutines for message processing
- **Buffered Channels**: Prevents blocking on message sends
- **Atomic Operations**: Lock-free state checks where possible
- **Efficient Serialization**: Uses encoding/json with minimal allocations
- **Connection Pooling**: HTTP client reuses connections

## Security Notes

1. **Authentication**: Not implemented - add authentication middleware for production
2. **Authorization**: No participant authorization - implement if needed
3. **TLS**: HTTP transport can use TLS (configure http.Server)
4. **Input Validation**: All inputs validated before processing
5. **DoS Protection**: No rate limiting - add middleware for production
6. **Secret Handling**: Secret shares are in memory - use secure memory if needed

## Integration with AI Models

The MCP transport is specifically designed for AI model integration:

1. **Tool Discovery**: AI can query `/tools` endpoint to discover capabilities
2. **Self-Describing**: Each tool has complete JSON Schema
3. **Stateful Sessions**: AI can track session state through tool responses
4. **Error Recovery**: Clear error messages help AI recover from failures
5. **Notifications**: Support for async updates (though not heavily used)

Example Claude integration:
```python
# Claude can call tools via MCP
result = await mcp_client.call_tool(
    "dkg_create_session",
    {
        "session_id": "ai-session-1",
        "threshold": 2,
        "num_participants": 3,
        "ciphersuite": "FROST-ED25519-SHA512-v1"
    }
)
```

## Limitations

1. **No Persistence**: Sessions are in-memory only (restart loses state)
2. **No Recovery**: Failed sessions cannot be resumed
3. **Single Coordinator**: No coordinator redundancy
4. **Synchronous Tools**: All tool calls are synchronous (no streaming)
5. **No Partial Results**: Must wait for full DKG completion

## Future Enhancements

Potential improvements:
- [ ] Session persistence (Redis, database)
- [ ] Session recovery mechanisms
- [ ] WebSocket support for real-time updates
- [ ] Coordinator clustering for HA
- [ ] Streaming tool responses
- [ ] Partial result retrieval
- [ ] Metrics and monitoring endpoints
- [ ] Rate limiting and quotas
- [ ] Authentication/authorization layer

## API Reference

See `tools.go` for complete tool definitions and schemas.

See `interfaces.go` in parent package for interface contracts.

## License

Apache 2.0 - See LICENSE.md file for details.
