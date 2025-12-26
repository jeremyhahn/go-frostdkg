# FROST DKG Integration Test Framework

A centralized, protocol-agnostic integration test framework for the go-frostdkg library.

## Overview

This framework provides a comprehensive testing infrastructure that ensures **protocol parity** across all transport implementations. All transports (gRPC, HTTP, QUIC, Unix sockets, in-memory) must pass identical test cases, proving they are functionally equivalent.

## Architecture

### Core Components

#### 1. Test Actions (`commands.go`)

Protocol-agnostic test actions that can be executed against any transport:

- `CreateSessionAction` - Creates a DKG session on the coordinator
- `JoinSessionAction` - Joins a participant to the session
- `RunDKGAction` - Executes the DKG protocol for a participant
- `WaitForParticipantsAction` - Waits for participants to connect
- `StopCoordinatorAction` - Stops the coordinator
- `DisconnectParticipantAction` - Disconnects a participant
- `VerifyResultAction` - Verifies DKG result correctness
- `CompareResultsAction` - Compares results across participants

All actions implement the `TestAction` interface:

```go
type TestAction interface {
    Execute(ctx context.Context) error
    Name() string
}
```

#### 2. Test Runner (`runner.go`)

Orchestrates test execution with timeout handling and error collection:

- `TestRunner` - Executes actions sequentially or in parallel
- `ConcurrentDKGRunner` - Runs DKG for multiple participants concurrently
- `ErrorCollector` - Collects and reports errors from concurrent operations

#### 3. Helper Functions (`helpers.go`, `helpers_transports.go`)

Utilities for test setup and teardown:

**General Helpers:**
- `GenerateSessionID()` - Creates unique session identifiers
- `GenerateHostKeys(n)` - Generates n host key pairs
- `GenerateDKGParams()` - Creates DKG parameters for testing
- `GenerateTestCertificates()` - Creates TLS certificates for testing
- `CleanupManager` - Manages cleanup of resources

**Transport-Specific Helpers:**
- `CreateMemoryCoordinator()` / `CreateMemoryParticipants()` - In-memory transport
- `CreateGRPCCoordinator()` / `CreateGRPCParticipants()` - gRPC with TLS 1.3
- `CreateHTTPCoordinator()` / `CreateHTTPParticipants()` - HTTP with TLS 1.3
- `CreateQUICCoordinator()` / `CreateQUICParticipants()` - QUIC with built-in TLS
- `CreateUnixCoordinator()` / `CreateUnixParticipants()` - Unix domain sockets

## Test Organization

### Protocol Parity Tests (`protocol_parity_test.go`)

Table-driven tests that verify all transports behave identically:

```go
func TestProtocolParity_2of3_Threshold(t *testing.T) {
    testCases := []struct {
        name    string
        factory TransportFactory
    }{
        {"Memory", createMemoryTransport},
        {"gRPC", createGRPCTransport},
        {"HTTP", createHTTPTransport},
        {"QUIC", createQUICTransport},
        {"Unix", createUnixTransport},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            runDKGTest(t, 2, 3, "FROST-SECP256K1-SHA256-v1", tc.factory)
        })
    }
}
```

### Transport-Specific Tests

Individual test files for each transport provide additional protocol-specific scenarios:

- `memory_test.go` - In-memory transport tests
- `grpc/grpc_test.go` - gRPC transport tests
- `http/http_test.go` - HTTP transport tests
- `quic/quic_test.go` - QUIC transport tests
- `unix/unix_test.go` - Unix socket transport tests

## Test Scenarios

All transports are tested with:

1. **2-of-3 Threshold DKG** - Basic threshold signing scenario
2. **3-of-5 Threshold DKG** - Larger participant set
3. **Error Cases**:
   - Invalid threshold (threshold = 0)
   - Threshold too high (threshold > n)
   - Connection timeout
   - Not enough participants

## Running Tests

### Run All Integration Tests

```bash
make integration-test
```

### Run Protocol Parity Tests

```bash
go test -tags=integration -v ./test/integration/api -run TestProtocolParity
```

### Run Transport-Specific Tests

```bash
# Memory transport
go test -tags=integration -v ./test/integration/api -run TestMemory

# gRPC transport
go test -tags=integration -v ./test/integration/api/grpc

# HTTP transport
go test -tags=integration -v ./test/integration/api/http

# QUIC transport
go test -tags=integration -v ./test/integration/api/quic

# Unix socket transport
go test -tags=integration -v ./test/integration/api/unix
```

### Run Specific Test Cases

```bash
# Test 2-of-3 threshold across all transports
go test -tags=integration -v ./test/integration/api -run TestProtocolParity_2of3

# Test error handling across all transports
go test -tags=integration -v ./test/integration/api -run TestProtocolParity_ErrorCases
```

## Usage Examples

### Basic Test Pattern

```go
func TestMyTransport(t *testing.T) {
    ctx := context.Background()
    cleanup := api.NewCleanupManager()
    defer cleanup.Cleanup()

    // Generate test data
    sessionID := api.GenerateSessionID()
    hostSeckeys, hostPubkeys, _ := api.GenerateHostKeys(3)

    // Create coordinator and participants
    coord, address, _ := api.CreateGRPCCoordinator(sessionID, 2, 3, "FROST-SECP256K1-SHA256-v1", certs)
    participants, _ := api.CreateGRPCParticipants(3, certs, "FROST-SECP256K1-SHA256-v1")

    // Register cleanup
    cleanup.AddCoordinator(coord)
    for _, p := range participants {
        cleanup.AddParticipant(p)
    }

    // Start coordinator
    coord.Start(ctx)

    // Connect participants
    for _, p := range participants {
        p.Connect(ctx, address)
    }

    // Run DKG
    params := make([]*transport.DKGParams, 3)
    for i := 0; i < 3; i++ {
        params[i], _ = api.GenerateDKGParams(i, 2, hostSeckeys, hostPubkeys)
    }

    dkgRunner := api.NewConcurrentDKGRunner(2 * time.Minute)
    results, _ := dkgRunner.RunParticipants(ctx, participants, params)

    // Verify results
    compareAction := &api.CompareResultsAction{Results: results}
    compareAction.Execute(ctx)
}
```

### Using Test Actions

```go
runner := api.NewTestRunner(5 * time.Minute)

// Add actions sequentially
runner.AddAction(&api.CreateSessionAction{...})
runner.AddAction(&api.JoinSessionAction{...})
runner.AddAction(&api.WaitForParticipantsAction{...})

// Execute all actions
err := runner.Run(ctx)
```

### Concurrent Execution

```go
// Run multiple actions in parallel
err := runner.RunParallel(ctx,
    &api.JoinSessionAction{Participant: p1, Address: addr},
    &api.JoinSessionAction{Participant: p2, Address: addr},
    &api.JoinSessionAction{Participant: p3, Address: addr},
)
```

## Design Principles

### 1. Protocol Agnostic

All test actions and utilities work identically across transports. The framework abstracts away protocol-specific details.

### 2. Protocol Parity

The key goal is ensuring all transports behave identically. Table-driven tests enforce this by running the same test logic against all implementations.

### 3. Resource Management

`CleanupManager` ensures proper cleanup of:
- Coordinator servers
- Participant connections
- Temporary TLS certificates
- Unix socket files

### 4. Error Handling

Comprehensive error checking with:
- Typed errors from `transport` package
- Error collection for concurrent operations
- Detailed error messages with context

### 5. Timeout Management

All operations use context-based timeouts to prevent hanging tests:
- Default 2-minute DKG timeout
- Configurable per-test timeouts
- Proper context cancellation

## Key Metrics

The framework verifies these DKG result properties:

- **Session ID** - Matches expected session
- **Secret Share** - 32 bytes, unique per participant
- **Threshold Pubkey** - 33 bytes, identical across participants
- **Public Shares** - One per participant, 33 bytes each
- **Recovery Data** - Non-empty, identical across participants

## Build Tags

All integration tests use the `integration` build tag:

```go
//go:build integration
```

This ensures integration tests only run when explicitly requested, not during normal unit test runs.

## Contributing

When adding a new transport:

1. Create helper functions in `helpers_transports.go`
2. Add factory function to `protocol_parity_test.go`
3. Create transport-specific test file in subdirectory
4. Verify all protocol parity tests pass

## Dependencies

- `pkg/transport` - Transport layer interfaces and implementations
- `pkg/schnorr` - Key generation for testing
- `pkg/dkg` - DKG protocol implementation (used by transports)

## Future Enhancements

- Benchmark tests for transport performance comparison
- Network fault injection for resilience testing
- Multi-machine distributed testing
- Load testing with many participants
- Protocol version compatibility testing
