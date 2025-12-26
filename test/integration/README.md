# Integration Tests

This directory contains comprehensive end-to-end integration tests for go-frostdkg.

## Overview

Integration tests run in Docker containers and perform complete E2E testing with real services, never modifying the host OS. These tests validate:

1. **FROST-DKG Protocol**: Full distributed key generation with all 5 compatible ciphersuites
   - FROST-ED25519-SHA512-v1
   - FROST-SECP256K1-SHA256-v1
   - FROST-P256-SHA256-v1
   - FROST-ED25519-SHA512-v1
   - FROST-RISTRETTO255-SHA512-v1
   - FROST-ED448-SHAKE256-v1

2. **FROST DKG Protocol**: Complete DKG protocol with additional ciphersuites
   - FROST-DKG-ED25519-SHA512
   - FROST-DKG-SECP256K1-SHA256

3. **Protocol Variants**:
   - SimplPedPoP (Simplified Pedersen PoP)
   - EncPedPoP (Encrypted Pedersen PoP)
   - Full protocol simulations with multiple participants

4. **Test Coverage**:
   - Multiple participant configurations (3, 5, 7, 10+ participants)
   - Various threshold settings
   - Edge cases (minimum/maximum thresholds, minimum participants)
   - Scaling tests

## Running Integration Tests

### Using Make (Recommended)

Run integration tests in Docker:
```bash
make integration-test
```

This will:
1. Build a Docker image with the test environment
2. Run all integration tests in isolation
3. Display test results

### Using Docker Compose

Alternatively, use docker-compose directly:
```bash
cd test/integration
docker-compose up --build --abort-on-container-exit
```

### Running Locally (Not Recommended)

If you must run locally without Docker:
```bash
go test -v -race -timeout 300s -tags=integration ./test/integration/...
```

**Warning**: Integration tests are designed to run in Docker containers. Running locally may have unexpected side effects.

## Test Structure

### TestFROSTDKGIntegration
Tests the full FROST-DKG protocol with all supported ciphersuites. Each test:
- Generates VSS polynomials for each participant
- Creates and verifies proofs of possession
- Distributes and verifies secret shares
- Aggregates shares to compute signing shares
- Validates the group verification key

### TestFROSTDKGProtocol
Tests the complete FROST DKG protocol including:
- Host key generation
- Session parameter setup
- Round 1: Participant messages
- Coordinator aggregation
- Round 2: Certificate generation
- Finalization and output validation
- Recovery data verification

### TestSimplPedPoP
Tests the SimplPedPoP variant which is suitable for environments where:
- Secure channels exist between participants
- Broadcast channel is available
- No encryption is needed for share distribution

### TestMultiParticipantScaling
Validates protocol performance with varying participant counts:
- 3, 5, 7, 10 participants
- 2/3 threshold configurations
- Ensures protocol scales linearly

### TestProtocolRobustness
Tests edge cases:
- Minimum participants (2 of 2)
- Maximal threshold (t = n)
- Minimal threshold (2 of 10)

### TestVSSBasicOperations
Validates basic VSS operations across all ciphersuites:
- VSS generation from seed
- Share generation
- Share verification

## Docker Environment

### Base Image
- golang:1.25-alpine

### Dependencies
- git
- make
- gcc (for CGO)
- musl-dev
- bash

### Environment Variables
- `CGO_ENABLED=1`: Required for some cryptographic operations
- `GOOS=linux`
- `GOARCH=amd64`
- `GO_TEST_TIMEOUT=300s`: 5-minute timeout for complete test suite

### Volumes
- `go-mod-cache`: Caches Go module downloads
- `go-build-cache`: Caches build artifacts
- Source code mounted at `/app`

## CI/CD Integration

### Quick CI (Unit Tests Only)
```bash
make ci
```

### Full CI (With Integration Tests)
```bash
make ci-full
```

This runs:
1. Dependency tidying
2. Code formatting
3. Linting
4. Unit tests
5. Integration tests in Docker
6. Build verification

## Test Coverage

Generate coverage report for integration tests:
```bash
make coverage-integration
```

This creates:
- `coverage/integration.out`: Raw coverage data
- `coverage/integration.html`: HTML coverage report
- Console output with function-level coverage

## Troubleshooting

### Docker Build Fails
```bash
# Clean docker cache and rebuild
docker system prune -a
make integration-test
```

### Tests Timeout
Increase timeout in `docker-compose.yml`:
```yaml
environment:
  - GO_TEST_TIMEOUT=600s  # 10 minutes
```

### Out of Memory
Reduce parallel test execution or increase Docker memory allocation.

### Port Conflicts
Integration tests don't expose ports, but ensure Docker has sufficient resources.

## Best Practices

1. **Always run in Docker**: Integration tests are designed for isolated environments
2. **Use make targets**: Simplifies the test execution process
3. **Check coverage**: Ensure new features have integration test coverage
4. **Monitor performance**: Watch for tests that take unusually long
5. **Clean up**: Use `make clean` to remove test artifacts

## Contributing

When adding new integration tests:
1. Follow the existing test structure
2. Use meaningful test names
3. Test both success and failure paths
4. Validate all protocol outputs
5. Add documentation for complex scenarios
6. Ensure tests are deterministic (no flaky tests)
7. Keep tests focused and fast (< 30s per test)

## References

- [FROST DKG Documentation](../../docs/)
- [FROST RFC 9591](https://datatracker.ietf.org/doc/rfc9591/)
- [BIP-340 Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
