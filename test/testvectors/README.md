# Test Vectors Package

This package provides RFC 9591 FROST DKG test vectors for all supported ciphersuites.

## Quick Start

```go
import "github.com/jeremyhahn/go-frostdkg/test/testvectors"

// Load test vectors
vectors, err := testvectors.GetEd25519Vectors()
if err != nil {
    log.Fatal(err)
}

// Access configuration
fmt.Println(vectors.Config.Name) // "FROST(Ed25519, SHA-512)"

// Access participant data
participant := vectors.Inputs.Participants["1"]
fmt.Println(participant.Identifier) // 1
```

## Available Loaders

- `GetEd25519Vectors()` - FROST(Ed25519, SHA-512)
- `GetEd448Vectors()` - FROST(Ed448, SHAKE256)
- `GetP256Vectors()` - FROST(P-256, SHA-256)
- `GetRistretto255Vectors()` - FROST(ristretto255, SHA-512)
- `GetSecp256k1Vectors()` - FROST(secp256k1, SHA-256)

## Test Coverage

Current test coverage: 83.3%

Run tests:
```bash
go test ./test/testvectors/...
```

View coverage:
```bash
go test -coverprofile=coverage.out ./test/testvectors
go tool cover -html=coverage.out
```
