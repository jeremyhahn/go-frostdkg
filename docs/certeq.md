# CertEq Protocol

Certificate Equality (CertEq) protocol implementation for FROST DKG.

## Overview

CertEq ensures all participants in a DKG session agree on the same output. Each participant signs the session transcript, and the coordinator assembles a certificate containing all signatures. Any participant can verify this certificate to confirm consensus.

## Protocol Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│Participant 0│    │ Coordinator │    │Participant 1│
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       │ Sign(transcript) │                  │
       │─────────────────>│                  │
       │                  │ Sign(transcript) │
       │                  │<─────────────────│
       │                  │                  │
       │    Assemble Certificate             │
       │                  │                  │
       │   Certificate    │   Certificate    │
       │<─────────────────│─────────────────>│
       │                  │                  │
       │ Verify(cert)     │     Verify(cert) │
       └──────────────────┴──────────────────┘
```

## API

### CertEqParticipantStep

```go
func CertEqParticipantStep(
    hostSeckey []byte,
    participantIndex int,
    transcript []byte,
    signer Signer,
) ([]byte, error)
```

Creates a participant's signature over the transcript.

**Parameters:**
- `hostSeckey`: 32-byte host secret key
- `participantIndex`: Participant's index (0-based)
- `transcript`: Session transcript to sign
- `signer`: Ciphersuite-specific signer

**Returns:** 64-byte signature

### CertEqCoordinatorStep

```go
func CertEqCoordinatorStep(signatures [][]byte) []byte
```

Assembles participant signatures into a certificate.

**Parameters:**
- `signatures`: Ordered slice of participant signatures

**Returns:** Concatenated certificate (n × 64 bytes)

### CertEqVerify

```go
func CertEqVerify(
    hostPubkeys [][]byte,
    transcript []byte,
    certificate []byte,
    signer Signer,
) error
```

Verifies a CertEq certificate.

**Parameters:**
- `hostPubkeys`: Ordered participant public keys
- `transcript`: Original transcript
- `certificate`: Certificate to verify
- `signer`: Ciphersuite-specific signer

**Returns:** `nil` if valid, error with details otherwise

## Message Format

```
message = prefix || participant_index || transcript

prefix            = domain tag (33 bytes)
participant_index = big-endian uint32 (4 bytes)
transcript        = session transcript (variable)
```

## Certificate Format

```
certificate = sig_0 || sig_1 || ... || sig_{n-1}

Each signature is 64 bytes
Total length = n × 64 bytes
```

## Supported Signers

| Signer | Curve | Signature Size |
|--------|-------|----------------|
| Ed25519Signer | Ed25519 | 64 bytes |
| P256Signer | P-256 | 64 bytes |
| Ristretto255Signer | ristretto255 | 64 bytes |
| Ed448Signer | Ed448 | 114 bytes |

## Example

```go
package main

import "github.com/jeremyhahn/go-frostdkg/pkg/dkg"

func main() {
    n := 3
    transcript := []byte("session-transcript-data")
    signer := dkg.NewEd25519Signer()

    // Each participant signs
    signatures := make([][]byte, n)
    for i := 0; i < n; i++ {
        sig, err := dkg.CertEqParticipantStep(
            hostSeckeys[i], i, transcript, signer,
        )
        if err != nil {
            panic(err)
        }
        signatures[i] = sig
    }

    // Coordinator assembles certificate
    cert := dkg.CertEqCoordinatorStep(signatures)

    // Anyone can verify
    if err := dkg.CertEqVerify(hostPubkeys, transcript, cert, signer); err != nil {
        panic("certificate invalid")
    }
}
```

## Error Types

| Error | Description |
|-------|-------------|
| `ErrNilSigner` | Signer is nil |
| `ErrInvalidSecretKeyLength` | Secret key wrong length |
| `ErrInvalidCertificateLength` | Certificate length mismatch |
| `InvalidSignatureError` | Signature verification failed (includes participant index) |

## Security

- **Domain Separation**: Each message includes a unique prefix preventing signature reuse
- **Participant Binding**: Signatures are bound to specific participant indices
- **Transcript Binding**: Any change to the transcript invalidates all signatures
