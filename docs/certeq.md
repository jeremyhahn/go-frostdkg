# CertEq Protocol

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of the CertEq step in `pkg/dkg`.

Certificate Equality (CertEq) protocol implementation for FROST DKG.

## Overview

CertEq ensures all participants in a DKG session agree on the same output. Each participant signs the session transcript, and the coordinator assembles a certificate containing all signatures. Any participant can verify this certificate to confirm consensus.

## Protocol Flow

```
   Participant 0            Coordinator            Participant 1
         │                       │                       │
         │── Sign(transcript) ──►│                       │
         │                       │◄── Sign(transcript) ──│
         │                       │                       │
         │              [Assemble Certificate]           │
         │                       │                       │
         │◄──── Certificate ─────│────── Certificate ───►│
         │                       │                       │
         │    Verify(cert)       │        Verify(cert)   │
         │                       │                       │
```

## API

### CertEqParticipantStep

```go
func CertEqParticipantStep(
    signer Signer,
    hostSeckey []byte,
    participantIndex int,
    hostPubkeys [][]byte,
    threshold int,
    transcript []byte,
    auxRand []byte,
) ([]byte, error)
```

Creates a participant's signature over the transcript.

**Parameters:**
- `signer`: Ciphersuite-specific signer
- `hostSeckey`: Host secret key (`signer.SecretKeySize()` bytes)
- `participantIndex`: Participant's index (0-based)
- `hostPubkeys`: Ordered participant public keys (bound into the message)
- `threshold`: Session threshold (bound into the message)
- `transcript`: Session transcript to sign
- `auxRand`: Auxiliary randomness for signing (may be nil)

**Returns:** Signature (`signer.SignatureSize()` bytes)

### CertEqCoordinatorStep

```go
func CertEqCoordinatorStep(signatures [][]byte) []byte
```

Assembles participant signatures into a certificate.

**Parameters:**
- `signatures`: Ordered slice of participant signatures

**Returns:** Concatenated certificate (n × signature size bytes)

### CertEqVerify

```go
func CertEqVerify(
    signer Signer,
    hostPubkeys [][]byte,
    threshold int,
    transcript []byte,
    certificate []byte,
) error
```

Verifies a CertEq certificate.

**Parameters:**
- `signer`: Ciphersuite-specific signer
- `hostPubkeys`: Ordered participant public keys
- `threshold`: Session threshold
- `transcript`: Original transcript
- `certificate`: Certificate to verify

**Returns:** `nil` if valid, error with details otherwise

## Message Format

```
message = prefix || participant_index || threshold || n || hostPubkeys || transcript

prefix            = domain tag (33 bytes)
participant_index = big-endian uint32 (4 bytes)
threshold         = big-endian uint32 (4 bytes)
n                 = big-endian uint32 (4 bytes), number of host public keys
hostPubkeys       = concatenated host public keys (variable)
transcript        = session transcript (variable)
```

## Certificate Format

```
certificate = sig_0 || sig_1 || ... || sig_{n-1}

Each signature is signer.SignatureSize() bytes
Total length = n × signer.SignatureSize() bytes
```

## Supported Signers

| Signer | Curve | Signature Size |
|--------|-------|----------------|
| Ed25519Signer | Ed25519 | 64 bytes |
| P256Signer | P-256 | 64 bytes |
| Ristretto255Signer | ristretto255 | 64 bytes |
| Ed448Signer | Ed448 | 114 bytes |
| Secp256k1Signer | secp256k1 | 65 bytes |

## Example

```go
package main

import "github.com/jeremyhahn/go-frostdkg/pkg/dkg"

func main() {
    n := 3
    threshold := 2
    transcript := []byte("session-transcript-data")
    signer := &dkg.Ed25519Signer{}

    // Each participant signs
    signatures := make([][]byte, n)
    for i := 0; i < n; i++ {
        sig, err := dkg.CertEqParticipantStep(
            signer, hostSeckeys[i], i, hostPubkeys, threshold, transcript, nil,
        )
        if err != nil {
            panic(err)
        }
        signatures[i] = sig
    }

    // Coordinator assembles certificate
    cert := dkg.CertEqCoordinatorStep(signatures)

    // Anyone can verify
    if err := dkg.CertEqVerify(signer, hostPubkeys, threshold, transcript, cert); err != nil {
        panic("certificate invalid")
    }
}
```

## Error Types

| Error | Description |
|-------|-------------|
| `ErrSignerRequired` | Signer is nil |
| `ErrInvalidSecretKey` | Secret key wrong length |
| `ErrInvalidCertificateLength` | Certificate length mismatch (returned as `*CertificateLengthError`, which matches it via `errors.Is`) |
| `InvalidSignatureError` | Signature verification failed (includes participant index) |

## Security

- **Domain Separation**: Each message includes a unique prefix preventing signature reuse
- **Participant Binding**: Signatures are bound to specific participant indices, the threshold, and the host public keys
- **Transcript Binding**: Any change to the transcript invalidates all signatures
