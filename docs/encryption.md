# Encrypted DKG and HostKey

This document covers application-level encryption for FROST-DKG secret shares and the HostKey interface for hardware security module integration.

## DKG Modes

go-frostdkg supports two modes for protecting secret shares during distribution:

### Standard DKG

Uses transport-layer security (TLS, QUIC, mTLS) for confidentiality:

- Secret shares transmitted in plaintext at application layer
- Security relies on the transport protocol (TLS 1.3, QUIC)
- Simpler implementation, fewer cryptographic operations
- Suitable when transport security is trusted and properly configured

```go
// Standard DKG - shares protected by TLS transport
state, msg, shares, err := dkg.FROSTDKGParticipantRound1(cs, seed, t, n, index)
```

### Encrypted DKG

Adds application-level ECDH encryption of secret shares:

- Shares encrypted using ECDH key agreement before transmission
- Provides defense-in-depth (protection even if transport compromised)
- Required when using untrusted broadcast channels
- Uses participant host keys for encryption

```go
// Encrypted DKG - shares encrypted at application layer
state, msg, err := dkg.FROSTDKGEncParticipantRound1(
    cs, seed, hostSeckey, hostPubkeys, t, index, random,
)
```

### When to Use Each Mode

| Scenario | Recommended Mode |
|----------|-----------------|
| Private network with mTLS | Standard DKG |
| Internet with TLS 1.3 | Either (Encrypted for defense-in-depth) |
| Broadcast/multicast channel | Encrypted DKG |
| Untrusted coordinator | Encrypted DKG |
| HSM/TPM key storage | Encrypted DKG with HostKey |
| Maximum security | Encrypted DKG with HostKey |

## Encrypted DKG Protocol

The encrypted protocol adds ECDH-based encryption on top of standard FROST-DKG.

### Protocol Flow

```
Round 1:
  Participant i:
    1. Generate VSS polynomial and commitment
    2. Create proof of possession (POP)
    3. Generate ephemeral nonce for ECDH
    4. For each participant j:
       - Compute ECDH shared secret with j's public key
       - Derive encryption pad from shared secret
       - Encrypt share[j] using XOR with pad
    5. Send: commitment, POP, pubnonce, encrypted_shares[]

  Coordinator:
    1. Verify all POPs
    2. Validate commitment coefficient counts
    3. Collect and forward all pubnonces
    4. Route encrypted shares to recipients

Round 2:
  Participant i:
    1. Decrypt received shares using ECDH
    2. Verify shares against commitments
    3. Compute final secret share and threshold pubkey
    4. Sign equality input for CertEq consensus
```

### ECDH Key Agreement

The ECDH shared secret is computed as:

```
shared_point = my_scalar * their_pubkey
pad = H4("FROST-DKG/ecdh pad" || my_nonce || their_nonce || shared_point)
encrypted_share = share XOR pad[:share_len]
```

Nonce ordering ensures encryption/decryption symmetry:
- Encryption: `my_nonce || their_nonce`
- Decryption: `their_nonce || my_nonce`

### API Reference

#### Encrypted Round 1 (Participant)

```go
func FROSTDKGEncParticipantRound1(
    cs ciphersuite.Ciphersuite,  // FROST ciphersuite
    seed []byte,                  // Random seed for VSS polynomial
    hostSeckey []byte,            // Host secret key for ECDH
    hostPubkeys [][]byte,         // All participants' public keys
    t, index int,                 // Threshold and participant index
    random []byte,                // Additional randomness for nonce
) (*FROSTDKGEncParticipantState, *FROSTDKGEncParticipantMsg, error)
```

#### Encrypted Round 1 (Coordinator)

```go
func FROSTDKGEncCoordinatorRound1(
    cs ciphersuite.Ciphersuite,
    msgs []*FROSTDKGEncParticipantMsg,
    t int,
    hostPubkeys [][]byte,
) (*FROSTDKGEncCoordinatorMsg, *FROSTDKGOutput, []byte, [][]byte, error)
```

Returns: coordinator message, output, equality input, per-participant encrypted shares.

#### Encrypted Round 2 (Participant)

```go
func FROSTDKGEncParticipantRound2(
    cs ciphersuite.Ciphersuite,
    state *FROSTDKGEncParticipantState,
    coordMsg *FROSTDKGEncCoordinatorMsg,
    encryptedSharesForMe []byte,
) (*FROSTDKGOutput, []byte, error)
```

## HostKey Interface

The HostKey interface abstracts cryptographic operations to support both software keys and hardware-backed keys (TPM, HSM).

### Interface Definition

```go
type HostKey interface {
    // ECDH computes shared secret without exposing private key
    ECDH(theirPubkey []byte) (sharedSecret []byte, err error)

    // Sign creates a signature for CertEq protocol
    Sign(message []byte) (signature []byte, err error)

    // PublicKey returns the serialized public key
    PublicKey() []byte
}
```

### HostKeyGenerator Interface

```go
type HostKeyGenerator interface {
    // GenerateHostKey creates a new key pair
    GenerateHostKey() (HostKey, error)

    // LoadHostKey loads from serialized secret key
    LoadHostKey(secretKey []byte) (HostKey, error)
}
```

### SoftwareHostKey Implementation

The built-in software implementation holds keys in memory:

```go
// Create from existing secret key
hostKey, err := dkg.NewSoftwareHostKey(cs, secretKeyBytes)

// Generate new random key
hostKey, err := dkg.GenerateSoftwareHostKey(cs)

// Use with custom RNG (for hardware RNG)
hostKey, err := dkg.GenerateSoftwareHostKeyWithRNG(cs, tpmRNG)

// Access secret key (software only)
secretBytes := hostKey.(*dkg.SoftwareHostKey).SecretKey()
```

### Supported Key Formats by Ciphersuite

| Ciphersuite | Secret Key | Derivation |
|-------------|-----------|------------|
| P256 | 32 bytes (ECDSA D value) | Direct scalar |
| Ed25519 | 32 bytes (seed) | H3(seed) |
| Ristretto255 | 32 bytes (seed) | H3(seed) |
| Ed448 | 57 bytes (seed) | H3(seed) |
| Secp256k1 | 32 bytes (seed) | H3(seed) |

### Signature Schemes

HostKey signing uses:
- **P256**: ECDSA with SHA-256 (64-byte R||S signature)
- **Ed25519/Ristretto255/Ed448/Secp256k1**: Schnorr (R||s format)

## Implementing Custom HostKey

For hardware security modules (TPM, HSM, smart cards):

```go
type TPMHostKey struct {
    tpmHandle *tpm2.TPM
    keyHandle tpm2.KeyHandle
    publicKey []byte
}

func (k *TPMHostKey) ECDH(theirPubkey []byte) ([]byte, error) {
    // Use TPM2_ECDH_ZGen command
    return k.tpmHandle.ECDHZGen(k.keyHandle, theirPubkey)
}

func (k *TPMHostKey) Sign(message []byte) ([]byte, error) {
    // Use TPM2_Sign command
    return k.tpmHandle.Sign(k.keyHandle, message)
}

func (k *TPMHostKey) PublicKey() []byte {
    return k.publicKey
}
```

Key implementation requirements:
1. ECDH must return raw shared point (not hashed)
2. Sign must produce deterministic Schnorr signatures
3. PublicKey must match the format expected by the ciphersuite

## Full Protocol with HostKey

### Complete Example

```go
func runEncryptedDKGWithHostKey(cs ciphersuite.Ciphersuite, t, n int) error {
    // Generate host keys for all participants
    hostKeys := make([]dkg.HostKey, n)
    hostPubkeys := make([][]byte, n)
    for i := 0; i < n; i++ {
        key, _ := dkg.GenerateSoftwareHostKey(cs)
        hostKeys[i] = key
        hostPubkeys[i] = key.PublicKey()
    }

    // Step 1: Each participant generates round 1 message
    states1 := make([]*dkg.FROSTDKGFullParticipantStateHK1, n)
    msgs1 := make([]*dkg.FROSTDKGFullParticipantMsg1, n)
    for i := 0; i < n; i++ {
        random := make([]byte, 32)
        rand.Read(random)
        states1[i], msgs1[i], _ = dkg.FROSTDKGFullParticipantStep1WithHostKey(
            cs, hostKeys[i], hostPubkeys, t, i, random,
        )
    }

    // Coordinator processes round 1
    coordState, coordMsg1, _ := dkg.FROSTDKGFullCoordinatorStep1WithHostKey(
        cs, msgs1, t, hostPubkeys,
    )

    // Step 2: Participants process coordinator message
    states2 := make([]*dkg.FROSTDKGFullParticipantStateHK2, n)
    msgs2 := make([]*dkg.FROSTDKGFullParticipantMsg2, n)
    for i := 0; i < n; i++ {
        states2[i], msgs2[i], _ = dkg.FROSTDKGFullParticipantStep2WithHostKey(
            cs, states1[i], coordMsg1,
        )
    }

    // Coordinator finalizes and creates certificate
    coordMsg2, coordOutput, _ := dkg.FROSTDKGFullCoordinatorFinalizeWithHostKey(
        coordState, msgs2,
    )

    // Participants verify certificate and get output
    for i := 0; i < n; i++ {
        output, _ := dkg.FROSTDKGFullParticipantFinalizeWithHostKey(
            states2[i], coordMsg2, hostPubkeys,
        )
        // output.SecretShare, output.ThresholdPubkey, output.PublicShares
    }

    return nil
}
```

## CLI Usage

### Host Key Flag

The `--hostkey` flag provides the participant's host secret key:

```bash
# With explicit host key (32 bytes hex for most ciphersuites)
frostdkg participant --id 0 --hostkey abcd1234...5678 \
    --threshold 2 --output share.json

# Auto-generate if not provided (printed to stdout when verbose)
frostdkg participant --id 0 --threshold 2 --output share.json --verbose
```

### Host Public Keys Flag

The `--hostpubkeys` flag specifies all participants' public keys:

```bash
frostdkg participant --id 0 \
    --hostkey $MY_SECRET_KEY \
    --hostpubkeys "$PK0,$PK1,$PK2" \
    --threshold 2 --output share.json
```

### Configuration File

```yaml
participant:
  hostkey: ""           # Auto-generated if empty
  hostpubkeys: ""       # Comma-separated hex public keys
  threshold: 2
```

## Security Considerations

### Key Management

1. **Never reuse host keys** across different DKG sessions with different participant sets
2. **Protect host secret keys** with file permissions (0600) or hardware storage
3. **Verify host public keys** out-of-band before DKG session
4. **Zeroize sensitive data** after use:

```go
defer state.Zeroize()
defer output.ZeroizeWithGroup(cs.Group())
```

### ECDH Security

- Ephemeral nonces provide forward secrecy within a session
- Shared secrets are hashed with nonces before use as encryption keys
- XOR encryption is secure when pad is derived from cryptographic hash

### CertEq Binding

The encrypted DKG uses CertEq protocol with session context binding:

```
message = prefix || participant_index || threshold || n || hostpubkeys || transcript
```

This prevents:
- Cross-session replay attacks
- Signature forgery
- Participant impersonation

See [certeq.md](certeq.md) for CertEq protocol details.
