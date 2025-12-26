// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// HostKey represents a host identity key used for DKG operations.
// This interface abstracts the cryptographic operations to support both
// software keys and hardware-backed keys (TPM, HSM, etc.) where the
// private key material is not directly accessible.
//
// Implementations must provide:
//   - ECDH: Compute shared secrets for encrypting DKG shares
//   - Sign: Create signatures for CertEq protocol
//   - PublicKey: Return the serialized public key
type HostKey interface {
	// ECDH computes a Diffie-Hellman shared secret with the given public key.
	// For hardware-backed keys, this operation is performed inside the secure
	// element without exposing the private key.
	//
	// Parameters:
	//   - theirPubkey: The serialized public key of the other party
	//
	// Returns:
	//   - sharedSecret: The raw shared secret (x-coordinate or full point)
	//   - err: Any error that occurred during the operation
	ECDH(theirPubkey []byte) (sharedSecret []byte, err error)

	// Sign creates a signature on the given message.
	// For hardware-backed keys, this operation is performed inside the secure
	// element without exposing the private key.
	//
	// Parameters:
	//   - message: The message to sign
	//
	// Returns:
	//   - signature: The signature bytes
	//   - err: Any error that occurred during the operation
	Sign(message []byte) (signature []byte, err error)

	// PublicKey returns the serialized public key.
	PublicKey() []byte
}

// HostKeyGenerator generates host keys for a specific ciphersuite.
type HostKeyGenerator interface {
	// GenerateHostKey creates a new host key pair.
	// For software implementations, this generates random keys.
	// For hardware implementations, this may create keys in the secure element.
	GenerateHostKey() (HostKey, error)

	// LoadHostKey loads an existing host key from serialized secret key bytes.
	// This is only applicable for software keys where the secret is exportable.
	// Hardware implementations should return an error or load from a key handle.
	LoadHostKey(secretKey []byte) (HostKey, error)
}

// SoftwareHostKey is a software implementation of HostKey.
// The private key is held in memory and can be used for ECDH and signing.
type SoftwareHostKey struct {
	cs        ciphersuite.Ciphersuite
	secretKey []byte
	publicKey []byte
	scalar    group.Scalar // Derived scalar for ECDH
	rng       io.Reader    // Random number generator for signing
}

// NewSoftwareHostKey creates a new software host key from a secret key
// using the default crypto/rand RNG.
func NewSoftwareHostKey(cs ciphersuite.Ciphersuite, secretKey []byte) (*SoftwareHostKey, error) {
	return NewSoftwareHostKeyWithRNG(cs, secretKey, rand.Reader)
}

// NewSoftwareHostKeyWithRNG creates a new software host key from a secret key
// with a custom RNG for signing operations.
func NewSoftwareHostKeyWithRNG(cs ciphersuite.Ciphersuite, secretKey []byte, rng io.Reader) (*SoftwareHostKey, error) {
	if rng == nil {
		rng = rand.Reader
	}

	grp := cs.Group()

	// Validate key length and derive scalar based on ciphersuite
	var scalar group.Scalar
	var publicKey []byte

	switch cs.ID() {
	case CiphersuiteP256:
		if len(secretKey) != 32 {
			return nil, ErrInvalidSecretKey
		}
		// P256 uses the key directly as the scalar
		var err error
		scalar, err = grp.DeserializeScalar(secretKey)
		if err != nil {
			return nil, err
		}
		// Compute public key using group serialization for consistency
		pubPoint := grp.ScalarBaseMult(scalar)
		publicKey, err = grp.SerializeElement(pubPoint)
		if err != nil {
			return nil, err
		}

	case CiphersuiteEd25519, CiphersuiteRistretto255:
		if len(secretKey) != 32 {
			return nil, ErrInvalidSecretKey
		}
		// Derive scalar using H3
		scalar = cs.H3(secretKey)
		// Compute public key
		pubPoint := grp.ScalarBaseMult(scalar)
		var err error
		publicKey, err = grp.SerializeElement(pubPoint)
		if err != nil {
			return nil, err
		}

	case CiphersuiteEd448:
		if len(secretKey) != 57 {
			return nil, ErrInvalidSecretKey
		}
		// Derive scalar using H3
		scalar = cs.H3(secretKey)
		// Compute public key
		pubPoint := grp.ScalarBaseMult(scalar)
		var err error
		publicKey, err = grp.SerializeElement(pubPoint)
		if err != nil {
			return nil, err
		}

	case CiphersuiteSecp256k1:
		if len(secretKey) != 32 {
			return nil, ErrInvalidSecretKey
		}
		// Derive scalar using H3
		scalar = cs.H3(secretKey)
		// Compute public key
		pubPoint := grp.ScalarBaseMult(scalar)
		var err error
		publicKey, err = grp.SerializeElement(pubPoint)
		if err != nil {
			return nil, err
		}

	default:
		return nil, ErrUnknownCiphersuite
	}

	return &SoftwareHostKey{
		cs:        cs,
		secretKey: secretKey,
		publicKey: publicKey,
		scalar:    scalar,
		rng:       rng,
	}, nil
}

// GenerateSoftwareHostKey generates a new random software host key
// using the default crypto/rand RNG.
func GenerateSoftwareHostKey(cs ciphersuite.Ciphersuite) (*SoftwareHostKey, error) {
	return GenerateSoftwareHostKeyWithRNG(cs, rand.Reader)
}

// GenerateSoftwareHostKeyWithRNG generates a new random software host key
// using a custom RNG source. This enables hardware-backed RNG (TPM, HSM).
func GenerateSoftwareHostKeyWithRNG(cs ciphersuite.Ciphersuite, rng io.Reader) (*SoftwareHostKey, error) {
	if rng == nil {
		rng = rand.Reader
	}

	var keyLen int
	switch cs.ID() {
	case CiphersuiteP256, CiphersuiteEd25519,
		CiphersuiteRistretto255, CiphersuiteSecp256k1:
		keyLen = 32
	case CiphersuiteEd448:
		keyLen = 57
	default:
		return nil, ErrUnknownCiphersuite
	}

	secretKey := make([]byte, keyLen)
	if _, err := io.ReadFull(rng, secretKey); err != nil {
		return nil, err
	}

	return NewSoftwareHostKeyWithRNG(cs, secretKey, rng)
}

// ECDH computes a Diffie-Hellman shared secret.
func (k *SoftwareHostKey) ECDH(theirPubkey []byte) ([]byte, error) {
	grp := k.cs.Group()

	// Deserialize their public key
	theirPoint, err := grp.DeserializeElement(theirPubkey)
	if err != nil {
		return nil, ErrHostKeyECDHFailed
	}

	// Compute shared secret: myScalar * theirPoint
	sharedPoint := grp.ScalarMult(theirPoint, k.scalar)

	// Serialize the shared point
	sharedBytes, err := grp.SerializeElement(sharedPoint)
	if err != nil {
		return nil, ErrHostKeyECDHFailed
	}

	return sharedBytes, nil
}

// Sign creates a signature on the message.
func (k *SoftwareHostKey) Sign(message []byte) ([]byte, error) {
	grp := k.cs.Group()

	switch k.cs.ID() {
	case CiphersuiteP256:
		return k.signP256(message)

	default:
		// Schnorr signature for Ed25519, Ristretto255, Ed448, Secp256k1
		return k.signSchnorr(grp, message)
	}
}

// signP256 creates an ECDSA signature for P256.
func (k *SoftwareHostKey) signP256(message []byte) ([]byte, error) {
	curve := elliptic.P256()
	privKey := new(ecdsa.PrivateKey)
	privKey.Curve = curve
	privKey.D = new(big.Int).SetBytes(k.secretKey)
	privKey.X, privKey.Y = curve.ScalarBaseMult(k.secretKey)

	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(k.rng, privKey, hash[:])
	if err != nil {
		return nil, ErrHostKeySignFailed
	}

	// Encode as 64 bytes (32 bytes r + 32 bytes s)
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return sig, nil
}

// signSchnorr creates a Schnorr signature.
func (k *SoftwareHostKey) signSchnorr(grp group.Group, message []byte) ([]byte, error) {
	// Generate nonce: r = H3(secretKey || message)
	nonceInput := make([]byte, len(k.secretKey)+len(message))
	copy(nonceInput, k.secretKey)
	copy(nonceInput[len(k.secretKey):], message)
	r := k.cs.H3(nonceInput)

	// R = r * G
	R := grp.ScalarBaseMult(r)

	// Serialize R and A (public key)
	RBytes, err := grp.SerializeElement(R)
	if err != nil {
		return nil, ErrHostKeySignFailed
	}

	// c = H3(R || A || message)
	cInput := make([]byte, len(RBytes)+len(k.publicKey)+len(message))
	copy(cInput, RBytes)
	copy(cInput[len(RBytes):], k.publicKey)
	copy(cInput[len(RBytes)+len(k.publicKey):], message)
	c := k.cs.H3(cInput)

	// s = r + c * scalar
	s := c.Mul(k.scalar)
	s = r.Add(s)

	// Signature is R || s
	sBytes := grp.SerializeScalar(s)

	sig := make([]byte, len(RBytes)+len(sBytes))
	copy(sig[:len(RBytes)], RBytes)
	copy(sig[len(RBytes):], sBytes)

	return sig, nil
}

// PublicKey returns the serialized public key.
func (k *SoftwareHostKey) PublicKey() []byte {
	return k.publicKey
}

// SecretKey returns the secret key bytes.
// This is only available for software keys; hardware keys would not expose this.
func (k *SoftwareHostKey) SecretKey() []byte {
	return k.secretKey
}

// SoftwareHostKeyGenerator generates software host keys.
type SoftwareHostKeyGenerator struct {
	cs  ciphersuite.Ciphersuite
	rng io.Reader
}

// NewSoftwareHostKeyGenerator creates a new software host key generator
// using the default crypto/rand RNG.
func NewSoftwareHostKeyGenerator(cs ciphersuite.Ciphersuite) *SoftwareHostKeyGenerator {
	return NewSoftwareHostKeyGeneratorWithRNG(cs, rand.Reader)
}

// NewSoftwareHostKeyGeneratorWithRNG creates a new software host key generator
// with a custom RNG source. This enables hardware-backed RNG (TPM, HSM).
func NewSoftwareHostKeyGeneratorWithRNG(cs ciphersuite.Ciphersuite, rng io.Reader) *SoftwareHostKeyGenerator {
	if rng == nil {
		rng = rand.Reader
	}
	return &SoftwareHostKeyGenerator{cs: cs, rng: rng}
}

// GenerateHostKey creates a new random host key.
func (g *SoftwareHostKeyGenerator) GenerateHostKey() (HostKey, error) {
	return GenerateSoftwareHostKeyWithRNG(g.cs, g.rng)
}

// LoadHostKey loads a host key from secret key bytes.
func (g *SoftwareHostKeyGenerator) LoadHostKey(secretKey []byte) (HostKey, error) {
	return NewSoftwareHostKeyWithRNG(g.cs, secretKey, g.rng)
}

// GetHostKeyGenerator returns the appropriate HostKeyGenerator for a ciphersuite.
// By default, this returns a SoftwareHostKeyGenerator.
// Users can replace this with hardware-backed implementations.
func GetHostKeyGenerator(cs ciphersuite.Ciphersuite) (HostKeyGenerator, error) {
	switch cs.ID() {
	case CiphersuiteP256, CiphersuiteEd25519,
		CiphersuiteRistretto255, CiphersuiteEd448,
		CiphersuiteSecp256k1:
		return NewSoftwareHostKeyGenerator(cs), nil
	default:
		return nil, ErrUnknownCiphersuite
	}
}

// VerifyHostKeySignature verifies a signature created by a HostKey.
func VerifyHostKeySignature(cs ciphersuite.Ciphersuite, publicKey, message, signature []byte) error {
	grp := cs.Group()

	switch cs.ID() {
	case CiphersuiteP256:
		return verifyP256Signature(publicKey, message, signature)

	default:
		return verifySchnorrSignature(cs, grp, publicKey, message, signature)
	}
}

// verifyP256Signature verifies an ECDSA signature.
func verifyP256Signature(publicKey, message, signature []byte) error {
	if len(signature) != 64 {
		return ErrInvalidSignature
	}

	curve := elliptic.P256()
	var x, y *big.Int

	if len(publicKey) == 33 {
		x, y = decompressP256Point(publicKey)
		if x == nil {
			return ErrInvalidPublicKey
		}
	} else if len(publicKey) == 65 && publicKey[0] == 0x04 {
		x = new(big.Int).SetBytes(publicKey[1:33])
		y = new(big.Int).SetBytes(publicKey[33:65])
	} else {
		return ErrInvalidPublicKey
	}

	pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	hash := sha256.Sum256(message)

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return ErrVerificationFailed
	}

	return nil
}

// verifySchnorrSignature verifies a Schnorr signature.
func verifySchnorrSignature(cs ciphersuite.Ciphersuite, grp group.Group, publicKey, message, signature []byte) error {
	// Determine sizes based on ciphersuite
	var elemLen, scalarLen int
	switch cs.ID() {
	case CiphersuiteEd25519, CiphersuiteRistretto255:
		elemLen, scalarLen = 32, 32
	case CiphersuiteEd448:
		elemLen, scalarLen = 57, 57
	case CiphersuiteSecp256k1:
		elemLen, scalarLen = 33, 32
	default:
		return ErrUnknownCiphersuite
	}

	if len(signature) != elemLen+scalarLen {
		return ErrInvalidSignature
	}

	// Parse R
	R, err := grp.DeserializeElement(signature[:elemLen])
	if err != nil {
		return ErrInvalidSignature
	}

	// Parse s
	s, err := grp.DeserializeScalar(signature[elemLen:])
	if err != nil {
		return ErrInvalidSignature
	}

	// Parse A (public key)
	A, err := grp.DeserializeElement(publicKey)
	if err != nil {
		return ErrInvalidPublicKey
	}

	// c = H3(R || A || message)
	RBytes := signature[:elemLen]
	cInput := make([]byte, elemLen+len(publicKey)+len(message))
	copy(cInput, RBytes)
	copy(cInput[elemLen:], publicKey)
	copy(cInput[elemLen+len(publicKey):], message)
	c := cs.H3(cInput)

	// Verify: s * G == R + c * A
	// SECURITY: Use constant-time comparison to prevent timing side-channel attacks
	sG := grp.ScalarBaseMult(s)
	cA := grp.ScalarMult(A, c)
	RpluscA := R.Add(cA)

	if !constantTimeElementEqual(grp, sG, RpluscA) {
		return ErrVerificationFailed
	}

	return nil
}

// Helper to get ciphersuite from ID for verification
func getCiphersuiteByID(id string) ciphersuite.Ciphersuite {
	switch id {
	case CiphersuiteEd25519:
		return ed25519_sha512.New()
	case CiphersuiteRistretto255:
		return ristretto255_sha512.New()
	case CiphersuiteEd448:
		return ed448_shake256.New()
	case CiphersuiteSecp256k1:
		return secp256k1_sha256.New()
	default:
		return nil
	}
}
