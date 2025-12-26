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
	"math/big"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
)

// Signer provides signing and verification operations for a specific curve.
// This interface abstracts the underlying signature scheme, allowing
// different curves to use their native signature algorithms.
type Signer interface {
	// Sign creates a signature on the message using the secret key.
	// The auxRand parameter provides optional auxiliary randomness (can be nil).
	Sign(secretKey []byte, message []byte, auxRand []byte) ([]byte, error)

	// Verify verifies a signature on a message against a public key.
	Verify(publicKey []byte, message []byte, signature []byte) error

	// SecretKeySize returns the expected size of a secret key in bytes.
	SecretKeySize() int

	// PublicKeySize returns the expected size of a public key in bytes.
	PublicKeySize() int

	// SignatureSize returns the size of a signature in bytes.
	SignatureSize() int

	// GenerateKey generates a new key pair.
	GenerateKey() (secretKey []byte, publicKey []byte, err error)
}

// Ciphersuite ID constants
const (
	idP256         = "FROST-P256-SHA256-v1"
	idEd25519      = "FROST-ED25519-SHA512-v1"
	idRistretto255 = "FROST-RISTRETTO255-SHA512-v1"
	idEd448        = "FROST-ED448-SHAKE256-v1"
	idSecp256k1    = "FROST-secp256k1-SHA256-v1"
)

// GetSigner returns the appropriate Signer implementation for a ciphersuite.
func GetSigner(cs ciphersuite.Ciphersuite) (Signer, error) {
	return GetSignerByID(cs.ID())
}

// GetSignerByID returns the appropriate Signer implementation for a ciphersuite ID.
func GetSignerByID(id string) (Signer, error) {
	switch id {
	case idP256:
		return &P256Signer{}, nil
	case idEd25519:
		return &Ed25519Signer{}, nil
	case idRistretto255:
		return &Ristretto255Signer{}, nil
	case idEd448:
		return &Ed448Signer{}, nil
	case idSecp256k1:
		return &Secp256k1Signer{}, nil
	default:
		return nil, ErrUnknownCiphersuite
	}
}

// P256Signer implements Signer using ECDSA on P-256.
type P256Signer struct{}

func (s *P256Signer) Sign(secretKey []byte, message []byte, auxRand []byte) ([]byte, error) {
	if len(secretKey) != 32 {
		return nil, ErrSigningFailed
	}

	// Create ECDSA private key
	curve := elliptic.P256()
	privKey := new(ecdsa.PrivateKey)
	privKey.Curve = curve
	privKey.D = new(big.Int).SetBytes(secretKey)
	privKey.X, privKey.Y = curve.ScalarBaseMult(secretKey)

	// Hash the message
	hash := sha256.Sum256(message)

	// Sign
	r, sigS, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, ErrSigningFailed
	}

	// Encode as 64 bytes (32 bytes r + 32 bytes s)
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := sigS.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return sig, nil
}

func (s *P256Signer) Verify(publicKey []byte, message []byte, signature []byte) error {
	if len(signature) != 64 {
		return ErrInvalidSignature
	}

	// Parse public key
	curve := elliptic.P256()
	var x, y *big.Int

	if len(publicKey) == 33 {
		// Compressed format
		x, y = decompressP256Point(publicKey)
		if x == nil {
			return ErrInvalidPublicKey
		}
	} else if len(publicKey) == 65 {
		// Uncompressed format (0x04 || x || y)
		if publicKey[0] != 0x04 {
			return ErrInvalidPublicKey
		}
		x = new(big.Int).SetBytes(publicKey[1:33])
		y = new(big.Int).SetBytes(publicKey[33:65])
	} else {
		return ErrInvalidPublicKey
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Hash the message
	hash := sha256.Sum256(message)

	// Parse signature
	r := new(big.Int).SetBytes(signature[:32])
	sigS := new(big.Int).SetBytes(signature[32:])

	// Verify
	if !ecdsa.Verify(pubKey, hash[:], r, sigS) {
		return ErrVerificationFailed
	}

	return nil
}

func (s *P256Signer) SecretKeySize() int { return 32 }
func (s *P256Signer) PublicKeySize() int { return 33 }
func (s *P256Signer) SignatureSize() int { return 64 }
func (s *P256Signer) GenerateKey() ([]byte, []byte, error) {
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Secret key is D as 32 bytes
	secretKey := make([]byte, 32)
	dBytes := privKey.D.Bytes()
	copy(secretKey[32-len(dBytes):], dBytes)

	// Public key in compressed format
	publicKey := compressP256Point(privKey.X, privKey.Y)

	return secretKey, publicKey, nil
}

// Ed25519Signer implements Signer using Schnorr signatures on Ed25519.
// Note: This uses a simplified Schnorr construction compatible with the FROST
// Ed25519 ciphersuite, not the standard Ed25519 (EdDSA) signature scheme.
type Ed25519Signer struct{}

func (s *Ed25519Signer) Sign(secretKey []byte, message []byte, auxRand []byte) ([]byte, error) {
	if len(secretKey) != 32 {
		return nil, ErrSigningFailed
	}

	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Derive private scalar using H3 (same as GenerateKey)
	scalar := cs.H3(secretKey)

	// Compute public key A = scalar * G
	pubPoint := grp.ScalarBaseMult(scalar)

	// Generate nonce: r = H3(secretKey || message)
	nonceInput := make([]byte, len(secretKey)+len(message))
	copy(nonceInput, secretKey)
	copy(nonceInput[len(secretKey):], message)
	r := cs.H3(nonceInput)

	// R = r * G
	R := grp.ScalarBaseMult(r)

	// Serialize R and A
	RBytes, err := grp.SerializeElement(R)
	if err != nil {
		return nil, ErrSigningFailed
	}
	ABytes, err := grp.SerializeElement(pubPoint)
	if err != nil {
		return nil, ErrSigningFailed
	}

	// c = H3(R || A || message)
	cInput := make([]byte, len(RBytes)+len(ABytes)+len(message))
	copy(cInput, RBytes)
	copy(cInput[len(RBytes):], ABytes)
	copy(cInput[len(RBytes)+len(ABytes):], message)
	c := cs.H3(cInput)

	// s = r + c * scalar
	sigS := c.Mul(scalar)
	sigS = r.Add(sigS)

	// Signature is R || s
	sBytes := grp.SerializeScalar(sigS)

	sig := make([]byte, 64)
	copy(sig[:32], RBytes)
	copy(sig[32:], sBytes)

	return sig, nil
}

func (s *Ed25519Signer) Verify(publicKey []byte, message []byte, signature []byte) error {
	if len(signature) != 64 || len(publicKey) != 32 {
		return ErrInvalidSignature
	}

	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Parse R
	R, err := grp.DeserializeElement(signature[:32])
	if err != nil {
		return ErrInvalidSignature
	}

	// Parse s
	sigS, err := grp.DeserializeScalar(signature[32:])
	if err != nil {
		return ErrInvalidSignature
	}

	// Parse A (public key)
	A, err := grp.DeserializeElement(publicKey)
	if err != nil {
		return ErrInvalidPublicKey
	}

	// c = H3(R || A || message)
	cInput := make([]byte, 32+32+len(message))
	copy(cInput, signature[:32])
	copy(cInput[32:], publicKey)
	copy(cInput[64:], message)
	c := cs.H3(cInput)

	// Verify: s * G == R + c * A
	// SECURITY: Use constant-time comparison to prevent timing side-channel attacks
	sG := grp.ScalarBaseMult(sigS)
	cA := grp.ScalarMult(A, c)
	RpluscA := R.Add(cA)

	if !constantTimeElementEqual(grp, sG, RpluscA) {
		return ErrVerificationFailed
	}

	return nil
}

func (s *Ed25519Signer) SecretKeySize() int { return 32 }
func (s *Ed25519Signer) PublicKeySize() int { return 32 }
func (s *Ed25519Signer) SignatureSize() int { return 64 }
func (s *Ed25519Signer) GenerateKey() ([]byte, []byte, error) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Generate random seed (this is the secret key)
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}

	// Use H3 to derive a valid scalar from the seed
	scalar := cs.H3(seed)

	// Compute public key
	pubPoint := grp.ScalarBaseMult(scalar)
	pubKey, err := grp.SerializeElement(pubPoint)
	if err != nil {
		return nil, nil, err
	}

	return seed, pubKey, nil
}

// Ristretto255Signer implements Signer using Schnorr signatures on ristretto255.
type Ristretto255Signer struct{}

func (s *Ristretto255Signer) Sign(secretKey []byte, message []byte, auxRand []byte) ([]byte, error) {
	if len(secretKey) != 32 {
		return nil, ErrSigningFailed
	}

	cs := ristretto255_sha512.New()
	grp := cs.Group()

	// Use H3 to derive scalar from secret key
	scalar := cs.H3(secretKey)

	// Compute public key A = scalar * G
	pubPoint := grp.ScalarBaseMult(scalar)

	// Generate nonce: r = H3(secretKey || message)
	nonceInput := make([]byte, len(secretKey)+len(message))
	copy(nonceInput, secretKey)
	copy(nonceInput[len(secretKey):], message)
	r := cs.H3(nonceInput)

	// R = r * G
	R := grp.ScalarBaseMult(r)

	// Serialize R and A
	RBytes, err := grp.SerializeElement(R)
	if err != nil {
		return nil, ErrSigningFailed
	}
	ABytes, err := grp.SerializeElement(pubPoint)
	if err != nil {
		return nil, ErrSigningFailed
	}

	// c = H3(R || A || message)
	cInput := make([]byte, len(RBytes)+len(ABytes)+len(message))
	copy(cInput, RBytes)
	copy(cInput[len(RBytes):], ABytes)
	copy(cInput[len(RBytes)+len(ABytes):], message)
	c := cs.H3(cInput)

	// s = r + c * scalar
	sigS := c.Mul(scalar)
	sigS = r.Add(sigS)

	// Signature is R || s
	sBytes := grp.SerializeScalar(sigS)

	sig := make([]byte, 64)
	copy(sig[:32], RBytes)
	copy(sig[32:], sBytes)

	return sig, nil
}

func (s *Ristretto255Signer) Verify(publicKey []byte, message []byte, signature []byte) error {
	if len(signature) != 64 || len(publicKey) != 32 {
		return ErrInvalidSignature
	}

	cs := ristretto255_sha512.New()
	grp := cs.Group()

	// Parse R
	R, err := grp.DeserializeElement(signature[:32])
	if err != nil {
		return ErrInvalidSignature
	}

	// Parse s
	sigS, err := grp.DeserializeScalar(signature[32:])
	if err != nil {
		return ErrInvalidSignature
	}

	// Parse A (public key)
	A, err := grp.DeserializeElement(publicKey)
	if err != nil {
		return ErrInvalidPublicKey
	}

	// c = H3(R || A || message)
	cInput := make([]byte, 32+32+len(message))
	copy(cInput, signature[:32])
	copy(cInput[32:], publicKey)
	copy(cInput[64:], message)
	c := cs.H3(cInput)

	// Verify: s * G == R + c * A
	// SECURITY: Use constant-time comparison to prevent timing side-channel attacks
	sG := grp.ScalarBaseMult(sigS)
	cA := grp.ScalarMult(A, c)
	RpluscA := R.Add(cA)

	if !constantTimeElementEqual(grp, sG, RpluscA) {
		return ErrVerificationFailed
	}

	return nil
}

func (s *Ristretto255Signer) SecretKeySize() int { return 32 }
func (s *Ristretto255Signer) PublicKeySize() int { return 32 }
func (s *Ristretto255Signer) SignatureSize() int { return 64 }
func (s *Ristretto255Signer) GenerateKey() ([]byte, []byte, error) {
	cs := ristretto255_sha512.New()
	grp := cs.Group()

	// Generate random secret key
	secretKey := make([]byte, 32)
	if _, err := rand.Read(secretKey); err != nil {
		return nil, nil, err
	}

	// Derive scalar and compute public key
	scalar := cs.H3(secretKey)
	pubPoint := grp.ScalarBaseMult(scalar)
	pubKey, err := grp.SerializeElement(pubPoint)
	if err != nil {
		return nil, nil, err
	}

	return secretKey, pubKey, nil
}

// Ed448Signer implements Signer using Ed448 signatures.
type Ed448Signer struct{}

func (s *Ed448Signer) Sign(secretKey []byte, message []byte, auxRand []byte) ([]byte, error) {
	if len(secretKey) != 57 {
		return nil, ErrSigningFailed
	}

	cs := ed448_shake256.New()
	grp := cs.Group()

	// Use H3 to derive scalar from secret key
	scalar := cs.H3(secretKey)

	// Compute public key A = scalar * G
	pubPoint := grp.ScalarBaseMult(scalar)

	// Generate nonce: r = H3(secretKey || message)
	nonceInput := make([]byte, len(secretKey)+len(message))
	copy(nonceInput, secretKey)
	copy(nonceInput[len(secretKey):], message)
	r := cs.H3(nonceInput)

	// R = r * G
	R := grp.ScalarBaseMult(r)

	// Serialize R and A
	RBytes, err := grp.SerializeElement(R)
	if err != nil {
		return nil, ErrSigningFailed
	}
	ABytes, err := grp.SerializeElement(pubPoint)
	if err != nil {
		return nil, ErrSigningFailed
	}

	// c = H3(R || A || message)
	cInput := make([]byte, len(RBytes)+len(ABytes)+len(message))
	copy(cInput, RBytes)
	copy(cInput[len(RBytes):], ABytes)
	copy(cInput[len(RBytes)+len(ABytes):], message)
	c := cs.H3(cInput)

	// s = r + c * scalar
	sigS := c.Mul(scalar)
	sigS = r.Add(sigS)

	// Signature is R || s
	sBytes := grp.SerializeScalar(sigS)

	sig := make([]byte, 114) // 57 bytes for R + 57 bytes for s
	copy(sig[:57], RBytes)
	copy(sig[57:], sBytes)

	return sig, nil
}

func (s *Ed448Signer) Verify(publicKey []byte, message []byte, signature []byte) error {
	if len(signature) != 114 || len(publicKey) != 57 {
		return ErrInvalidSignature
	}

	cs := ed448_shake256.New()
	grp := cs.Group()

	// Parse R
	R, err := grp.DeserializeElement(signature[:57])
	if err != nil {
		return ErrInvalidSignature
	}

	// Parse s
	sigS, err := grp.DeserializeScalar(signature[57:])
	if err != nil {
		return ErrInvalidSignature
	}

	// Parse A (public key)
	A, err := grp.DeserializeElement(publicKey)
	if err != nil {
		return ErrInvalidPublicKey
	}

	// c = H3(R || A || message)
	cInput := make([]byte, 57+57+len(message))
	copy(cInput, signature[:57])
	copy(cInput[57:], publicKey)
	copy(cInput[114:], message)
	c := cs.H3(cInput)

	// Verify: s * G == R + c * A
	// SECURITY: Use constant-time comparison to prevent timing side-channel attacks
	sG := grp.ScalarBaseMult(sigS)
	cA := grp.ScalarMult(A, c)
	RpluscA := R.Add(cA)

	if !constantTimeElementEqual(grp, sG, RpluscA) {
		return ErrVerificationFailed
	}

	return nil
}

func (s *Ed448Signer) SecretKeySize() int { return 57 }
func (s *Ed448Signer) PublicKeySize() int { return 57 }
func (s *Ed448Signer) SignatureSize() int { return 114 }
func (s *Ed448Signer) GenerateKey() ([]byte, []byte, error) {
	cs := ed448_shake256.New()
	grp := cs.Group()

	// Generate random secret key
	secretKey := make([]byte, 57)
	if _, err := rand.Read(secretKey); err != nil {
		return nil, nil, err
	}

	// Derive scalar and compute public key
	scalar := cs.H3(secretKey)
	pubPoint := grp.ScalarBaseMult(scalar)
	pubKey, err := grp.SerializeElement(pubPoint)
	if err != nil {
		return nil, nil, err
	}

	return secretKey, pubKey, nil
}

// Secp256k1Signer implements Signer using Schnorr signatures on secp256k1.
// This is compatible with the FROST secp256k1 ciphersuite (RFC 9591 Section 6.5).
type Secp256k1Signer struct{}

func (s *Secp256k1Signer) Sign(secretKey []byte, message []byte, auxRand []byte) ([]byte, error) {
	if len(secretKey) != 32 {
		return nil, ErrSigningFailed
	}

	cs := secp256k1_sha256.New()
	grp := cs.Group()

	// Use H3 to derive scalar from secret key
	scalar := cs.H3(secretKey)

	// Compute public key A = scalar * G
	pubPoint := grp.ScalarBaseMult(scalar)

	// Generate nonce: r = H3(secretKey || message)
	nonceInput := make([]byte, len(secretKey)+len(message))
	copy(nonceInput, secretKey)
	copy(nonceInput[len(secretKey):], message)
	r := cs.H3(nonceInput)

	// R = r * G
	R := grp.ScalarBaseMult(r)

	// Serialize R and A
	RBytes, err := grp.SerializeElement(R)
	if err != nil {
		return nil, ErrSigningFailed
	}
	ABytes, err := grp.SerializeElement(pubPoint)
	if err != nil {
		return nil, ErrSigningFailed
	}

	// c = H3(R || A || message)
	cInput := make([]byte, len(RBytes)+len(ABytes)+len(message))
	copy(cInput, RBytes)
	copy(cInput[len(RBytes):], ABytes)
	copy(cInput[len(RBytes)+len(ABytes):], message)
	c := cs.H3(cInput)

	// s = r + c * scalar
	sigS := c.Mul(scalar)
	sigS = r.Add(sigS)

	// Signature is R || s (33 bytes + 32 bytes = 65 bytes)
	sBytes := grp.SerializeScalar(sigS)

	sig := make([]byte, 65)
	copy(sig[:33], RBytes)
	copy(sig[33:], sBytes)

	return sig, nil
}

func (s *Secp256k1Signer) Verify(publicKey []byte, message []byte, signature []byte) error {
	if len(signature) != 65 || len(publicKey) != 33 {
		return ErrInvalidSignature
	}

	cs := secp256k1_sha256.New()
	grp := cs.Group()

	// Parse R (33 bytes compressed point)
	R, err := grp.DeserializeElement(signature[:33])
	if err != nil {
		return ErrInvalidSignature
	}

	// Parse s (32 bytes scalar)
	sigS, err := grp.DeserializeScalar(signature[33:])
	if err != nil {
		return ErrInvalidSignature
	}

	// Parse A (public key)
	A, err := grp.DeserializeElement(publicKey)
	if err != nil {
		return ErrInvalidPublicKey
	}

	// c = H3(R || A || message)
	cInput := make([]byte, 33+33+len(message))
	copy(cInput, signature[:33])
	copy(cInput[33:], publicKey)
	copy(cInput[66:], message)
	c := cs.H3(cInput)

	// Verify: s * G == R + c * A
	// SECURITY: Use constant-time comparison to prevent timing side-channel attacks
	sG := grp.ScalarBaseMult(sigS)
	cA := grp.ScalarMult(A, c)
	RpluscA := R.Add(cA)

	if !constantTimeElementEqual(grp, sG, RpluscA) {
		return ErrVerificationFailed
	}

	return nil
}

func (s *Secp256k1Signer) SecretKeySize() int { return 32 }
func (s *Secp256k1Signer) PublicKeySize() int { return 33 }
func (s *Secp256k1Signer) SignatureSize() int { return 65 }
func (s *Secp256k1Signer) GenerateKey() ([]byte, []byte, error) {
	cs := secp256k1_sha256.New()
	grp := cs.Group()

	// Generate random secret key
	secretKey := make([]byte, 32)
	if _, err := rand.Read(secretKey); err != nil {
		return nil, nil, err
	}

	// Derive scalar and compute public key
	scalar := cs.H3(secretKey)
	pubPoint := grp.ScalarBaseMult(scalar)
	pubKey, err := grp.SerializeElement(pubPoint)
	if err != nil {
		return nil, nil, err
	}

	return secretKey, pubKey, nil
}

// Helper functions

// compressP256Point compresses a P-256 point to 33 bytes.
func compressP256Point(x, y *big.Int) []byte {
	result := make([]byte, 33)
	if y.Bit(0) == 0 {
		result[0] = 0x02
	} else {
		result[0] = 0x03
	}
	xBytes := x.Bytes()
	copy(result[33-len(xBytes):], xBytes)
	return result
}

// decompressP256Point decompresses a P-256 point from 33 bytes.
func decompressP256Point(data []byte) (*big.Int, *big.Int) {
	if len(data) != 33 {
		return nil, nil
	}

	prefix := data[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, nil
	}

	x := new(big.Int).SetBytes(data[1:])
	curve := elliptic.P256()
	params := curve.Params()

	// y^2 = x^3 - 3x + b (mod p)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, params.P)

	threeX := new(big.Int).Mul(x, big.NewInt(3))
	threeX.Mod(threeX, params.P)

	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, params.B)
	y2.Mod(y2, params.P)

	// Compute y = sqrt(y2) mod p
	y := new(big.Int).ModSqrt(y2, params.P)
	if y == nil {
		return nil, nil
	}

	// Choose the correct y based on prefix
	if (prefix == 0x02 && y.Bit(0) != 0) || (prefix == 0x03 && y.Bit(0) == 0) {
		y.Sub(params.P, y)
	}

	return x, y
}
