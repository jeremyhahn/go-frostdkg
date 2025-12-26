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
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
)

// TestGetSigner tests that we can get signers for all ciphersuites.
func TestGetSigner(t *testing.T) {
	tests := []struct {
		name        string
		ciphersuite interface{ ID() string }
	}{
		{name: "P256", ciphersuite: p256_sha256.New()},
		{name: "Ed25519", ciphersuite: ed25519_sha512.New()},
		{name: "ristretto255", ciphersuite: ristretto255_sha512.New()},
		{name: "Ed448", ciphersuite: ed448_shake256.New()},
		{name: "secp256k1", ciphersuite: secp256k1_sha256.New()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := GetSignerByID(tt.ciphersuite.ID())
			if err != nil {
				t.Fatalf("GetSignerByID() error = %v", err)
			}
			if signer == nil {
				t.Fatal("GetSignerByID() returned nil signer")
			}
		})
	}
}

// TestGetSignerUnknown tests that we get an error for unknown ciphersuites.
func TestGetSignerUnknown(t *testing.T) {
	_, err := GetSignerByID("unknown-ciphersuite")
	if err == nil {
		t.Fatal("GetSignerByID() expected error for unknown ciphersuite")
	}
	if err != ErrUnknownCiphersuite {
		t.Errorf("GetSignerByID() error = %v, want %v", err, ErrUnknownCiphersuite)
	}
}

// TestSignerRoundTrip tests sign and verify for all signer implementations.
func TestSignerRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		signer Signer
	}{
		{name: "P256", signer: &P256Signer{}},
		{name: "Ed25519", signer: &Ed25519Signer{}},
		{name: "ristretto255", signer: &Ristretto255Signer{}},
		{name: "Ed448", signer: &Ed448Signer{}},
		{name: "secp256k1", signer: &Secp256k1Signer{}},
	}

	message := []byte("test message for signing")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate key pair
			secretKey, publicKey, err := tt.signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			// Verify key sizes
			if len(secretKey) != tt.signer.SecretKeySize() {
				t.Errorf("SecretKey size = %d, want %d", len(secretKey), tt.signer.SecretKeySize())
			}
			if len(publicKey) != tt.signer.PublicKeySize() {
				t.Errorf("PublicKey size = %d, want %d", len(publicKey), tt.signer.PublicKeySize())
			}

			// Sign message
			signature, err := tt.signer.Sign(secretKey, message, nil)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			// Verify signature size
			if len(signature) != tt.signer.SignatureSize() {
				t.Errorf("Signature size = %d, want %d", len(signature), tt.signer.SignatureSize())
			}

			// Verify signature
			if err := tt.signer.Verify(publicKey, message, signature); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			// Verify with wrong message fails
			wrongMessage := []byte("wrong message")
			if err := tt.signer.Verify(publicKey, wrongMessage, signature); err == nil {
				t.Error("Verify() should fail with wrong message")
			}

			// Verify with corrupted signature fails
			corruptedSig := make([]byte, len(signature))
			copy(corruptedSig, signature)
			corruptedSig[0] ^= 0xff
			if err := tt.signer.Verify(publicKey, message, corruptedSig); err == nil {
				t.Error("Verify() should fail with corrupted signature")
			}
		})
	}
}

// TestSignerInvalidSecretKey tests that signing with invalid secret key fails.
func TestSignerInvalidSecretKey(t *testing.T) {
	tests := []struct {
		name   string
		signer Signer
	}{
		{name: "P256", signer: &P256Signer{}},
		{name: "Ed25519", signer: &Ed25519Signer{}},
		{name: "ristretto255", signer: &Ristretto255Signer{}},
		{name: "Ed448", signer: &Ed448Signer{}},
		{name: "secp256k1", signer: &Secp256k1Signer{}},
	}

	message := []byte("test message")
	invalidSecretKey := []byte{0x00} // Too short

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.signer.Sign(invalidSecretKey, message, nil)
			if err == nil {
				t.Error("Sign() should fail with invalid secret key")
			}
		})
	}
}

// TestSignerInvalidPublicKey tests that verification with invalid public key fails.
func TestSignerInvalidPublicKey(t *testing.T) {
	tests := []struct {
		name   string
		signer Signer
	}{
		{name: "P256", signer: &P256Signer{}},
		{name: "Ed25519", signer: &Ed25519Signer{}},
		{name: "ristretto255", signer: &Ristretto255Signer{}},
		{name: "Ed448", signer: &Ed448Signer{}},
		{name: "secp256k1", signer: &Secp256k1Signer{}},
	}

	message := []byte("test message")
	invalidPublicKey := []byte{0x00} // Too short
	dummySignature := make([]byte, 64)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.signer.Verify(invalidPublicKey, message, dummySignature)
			if err == nil {
				t.Error("Verify() should fail with invalid public key")
			}
		})
	}
}

// TestSignerInvalidSignature tests that verification with invalid signature fails.
func TestSignerInvalidSignature(t *testing.T) {
	tests := []struct {
		name   string
		signer Signer
	}{
		{name: "P256", signer: &P256Signer{}},
		{name: "Ed25519", signer: &Ed25519Signer{}},
		{name: "ristretto255", signer: &Ristretto255Signer{}},
		{name: "Ed448", signer: &Ed448Signer{}},
		{name: "secp256k1", signer: &Secp256k1Signer{}},
	}

	message := []byte("test message")
	invalidSignature := []byte{0x00} // Too short

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate valid public key
			_, publicKey, err := tt.signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			err = tt.signer.Verify(publicKey, message, invalidSignature)
			if err == nil {
				t.Error("Verify() should fail with invalid signature")
			}
		})
	}
}

// TestP256CompressedPublicKey tests that P256 signer handles compressed public keys.
func TestP256CompressedPublicKey(t *testing.T) {
	signer := &P256Signer{}
	secretKey, compressedPubKey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Verify compressed format
	if len(compressedPubKey) != 33 {
		t.Fatalf("Expected compressed public key (33 bytes), got %d bytes", len(compressedPubKey))
	}
	if compressedPubKey[0] != 0x02 && compressedPubKey[0] != 0x03 {
		t.Fatalf("Expected compressed prefix (0x02 or 0x03), got 0x%02x", compressedPubKey[0])
	}

	// Sign and verify with compressed key
	message := []byte("test message")
	signature, err := signer.Sign(secretKey, message, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if err := signer.Verify(compressedPubKey, message, signature); err != nil {
		t.Fatalf("Verify() with compressed key error = %v", err)
	}
}

// TestMultipleSignatures tests that multiple signatures can be created and verified.
func TestMultipleSignatures(t *testing.T) {
	signer := &Ed25519Signer{}
	n := 5
	messages := make([][]byte, n)
	secretKeys := make([][]byte, n)
	publicKeys := make([][]byte, n)
	signatures := make([][]byte, n)

	// Generate keys and sign messages
	for i := 0; i < n; i++ {
		sk, pk, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		secretKeys[i] = sk
		publicKeys[i] = pk
		messages[i] = []byte("message " + string(rune('A'+i)))

		sig, err := signer.Sign(sk, messages[i], nil)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		signatures[i] = sig
	}

	// Verify all signatures
	for i := 0; i < n; i++ {
		if err := signer.Verify(publicKeys[i], messages[i], signatures[i]); err != nil {
			t.Errorf("Verify() error for signature %d: %v", i, err)
		}

		// Cross-verify should fail
		for j := 0; j < n; j++ {
			if i != j {
				if err := signer.Verify(publicKeys[j], messages[i], signatures[i]); err == nil {
					t.Errorf("Cross-verify should fail for signature %d with key %d", i, j)
				}
			}
		}
	}
}

// TestGetSignerFromCiphersuite tests the GetSigner and GetSignerByID functions.
func TestGetSignerFromCiphersuite(t *testing.T) {
	testCases := []struct {
		name string
		cs   interface {
			ID() string
		}
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := GetSignerByID(tc.cs.ID())
			if err != nil {
				t.Fatalf("GetSignerByID(%s) failed: %v", tc.cs.ID(), err)
			}
			if signer == nil {
				t.Error("GetSignerByID returned nil signer")
			}
		})
	}

	t.Run("unknown_ciphersuite", func(t *testing.T) {
		_, err := GetSignerByID("unknown-ciphersuite")
		if err != ErrUnknownCiphersuite {
			t.Errorf("Expected ErrUnknownCiphersuite, got %v", err)
		}
	})
}

// TestSignerVerifyErrors tests signature verification error cases.
func TestSignerVerifyErrors(t *testing.T) {
	signers := []struct {
		name   string
		signer Signer
	}{
		{"Ed25519", &Ed25519Signer{}},
		{"P256", &P256Signer{}},
		{"Ristretto255", &Ristretto255Signer{}},
		{"Secp256k1", &Secp256k1Signer{}},
	}

	for _, s := range signers {
		t.Run(s.name+"_invalid_pubkey", func(t *testing.T) {
			err := s.signer.Verify([]byte("invalid"), []byte("msg"), []byte("sig"))
			if err == nil {
				t.Error("Expected error for invalid public key")
			}
		})

		t.Run(s.name+"_invalid_signature", func(t *testing.T) {
			sk, pk, err := s.signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			_ = sk

			err = s.signer.Verify(pk, []byte("msg"), []byte("invalid signature"))
			if err == nil {
				t.Error("Expected error for invalid signature")
			}
		})

		t.Run(s.name+"_wrong_message", func(t *testing.T) {
			sk, pk, err := s.signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			sig, err := s.signer.Sign(sk, []byte("original message"), nil)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			err = s.signer.Verify(pk, []byte("different message"), sig)
			if err == nil {
				t.Error("Expected error for wrong message")
			}
		})
	}
}

// TestP256SignerVerifyComprehensive tests all code paths in P256Signer.Verify.
func TestP256SignerVerifyComprehensive(t *testing.T) {
	signer := &P256Signer{}
	message := []byte("test message for comprehensive verification")

	// Generate a valid key pair and signature for testing
	secretKey, publicKey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	validSignature, err := signer.Sign(secretKey, message, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	tests := []struct {
		name      string
		publicKey []byte
		message   []byte
		signature []byte
		wantErr   error
	}{
		{
			name:      "valid_compressed_signature",
			publicKey: publicKey, // 33 bytes compressed
			message:   message,
			signature: validSignature,
			wantErr:   nil,
		},
		{
			name:      "invalid_signature_length_too_short",
			publicKey: publicKey,
			message:   message,
			signature: []byte{0x01, 0x02, 0x03}, // Not 64 bytes
			wantErr:   ErrInvalidSignature,
		},
		{
			name:      "invalid_signature_length_too_long",
			publicKey: publicKey,
			message:   message,
			signature: make([]byte, 65), // Not 64 bytes
			wantErr:   ErrInvalidSignature,
		},
		{
			name: "invalid_compressed_public_key_bad_x",
			// Create a compressed key with invalid x coordinate (not on curve)
			publicKey: func() []byte {
				key := make([]byte, 33)
				key[0] = 0x02
				// Set all bits to 1 (very unlikely to be on curve)
				for i := 1; i < 33; i++ {
					key[i] = 0xff
				}
				return key
			}(),
			message:   message,
			signature: validSignature,
			wantErr:   ErrInvalidPublicKey,
		},
		{
			name: "valid_uncompressed_public_key",
			// Convert compressed to uncompressed format
			publicKey: func() []byte {
				// Decompress the public key
				x, y := decompressP256Point(publicKey)
				if x == nil {
					t.Fatal("Failed to decompress public key")
				}
				// Create uncompressed format: 0x04 || x || y
				uncompressed := make([]byte, 65)
				uncompressed[0] = 0x04
				xBytes := x.Bytes()
				yBytes := y.Bytes()
				copy(uncompressed[33-len(xBytes):33], xBytes)
				copy(uncompressed[65-len(yBytes):65], yBytes)
				return uncompressed
			}(),
			message:   message,
			signature: validSignature,
			wantErr:   nil,
		},
		{
			name: "invalid_uncompressed_public_key_wrong_prefix",
			// Uncompressed format with wrong prefix
			publicKey: func() []byte {
				key := make([]byte, 65)
				key[0] = 0x05 // Wrong prefix (should be 0x04)
				return key
			}(),
			message:   message,
			signature: validSignature,
			wantErr:   ErrInvalidPublicKey,
		},
		{
			name: "invalid_public_key_length_32_bytes",
			// Invalid length (not 33 or 65)
			publicKey: make([]byte, 32),
			message:   message,
			signature: validSignature,
			wantErr:   ErrInvalidPublicKey,
		},
		{
			name: "invalid_public_key_length_64_bytes",
			// Invalid length (not 33 or 65)
			publicKey: make([]byte, 64),
			message:   message,
			signature: validSignature,
			wantErr:   ErrInvalidPublicKey,
		},
		{
			name:      "invalid_signature_wrong_values",
			publicKey: publicKey,
			message:   message,
			signature: func() []byte {
				// Create a signature with all zeros (invalid)
				sig := make([]byte, 64)
				return sig
			}(),
			wantErr: ErrVerificationFailed,
		},
		{
			name:      "invalid_signature_verification_fails",
			publicKey: publicKey,
			message:   message,
			signature: func() []byte {
				// Create a signature with random values
				sig := make([]byte, 64)
				sig[0] = 0x01
				sig[32] = 0x02
				return sig
			}(),
			wantErr: ErrVerificationFailed,
		},
		{
			name:      "invalid_message_different",
			publicKey: publicKey,
			message:   []byte("different message"),
			signature: validSignature,
			wantErr:   ErrVerificationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := signer.Verify(tt.publicKey, tt.message, tt.signature)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Verify() error = %v, want nil", err)
				}
			} else {
				if err != tt.wantErr {
					t.Errorf("Verify() error = %v, want %v", err, tt.wantErr)
				}
			}
		})
	}
}

// TestP256SignerVerifyUncompressedFormat tests uncompressed public key handling.
func TestP256SignerVerifyUncompressedFormat(t *testing.T) {
	signer := &P256Signer{}
	message := []byte("test message for uncompressed key")

	// Generate a key pair
	curve := elliptic.P256()
	privKey := new(ecdsa.PrivateKey)
	privKey.Curve = curve

	// Create a known secret key
	secretKeyBytes := make([]byte, 32)
	for i := range secretKeyBytes {
		secretKeyBytes[i] = byte(i + 1)
	}
	privKey.D = new(big.Int).SetBytes(secretKeyBytes)
	privKey.X, privKey.Y = curve.ScalarBaseMult(secretKeyBytes)

	// Create signature
	signature, err := signer.Sign(secretKeyBytes, message, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Test with uncompressed public key (65 bytes: 0x04 || x || y)
	uncompressedPubKey := make([]byte, 65)
	uncompressedPubKey[0] = 0x04
	xBytes := privKey.X.Bytes()
	yBytes := privKey.Y.Bytes()
	copy(uncompressedPubKey[33-len(xBytes):33], xBytes)
	copy(uncompressedPubKey[65-len(yBytes):65], yBytes)

	err = signer.Verify(uncompressedPubKey, message, signature)
	if err != nil {
		t.Errorf("Verify() with uncompressed key error = %v, want nil", err)
	}

	// Test with wrong prefix
	invalidPrefixKey := make([]byte, 65)
	copy(invalidPrefixKey, uncompressedPubKey)
	invalidPrefixKey[0] = 0x02 // Wrong prefix for uncompressed format

	err = signer.Verify(invalidPrefixKey, message, signature)
	if err != ErrInvalidPublicKey {
		t.Errorf("Verify() with invalid prefix error = %v, want %v", err, ErrInvalidPublicKey)
	}
}

// TestP256SignerVerifyCompressedFormat tests compressed public key edge cases.
func TestP256SignerVerifyCompressedFormat(t *testing.T) {
	signer := &P256Signer{}
	message := []byte("test message for compressed key")

	// Generate a valid key pair
	secretKey, publicKey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	signature, err := signer.Sign(secretKey, message, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Test with valid compressed key
	err = signer.Verify(publicKey, message, signature)
	if err != nil {
		t.Errorf("Verify() with valid compressed key error = %v, want nil", err)
	}

	// Test with invalid compressed key (bad x coordinate)
	invalidCompressed := make([]byte, 33)
	invalidCompressed[0] = 0x02
	// Fill with maximum value that won't decompress
	for i := 1; i < 33; i++ {
		invalidCompressed[i] = 0xff
	}

	err = signer.Verify(invalidCompressed, message, signature)
	if err != ErrInvalidPublicKey {
		t.Errorf("Verify() with invalid compressed key error = %v, want %v", err, ErrInvalidPublicKey)
	}
}

// TestSignerGenerateKeyDeterminism tests that GenerateKey produces different keys.
func TestSignerGenerateKeyDeterminism(t *testing.T) {
	tests := []struct {
		name   string
		signer Signer
	}{
		{name: "P256", signer: &P256Signer{}},
		{name: "Ed25519", signer: &Ed25519Signer{}},
		{name: "ristretto255", signer: &Ristretto255Signer{}},
		{name: "Ed448", signer: &Ed448Signer{}},
		{name: "secp256k1", signer: &Secp256k1Signer{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate two keys
			sk1, pk1, err := tt.signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			sk2, pk2, err := tt.signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			// Keys should be different (extremely unlikely to be equal)
			if string(sk1) == string(sk2) {
				t.Error("GenerateKey() generated identical secret keys")
			}
			if string(pk1) == string(pk2) {
				t.Error("GenerateKey() generated identical public keys")
			}
		})
	}
}

// TestSignerGenerateKeyCorrectSize tests that generated keys have correct sizes.
func TestSignerGenerateKeyCorrectSize(t *testing.T) {
	tests := []struct {
		name   string
		signer Signer
	}{
		{name: "P256", signer: &P256Signer{}},
		{name: "Ed25519", signer: &Ed25519Signer{}},
		{name: "ristretto255", signer: &Ristretto255Signer{}},
		{name: "Ed448", signer: &Ed448Signer{}},
		{name: "secp256k1", signer: &Secp256k1Signer{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sk, pk, err := tt.signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			if len(sk) != tt.signer.SecretKeySize() {
				t.Errorf("Secret key size = %d, want %d", len(sk), tt.signer.SecretKeySize())
			}

			if len(pk) != tt.signer.PublicKeySize() {
				t.Errorf("Public key size = %d, want %d", len(pk), tt.signer.PublicKeySize())
			}
		})
	}
}

// TestSignerGenerateKeyAndSignVerify tests that generated keys work for signing.
func TestSignerGenerateKeyAndSignVerify(t *testing.T) {
	tests := []struct {
		name   string
		signer Signer
	}{
		{name: "P256", signer: &P256Signer{}},
		{name: "Ed25519", signer: &Ed25519Signer{}},
		{name: "ristretto255", signer: &Ristretto255Signer{}},
		{name: "Ed448", signer: &Ed448Signer{}},
		{name: "secp256k1", signer: &Secp256k1Signer{}},
	}

	message := []byte("test message for key generation")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate key pair
			sk, pk, err := tt.signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			// Sign with generated key
			sig, err := tt.signer.Sign(sk, message, nil)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			// Verify with generated public key
			if err := tt.signer.Verify(pk, message, sig); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

// TestGetSignerWithCiphersuiteInterface tests GetSigner function with GetSignerByID.
func TestGetSignerWithCiphersuiteInterface(t *testing.T) {
	tests := []struct {
		name string
		csID string
	}{
		{name: "P256", csID: p256_sha256.New().ID()},
		{name: "Ed25519", csID: ed25519_sha512.New().ID()},
		{name: "ristretto255", csID: ristretto255_sha512.New().ID()},
		{name: "Ed448", csID: ed448_shake256.New().ID()},
		{name: "secp256k1", csID: secp256k1_sha256.New().ID()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test GetSignerByID
			signer, err := GetSignerByID(tt.csID)
			if err != nil {
				t.Fatalf("GetSignerByID() error = %v", err)
			}
			if signer == nil {
				t.Fatal("GetSignerByID() returned nil signer")
			}

			// Verify it works by generating a key
			_, _, err = signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}
		})
	}
}

// TestSignerEdgeCases tests various edge cases for all signers.
func TestSignerEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		signer Signer
	}{
		{name: "P256", signer: &P256Signer{}},
		{name: "Ed25519", signer: &Ed25519Signer{}},
		{name: "ristretto255", signer: &Ristretto255Signer{}},
		{name: "Ed448", signer: &Ed448Signer{}},
		{name: "secp256k1", signer: &Secp256k1Signer{}},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/empty_message", func(t *testing.T) {
			sk, pk, err := tt.signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			// Sign empty message
			sig, err := tt.signer.Sign(sk, []byte{}, nil)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			// Verify empty message
			if err := tt.signer.Verify(pk, []byte{}, sig); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})

		t.Run(tt.name+"/large_message", func(t *testing.T) {
			sk, pk, err := tt.signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			// Sign large message (1MB)
			largeMessage := make([]byte, 1024*1024)
			for i := range largeMessage {
				largeMessage[i] = byte(i % 256)
			}

			sig, err := tt.signer.Sign(sk, largeMessage, nil)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			// Verify large message
			if err := tt.signer.Verify(pk, largeMessage, sig); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

// TestP256DecompressInvalidPoint tests decompression of invalid points.
func TestP256DecompressInvalidPoint(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "wrong_length",
			data: make([]byte, 32), // Should be 33
		},
		{
			name: "invalid_prefix",
			data: append([]byte{0x05}, make([]byte, 32)...), // Invalid prefix
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x, y := decompressP256Point(tt.data)
			if x != nil || y != nil {
				t.Error("decompressP256Point() should return nil for invalid point")
			}
		})
	}
}

// TestP256CompressDecompressRoundTrip tests compression and decompression round trip.
func TestP256CompressDecompressRoundTrip(t *testing.T) {
	signer := &P256Signer{}

	// Generate multiple keys and test compression/decompression
	for i := 0; i < 10; i++ {
		_, pk, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}

		// Decompress
		x, y := decompressP256Point(pk)
		if x == nil || y == nil {
			t.Fatal("Failed to decompress valid public key")
		}

		// Recompress
		pk2 := compressP256Point(x, y)

		// Should match original
		if string(pk) != string(pk2) {
			t.Error("Compress/decompress round trip failed")
		}
	}
}
