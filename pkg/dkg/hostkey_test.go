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
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
)

// TestGenerateSoftwareHostKey tests key generation for all 5 ciphersuites.
func TestGenerateSoftwareHostKey(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GenerateSoftwareHostKey(tc.cs)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
			}

			if key == nil {
				t.Fatal("Expected non-nil key")
			}

			pubkey := key.PublicKey()
			if len(pubkey) == 0 {
				t.Error("Expected non-empty public key")
			}

			seckey := key.SecretKey()
			if len(seckey) == 0 {
				t.Error("Expected non-empty secret key")
			}
		})
	}
}

// TestNewSoftwareHostKeyErrors tests error handling in key creation.
func TestNewSoftwareHostKeyErrors(t *testing.T) {
	cs := ed25519_sha512.New()

	t.Run("invalid_key_length", func(t *testing.T) {
		_, err := NewSoftwareHostKey(cs, []byte{0x01, 0x02, 0x03})
		if err != ErrInvalidSecretKey {
			t.Errorf("Expected ErrInvalidSecretKey, got %v", err)
		}
	})

	t.Run("empty_key", func(t *testing.T) {
		_, err := NewSoftwareHostKey(cs, []byte{})
		if err != ErrInvalidSecretKey {
			t.Errorf("Expected ErrInvalidSecretKey, got %v", err)
		}
	})
}

// TestHostKeyECDH tests ECDH key exchange between two parties for all 5 ciphersuites.
func TestHostKeyECDH(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate two key pairs
			alice, err := GenerateSoftwareHostKey(tc.cs)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKey for Alice failed: %v", err)
			}

			bob, err := GenerateSoftwareHostKey(tc.cs)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKey for Bob failed: %v", err)
			}

			// Alice computes shared secret with Bob's public key
			aliceSecret, err := alice.ECDH(bob.PublicKey())
			if err != nil {
				t.Fatalf("Alice ECDH failed: %v", err)
			}

			// Bob computes shared secret with Alice's public key
			bobSecret, err := bob.ECDH(alice.PublicKey())
			if err != nil {
				t.Fatalf("Bob ECDH failed: %v", err)
			}

			// Shared secrets must be equal
			if !bytes.Equal(aliceSecret, bobSecret) {
				t.Error("ECDH shared secrets do not match")
			}

			// Shared secret must not be empty
			if len(aliceSecret) == 0 {
				t.Error("Shared secret is empty")
			}
		})
	}
}

// TestHostKeyECDHErrors tests ECDH error handling.
func TestHostKeyECDHErrors(t *testing.T) {
	cs := ed25519_sha512.New()

	key, err := GenerateSoftwareHostKey(cs)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
	}

	t.Run("invalid_pubkey", func(t *testing.T) {
		_, err := key.ECDH([]byte{0x01, 0x02, 0x03})
		if err != ErrHostKeyECDHFailed {
			t.Errorf("Expected ErrHostKeyECDHFailed, got %v", err)
		}
	})

	t.Run("empty_pubkey", func(t *testing.T) {
		_, err := key.ECDH([]byte{})
		if err != ErrHostKeyECDHFailed {
			t.Errorf("Expected ErrHostKeyECDHFailed, got %v", err)
		}
	})
}

// TestHostKeySign tests signing and verification for all 5 ciphersuites.
func TestHostKeySign(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	message := []byte("test message for signing")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GenerateSoftwareHostKey(tc.cs)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
			}

			sig, err := key.Sign(message)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if len(sig) == 0 {
				t.Error("Signature is empty")
			}

			// Verify the signature
			err = VerifyHostKeySignature(tc.cs, key.PublicKey(), message, sig)
			if err != nil {
				t.Errorf("Signature verification failed: %v", err)
			}
		})
	}
}

// TestHostKeySignVerifyErrors tests signature verification error handling.
func TestHostKeySignVerifyErrors(t *testing.T) {
	cs := ed25519_sha512.New()

	key, err := GenerateSoftwareHostKey(cs)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
	}

	message := []byte("test message")
	sig, err := key.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	t.Run("wrong_message", func(t *testing.T) {
		err := VerifyHostKeySignature(cs, key.PublicKey(), []byte("wrong message"), sig)
		if err != ErrVerificationFailed {
			t.Errorf("Expected ErrVerificationFailed, got %v", err)
		}
	})

	t.Run("wrong_pubkey", func(t *testing.T) {
		otherKey, _ := GenerateSoftwareHostKey(cs)
		err := VerifyHostKeySignature(cs, otherKey.PublicKey(), message, sig)
		if err != ErrVerificationFailed {
			t.Errorf("Expected ErrVerificationFailed, got %v", err)
		}
	})

	t.Run("invalid_signature", func(t *testing.T) {
		err := VerifyHostKeySignature(cs, key.PublicKey(), message, []byte("bad sig"))
		if err != ErrInvalidSignature {
			t.Errorf("Expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("corrupted_signature", func(t *testing.T) {
		corruptSig := make([]byte, len(sig))
		copy(corruptSig, sig)
		corruptSig[0] ^= 0xFF
		err := VerifyHostKeySignature(cs, key.PublicKey(), message, corruptSig)
		if err == nil {
			t.Error("Expected error for corrupted signature")
		}
	})
}

// TestHostKeyGenerator tests the HostKeyGenerator interface for all 5 ciphersuites.
func TestHostKeyGenerator(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gen, err := GetHostKeyGenerator(tc.cs)
			if err != nil {
				t.Fatalf("GetHostKeyGenerator failed: %v", err)
			}

			// Test GenerateHostKey
			key1, err := gen.GenerateHostKey()
			if err != nil {
				t.Fatalf("GenerateHostKey failed: %v", err)
			}

			// Test LoadHostKey with the generated secret key
			softKey := key1.(*SoftwareHostKey)
			key2, err := gen.LoadHostKey(softKey.SecretKey())
			if err != nil {
				t.Fatalf("LoadHostKey failed: %v", err)
			}

			// Both should have the same public key
			if !bytes.Equal(key1.PublicKey(), key2.PublicKey()) {
				t.Error("LoadHostKey produced different public key")
			}
		})
	}
}

// TestHostKeyDeterministic tests that the same secret key produces the same key for all 5 ciphersuites.
func TestHostKeyDeterministic(t *testing.T) {
	testCases := []struct {
		name   string
		cs     ciphersuite.Ciphersuite
		keyLen int
	}{
		{"Ed25519", ed25519_sha512.New(), 32},
		{"Ed448", ed448_shake256.New(), 57},
		{"P256", p256_sha256.New(), 32},
		{"Ristretto255", ristretto255_sha512.New(), 32},
		{"Secp256k1", secp256k1_sha256.New(), 32},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a fixed secret key
			secretKey := make([]byte, tc.keyLen)
			_, _ = rand.Read(secretKey)

			// Create two keys from the same secret
			key1, err := NewSoftwareHostKey(tc.cs, secretKey)
			if err != nil {
				t.Fatalf("NewSoftwareHostKey 1 failed: %v", err)
			}

			key2, err := NewSoftwareHostKey(tc.cs, secretKey)
			if err != nil {
				t.Fatalf("NewSoftwareHostKey 2 failed: %v", err)
			}

			// Public keys must be identical
			if !bytes.Equal(key1.PublicKey(), key2.PublicKey()) {
				t.Error("Same secret key produced different public keys")
			}

			// ECDH with the same counterparty should produce the same result
			counterparty, _ := GenerateSoftwareHostKey(tc.cs)

			secret1, _ := key1.ECDH(counterparty.PublicKey())
			secret2, _ := key2.ECDH(counterparty.PublicKey())

			if !bytes.Equal(secret1, secret2) {
				t.Error("Same key produced different ECDH secrets")
			}
		})
	}
}

// TestP256SignatureVerification specifically tests P256 ECDSA signing.
func TestP256SignatureVerification(t *testing.T) {
	cs := p256_sha256.New()

	key, err := GenerateSoftwareHostKey(cs)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
	}

	// Test with various message sizes
	messages := [][]byte{
		[]byte(""),
		[]byte("short"),
		make([]byte, 100),
		make([]byte, 1000),
	}

	for i, msg := range messages {
		if len(msg) > 5 {
			_, _ = rand.Read(msg)
		}

		sig, err := key.Sign(msg)
		if err != nil {
			t.Fatalf("Sign message %d failed: %v", i, err)
		}

		err = VerifyHostKeySignature(cs, key.PublicKey(), msg, sig)
		if err != nil {
			t.Errorf("Verify message %d failed: %v", i, err)
		}
	}
}

// TestVerifyHostKeySignatureErrors tests verification error cases.
func TestVerifyHostKeySignatureErrors(t *testing.T) {
	t.Run("p256_invalid_pubkey_length", func(t *testing.T) {
		cs := p256_sha256.New()
		err := VerifyHostKeySignature(cs, []byte{0x01, 0x02}, []byte("msg"), make([]byte, 64))
		if err != ErrInvalidPublicKey {
			t.Errorf("Expected ErrInvalidPublicKey, got %v", err)
		}
	})

	t.Run("p256_invalid_signature_length", func(t *testing.T) {
		cs := p256_sha256.New()
		key, _ := GenerateSoftwareHostKey(cs)
		err := VerifyHostKeySignature(cs, key.PublicKey(), []byte("msg"), []byte("short"))
		if err != ErrInvalidSignature {
			t.Errorf("Expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("schnorr_invalid_signature_length", func(t *testing.T) {
		cs := ed25519_sha512.New()
		key, _ := GenerateSoftwareHostKey(cs)
		err := VerifyHostKeySignature(cs, key.PublicKey(), []byte("msg"), []byte("short"))
		if err != ErrInvalidSignature {
			t.Errorf("Expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("schnorr_invalid_pubkey", func(t *testing.T) {
		cs := ed25519_sha512.New()
		sig := make([]byte, 64) // 32 element + 32 scalar for Ed25519
		err := VerifyHostKeySignature(cs, []byte("bad"), []byte("msg"), sig)
		if err != ErrInvalidPublicKey {
			t.Errorf("Expected ErrInvalidPublicKey, got %v", err)
		}
	})
}

// mockRNG is a deterministic RNG for testing.
type mockRNG struct {
	seed byte
}

func (r *mockRNG) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = r.seed
		r.seed++
	}
	return len(p), nil
}

// TestGenerateSoftwareHostKeyWithRNG tests key generation with custom RNG for all 5 ciphersuites.
func TestGenerateSoftwareHostKeyWithRNG(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate two keys with the same mock RNG - should be identical
			rng1 := &mockRNG{seed: 42}
			rng2 := &mockRNG{seed: 42}

			key1, err := GenerateSoftwareHostKeyWithRNG(tc.cs, rng1)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKeyWithRNG 1 failed: %v", err)
			}

			key2, err := GenerateSoftwareHostKeyWithRNG(tc.cs, rng2)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKeyWithRNG 2 failed: %v", err)
			}

			// Keys should be identical
			if !bytes.Equal(key1.PublicKey(), key2.PublicKey()) {
				t.Error("Same RNG seed should produce identical keys")
			}

			// Different RNG seed should produce different keys
			rng3 := &mockRNG{seed: 0}
			key3, err := GenerateSoftwareHostKeyWithRNG(tc.cs, rng3)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKeyWithRNG 3 failed: %v", err)
			}

			if bytes.Equal(key1.PublicKey(), key3.PublicKey()) {
				t.Error("Different RNG seed should produce different keys")
			}
		})
	}
}

// TestGenerateSoftwareHostKeyWithRNG_NilRNG tests that nil RNG defaults to crypto/rand.
func TestGenerateSoftwareHostKeyWithRNG_NilRNG(t *testing.T) {
	cs := ed25519_sha512.New()

	// Should not panic with nil RNG
	key, err := GenerateSoftwareHostKeyWithRNG(cs, nil)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKeyWithRNG with nil RNG failed: %v", err)
	}

	if key == nil {
		t.Error("Expected non-nil key")
	}
}

// TestSoftwareHostKeyGeneratorWithRNG tests the generator with custom RNG.
func TestSoftwareHostKeyGeneratorWithRNG(t *testing.T) {
	cs := ed25519_sha512.New()

	// Create generator with mock RNG
	rng1 := &mockRNG{seed: 100}
	gen := NewSoftwareHostKeyGeneratorWithRNG(cs, rng1)

	key1, err := gen.GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey failed: %v", err)
	}

	// Create another generator with same seed
	rng2 := &mockRNG{seed: 100}
	gen2 := NewSoftwareHostKeyGeneratorWithRNG(cs, rng2)

	key2, err := gen2.GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey 2 failed: %v", err)
	}

	// Keys should be identical
	if !bytes.Equal(key1.PublicKey(), key2.PublicKey()) {
		t.Error("Same RNG seed should produce identical keys")
	}
}

// TestP256SignWithCustomRNG tests P256 signing with custom RNG.
func TestP256SignWithCustomRNG(t *testing.T) {
	cs := p256_sha256.New()

	// Use deterministic RNG for signing
	rng := &mockRNG{seed: 0}
	secretKey := make([]byte, 32)
	_, _ = io.ReadFull(rng, secretKey)

	// Reset RNG for deterministic signing
	rng = &mockRNG{seed: 200}
	key, err := NewSoftwareHostKeyWithRNG(cs, secretKey, rng)
	if err != nil {
		t.Fatalf("NewSoftwareHostKeyWithRNG failed: %v", err)
	}

	message := []byte("test message")
	sig, err := key.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify the signature
	err = VerifyHostKeySignature(cs, key.PublicKey(), message, sig)
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	}
}

// TestGetCiphersuiteByID tests the getCiphersuiteByID function.
func TestGetCiphersuiteByID(t *testing.T) {
	testCases := []struct {
		id       string
		expected bool
	}{
		{"FROST-ED25519-SHA512-v1", true},
		{"FROST-RISTRETTO255-SHA512-v1", true},
		{"FROST-ED448-SHAKE256-v1", true},
		{"FROST-secp256k1-SHA256-v1", true},
		{"FROST-P256-SHA256-v1", false}, // P256 not in the ID map
		{"invalid-id", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.id, func(t *testing.T) {
			cs := getCiphersuiteByID(tc.id)
			if tc.expected && cs == nil {
				t.Errorf("Expected ciphersuite for %s, got nil", tc.id)
			}
			if !tc.expected && cs != nil {
				t.Errorf("Expected nil for %s, got ciphersuite", tc.id)
			}
		})
	}
}

// TestNewSoftwareHostKeyWithRNGErrors tests error cases.
func TestNewSoftwareHostKeyWithRNGErrors(t *testing.T) {
	testCases := []struct {
		name   string
		cs     ciphersuite.Ciphersuite
		keyLen int
	}{
		{"Ed25519", ed25519_sha512.New(), 32},
		{"Ed448", ed448_shake256.New(), 57},
		{"P256", p256_sha256.New(), 32},
		{"Ristretto255", ristretto255_sha512.New(), 32},
		{"Secp256k1", secp256k1_sha256.New(), 32},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_invalid_length", func(t *testing.T) {
			_, err := NewSoftwareHostKeyWithRNG(tc.cs, []byte{0x01, 0x02}, nil)
			if err != ErrInvalidSecretKey {
				t.Errorf("Expected ErrInvalidSecretKey, got %v", err)
			}
		})

		t.Run(tc.name+"_nil_key", func(t *testing.T) {
			_, err := NewSoftwareHostKeyWithRNG(tc.cs, nil, nil)
			if err != ErrInvalidSecretKey {
				t.Errorf("Expected ErrInvalidSecretKey, got %v", err)
			}
		})

		t.Run(tc.name+"_valid_with_nil_rng", func(t *testing.T) {
			secretKey := make([]byte, tc.keyLen)
			_, _ = rand.Read(secretKey)
			key, err := NewSoftwareHostKeyWithRNG(tc.cs, secretKey, nil)
			if err != nil {
				t.Fatalf("Expected success, got %v", err)
			}
			if key == nil {
				t.Error("Expected non-nil key")
			}
		})
	}
}

// TestGetHostKeyGeneratorAllCiphersuites tests GetHostKeyGenerator for all ciphersuites.
func TestGetHostKeyGeneratorAllCiphersuites(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gen, err := GetHostKeyGenerator(tc.cs)
			if err != nil {
				t.Fatalf("GetHostKeyGenerator failed: %v", err)
			}

			// Generate a key
			key, err := gen.GenerateHostKey()
			if err != nil {
				t.Fatalf("GenerateHostKey failed: %v", err)
			}

			// Verify it can sign
			msg := []byte("test message")
			sig, err := key.Sign(msg)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			err = VerifyHostKeySignature(tc.cs, key.PublicKey(), msg, sig)
			if err != nil {
				t.Errorf("Verification failed: %v", err)
			}
		})
	}
}

// TestNewSoftwareHostKeyGeneratorWithRNGNil tests nil RNG handling.
func TestNewSoftwareHostKeyGeneratorWithRNGNil(t *testing.T) {
	cs := ed25519_sha512.New()

	// Should work with nil RNG (defaults to crypto/rand)
	gen := NewSoftwareHostKeyGeneratorWithRNG(cs, nil)
	if gen == nil {
		t.Fatal("Expected non-nil generator")
	}

	key, err := gen.GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey failed: %v", err)
	}

	if key == nil {
		t.Error("Expected non-nil key")
	}
}

// TestP256ECDHWithCoordinates exercises P256 ECDH which uses getP256Coordinates.
func TestP256ECDHWithCoordinates(t *testing.T) {
	cs := p256_sha256.New()

	// Generate multiple key pairs to exercise coordinate handling
	for i := 0; i < 5; i++ {
		alice, err := GenerateSoftwareHostKey(cs)
		if err != nil {
			t.Fatalf("GenerateSoftwareHostKey alice failed: %v", err)
		}

		bob, err := GenerateSoftwareHostKey(cs)
		if err != nil {
			t.Fatalf("GenerateSoftwareHostKey bob failed: %v", err)
		}

		// Exercise ECDH which internally uses getP256Coordinates
		secret1, err := alice.ECDH(bob.PublicKey())
		if err != nil {
			t.Fatalf("ECDH 1 failed: %v", err)
		}

		secret2, err := bob.ECDH(alice.PublicKey())
		if err != nil {
			t.Fatalf("ECDH 2 failed: %v", err)
		}

		if !bytes.Equal(secret1, secret2) {
			t.Errorf("ECDH secrets mismatch on iteration %d", i)
		}
	}
}

// TestVerifyP256SignatureEdgeCases tests P256 signature verification edge cases.
func TestVerifyP256SignatureEdgeCases(t *testing.T) {
	cs := p256_sha256.New()

	key, err := GenerateSoftwareHostKey(cs)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
	}

	msg := []byte("test message")
	sig, err := key.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	t.Run("truncated_signature", func(t *testing.T) {
		err := VerifyHostKeySignature(cs, key.PublicKey(), msg, sig[:32])
		if err != ErrInvalidSignature {
			t.Errorf("Expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("zero_r_value", func(t *testing.T) {
		badSig := make([]byte, len(sig))
		copy(badSig, sig)
		// Zero out r value
		for i := 0; i < 32; i++ {
			badSig[i] = 0
		}
		err := VerifyHostKeySignature(cs, key.PublicKey(), msg, badSig)
		if err == nil {
			t.Error("Expected error for zero r value")
		}
	})

	t.Run("zero_s_value", func(t *testing.T) {
		badSig := make([]byte, len(sig))
		copy(badSig, sig)
		// Zero out s value
		for i := 32; i < 64; i++ {
			badSig[i] = 0
		}
		err := VerifyHostKeySignature(cs, key.PublicKey(), msg, badSig)
		if err == nil {
			t.Error("Expected error for zero s value")
		}
	})

	t.Run("invalid_pubkey_prefix", func(t *testing.T) {
		// Create pubkey with invalid prefix
		badPubkey := make([]byte, 33)
		badPubkey[0] = 0x05 // Invalid prefix
		err := VerifyHostKeySignature(cs, badPubkey, msg, sig)
		if err != ErrInvalidPublicKey {
			t.Errorf("Expected ErrInvalidPublicKey, got %v", err)
		}
	})
}

// TestSchnorrSignatureEdgeCases tests Schnorr signature edge cases for non-P256 curves.
func TestSchnorrSignatureEdgeCases(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GenerateSoftwareHostKey(tc.cs)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
			}

			msg := []byte("test message")
			sig, err := key.Sign(msg)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Test with truncated signature
			t.Run("truncated", func(t *testing.T) {
				err := VerifyHostKeySignature(tc.cs, key.PublicKey(), msg, sig[:len(sig)/2])
				if err != ErrInvalidSignature {
					t.Errorf("Expected ErrInvalidSignature, got %v", err)
				}
			})

			// Test with corrupted R value
			t.Run("corrupted_R", func(t *testing.T) {
				badSig := make([]byte, len(sig))
				copy(badSig, sig)
				badSig[0] ^= 0xFF
				err := VerifyHostKeySignature(tc.cs, key.PublicKey(), msg, badSig)
				if err == nil {
					t.Error("Expected error for corrupted R")
				}
			})

			// Test with empty message
			t.Run("empty_message", func(t *testing.T) {
				emptySig, err := key.Sign([]byte{})
				if err != nil {
					t.Fatalf("Sign empty failed: %v", err)
				}
				err = VerifyHostKeySignature(tc.cs, key.PublicKey(), []byte{}, emptySig)
				if err != nil {
					t.Errorf("Verify empty message failed: %v", err)
				}
			})
		})
	}
}

// failingRNG is an RNG that fails after a certain number of reads.
type failingRNG struct {
	failAfter int
	count     int
}

func (r *failingRNG) Read(p []byte) (n int, err error) {
	r.count++
	if r.count > r.failAfter {
		return 0, io.ErrUnexpectedEOF
	}
	for i := range p {
		p[i] = byte(r.count)
	}
	return len(p), nil
}

// TestGenerateSoftwareHostKeyWithRNGFailure tests RNG failure handling.
func TestGenerateSoftwareHostKeyWithRNGFailure(t *testing.T) {
	cs := ed25519_sha512.New()

	// RNG that fails immediately
	rng := &failingRNG{failAfter: 0}
	_, err := GenerateSoftwareHostKeyWithRNG(cs, rng)
	if err == nil {
		t.Error("Expected error for failing RNG")
	}
}
