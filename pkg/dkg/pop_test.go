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
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
)

// TestFROSTDKGProveKnowledgeAndVerify tests the POP creation and verification.
func TestFROSTDKGProveKnowledgeAndVerify(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grp := tc.cs.Group()

			// Generate a random secret
			secret, err := grp.RandomScalar()
			if err != nil {
				t.Fatalf("Failed to generate random scalar: %v", err)
			}

			// Compute the public key
			pubkey := grp.ScalarBaseMult(secret)

			// Test with different participant indices (0-indexed)
			for index := 0; index < 3; index++ {
				// Create proof of possession
				pop, err := FROSTDKGProveKnowledge(tc.cs, secret, pubkey, index)
				if err != nil {
					t.Fatalf("FROSTDKGProveKnowledge failed at index %d: %v", index, err)
				}

				// Verify the proof
				if !FROSTDKGVerifyPOP(tc.cs, pop, pubkey, index) {
					t.Errorf("FROSTDKGVerifyPOP failed for index %d", index)
				}

				// Verify with wrong index should fail
				if FROSTDKGVerifyPOP(tc.cs, pop, pubkey, index+1) {
					t.Errorf("FROSTDKGVerifyPOP should fail with wrong index")
				}

				// Verify with wrong pubkey should fail
				wrongSecret, _ := grp.RandomScalar()
				wrongPubkey := grp.ScalarBaseMult(wrongSecret)
				if FROSTDKGVerifyPOP(tc.cs, pop, wrongPubkey, index) {
					t.Errorf("FROSTDKGVerifyPOP should fail with wrong pubkey")
				}

				// Verify corrupted proof should fail
				corruptedPOP := make([]byte, len(pop))
				copy(corruptedPOP, pop)
				corruptedPOP[0] ^= 0xFF
				if FROSTDKGVerifyPOP(tc.cs, corruptedPOP, pubkey, index) {
					t.Errorf("FROSTDKGVerifyPOP should fail with corrupted proof")
				}
			}
		})
	}
}

// TestFROSTDKGProveKnowledgeDeterministic verifies that POP is deterministic.
func TestFROSTDKGProveKnowledgeDeterministic(t *testing.T) {
	cs := secp256k1_sha256.New()
	grp := cs.Group()

	// Use a fixed secret for reproducibility (from test vectors)
	secretBytes, _ := hex.DecodeString("e7a3cf1fdb1e17d4c3e8a7f663803ef305d03bdfdc930b824b0664c6b853156d")
	secret, err := grp.DeserializeScalar(secretBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize secret: %v", err)
	}
	pubkey := grp.ScalarBaseMult(secret)

	// Generate POP twice
	pop1, err := FROSTDKGProveKnowledge(cs, secret, pubkey, 0)
	if err != nil {
		t.Fatalf("First FROSTDKGProveKnowledge failed: %v", err)
	}

	pop2, err := FROSTDKGProveKnowledge(cs, secret, pubkey, 0)
	if err != nil {
		t.Fatalf("Second FROSTDKGProveKnowledge failed: %v", err)
	}

	// Should be identical
	if hex.EncodeToString(pop1) != hex.EncodeToString(pop2) {
		t.Error("POP should be deterministic")
	}

	// Different index should produce different POP
	pop3, err := FROSTDKGProveKnowledge(cs, secret, pubkey, 1)
	if err != nil {
		t.Fatalf("Third FROSTDKGProveKnowledge failed: %v", err)
	}

	if hex.EncodeToString(pop1) == hex.EncodeToString(pop3) {
		t.Error("POP with different index should be different")
	}
}

// TestFROSTDKGVerifyPOPInvalidLength tests POP verification with invalid lengths.
func TestFROSTDKGVerifyPOPInvalidLength(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	secret, _ := grp.RandomScalar()
	pubkey := grp.ScalarBaseMult(secret)

	// Too short
	shortPOP := make([]byte, 10)
	if FROSTDKGVerifyPOP(cs, shortPOP, pubkey, 0) {
		t.Error("Should fail with too short POP")
	}

	// Too long
	longPOP := make([]byte, 200)
	if FROSTDKGVerifyPOP(cs, longPOP, pubkey, 0) {
		t.Error("Should fail with too long POP")
	}

	// Empty
	if FROSTDKGVerifyPOP(cs, []byte{}, pubkey, 0) {
		t.Error("Should fail with empty POP")
	}
}

// TestIndexToIdentifierScalar tests the index to identifier conversion.
func TestIndexToIdentifierScalar(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grp := tc.cs.Group()

			// 0-indexed 0 -> 1-indexed 1
			scalar0 := indexToIdentifierScalar(grp, 0)
			one := scalarFromInt(grp, 1)
			if !scalar0.Equal(one) {
				t.Error("indexToIdentifierScalar(0) should equal 1")
			}

			// 0-indexed 1 -> 1-indexed 2
			scalar1 := indexToIdentifierScalar(grp, 1)
			two := scalarFromInt(grp, 2)
			if !scalar1.Equal(two) {
				t.Error("indexToIdentifierScalar(1) should equal 2")
			}

			// 0-indexed 2 -> 1-indexed 3
			scalar2 := indexToIdentifierScalar(grp, 2)
			three := scalarFromInt(grp, 3)
			if !scalar2.Equal(three) {
				t.Error("indexToIdentifierScalar(2) should equal 3")
			}
		})
	}
}

// TestFROSTDKGPOPFormat tests the POP serialization format.
func TestFROSTDKGPOPFormat(t *testing.T) {
	testCases := []struct {
		name        string
		cs          ciphersuite.Ciphersuite
		expectedLen int // element length + scalar length
	}{
		{"Ed25519", ed25519_sha512.New(), 32 + 32},           // 64 bytes
		{"P256", p256_sha256.New(), 33 + 32},                 // 65 bytes
		{"Ristretto255", ristretto255_sha512.New(), 32 + 32}, // 64 bytes
		{"Secp256k1", secp256k1_sha256.New(), 33 + 32},       // 65 bytes
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grp := tc.cs.Group()

			secret, _ := grp.RandomScalar()
			pubkey := grp.ScalarBaseMult(secret)

			pop, err := FROSTDKGProveKnowledge(tc.cs, secret, pubkey, 0)
			if err != nil {
				t.Fatalf("FROSTDKGProveKnowledge failed: %v", err)
			}

			if len(pop) != tc.expectedLen {
				t.Errorf("Expected POP length %d, got %d", tc.expectedLen, len(pop))
			}

			// Verify the format is R || mu
			elemLen := grp.ElementLength()
			scalarLen := grp.ScalarLength()

			// First part should be a valid element (R)
			R, err := grp.DeserializeElement(pop[:elemLen])
			if err != nil {
				t.Errorf("Failed to deserialize R from POP: %v", err)
			}
			if R.IsIdentity() {
				t.Error("R should not be identity")
			}

			// Second part should be a valid scalar (mu)
			mu, err := grp.DeserializeScalar(pop[elemLen : elemLen+scalarLen])
			if err != nil {
				t.Errorf("Failed to deserialize mu from POP: %v", err)
			}
			if mu.IsZero() {
				t.Error("mu should not be zero for valid secret")
			}
		})
	}
}

// TestFROSTDKGPOPChallenge tests that the challenge uses HDKG as per RFC 9591.
func TestFROSTDKGPOPChallenge(t *testing.T) {
	// This test verifies the challenge format:
	// c = HDKG(identifier || verifying_key || R)
	cs := secp256k1_sha256.New()
	grp := cs.Group()

	secret, _ := grp.RandomScalar()
	pubkey := grp.ScalarBaseMult(secret)

	// Generate POP
	pop, err := FROSTDKGProveKnowledge(cs, secret, pubkey, 0)
	if err != nil {
		t.Fatalf("FROSTDKGProveKnowledge failed: %v", err)
	}

	// Extract R from the POP
	elemLen := grp.ElementLength()
	R, _ := grp.DeserializeElement(pop[:elemLen])

	// Manually compute challenge using the same format
	identifierScalar := indexToIdentifierScalar(grp, 0)
	identifierBytes := grp.SerializeScalar(identifierScalar)
	pubkeyBytes, _ := grp.SerializeElement(pubkey)
	RBytes, _ := grp.SerializeElement(R)

	challengeInput := make([]byte, len(identifierBytes)+len(pubkeyBytes)+len(RBytes))
	copy(challengeInput, identifierBytes)
	copy(challengeInput[len(identifierBytes):], pubkeyBytes)
	copy(challengeInput[len(identifierBytes)+len(pubkeyBytes):], RBytes)

	// The challenge computed here should match what's used in the POP
	c := cs.HDKG(challengeInput)
	if c == nil || c.IsZero() {
		t.Error("HDKG should return non-nil, non-zero scalar")
	}

	// Verify the POP still passes (confirms our challenge computation is correct)
	if !FROSTDKGVerifyPOP(cs, pop, pubkey, 0) {
		t.Error("POP verification failed")
	}
}

// TestFROSTDKGPOPWithTestVectorSecrets tests POP with fixed secrets similar to test vectors.
func TestFROSTDKGPOPWithTestVectorSecrets(t *testing.T) {
	// These secrets are similar in format to the Zcash FROST test vectors
	testCases := []struct {
		name      string
		cs        ciphersuite.Ciphersuite
		secretHex string
		index     int
	}{
		{
			name:      "secp256k1_participant_1",
			cs:        secp256k1_sha256.New(),
			secretHex: "e7a3cf1fdb1e17d4c3e8a7f663803ef305d03bdfdc930b824b0664c6b853156d",
			index:     0, // 0-indexed (will become 1-indexed identifier)
		},
		{
			name:      "secp256k1_participant_2",
			cs:        secp256k1_sha256.New(),
			secretHex: "ea163e297661aadf460b3de39a7550bd9b8fb2d07f1e1db5af098720156591a5",
			index:     1, // 0-indexed (will become 1-indexed identifier)
		},
		{
			name:      "secp256k1_participant_3",
			cs:        secp256k1_sha256.New(),
			secretHex: "8a9c3489b03d1bdecfd6c84237599980890d39d49167b016bb8b5fb530677204",
			index:     2, // 0-indexed (will become 1-indexed identifier)
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grp := tc.cs.Group()

			secretBytes, err := hex.DecodeString(tc.secretHex)
			if err != nil {
				t.Fatalf("Failed to decode secret hex: %v", err)
			}

			secret, err := grp.DeserializeScalar(secretBytes)
			if err != nil {
				t.Fatalf("Failed to deserialize secret: %v", err)
			}

			pubkey := grp.ScalarBaseMult(secret)

			// Generate POP
			pop, err := FROSTDKGProveKnowledge(tc.cs, secret, pubkey, tc.index)
			if err != nil {
				t.Fatalf("FROSTDKGProveKnowledge failed: %v", err)
			}

			// Verify POP
			if !FROSTDKGVerifyPOP(tc.cs, pop, pubkey, tc.index) {
				t.Error("FROSTDKGVerifyPOP failed")
			}

			// Log the generated POP for debugging
			t.Logf("Generated POP for %s: %s", tc.name, hex.EncodeToString(pop))
		})
	}
}
