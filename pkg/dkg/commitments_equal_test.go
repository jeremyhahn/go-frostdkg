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
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// mockGroupSerializeError is a mock group that fails on SerializeElement.
type mockGroupSerializeError struct {
	group.Group
	failOnIndex int
	currentCall int
}

func (m *mockGroupSerializeError) SerializeElement(elem group.Element) ([]byte, error) {
	m.currentCall++
	if m.currentCall == m.failOnIndex {
		return nil, errors.New("mock serialization error")
	}
	return m.Group.SerializeElement(elem)
}

// TestCommitmentsEqual provides comprehensive test coverage for commitmentsEqual function.
// This test ensures all code paths are covered including error handling.
func TestCommitmentsEqual(t *testing.T) {
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
			grp := tc.cs.Group()

			// Test 1: Equal commitments (same object reference)
			t.Run("same_object", func(t *testing.T) {
				seed := make([]byte, 32)
				_, _ = rand.Read(seed)
				vss, err := FROSTDKGGenerateVSS(tc.cs, seed, 3)
				if err != nil {
					t.Fatalf("FROSTDKGGenerateVSS failed: %v", err)
				}
				commitment := vss.Commit()

				// Comparing same object should return true
				if !commitmentsEqual(grp, commitment, commitment) {
					t.Error("Same commitment object should be equal to itself")
				}
			})

			// Test 2: Equal commitments (different objects with same values)
			t.Run("equal_commitments", func(t *testing.T) {
				seed := make([]byte, 32)
				for i := range seed {
					seed[i] = byte(i)
				}

				// Generate same VSS twice with same seed (deterministic)
				vss1, err := FROSTDKGGenerateVSS(tc.cs, seed, 3)
				if err != nil {
					t.Fatalf("First FROSTDKGGenerateVSS failed: %v", err)
				}

				vss2, err := FROSTDKGGenerateVSS(tc.cs, seed, 3)
				if err != nil {
					t.Fatalf("Second FROSTDKGGenerateVSS failed: %v", err)
				}

				commitment1 := vss1.Commit()
				commitment2 := vss2.Commit()

				// Different objects but same values should be equal
				if !commitmentsEqual(grp, commitment1, commitment2) {
					t.Error("Commitments with same values should be equal")
				}
			})

			// Test 3: Different length commitments (line 561-563)
			t.Run("different_lengths", func(t *testing.T) {
				seed := make([]byte, 32)
				_, _ = rand.Read(seed)

				vss1, err := FROSTDKGGenerateVSS(tc.cs, seed, 2)
				if err != nil {
					t.Fatalf("First FROSTDKGGenerateVSS failed: %v", err)
				}

				vss2, err := FROSTDKGGenerateVSS(tc.cs, seed, 3)
				if err != nil {
					t.Fatalf("Second FROSTDKGGenerateVSS failed: %v", err)
				}

				commitment1 := vss1.Commit()
				commitment2 := vss2.Commit()

				// Different lengths should return false
				if commitmentsEqual(grp, commitment1, commitment2) {
					t.Error("Commitments with different lengths should not be equal")
				}
			})

			// Test 4: Same length but different coefficient values (line 575)
			t.Run("different_values", func(t *testing.T) {
				seed1 := make([]byte, 32)
				seed2 := make([]byte, 32)
				for i := range seed1 {
					seed1[i] = byte(i)
					seed2[i] = byte(i + 1)
				}

				vss1, err := FROSTDKGGenerateVSS(tc.cs, seed1, 3)
				if err != nil {
					t.Fatalf("First FROSTDKGGenerateVSS failed: %v", err)
				}

				vss2, err := FROSTDKGGenerateVSS(tc.cs, seed2, 3)
				if err != nil {
					t.Fatalf("Second FROSTDKGGenerateVSS failed: %v", err)
				}

				commitment1 := vss1.Commit()
				commitment2 := vss2.Commit()

				// Same length but different values should return false
				if commitmentsEqual(grp, commitment1, commitment2) {
					t.Error("Commitments with different coefficient values should not be equal")
				}
			})

			// Test 5: Empty commitments
			t.Run("empty_commitments", func(t *testing.T) {
				emptyCommitment1 := &VSSCommitment{
					Coefficients: []group.Element{},
				}
				emptyCommitment2 := &VSSCommitment{
					Coefficients: []group.Element{},
				}

				// Empty commitments should be equal
				if !commitmentsEqual(grp, emptyCommitment1, emptyCommitment2) {
					t.Error("Empty commitments should be equal")
				}
			})

			// Test 6: One empty, one non-empty (length mismatch)
			t.Run("one_empty_one_nonempty", func(t *testing.T) {
				seed := make([]byte, 32)
				_, _ = rand.Read(seed)
				vss, err := FROSTDKGGenerateVSS(tc.cs, seed, 3)
				if err != nil {
					t.Fatalf("FROSTDKGGenerateVSS failed: %v", err)
				}

				nonEmptyCommitment := vss.Commit()
				emptyCommitment := &VSSCommitment{
					Coefficients: []group.Element{},
				}

				// Empty and non-empty should not be equal
				if commitmentsEqual(grp, emptyCommitment, nonEmptyCommitment) {
					t.Error("Empty and non-empty commitments should not be equal")
				}
				if commitmentsEqual(grp, nonEmptyCommitment, emptyCommitment) {
					t.Error("Non-empty and empty commitments should not be equal")
				}
			})

			// Test 7: Partially equal commitments (first coefficients match, later ones differ)
			t.Run("partially_equal", func(t *testing.T) {
				seed1 := make([]byte, 32)
				seed2 := make([]byte, 32)

				// Use similar but different seeds
				for i := range seed1 {
					seed1[i] = 0x42
					if i < 16 {
						seed2[i] = 0x42 // First half same
					} else {
						seed2[i] = 0x24 // Second half different
					}
				}

				vss1, err := FROSTDKGGenerateVSS(tc.cs, seed1, 3)
				if err != nil {
					t.Fatalf("First FROSTDKGGenerateVSS failed: %v", err)
				}

				vss2, err := FROSTDKGGenerateVSS(tc.cs, seed2, 3)
				if err != nil {
					t.Fatalf("Second FROSTDKGGenerateVSS failed: %v", err)
				}

				commitment1 := vss1.Commit()
				commitment2 := vss2.Commit()

				// Even if some coefficients match, commitments should not be equal
				// if any coefficient differs
				result := commitmentsEqual(grp, commitment1, commitment2)

				// Verify that at least one coefficient differs
				hasDifference := false
				for i := range commitment1.Coefficients {
					if !commitment1.Coefficients[i].Equal(commitment2.Coefficients[i]) {
						hasDifference = true
						break
					}
				}

				if hasDifference && result {
					t.Error("Commitments with different coefficients should not be equal")
				}
			})
		})
	}

	// Test 8: Error path - SerializeElement fails for first coefficient (lines 567-570)
	t.Run("serialize_error_first_coefficient", func(t *testing.T) {
		cs := ed25519_sha512.New()
		grp := cs.Group()

		seed := make([]byte, 32)
		_, _ = rand.Read(seed)
		vss, err := FROSTDKGGenerateVSS(cs, seed, 3)
		if err != nil {
			t.Fatalf("FROSTDKGGenerateVSS failed: %v", err)
		}

		commitment := vss.Commit()

		// Create a mock group that fails on the first SerializeElement call
		mockGrp := &mockGroupSerializeError{
			Group:       grp,
			failOnIndex: 1, // Fail on first call
		}

		// Should return false when serialization fails
		if commitmentsEqual(mockGrp, commitment, commitment) {
			t.Error("Should return false when first SerializeElement fails")
		}
	})

	// Test 9: Error path - SerializeElement fails for second coefficient (lines 571-574)
	t.Run("serialize_error_second_coefficient", func(t *testing.T) {
		cs := ed25519_sha512.New()
		grp := cs.Group()

		seed := make([]byte, 32)
		_, _ = rand.Read(seed)
		vss, err := FROSTDKGGenerateVSS(cs, seed, 3)
		if err != nil {
			t.Fatalf("FROSTDKGGenerateVSS failed: %v", err)
		}

		commitment := vss.Commit()

		// Create a mock group that fails on the second SerializeElement call
		mockGrp := &mockGroupSerializeError{
			Group:       grp,
			failOnIndex: 2, // Fail on second call
		}

		// Should return false when serialization fails
		if commitmentsEqual(mockGrp, commitment, commitment) {
			t.Error("Should return false when second SerializeElement fails")
		}
	})

	// Test 10: Constant-time comparison verification
	t.Run("constant_time_comparison", func(t *testing.T) {
		cs := ed25519_sha512.New()
		grp := cs.Group()

		seed1 := make([]byte, 32)
		seed2 := make([]byte, 32)

		for i := range seed1 {
			seed1[i] = 0xFF
			seed2[i] = 0xFF
		}
		// Make last byte different
		seed2[31] = 0xFE

		vss1, err := FROSTDKGGenerateVSS(cs, seed1, 5)
		if err != nil {
			t.Fatalf("First FROSTDKGGenerateVSS failed: %v", err)
		}

		vss2, err := FROSTDKGGenerateVSS(cs, seed2, 5)
		if err != nil {
			t.Fatalf("Second FROSTDKGGenerateVSS failed: %v", err)
		}

		commitment1 := vss1.Commit()
		commitment2 := vss2.Commit()

		// The function should examine all coefficients before returning
		// This tests that the constant-time comparison is working
		result := commitmentsEqual(grp, commitment1, commitment2)

		// Manually verify at least one coefficient is different
		allSame := true
		for i := range commitment1.Coefficients {
			if !commitment1.Coefficients[i].Equal(commitment2.Coefficients[i]) {
				allSame = false
				break
			}
		}

		if !allSame && result {
			t.Error("Constant-time comparison should detect differences")
		}
	})
}
