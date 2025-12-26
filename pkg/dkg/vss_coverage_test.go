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
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestCommitmentToSecretEdgeCases tests CommitmentToSecret with nil and non-empty coefficients.
func TestCommitmentToSecretEdgeCases(t *testing.T) {
	cs := ed25519_sha512.New()

	t.Run("nil coefficients", func(t *testing.T) {
		vss := &VSSCommitment{
			Coefficients: nil,
		}

		result := vss.CommitmentToSecret()
		if result != nil {
			t.Error("CommitmentToSecret should return nil for nil coefficients")
		}
	})

	t.Run("empty coefficients", func(t *testing.T) {
		vss := &VSSCommitment{
			Coefficients: []group.Element{},
		}

		result := vss.CommitmentToSecret()
		if result != nil {
			t.Error("CommitmentToSecret should return nil for empty coefficients")
		}
	})

	t.Run("non-empty coefficients", func(t *testing.T) {
		// Generate a VSS with actual coefficients
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		vssObj, err := Generate(cs, seed, 3)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}

		vss := vssObj.Commit()

		result := vss.CommitmentToSecret()
		if result == nil {
			t.Error("CommitmentToSecret should return non-nil for non-empty coefficients")
		}
	})
}

// TestScalarFromIntEdgeCases tests scalarFromInt with various integer values.
func TestScalarFromIntEdgeCases(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	t.Run("zero value", func(t *testing.T) {
		result := scalarFromInt(grp, 0)
		if result == nil {
			t.Error("scalarFromInt should return non-nil scalar for 0")
		}

		// Verify it represents zero
		zero := grp.NewScalar()
		if !result.Equal(zero) {
			t.Error("scalarFromInt(0) should equal zero scalar")
		}
	})

	t.Run("small positive values", func(t *testing.T) {
		testCases := []int{1, 2, 5, 10, 100, 255, 256, 1000}

		for _, n := range testCases {
			result := scalarFromInt(grp, n)
			if result == nil {
				t.Errorf("scalarFromInt(%d) returned nil", n)
			}

			// Verify it's a valid scalar
			encoded := result.Bytes()
			if len(encoded) != grp.ScalarLength() {
				t.Errorf("scalarFromInt(%d) produced invalid scalar length", n)
			}
		}
	})

	t.Run("deterministic generation", func(t *testing.T) {
		n := 42
		result1 := scalarFromInt(grp, n)
		result2 := scalarFromInt(grp, n)

		if !result1.Equal(result2) {
			t.Error("scalarFromInt should be deterministic")
		}
	})
}

// TestVSSCommitmentVerifyEdgeCases tests share verification with edge cases.
func TestVSSCommitmentVerifyEdgeCases(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	vss, err := Generate(cs, seed, 3)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	commitment := vss.Commit()

	t.Run("verify with zero share", func(t *testing.T) {
		zeroShare := grp.NewScalar()
		pubshare, err := commitment.Pubshare(grp, 0)
		if err != nil {
			t.Fatalf("Pubshare failed: %v", err)
		}

		result := VerifySecshare(grp, zeroShare, pubshare)
		if result {
			t.Error("VerifySecshare should fail for zero share (unless it's the actual share)")
		}
	})

	t.Run("verify with negative index", func(t *testing.T) {
		share, _ := vss.SecshareFor(0)
		// Using negative index should return error from Pubshare
		_, err := commitment.Pubshare(grp, -1)
		if err == nil {
			t.Error("Pubshare should fail for negative index")
		}

		// If we did get a pubshare somehow, verify would fail
		if err == nil {
			// This branch won't be reached due to error above
			pubshare, _ := commitment.Pubshare(grp, -1)
			result := VerifySecshare(grp, share, pubshare)
			if result {
				t.Error("VerifySecshare should fail for negative index")
			}
		}
	})

	t.Run("verify correct share", func(t *testing.T) {
		index := 5
		share, err := vss.SecshareFor(index)
		if err != nil {
			t.Fatalf("SecshareFor failed: %v", err)
		}

		pubshare, err := commitment.Pubshare(grp, index)
		if err != nil {
			t.Fatalf("Pubshare failed: %v", err)
		}

		if !VerifySecshare(grp, share, pubshare) {
			t.Error("VerifySecshare should succeed for correct share")
		}
	})
}

// TestGenerateWithDifferentSeeds tests that different seeds produce different VSS instances.
func TestGenerateWithDifferentSeeds(t *testing.T) {
	cs := ed25519_sha512.New()

	seed1 := make([]byte, 32)
	seed2 := make([]byte, 32)

	for i := range seed1 {
		seed1[i] = byte(i)
		seed2[i] = byte(i + 1)
	}

	threshold := 3

	vss1, err := Generate(cs, seed1, threshold)
	if err != nil {
		t.Fatalf("Generate with seed1 failed: %v", err)
	}

	vss2, err := Generate(cs, seed2, threshold)
	if err != nil {
		t.Fatalf("Generate with seed2 failed: %v", err)
	}

	// Get shares
	share1, err := vss1.SecshareFor(0)
	if err != nil {
		t.Fatalf("SecshareFor from vss1 failed: %v", err)
	}

	share2, err := vss2.SecshareFor(0)
	if err != nil {
		t.Fatalf("SecshareFor from vss2 failed: %v", err)
	}

	// Shares should be different
	if share1.Equal(share2) {
		t.Error("Different seeds should produce different shares")
	}

	// Commitments should be different
	commitment1 := vss1.Commit()
	commitment2 := vss2.Commit()

	if len(commitment1.Coefficients) != len(commitment2.Coefficients) {
		t.Error("Commitments should have same length")
	}

	allEqual := true
	for i := range commitment1.Coefficients {
		if !commitment1.Coefficients[i].Equal(commitment2.Coefficients[i]) {
			allEqual = false
			break
		}
	}

	if allEqual {
		t.Error("Different seeds should produce different commitments")
	}
}

// TestGenerateWithDifferentThresholds tests VSS with different threshold values.
func TestGenerateWithDifferentThresholds(t *testing.T) {
	cs := ed25519_sha512.New()

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	testCases := []struct {
		name      string
		threshold int
	}{
		{"threshold 1", 1},
		{"threshold 2", 2},
		{"threshold 5", 5},
		{"threshold 10", 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vss, err := Generate(cs, seed, tc.threshold)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			commitment := vss.Commit()
			if len(commitment.Coefficients) != tc.threshold {
				t.Errorf("Expected %d coefficients, got %d", tc.threshold, len(commitment.Coefficients))
			}

			// Verify shares can be generated
			share, err := vss.SecshareFor(0)
			if err != nil {
				t.Errorf("SecshareFor failed: %v", err)
			}

			if share == nil || share.IsZero() {
				t.Error("Expected valid non-zero share")
			}

			// Verify commitment works
			pubshare, err := commitment.Pubshare(cs.Group(), 0)
			if err != nil {
				t.Fatalf("Pubshare failed: %v", err)
			}

			if !VerifySecshare(cs.Group(), share, pubshare) {
				t.Error("Share verification failed")
			}
		})
	}
}

// TestVSSMultipleParticipants tests VSS with varying numbers of participants.
func TestVSSMultipleParticipants(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	threshold := 3
	vss, err := Generate(cs, seed, threshold)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	commitment := vss.Commit()

	testCases := []int{1, 3, 5, 10, 20, 100}

	for _, numParticipants := range testCases {
		t.Run("participants", func(t *testing.T) {
			shares, err := vss.Secshares(numParticipants)
			if err != nil {
				t.Fatalf("Secshares(%d) failed: %v", numParticipants, err)
			}

			if len(shares) != numParticipants {
				t.Errorf("Expected %d shares, got %d", numParticipants, len(shares))
			}

			// Verify all shares
			for i := 0; i < numParticipants; i++ {
				if shares[i] == nil {
					t.Errorf("Share %d is nil", i)
					continue
				}

				if shares[i].IsZero() {
					t.Errorf("Share %d is zero", i)
					continue
				}

				pubshare, err := commitment.Pubshare(grp, i)
				if err != nil {
					t.Errorf("Pubshare(%d) failed: %v", i, err)
					continue
				}

				if !VerifySecshare(grp, shares[i], pubshare) {
					t.Errorf("Share %d failed verification", i)
				}
			}
		})
	}
}

// TestVSSShareUniqueness tests that all shares are unique.
func TestVSSShareUniqueness(t *testing.T) {
	cs := ed25519_sha512.New()

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	threshold := 3
	numParticipants := 10

	vss, err := Generate(cs, seed, threshold)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	shares, err := vss.Secshares(numParticipants)
	if err != nil {
		t.Fatalf("Secshares failed: %v", err)
	}

	// Check all shares are unique
	for i := 0; i < numParticipants; i++ {
		for j := i + 1; j < numParticipants; j++ {
			if shares[i].Equal(shares[j]) {
				t.Errorf("Shares %d and %d are equal", i, j)
			}
		}
	}
}

// TestVSSCommitmentSerialization tests that commitments can be serialized.
func TestVSSCommitmentSerialization(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	vss, err := Generate(cs, seed, 3)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	commitment := vss.Commit()

	// Serialize coefficients
	serialized := make([][]byte, len(commitment.Coefficients))
	for i, coeff := range commitment.Coefficients {
		data, err := grp.SerializeElement(coeff)
		if err != nil {
			t.Fatalf("SerializeElement failed: %v", err)
		}
		serialized[i] = data
	}

	// Deserialize coefficients
	deserialized := make([]group.Element, len(serialized))
	for i, data := range serialized {
		elem, err := grp.DeserializeElement(data)
		if err != nil {
			t.Fatalf("DeserializeElement failed: %v", err)
		}
		deserialized[i] = elem
	}

	// Verify deserialized matches original
	for i := range commitment.Coefficients {
		if !commitment.Coefficients[i].Equal(deserialized[i]) {
			t.Errorf("Coefficient %d mismatch after serialization", i)
		}
	}
}

// TestVSSEmptySeed tests VSS generation with empty seed.
func TestVSSEmptySeed(t *testing.T) {
	cs := ed25519_sha512.New()

	// Empty seed should still work
	seed := []byte{}
	threshold := 3

	vss, err := Generate(cs, seed, threshold)
	if err != nil {
		t.Fatalf("Generate with empty seed failed: %v", err)
	}

	share, err := vss.SecshareFor(0)
	if err != nil {
		t.Fatalf("SecshareFor failed: %v", err)
	}

	if share == nil || share.IsZero() {
		t.Error("Expected valid share even with empty seed")
	}
}

// TestVSSLargeSeed tests VSS generation with large seed.
func TestVSSLargeSeed(t *testing.T) {
	cs := ed25519_sha512.New()

	// Large seed
	seed := make([]byte, 1024)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	threshold := 3

	vss, err := Generate(cs, seed, threshold)
	if err != nil {
		t.Fatalf("Generate with large seed failed: %v", err)
	}

	share, err := vss.SecshareFor(0)
	if err != nil {
		t.Fatalf("SecshareFor failed: %v", err)
	}

	if share == nil || share.IsZero() {
		t.Error("Expected valid share with large seed")
	}
}
