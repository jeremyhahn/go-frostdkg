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
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestNewVSSError tests error cases for NewVSS.
func TestNewVSSError(t *testing.T) {
	grp := ed25519_sha512.New().Group()

	t.Run("nil polynomial", func(t *testing.T) {
		vss, err := NewVSS(grp, nil)
		if err == nil {
			t.Error("Expected error for nil polynomial")
		}
		if err != ErrInvalidPolynomial {
			t.Errorf("Expected ErrInvalidPolynomial, got %v", err)
		}
		if vss != nil {
			t.Error("Expected nil VSS on error")
		}
	})
}

// TestSecshareForError tests error cases for SecshareFor.
func TestSecshareForError(t *testing.T) {
	cs := ed25519_sha512.New()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	vss, err := Generate(cs, seed, 3)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	t.Run("negative index", func(t *testing.T) {
		share, err := vss.SecshareFor(-1)
		if err == nil {
			t.Error("Expected error for negative index")
		}
		if err != ErrInvalidParticipantIndex {
			t.Errorf("Expected ErrInvalidParticipantIndex, got %v", err)
		}
		if share != nil {
			t.Error("Expected nil share on error")
		}
	})

	t.Run("valid index zero", func(t *testing.T) {
		share, err := vss.SecshareFor(0)
		if err != nil {
			t.Errorf("SecshareFor(0) failed: %v", err)
		}
		if share == nil {
			t.Error("Expected non-nil share for valid index")
		}
		if share.IsZero() {
			t.Error("Expected non-zero share")
		}
	})

	t.Run("valid large index", func(t *testing.T) {
		share, err := vss.SecshareFor(100)
		if err != nil {
			t.Errorf("SecshareFor(100) failed: %v", err)
		}
		if share == nil {
			t.Error("Expected non-nil share for valid index")
		}
	})
}

// TestSecsharesError tests error cases for Secshares.
func TestSecsharesError(t *testing.T) {
	cs := ed25519_sha512.New()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	vss, err := Generate(cs, seed, 3)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	t.Run("zero count", func(t *testing.T) {
		shares, err := vss.Secshares(0)
		if err == nil {
			t.Error("Expected error for zero count")
		}
		if shares != nil {
			t.Error("Expected nil shares on error")
		}
	})

	t.Run("negative count", func(t *testing.T) {
		shares, err := vss.Secshares(-1)
		if err == nil {
			t.Error("Expected error for negative count")
		}
		if shares != nil {
			t.Error("Expected nil shares on error")
		}
	})

	t.Run("valid count", func(t *testing.T) {
		n := 5
		shares, err := vss.Secshares(n)
		if err != nil {
			t.Errorf("Secshares(%d) failed: %v", n, err)
		}
		if len(shares) != n {
			t.Errorf("Expected %d shares, got %d", n, len(shares))
		}
		for i, share := range shares {
			if share == nil {
				t.Errorf("Share %d is nil", i)
			}
			if share.IsZero() {
				t.Errorf("Share %d is zero", i)
			}
		}
	})
}

// TestCommitMethod tests the Commit method.
func TestCommitMethod(t *testing.T) {
	cs := ed25519_sha512.New()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	t.Run("valid commit", func(t *testing.T) {
		vss, err := Generate(cs, seed, 3)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		commitment := vss.Commit()
		if commitment == nil {
			t.Error("Expected non-nil commitment")
			return
		}
		if len(commitment.Coefficients) == 0 {
			t.Error("Expected non-empty coefficients in commitment")
		}
	})
}

// TestVerifyMethod tests share verification with VSSCommitment.
func TestVerifyMethod(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	vss, err := Generate(cs, seed, 3)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	commitment := vss.Commit()

	t.Run("valid share verification", func(t *testing.T) {
		index := 0
		share, err := vss.SecshareFor(index)
		if err != nil {
			t.Fatalf("SecshareFor failed: %v", err)
		}
		pubshare, err := commitment.Pubshare(grp, index)
		if err != nil {
			t.Fatalf("Pubshare failed: %v", err)
		}
		if !VerifySecshare(grp, share, pubshare) {
			t.Error("Valid share failed verification")
		}
	})

	t.Run("invalid share verification", func(t *testing.T) {
		index := 0
		share, err := vss.SecshareFor(index)
		if err != nil {
			t.Fatalf("SecshareFor failed: %v", err)
		}
		// Get pubshare for different index
		pubshare, err := commitment.Pubshare(grp, index+1)
		if err != nil {
			t.Fatalf("Pubshare failed: %v", err)
		}
		// Verify with different pubshare should fail
		if VerifySecshare(grp, share, pubshare) {
			t.Error("Invalid share passed verification")
		}
	})

	t.Run("zero share verification", func(t *testing.T) {
		index := 0
		pubshare, err := commitment.Pubshare(grp, index)
		if err != nil {
			t.Fatalf("Pubshare failed: %v", err)
		}
		zeroShare := grp.NewScalar()
		if VerifySecshare(grp, zeroShare, pubshare) {
			t.Error("Zero share should not verify")
		}
	})
}

// TestGenerateError tests error cases for Generate.
func TestGenerateError(t *testing.T) {
	cs := ed25519_sha512.New()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	t.Run("zero threshold", func(t *testing.T) {
		vss, err := Generate(cs, seed, 0)
		if err == nil {
			t.Error("Expected error for zero threshold")
		}
		if err != ErrInvalidThreshold {
			t.Errorf("Expected ErrInvalidThreshold, got %v", err)
		}
		if vss != nil {
			t.Error("Expected nil VSS on error")
		}
	})

	t.Run("negative threshold", func(t *testing.T) {
		vss, err := Generate(cs, seed, -1)
		if err == nil {
			t.Error("Expected error for negative threshold")
		}
		if vss != nil {
			t.Error("Expected nil VSS on error")
		}
	})

	t.Run("valid threshold", func(t *testing.T) {
		vss, err := Generate(cs, seed, 3)
		if err != nil {
			t.Errorf("Generate with valid threshold failed: %v", err)
		}
		if vss == nil {
			t.Error("Expected non-nil VSS")
		}
	})
}

// TestVSSEndToEnd tests a complete VSS workflow.
func TestVSSEndToEnd(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()
	threshold := 3
	numParticipants := 5
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	// Generate VSS
	vss, err := Generate(cs, seed, threshold)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Get commitment
	commitment := vss.Commit()
	if commitment == nil {
		t.Fatal("Commit returned nil")
	}

	// Generate shares
	shares, err := vss.Secshares(numParticipants)
	if err != nil {
		t.Fatalf("Secshares failed: %v", err)
	}
	if len(shares) != numParticipants {
		t.Fatalf("Expected %d shares, got %d", numParticipants, len(shares))
	}

	// Verify all shares
	for i := 0; i < numParticipants; i++ {
		pubshare, err := commitment.Pubshare(grp, i)
		if err != nil {
			t.Fatalf("Pubshare(%d) failed: %v", i, err)
		}
		if !VerifySecshare(grp, shares[i], pubshare) {
			t.Errorf("Share %d failed verification", i)
		}
	}

	// Verify commitment to secret
	secret := commitment.CommitmentToSecret()
	if secret == nil {
		t.Error("CommitmentToSecret returned nil")
	}
}

// TestVSSDeterminism tests that VSS generation is deterministic.
func TestVSSDeterminism(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold := 3
	numShares := 5
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	// Generate two VSS instances with same seed
	vss1, err := Generate(cs, seed, threshold)
	if err != nil {
		t.Fatalf("Generate 1 failed: %v", err)
	}
	vss2, err := Generate(cs, seed, threshold)
	if err != nil {
		t.Fatalf("Generate 2 failed: %v", err)
	}

	// Get shares from both
	shares1, err := vss1.Secshares(numShares)
	if err != nil {
		t.Fatalf("Secshares 1 failed: %v", err)
	}
	shares2, err := vss2.Secshares(numShares)
	if err != nil {
		t.Fatalf("Secshares 2 failed: %v", err)
	}

	// Compare shares
	if len(shares1) != len(shares2) {
		t.Fatalf("Share count mismatch: %d vs %d", len(shares1), len(shares2))
	}
	for i := range shares1 {
		if !shares1[i].Equal(shares2[i]) {
			t.Errorf("Share %d differs between instances", i)
		}
	}

	// Compare commitments
	commitment1 := vss1.Commit()
	commitment2 := vss2.Commit()
	if len(commitment1.Coefficients) != len(commitment2.Coefficients) {
		t.Fatal("Commitment coefficient count mismatch")
	}
	for i := range commitment1.Coefficients {
		if !commitment1.Coefficients[i].Equal(commitment2.Coefficients[i]) {
			t.Errorf("Commitment coefficient %d differs between instances", i)
		}
	}
}

// TestVSSCommitmentFromBytes tests serialization and deserialization of commitments.
func TestVSSCommitmentFromBytes(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	vss, _ := Generate(cs, seed, 3)
	commitment := vss.Commit()

	t.Run("round_trip", func(t *testing.T) {
		bytes, err := commitment.ToBytes(grp)
		if err != nil {
			t.Fatalf("ToBytes failed: %v", err)
		}

		restored, err := VSSCommitmentFromBytes(grp, bytes, commitment.Threshold())
		if err != nil {
			t.Fatalf("VSSCommitmentFromBytes failed: %v", err)
		}

		if len(restored.Coefficients) != len(commitment.Coefficients) {
			t.Fatalf("Coefficient count mismatch: got %d, want %d",
				len(restored.Coefficients), len(commitment.Coefficients))
		}

		for i := range commitment.Coefficients {
			if !commitment.Coefficients[i].Equal(restored.Coefficients[i]) {
				t.Errorf("Coefficient %d mismatch", i)
			}
		}
	})

	t.Run("invalid_length", func(t *testing.T) {
		bytes := make([]byte, 10) // Wrong length
		_, err := VSSCommitmentFromBytes(grp, bytes, 3)
		if err != ErrInvalidCommitmentLength {
			t.Errorf("Expected ErrInvalidCommitmentLength, got %v", err)
		}
	})

	t.Run("empty_bytes_with_nonzero_threshold", func(t *testing.T) {
		// Empty bytes with threshold > 0 should fail
		_, err := VSSCommitmentFromBytes(grp, []byte{}, 2)
		if err != ErrInvalidCommitmentLength {
			t.Errorf("Expected ErrInvalidCommitmentLength, got %v", err)
		}
	})

	t.Run("zero_threshold_empty_bytes", func(t *testing.T) {
		// Empty bytes with threshold 0 is technically valid (0 * elemLen = 0)
		result, err := VSSCommitmentFromBytes(grp, []byte{}, 0)
		if err != nil {
			t.Errorf("Unexpected error for zero threshold: %v", err)
		}
		if result == nil {
			t.Error("Expected non-nil result for valid (though degenerate) input")
		}
	})

	t.Run("identity_element", func(t *testing.T) {
		// Create commitment with identity element (zeros)
		elemLen := grp.ElementLength()
		zeros := make([]byte, elemLen*2)
		restored, err := VSSCommitmentFromBytes(grp, zeros, 2)
		if err != nil {
			t.Fatalf("VSSCommitmentFromBytes failed: %v", err)
		}
		if len(restored.Coefficients) != 2 {
			t.Errorf("Expected 2 coefficients, got %d", len(restored.Coefficients))
		}
		// First coefficient should be identity
		if !restored.Coefficients[0].IsIdentity() {
			t.Error("Expected first coefficient to be identity")
		}
	})
}

// TestCommitmentToNonconstTerms tests extracting non-constant terms.
func TestCommitmentToNonconstTerms(t *testing.T) {
	cs := ed25519_sha512.New()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	t.Run("threshold_3", func(t *testing.T) {
		vss, _ := Generate(cs, seed, 3)
		commitment := vss.Commit()

		nonconst := commitment.CommitmentToNonconstTerms()
		if len(nonconst) != 2 {
			t.Errorf("Expected 2 non-constant terms, got %d", len(nonconst))
		}

		// Verify they match the original coefficients (excluding C_0)
		for i := 0; i < len(nonconst); i++ {
			if !nonconst[i].Equal(commitment.Coefficients[i+1]) {
				t.Errorf("Non-constant term %d doesn't match original", i)
			}
		}
	})

	t.Run("threshold_1", func(t *testing.T) {
		// Create a polynomial with only constant term
		grp := cs.Group()
		secret, _ := grp.RandomScalar()
		poly, err := NewPolynomial(grp, []group.Scalar{secret})
		if err != nil {
			t.Fatalf("NewPolynomial failed: %v", err)
		}
		vss, _ := NewVSS(grp, poly)
		commitment := vss.Commit()

		nonconst := commitment.CommitmentToNonconstTerms()
		if len(nonconst) != 0 {
			t.Errorf("Expected 0 non-constant terms, got %d", len(nonconst))
		}
	})

	t.Run("empty_commitment", func(t *testing.T) {
		commitment := &VSSCommitment{Coefficients: []group.Element{}}
		nonconst := commitment.CommitmentToNonconstTerms()
		if len(nonconst) != 0 {
			t.Errorf("Expected 0 non-constant terms, got %d", len(nonconst))
		}
	})
}

// TestCommitmentToSecretEmpty tests CommitmentToSecret with empty commitment.
func TestCommitmentToSecretEmpty(t *testing.T) {
	commitment := &VSSCommitment{Coefficients: []group.Element{}}
	secret := commitment.CommitmentToSecret()
	if secret != nil {
		t.Error("Expected nil for empty commitment")
	}
}

// TestVSSCommitmentToBytesComprehensive tests comprehensive scenarios for ToBytes.
func TestVSSCommitmentToBytesComprehensive(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	t.Run("valid_serialization", func(t *testing.T) {
		vss, err := Generate(cs, seed, 3)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		commitment := vss.Commit()

		bytes, err := commitment.ToBytes(grp)
		if err != nil {
			t.Fatalf("ToBytes failed: %v", err)
		}

		expectedLen := 3 * grp.ElementLength()
		if len(bytes) != expectedLen {
			t.Errorf("Expected %d bytes, got %d", expectedLen, len(bytes))
		}

		// Verify we can deserialize it back
		restored, err := VSSCommitmentFromBytes(grp, bytes, 3)
		if err != nil {
			t.Fatalf("VSSCommitmentFromBytes failed: %v", err)
		}

		for i := range commitment.Coefficients {
			if !commitment.Coefficients[i].Equal(restored.Coefficients[i]) {
				t.Errorf("Coefficient %d mismatch after round-trip", i)
			}
		}
	})

	t.Run("empty_commitment", func(t *testing.T) {
		commitment := &VSSCommitment{Coefficients: []group.Element{}}
		bytes, err := commitment.ToBytes(grp)
		if err != nil {
			t.Fatalf("ToBytes failed for empty commitment: %v", err)
		}

		if len(bytes) != 0 {
			t.Errorf("Expected 0 bytes for empty commitment, got %d", len(bytes))
		}

		// Verify round-trip
		restored, err := VSSCommitmentFromBytes(grp, bytes, 0)
		if err != nil {
			t.Fatalf("VSSCommitmentFromBytes failed: %v", err)
		}
		if len(restored.Coefficients) != 0 {
			t.Errorf("Expected 0 coefficients, got %d", len(restored.Coefficients))
		}
	})

	t.Run("large_commitment", func(t *testing.T) {
		// Create a large commitment with threshold of 10
		vss, err := Generate(cs, seed, 10)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		commitment := vss.Commit()

		bytes, err := commitment.ToBytes(grp)
		if err != nil {
			t.Fatalf("ToBytes failed for large commitment: %v", err)
		}

		expectedLen := 10 * grp.ElementLength()
		if len(bytes) != expectedLen {
			t.Errorf("Expected %d bytes, got %d", expectedLen, len(bytes))
		}

		// Verify round-trip
		restored, err := VSSCommitmentFromBytes(grp, bytes, 10)
		if err != nil {
			t.Fatalf("VSSCommitmentFromBytes failed: %v", err)
		}

		if len(restored.Coefficients) != 10 {
			t.Errorf("Expected 10 coefficients, got %d", len(restored.Coefficients))
		}

		for i := range commitment.Coefficients {
			if !commitment.Coefficients[i].Equal(restored.Coefficients[i]) {
				t.Errorf("Coefficient %d mismatch in large commitment", i)
			}
		}
	})

	t.Run("commitment_with_identity_elements", func(t *testing.T) {
		// Create a commitment with identity elements
		identity := grp.Identity()
		generator := grp.Generator()

		commitment := &VSSCommitment{
			Coefficients: []group.Element{
				identity,
				generator,
				identity,
			},
		}

		bytes, err := commitment.ToBytes(grp)
		if err != nil {
			t.Fatalf("ToBytes failed with identity elements: %v", err)
		}

		expectedLen := 3 * grp.ElementLength()
		if len(bytes) != expectedLen {
			t.Errorf("Expected %d bytes, got %d", expectedLen, len(bytes))
		}

		// Verify the first element is serialized as zeros
		elemLen := grp.ElementLength()
		firstElem := bytes[0:elemLen]
		allZeros := true
		for _, b := range firstElem {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if !allZeros {
			t.Error("Expected identity element to be serialized as all zeros")
		}

		// Verify round-trip
		restored, err := VSSCommitmentFromBytes(grp, bytes, 3)
		if err != nil {
			t.Fatalf("VSSCommitmentFromBytes failed: %v", err)
		}

		if !restored.Coefficients[0].IsIdentity() {
			t.Error("Expected first coefficient to be identity after round-trip")
		}
		if !restored.Coefficients[1].Equal(generator) {
			t.Error("Expected second coefficient to match generator")
		}
		if !restored.Coefficients[2].IsIdentity() {
			t.Error("Expected third coefficient to be identity after round-trip")
		}
	})

	t.Run("single_coefficient", func(t *testing.T) {
		// Create VSS with threshold 1 (single coefficient)
		vss, err := Generate(cs, seed, 1)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		commitment := vss.Commit()

		bytes, err := commitment.ToBytes(grp)
		if err != nil {
			t.Fatalf("ToBytes failed for single coefficient: %v", err)
		}

		expectedLen := grp.ElementLength()
		if len(bytes) != expectedLen {
			t.Errorf("Expected %d bytes, got %d", expectedLen, len(bytes))
		}

		// Verify round-trip
		restored, err := VSSCommitmentFromBytes(grp, bytes, 1)
		if err != nil {
			t.Fatalf("VSSCommitmentFromBytes failed: %v", err)
		}

		if len(restored.Coefficients) != 1 {
			t.Errorf("Expected 1 coefficient, got %d", len(restored.Coefficients))
		}

		if !commitment.Coefficients[0].Equal(restored.Coefficients[0]) {
			t.Error("Single coefficient mismatch after round-trip")
		}
	})
}

// TestScalarFromIntComprehensive tests comprehensive scenarios for scalarFromInt.
func TestScalarFromIntComprehensive(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	t.Run("zero_value", func(t *testing.T) {
		scalar := scalarFromInt(grp, 0)
		if scalar == nil {
			t.Fatal("Expected non-nil scalar for zero")
		}
		if !scalar.IsZero() {
			t.Error("Expected zero scalar")
		}
	})

	t.Run("positive_value_one", func(t *testing.T) {
		scalar := scalarFromInt(grp, 1)
		if scalar == nil {
			t.Fatal("Expected non-nil scalar for one")
		}
		if scalar.IsZero() {
			t.Error("Expected non-zero scalar for one")
		}

		// Verify it behaves as 1 by multiplying with generator
		expected := grp.Generator()
		actual := grp.ScalarBaseMult(scalar)
		if !expected.Equal(actual) {
			t.Error("Scalar 1 * G should equal G")
		}
	})

	t.Run("positive_value_small", func(t *testing.T) {
		testValues := []int{2, 5, 10, 42, 100, 255}
		for _, n := range testValues {
			t.Run("", func(t *testing.T) {
				scalar := scalarFromInt(grp, n)
				if scalar == nil {
					t.Fatalf("Expected non-nil scalar for %d", n)
				}
				if scalar.IsZero() {
					t.Errorf("Expected non-zero scalar for %d", n)
				}

				// Verify the value by converting back
				// We can test by adding scalar 1 n times
				one := scalarFromInt(grp, 1)
				sum := grp.NewScalar()
				for i := 0; i < n; i++ {
					sum = sum.Add(one)
				}
				if !scalar.Equal(sum) {
					t.Errorf("Scalar %d doesn't match expected value", n)
				}
			})
		}
	})

	t.Run("positive_value_large", func(t *testing.T) {
		// Test larger values that fit in multiple bytes
		testValues := []int{256, 1000, 65535, 100000, 1000000}
		for _, n := range testValues {
			t.Run("", func(t *testing.T) {
				scalar := scalarFromInt(grp, n)
				if scalar == nil {
					t.Fatalf("Expected non-nil scalar for %d", n)
				}
				if scalar.IsZero() {
					t.Errorf("Expected non-zero scalar for %d", n)
				}

				// Serialize and verify it's not all zeros
				bytes := grp.SerializeScalar(scalar)

				allZeros := true
				for _, b := range bytes {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Errorf("Scalar %d serialized to all zeros", n)
				}
			})
		}
	})

	t.Run("negative_value_panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for negative value")
			} else {
				errMsg, ok := r.(string)
				if !ok || errMsg != "scalarFromInt: negative integer not allowed" {
					t.Errorf("Expected specific panic message, got: %v", r)
				}
			}
		}()

		scalarFromInt(grp, -1)
	})

	t.Run("byte_order_consistency", func(t *testing.T) {
		// Test that values are correctly encoded regardless of byte order
		value := 0x1234
		scalar := scalarFromInt(grp, value)
		if scalar == nil {
			t.Fatal("Expected non-nil scalar")
		}

		// Use scalar in computation and verify it works correctly
		// For example, scalar * 2 should equal scalarFromInt(value * 2)
		two := scalarFromInt(grp, 2)
		doubleScalar := scalar.Mul(two)
		expectedDouble := scalarFromInt(grp, value*2)

		if !doubleScalar.Equal(expectedDouble) {
			t.Error("Byte order inconsistency detected")
		}
	})

	t.Run("sequential_values", func(t *testing.T) {
		// Test sequential values maintain proper ordering
		prev := scalarFromInt(grp, 0)
		one := scalarFromInt(grp, 1)

		for i := 1; i <= 10; i++ {
			current := scalarFromInt(grp, i)
			// current should equal prev + 1
			expected := prev.Add(one)
			if !current.Equal(expected) {
				t.Errorf("Sequential value %d doesn't match prev + 1", i)
			}
			prev = current
		}
	})

	t.Run("power_of_two_values", func(t *testing.T) {
		// Test powers of 2 which stress byte boundaries
		for power := 0; power < 20; power++ {
			value := 1 << power
			scalar := scalarFromInt(grp, value)
			if scalar == nil {
				t.Fatalf("Expected non-nil scalar for 2^%d", power)
			}
			if scalar.IsZero() {
				t.Errorf("Expected non-zero scalar for 2^%d", power)
			}
		}
	})

	t.Run("max_safe_value", func(t *testing.T) {
		// Test a large but safe value (well below group order)
		// Using 2^30 which is safe for all common curves
		value := 1 << 30
		scalar := scalarFromInt(grp, value)
		if scalar == nil {
			t.Fatal("Expected non-nil scalar for large value")
		}
		if scalar.IsZero() {
			t.Error("Expected non-zero scalar for large value")
		}
	})
}
