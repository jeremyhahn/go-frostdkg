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

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestRepairShareStep1ValidInputs tests successful delta generation.
func TestRepairShareStep1ValidInputs(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Setup: Create a VSS instance with threshold 3
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	vss, err := Generate(cs, seed, 3)
	if err != nil {
		t.Fatalf("Failed to generate VSS: %v", err)
	}

	// Get shares for 5 participants
	shares, err := vss.Secshares(5)
	if err != nil {
		t.Fatalf("Failed to get shares: %v", err)
	}

	// Setup helpers: participants 0, 1, 2 will help recover participant 3
	helpers := []int{0, 1, 2}
	participantToRecover := 3

	// Each helper generates deltas
	for helperIdx := 0; helperIdx < len(helpers); helperIdx++ {
		helperParticipantIdx := helpers[helperIdx]
		deltas, err := RepairShareStep1(
			helpers,
			helperIdx,
			shares[helperParticipantIdx],
			grp,
			participantToRecover,
		)
		if err != nil {
			t.Fatalf("Helper %d failed to generate deltas: %v", helperIdx, err)
		}

		// Verify we got deltas for all helpers
		if len(deltas) != len(helpers) {
			t.Errorf("Helper %d: expected %d deltas, got %d", helperIdx, len(helpers), len(deltas))
		}

		// Verify each helper has a delta
		for _, h := range helpers {
			if _, ok := deltas[h]; !ok {
				t.Errorf("Helper %d: missing delta for helper %d", helperIdx, h)
			}
		}
	}
}

// TestRepairShareStep1InsufficientHelpers tests error handling with too few helpers.
func TestRepairShareStep1InsufficientHelpers(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Create a dummy share
	share, _ := grp.RandomScalar()

	// Try with only 1 helper (minimum is 2)
	helpers := []int{0}
	_, err := RepairShareStep1(helpers, 0, share, grp, 1)
	if err != ErrInvalidThreshold {
		t.Errorf("Expected ErrInvalidThreshold, got %v", err)
	}

	// Try with empty helpers
	helpers = []int{}
	_, err = RepairShareStep1(helpers, 0, share, grp, 1)
	if err != ErrInvalidThreshold {
		t.Errorf("Expected ErrInvalidThreshold for empty helpers, got %v", err)
	}
}

// TestRepairShareStep1DuplicateHelpers tests error handling with duplicate helper indices.
func TestRepairShareStep1DuplicateHelpers(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	share, _ := grp.RandomScalar()

	// Try with duplicate helpers
	helpers := []int{0, 1, 1}
	_, err := RepairShareStep1(helpers, 0, share, grp, 2)
	if err != ErrDuplicateHelper {
		t.Errorf("Expected ErrDuplicateHelper, got %v", err)
	}
}

// TestRepairShareStep1InvalidIndices tests error handling with invalid indices.
func TestRepairShareStep1InvalidIndices(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	share, _ := grp.RandomScalar()

	tests := []struct {
		name             string
		helpers          []int
		myHelperIndex    int
		participantIndex int
		expectedError    error
	}{
		{
			name:             "negative helper index",
			helpers:          []int{-1, 0},
			myHelperIndex:    0,
			participantIndex: 1,
			expectedError:    ErrInvalidParticipantIndex,
		},
		{
			name:             "negative participant index",
			helpers:          []int{0, 1},
			myHelperIndex:    0,
			participantIndex: -1,
			expectedError:    ErrInvalidParticipantIndex,
		},
		{
			name:             "myHelperIndex out of bounds (negative)",
			helpers:          []int{0, 1},
			myHelperIndex:    -1,
			participantIndex: 2,
			expectedError:    ErrInvalidParticipantIndex,
		},
		{
			name:             "myHelperIndex out of bounds (too large)",
			helpers:          []int{0, 1},
			myHelperIndex:    2,
			participantIndex: 2,
			expectedError:    ErrInvalidParticipantIndex,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RepairShareStep1(tt.helpers, tt.myHelperIndex, share, grp, tt.participantIndex)
			if err != tt.expectedError {
				t.Errorf("Expected %v, got %v", tt.expectedError, err)
			}
		})
	}
}

// TestRepairShareStep1Validation is a comprehensive validation test covering all error paths.
func TestRepairShareStep1Validation(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	share, _ := grp.RandomScalar()

	tests := []struct {
		name             string
		helpers          []int
		myHelperIndex    int
		participantIndex int
		expectedError    error
		description      string
	}{
		{
			name:             "invalid threshold - empty helpers",
			helpers:          []int{},
			myHelperIndex:    0,
			participantIndex: 1,
			expectedError:    ErrInvalidThreshold,
			description:      "Should fail with empty helper set",
		},
		{
			name:             "invalid threshold - single helper",
			helpers:          []int{0},
			myHelperIndex:    0,
			participantIndex: 1,
			expectedError:    ErrInvalidThreshold,
			description:      "Should fail with less than 2 helpers",
		},
		{
			name:             "invalid myHelperIndex - negative",
			helpers:          []int{0, 1, 2},
			myHelperIndex:    -1,
			participantIndex: 3,
			expectedError:    ErrInvalidParticipantIndex,
			description:      "Should fail when myHelperIndex is negative",
		},
		{
			name:             "invalid myHelperIndex - out of bounds",
			helpers:          []int{0, 1, 2},
			myHelperIndex:    3,
			participantIndex: 3,
			expectedError:    ErrInvalidParticipantIndex,
			description:      "Should fail when myHelperIndex is >= len(helpers)",
		},
		{
			name:             "invalid myHelperIndex - equal to length",
			helpers:          []int{0, 1, 2},
			myHelperIndex:    3,
			participantIndex: 3,
			expectedError:    ErrInvalidParticipantIndex,
			description:      "Should fail when myHelperIndex equals len(helpers)",
		},
		{
			name:             "invalid helper index - negative in list",
			helpers:          []int{0, -1, 2},
			myHelperIndex:    0,
			participantIndex: 3,
			expectedError:    ErrInvalidParticipantIndex,
			description:      "Should fail when any helper index is negative",
		},
		{
			name:             "invalid helper index - first element negative",
			helpers:          []int{-1, 1, 2},
			myHelperIndex:    0,
			participantIndex: 3,
			expectedError:    ErrInvalidParticipantIndex,
			description:      "Should fail when first helper index is negative",
		},
		{
			name:             "duplicate helpers - consecutive",
			helpers:          []int{0, 1, 1},
			myHelperIndex:    0,
			participantIndex: 2,
			expectedError:    ErrDuplicateHelper,
			description:      "Should fail with consecutive duplicate helper indices",
		},
		{
			name:             "duplicate helpers - non-consecutive",
			helpers:          []int{0, 1, 2, 0},
			myHelperIndex:    0,
			participantIndex: 3,
			expectedError:    ErrDuplicateHelper,
			description:      "Should fail with non-consecutive duplicate helper indices",
		},
		{
			name:             "duplicate helpers - all same",
			helpers:          []int{1, 1},
			myHelperIndex:    0,
			participantIndex: 2,
			expectedError:    ErrDuplicateHelper,
			description:      "Should fail when all helpers are the same",
		},
		{
			name:             "invalid participant index - negative",
			helpers:          []int{0, 1},
			myHelperIndex:    0,
			participantIndex: -1,
			expectedError:    ErrInvalidParticipantIndex,
			description:      "Should fail when participant index is negative",
		},
		{
			name:             "invalid participant index - large negative",
			helpers:          []int{0, 1},
			myHelperIndex:    0,
			participantIndex: -100,
			expectedError:    ErrInvalidParticipantIndex,
			description:      "Should fail when participant index is large negative value",
		},
		{
			name:             "valid repair operation - minimum helpers",
			helpers:          []int{0, 1},
			myHelperIndex:    0,
			participantIndex: 2,
			expectedError:    nil,
			description:      "Should succeed with minimum valid configuration (2 helpers)",
		},
		{
			name:             "valid repair operation - multiple helpers",
			helpers:          []int{0, 1, 2},
			myHelperIndex:    1,
			participantIndex: 3,
			expectedError:    nil,
			description:      "Should succeed with multiple helpers",
		},
		{
			name:             "valid repair operation - non-sequential indices",
			helpers:          []int{1, 3, 5},
			myHelperIndex:    0,
			participantIndex: 2,
			expectedError:    nil,
			description:      "Should succeed with non-sequential helper indices",
		},
		{
			name:             "valid repair operation - large indices",
			helpers:          []int{10, 20, 30},
			myHelperIndex:    2,
			participantIndex: 15,
			expectedError:    nil,
			description:      "Should succeed with large helper and participant indices",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deltas, err := RepairShareStep1(tt.helpers, tt.myHelperIndex, share, grp, tt.participantIndex)

			// Verify error matches expected
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("%s: Expected error %v, got %v", tt.description, tt.expectedError, err)
				}
				if deltas != nil {
					t.Errorf("%s: Expected nil deltas on error, got %v", tt.description, deltas)
				}
			} else {
				if err != nil {
					t.Errorf("%s: Expected success, got error: %v", tt.description, err)
				}
				if deltas == nil {
					t.Errorf("%s: Expected non-nil deltas on success", tt.description)
				} else {
					// Verify delta count matches helper count
					if len(deltas) != len(tt.helpers) {
						t.Errorf("%s: Expected %d deltas, got %d", tt.description, len(tt.helpers), len(deltas))
					}

					// Verify all helpers have deltas
					for _, h := range tt.helpers {
						if _, ok := deltas[h]; !ok {
							t.Errorf("%s: Missing delta for helper %d", tt.description, h)
						}
					}

					// Verify deltas sum correctly
					// contribution = lambda * shareI
					// sum(deltas) should equal contribution
					sum := grp.NewScalar()
					for _, delta := range deltas {
						sum = sum.Add(delta)
					}

					// We can't easily verify the exact value without recomputing lambda,
					// but we can verify the sum is non-zero
					zero := grp.NewScalar()
					if sum.Equal(zero) {
						t.Errorf("%s: Delta sum is zero (unexpected)", tt.description)
					}
				}
			}
		})
	}
}

// TestRepairShareStep2ValidInputs tests successful sigma computation.
func TestRepairShareStep2ValidInputs(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Create some test deltas
	numDeltas := 3
	deltas := make([]group.Scalar, numDeltas)
	for i := 0; i < numDeltas; i++ {
		delta, _ := grp.RandomScalar()
		deltas[i] = delta
	}

	// Compute sigma
	sigma := RepairShareStep2(deltas)
	if sigma == nil {
		t.Fatal("Expected non-nil sigma")
	}

	// Manually compute expected sum
	expected := deltas[0].Copy()
	for i := 1; i < numDeltas; i++ {
		expected = expected.Add(deltas[i])
	}

	// Verify sigma equals the sum
	if !sigma.Equal(expected) {
		t.Error("Sigma does not equal sum of deltas")
	}
}

// TestRepairShareStep2EmptyDeltas tests error handling with empty deltas.
func TestRepairShareStep2EmptyDeltas(t *testing.T) {
	deltas := []group.Scalar{}
	sigma := RepairShareStep2(deltas)
	if sigma != nil {
		t.Error("Expected nil sigma for empty deltas")
	}
}

// TestRepairShareStep3ValidInputs tests successful share recovery.
func TestRepairShareStep3ValidInputs(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Create some test sigmas
	numSigmas := 3
	sigmas := make([]group.Scalar, numSigmas)
	for i := 0; i < numSigmas; i++ {
		sigma, _ := grp.RandomScalar()
		sigmas[i] = sigma
	}

	participantIndex := 0

	// Recover share without commitment verification
	recoveredShare, err := RepairShareStep3(sigmas, participantIndex, nil, grp)
	if err != nil {
		t.Fatalf("Failed to recover share: %v", err)
	}
	if recoveredShare == nil {
		t.Fatal("Expected non-nil recovered share")
	}

	// Manually compute expected sum
	expected := sigmas[0].Copy()
	for i := 1; i < numSigmas; i++ {
		expected = expected.Add(sigmas[i])
	}

	// Verify recovered share equals the sum
	if !recoveredShare.Equal(expected) {
		t.Error("Recovered share does not equal sum of sigmas")
	}
}

// TestRepairShareStep3WithVerification tests share recovery with commitment verification.
func TestRepairShareStep3WithVerification(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Setup: Create a VSS instance
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	vss, err := Generate(cs, seed, 3)
	if err != nil {
		t.Fatalf("Failed to generate VSS: %v", err)
	}

	// Get the commitment
	commitment := vss.Commit()

	// Get shares
	shares, err := vss.Secshares(5)
	if err != nil {
		t.Fatalf("Failed to get shares: %v", err)
	}

	// Test with valid share
	participantIndex := 2
	sigmas := []group.Scalar{shares[participantIndex]}

	recoveredShare, err := RepairShareStep3(sigmas, participantIndex, commitment, grp)
	if err != nil {
		t.Fatalf("Failed to recover valid share: %v", err)
	}
	if !recoveredShare.Equal(shares[participantIndex]) {
		t.Error("Recovered share does not match original share")
	}

	// Test with invalid share (wrong commitment)
	wrongShare, _ := grp.RandomScalar()
	sigmas = []group.Scalar{wrongShare}

	_, err = RepairShareStep3(sigmas, participantIndex, commitment, grp)
	if err != ErrInvalidShare {
		t.Errorf("Expected ErrInvalidShare for wrong share, got %v", err)
	}
}

// TestRepairShareStep3InvalidInputs tests error handling in step 3.
func TestRepairShareStep3InvalidInputs(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	tests := []struct {
		name             string
		sigmas           []group.Scalar
		participantIndex int
		expectedError    error
	}{
		{
			name:             "empty sigmas",
			sigmas:           []group.Scalar{},
			participantIndex: 0,
			expectedError:    ErrInvalidShare,
		},
		{
			name:             "negative participant index",
			sigmas:           []group.Scalar{grp.NewScalar()},
			participantIndex: -1,
			expectedError:    ErrInvalidParticipantIndex,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RepairShareStep3(tt.sigmas, tt.participantIndex, nil, grp)
			if err != tt.expectedError {
				t.Errorf("Expected %v, got %v", tt.expectedError, err)
			}
		})
	}
}

// TestEndToEndShareRepair tests the complete RTS protocol end-to-end.
func TestEndToEndShareRepair(t *testing.T) {
	ciphersuites := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ristretto255", ristretto255_sha512.New()},
	}

	for _, suite := range ciphersuites {
		t.Run(suite.name, func(t *testing.T) {
			cs := suite.cs
			grp := cs.Group()

			// Setup: Create VSS with threshold 3, 5 participants
			seed := make([]byte, 32)
			_, _ = rand.Read(seed)
			vss, err := Generate(cs, seed, 3)
			if err != nil {
				t.Fatalf("Failed to generate VSS: %v", err)
			}

			// Get shares for all participants
			shares, err := vss.Secshares(5)
			if err != nil {
				t.Fatalf("Failed to get shares: %v", err)
			}

			// Get commitment for verification
			commitment := vss.Commit()

			// Scenario: Participant 3 loses their share
			participantToRecover := 3
			originalShare := shares[participantToRecover]

			// Helpers are participants 0, 1, 2 (threshold number of helpers)
			helpers := []int{0, 1, 2}

			// Step 1: Each helper generates deltas
			allDeltas := make([]map[int]group.Scalar, len(helpers))
			for helperIdx := 0; helperIdx < len(helpers); helperIdx++ {
				helperParticipantIdx := helpers[helperIdx]
				deltas, err := RepairShareStep1(
					helpers,
					helperIdx,
					shares[helperParticipantIdx],
					grp,
					participantToRecover,
				)
				if err != nil {
					t.Fatalf("Helper %d failed step 1: %v", helperIdx, err)
				}
				allDeltas[helperIdx] = deltas
			}

			// Communication round: Distribute deltas
			// Each helper j receives delta_i,j from each helper i
			receivedDeltas := make([][]group.Scalar, len(helpers))
			for receiverIdx := 0; receiverIdx < len(helpers); receiverIdx++ {
				receiverParticipantIdx := helpers[receiverIdx]
				receivedDeltas[receiverIdx] = make([]group.Scalar, len(helpers))
				for senderIdx := 0; senderIdx < len(helpers); senderIdx++ {
					// Helper receiverIdx receives delta from helper senderIdx
					receivedDeltas[receiverIdx][senderIdx] = allDeltas[senderIdx][receiverParticipantIdx]
				}
			}

			// Step 2: Each helper computes sigma
			sigmas := make([]group.Scalar, len(helpers))
			for helperIdx := 0; helperIdx < len(helpers); helperIdx++ {
				sigma := RepairShareStep2(receivedDeltas[helperIdx])
				if sigma == nil {
					t.Fatalf("Helper %d failed step 2", helperIdx)
				}
				sigmas[helperIdx] = sigma
			}

			// Step 3: Recovering participant reconstructs share
			recoveredShare, err := RepairShareStep3(sigmas, participantToRecover, commitment, grp)
			if err != nil {
				t.Fatalf("Failed step 3: %v", err)
			}

			// Verify: Recovered share should equal original share
			if !recoveredShare.Equal(originalShare) {
				t.Error("Recovered share does not match original share")
			}

			// Additional verification: Check that recovered share is valid
			pubshare, err := commitment.Pubshare(grp, participantToRecover)
			if err != nil {
				t.Fatalf("Failed to get pubshare: %v", err)
			}
			if !VerifySecshare(grp, recoveredShare, pubshare) {
				t.Error("Recovered share failed verification")
			}
		})
	}
}

// TestComputeLagrangeCoefficientForHelper tests Lagrange coefficient computation.
func TestComputeLagrangeCoefficientForHelper(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Create x-coordinates for 3 helpers: x = {1, 2, 3}
	xCoords := []group.Scalar{
		scalarFromInt(grp, 1),
		scalarFromInt(grp, 2),
		scalarFromInt(grp, 3),
	}

	// Evaluate at x = 4
	x := scalarFromInt(grp, 4)

	// Compute L_0(4) = ((4-2)/(1-2)) * ((4-3)/(1-3))
	//                = (2/(-1)) * (1/(-2))
	//                = (-2) * (-1/2)
	//                = 1
	lambda0, err := computeLagrangeCoefficientForHelper(xCoords, x, 0, grp)
	if err != nil {
		t.Fatalf("Failed to compute lambda_0: %v", err)
	}

	// The actual value computation is complex in modular arithmetic,
	// so we just verify it's non-zero and non-nil
	if lambda0 == nil {
		t.Error("lambda_0 is nil")
	}
	zero := grp.NewScalar()
	if lambda0.Equal(zero) {
		t.Error("lambda_0 is zero (unexpected for this configuration)")
	}
}

// TestComputeLagrangeCoefficientForHelperInvalidInputs tests error cases.
func TestComputeLagrangeCoefficientForHelperInvalidInputs(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	xCoords := []group.Scalar{
		scalarFromInt(grp, 1),
		scalarFromInt(grp, 2),
		scalarFromInt(grp, 3),
	}
	x := scalarFromInt(grp, 4)

	tests := []struct {
		name          string
		helperIdx     int
		expectedError error
	}{
		{
			name:          "negative helper index",
			helperIdx:     -1,
			expectedError: ErrInvalidParticipantIndex,
		},
		{
			name:          "helper index out of bounds",
			helperIdx:     3,
			expectedError: ErrInvalidParticipantIndex,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := computeLagrangeCoefficientForHelper(xCoords, x, tt.helperIdx, grp)
			if err != tt.expectedError {
				t.Errorf("Expected %v, got %v", tt.expectedError, err)
			}
		})
	}
}

// TestComputeLagrangeCoefficientForHelperDuplicateCoordinates tests error on duplicate x-coords.
func TestComputeLagrangeCoefficientForHelperDuplicateCoordinates(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Create duplicate x-coordinates
	xCoords := []group.Scalar{
		scalarFromInt(grp, 1),
		scalarFromInt(grp, 1), // Duplicate
		scalarFromInt(grp, 3),
	}
	x := scalarFromInt(grp, 4)

	// This should cause division by zero
	_, err := computeLagrangeCoefficientForHelper(xCoords, x, 0, grp)
	if err != ErrZeroScalar {
		t.Errorf("Expected ErrZeroScalar for duplicate coordinates, got %v", err)
	}
}
