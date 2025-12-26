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
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestFROSTDKGFullProtocol tests the complete FROST-DKG protocol end-to-end.
func TestFROSTDKGFullProtocol(t *testing.T) {
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
			runFullDKGTest(t, tc.cs, 2, 3)
		})
	}
}

// TestFROSTDKGDifferentThresholds tests DKG with various threshold configurations.
func TestFROSTDKGDifferentThresholds(t *testing.T) {
	cs := ed25519_sha512.New()

	testCases := []struct {
		name string
		t, n int
	}{
		// Note: t=1 is not allowed per Zcash FROST (min_signers >= 2)
		{"t2_n2", 2, 2}, // minimum valid configuration
		{"t2_n3", 2, 3},
		{"t2_n4", 2, 4},
		{"t3_n5", 3, 5},
		{"t5_n5", 5, 5}, // max threshold
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runFullDKGTest(t, cs, tc.t, tc.n)
		})
	}
}

// runFullDKGTest runs a complete DKG protocol with the given parameters.
func runFullDKGTest(t *testing.T, cs ciphersuite.Ciphersuite, threshold, n int) {
	t.Helper()

	grp := cs.Group()

	// Generate seeds for each participant
	seeds := make([][]byte, n)
	for i := 0; i < n; i++ {
		seeds[i] = make([]byte, 32)
		_, err := rand.Read(seeds[i])
		if err != nil {
			t.Fatalf("Failed to generate seed for participant %d: %v", i, err)
		}
	}

	// Round 1: Each participant generates their state and message
	states := make([]*FROSTDKGParticipantState, n)
	msgs := make([]*FROSTDKGParticipantMsg, n)
	allShares := make([][]group.Scalar, n) // allShares[sender][receiver]

	for i := 0; i < n; i++ {
		state, msg, shares, err := FROSTDKGParticipantRound1(cs, seeds[i], threshold, n, i)
		if err != nil {
			t.Fatalf("Participant %d Round1 failed: %v", i, err)
		}
		states[i] = state
		msgs[i] = msg
		allShares[i] = shares
	}

	// Coordinator aggregates Round 1 messages
	coordMsg, err := FROSTDKGCoordinatorRound1(cs, msgs, threshold, n)
	if err != nil {
		t.Fatalf("Coordinator Round1 failed: %v", err)
	}

	// Round 2: Each participant processes coordinator message
	outputs := make([]*FROSTDKGOutput, n)
	eqInputs := make([][]byte, n)

	for i := 0; i < n; i++ {
		// Collect shares that this participant receives (from all other participants)
		receivedShares := make([]group.Scalar, n)
		for sender := 0; sender < n; sender++ {
			receivedShares[sender] = allShares[sender][i]
		}

		output, eqInput, err := FROSTDKGParticipantRound2(cs, states[i], coordMsg, receivedShares)
		if err != nil {
			t.Fatalf("Participant %d Round2 failed: %v", i, err)
		}
		outputs[i] = output
		eqInputs[i] = eqInput
	}

	// Verify all participants got the same threshold public key
	for i := 1; i < n; i++ {
		if !outputs[0].ThresholdPubkey.Equal(outputs[i].ThresholdPubkey) {
			t.Errorf("Participant %d has different threshold pubkey than participant 0", i)
		}
	}

	// Verify all participants got the same equality input
	for i := 1; i < n; i++ {
		if string(eqInputs[0]) != string(eqInputs[i]) {
			t.Errorf("Participant %d has different eqInput than participant 0", i)
		}
	}

	// Verify public shares are consistent
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if !outputs[i].PublicShares[j].Equal(outputs[0].PublicShares[j]) {
				t.Errorf("Public share %d differs between participants %d and 0", j, i)
			}
		}
	}

	// Verify secret share corresponds to public share for each participant
	for i := 0; i < n; i++ {
		expectedPub := grp.ScalarBaseMult(outputs[i].SecretShare)
		if !expectedPub.Equal(outputs[i].PublicShares[i]) {
			t.Errorf("Participant %d secret share doesn't match public share", i)
		}
	}

	t.Logf("DKG successful: threshold=%d, participants=%d", threshold, n)
}

// TestFROSTDKGParticipantRound1Errors tests error handling in Round 1.
func TestFROSTDKGParticipantRound1Errors(t *testing.T) {
	cs := ed25519_sha512.New()
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)

	testCases := []struct {
		name      string
		t, n, idx int
		wantErr   error
	}{
		// Zcash FROST aligned validation errors
		{"threshold_below_min", 1, 3, 0, ErrInvalidMinSigners}, // t < 2
		{"negative_threshold", -1, 3, 0, ErrInvalidMinSigners}, // t < 2
		{"zero_threshold", 0, 3, 0, ErrInvalidMinSigners},      // t < 2
		{"threshold_exceeds_n", 4, 3, 0, ErrFROSTDKGInvalidThreshold},
		{"n_below_min", 2, 1, 0, ErrInvalidMaxSigners}, // n < 2
		{"negative_n", 2, -1, 0, ErrInvalidMaxSigners}, // n < 2
		{"zero_n", 2, 0, 0, ErrInvalidMaxSigners},      // n < 2
		{"negative_index", 2, 3, -1, ErrInvalidParticipantIndex},
		{"index_exceeds_n", 2, 3, 3, ErrInvalidParticipantIndex},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := FROSTDKGParticipantRound1(cs, seed, tc.t, tc.n, tc.idx)
			if err != tc.wantErr {
				t.Errorf("Expected error %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestFROSTDKGParticipantRound1Comprehensive provides comprehensive coverage of Round 1.
func TestFROSTDKGParticipantRound1Comprehensive(t *testing.T) {
	// Test all ciphersuites with various configurations
	ciphersuites := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	configurations := []struct {
		name string
		t, n int
	}{
		{"min_config_t2_n2", 2, 2},     // minimum valid: t=n=2
		{"basic_t2_n3", 2, 3},          // basic 2-of-3
		{"basic_t2_n4", 2, 4},          // basic 2-of-4
		{"moderate_t3_n5", 3, 5},       // moderate 3-of-5
		{"equal_t3_n3", 3, 3},          // t=n edge case
		{"high_threshold_t4_n5", 4, 5}, // high threshold 4-of-5
		{"max_threshold_t5_n5", 5, 5},  // maximum threshold t=n
		{"large_group_t3_n10", 3, 10},  // larger group
		{"majority_t7_n10", 7, 10},     // high majority threshold
	}

	for _, csTest := range ciphersuites {
		t.Run(csTest.name, func(t *testing.T) {
			for _, config := range configurations {
				t.Run(config.name, func(t *testing.T) {
					testRound1Configuration(t, csTest.cs, config.t, config.n)
				})
			}
		})
	}
}

// testRound1Configuration tests a specific Round 1 configuration.
func testRound1Configuration(t *testing.T, cs ciphersuite.Ciphersuite, threshold, n int) {
	t.Helper()

	grp := cs.Group()

	// Test each participant index
	for index := 0; index < n; index++ {
		seed := make([]byte, 32)
		_, err := rand.Read(seed)
		if err != nil {
			t.Fatalf("Failed to generate seed: %v", err)
		}

		state, msg, shares, err := FROSTDKGParticipantRound1(cs, seed, threshold, n, index)
		if err != nil {
			t.Fatalf("Round1 failed for index %d: %v", index, err)
		}

		// Verify state is properly initialized
		if state == nil {
			t.Fatal("State should not be nil")
		}
		if state.Ciphersuite != cs {
			t.Error("State ciphersuite mismatch")
		}
		if state.Index != index {
			t.Errorf("State index = %d, want %d", state.Index, index)
		}
		if state.Threshold != threshold {
			t.Errorf("State threshold = %d, want %d", state.Threshold, threshold)
		}
		if state.NumParticipants != n {
			t.Errorf("State participants = %d, want %d", state.NumParticipants, n)
		}
		if state.VSS == nil {
			t.Error("State VSS should not be nil")
		}
		if state.Commitment == nil {
			t.Error("State commitment should not be nil")
		}
		if len(state.Seed) != len(seed) {
			t.Error("State seed length mismatch")
		}

		// Verify message is properly formed
		if msg == nil {
			t.Fatal("Message should not be nil")
		}
		if msg.Commitment == nil {
			t.Error("Message commitment should not be nil")
		}
		if len(msg.POP) == 0 {
			t.Error("Message POP should not be empty")
		}

		// Verify commitment has correct number of coefficients (threshold)
		if len(msg.Commitment.Coefficients) != threshold {
			t.Errorf("Commitment has %d coefficients, want %d",
				len(msg.Commitment.Coefficients), threshold)
		}

		// Verify all commitment coefficients are non-nil
		for i, coeff := range msg.Commitment.Coefficients {
			if coeff == nil {
				t.Errorf("Commitment coefficient %d is nil", i)
			}
		}

		// Verify shares are generated for all participants
		if len(shares) != n {
			t.Errorf("Got %d shares, want %d", len(shares), n)
		}

		// Verify all shares are non-nil
		for i, share := range shares {
			if share == nil {
				t.Errorf("Share %d is nil", i)
			}
		}

		// Verify shares can be verified against commitment
		for i, share := range shares {
			// Compute expected public share: sum of C_j * (i+1)^j
			expectedPub := grp.Identity()
			x := scalarFromInt(grp, i+1)
			xPower := scalarFromInt(grp, 1) // x^0 = 1

			for _, coeff := range msg.Commitment.Coefficients {
				term := grp.ScalarMult(coeff, xPower)
				expectedPub = expectedPub.Add(term)
				xPower = xPower.Mul(x)
			}

			// Verify share * G equals expected public share
			actualPub := grp.ScalarBaseMult(share)
			if !actualPub.Equal(expectedPub) {
				t.Errorf("Share %d verification failed", i)
			}
		}

		// Verify POP can be verified (basic format check)
		// POP should be R || mu where R is a group element and mu is a scalar
		elemSize, err := grp.SerializeElement(grp.Generator())
		if err != nil {
			t.Fatalf("Failed to get element size: %v", err)
		}
		scalarSize := len(grp.SerializeScalar(grp.NewScalar()))
		expectedPOPSize := len(elemSize) + scalarSize

		if len(msg.POP) != expectedPOPSize {
			t.Errorf("POP size = %d, want %d", len(msg.POP), expectedPOPSize)
		}
	}
}

// TestFROSTDKGParticipantRound1Determinism tests deterministic output with same seed.
func TestFROSTDKGParticipantRound1Determinism(t *testing.T) {
	cs := ed25519_sha512.New()
	seed := []byte("deterministic-test-seed-12345678")
	threshold, n, index := 2, 3, 0

	// Run Round1 twice with same inputs
	state1, msg1, shares1, err1 := FROSTDKGParticipantRound1(cs, seed, threshold, n, index)
	if err1 != nil {
		t.Fatalf("First Round1 failed: %v", err1)
	}

	state2, msg2, shares2, err2 := FROSTDKGParticipantRound1(cs, seed, threshold, n, index)
	if err2 != nil {
		t.Fatalf("Second Round1 failed: %v", err2)
	}

	// Verify states match
	if state1.Index != state2.Index {
		t.Error("State index should be deterministic")
	}
	if state1.Threshold != state2.Threshold {
		t.Error("State threshold should be deterministic")
	}
	if state1.NumParticipants != state2.NumParticipants {
		t.Error("State participants should be deterministic")
	}

	// Verify commitments match
	grp := cs.Group()
	if !commitmentsEqual(grp, msg1.Commitment, msg2.Commitment) {
		t.Error("Commitments should be deterministic")
	}

	// Verify POPs match
	if len(msg1.POP) != len(msg2.POP) {
		t.Error("POP length should be deterministic")
	}
	for i := range msg1.POP {
		if msg1.POP[i] != msg2.POP[i] {
			t.Error("POP should be deterministic")
		}
	}

	// Verify shares match
	if len(shares1) != len(shares2) {
		t.Error("Share count should be deterministic")
	}
	for i := range shares1 {
		if !shares1[i].Equal(shares2[i]) {
			t.Errorf("Share %d should be deterministic", i)
		}
	}
}

// TestFROSTDKGParticipantRound1DifferentSeeds tests that different seeds produce different outputs.
func TestFROSTDKGParticipantRound1DifferentSeeds(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold, n, index := 2, 3, 0

	seed1 := make([]byte, 32)
	seed2 := make([]byte, 32)
	_, _ = rand.Read(seed1)
	_, _ = rand.Read(seed2)

	// Ensure seeds are different
	if string(seed1) == string(seed2) {
		t.Skip("Random seeds happened to be identical")
	}

	state1, msg1, shares1, err1 := FROSTDKGParticipantRound1(cs, seed1, threshold, n, index)
	if err1 != nil {
		t.Fatalf("First Round1 failed: %v", err1)
	}

	state2, msg2, shares2, err2 := FROSTDKGParticipantRound1(cs, seed2, threshold, n, index)
	if err2 != nil {
		t.Fatalf("Second Round1 failed: %v", err2)
	}

	// Verify outputs are different
	grp := cs.Group()
	if commitmentsEqual(grp, msg1.Commitment, msg2.Commitment) {
		t.Error("Different seeds should produce different commitments")
	}

	// Verify VSS secrets are different
	if state1.VSS.Secret().Equal(state2.VSS.Secret()) {
		t.Error("Different seeds should produce different secrets")
	}

	// Verify shares are different
	sharesDifferent := false
	for i := range shares1 {
		if !shares1[i].Equal(shares2[i]) {
			sharesDifferent = true
			break
		}
	}
	if !sharesDifferent {
		t.Error("Different seeds should produce different shares")
	}
}

// TestFROSTDKGParticipantRound1SeedVariations tests various seed inputs.
func TestFROSTDKGParticipantRound1SeedVariations(t *testing.T) {
	cs := ed25519_sha512.New()

	t.Run("empty_seed", func(t *testing.T) {
		// Empty seed should still work (deterministic but different from nil)
		emptySeed := []byte{}
		state, msg, shares, err := FROSTDKGParticipantRound1(cs, emptySeed, 2, 3, 0)
		if err != nil {
			t.Errorf("Empty seed should be valid: %v", err)
		}
		if state == nil || msg == nil || shares == nil {
			t.Error("Empty seed should produce valid outputs")
		}
	})

	t.Run("nil_seed", func(t *testing.T) {
		// Nil seed should still work (hash of empty data)
		state, msg, shares, err := FROSTDKGParticipantRound1(cs, nil, 2, 3, 0)
		if err != nil {
			t.Errorf("Nil seed should be valid: %v", err)
		}
		if state == nil || msg == nil || shares == nil {
			t.Error("Nil seed should produce valid outputs")
		}
	})

	t.Run("large_seed", func(t *testing.T) {
		// Large seed should work
		largeSeed := make([]byte, 1024)
		_, _ = rand.Read(largeSeed)
		state, msg, shares, err := FROSTDKGParticipantRound1(cs, largeSeed, 2, 3, 0)
		if err != nil {
			t.Errorf("Large seed should be valid: %v", err)
		}
		if state == nil || msg == nil || shares == nil {
			t.Error("Large seed should produce valid outputs")
		}
	})

	t.Run("single_byte_seed", func(t *testing.T) {
		// Single byte seed
		singleByteSeed := []byte{0x42}
		state, msg, shares, err := FROSTDKGParticipantRound1(cs, singleByteSeed, 2, 3, 0)
		if err != nil {
			t.Errorf("Single byte seed should be valid: %v", err)
		}
		if state == nil || msg == nil || shares == nil {
			t.Error("Single byte seed should produce valid outputs")
		}
	})
}

// TestFROSTDKGParticipantRound1IndexBoundaries tests boundary conditions for participant index.
func TestFROSTDKGParticipantRound1IndexBoundaries(t *testing.T) {
	cs := ed25519_sha512.New()

	t.Run("boundary_index_zero", func(t *testing.T) {
		// Index 0 (first participant)
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)
		state, msg, shares, err := FROSTDKGParticipantRound1(cs, seed, 2, 3, 0)
		if err != nil {
			t.Errorf("Index 0 should be valid: %v", err)
		}
		if state.Index != 0 {
			t.Errorf("State index = %d, want 0", state.Index)
		}
		if state == nil || msg == nil || shares == nil {
			t.Error("Index 0 should produce valid outputs")
		}
	})

	t.Run("boundary_index_max", func(t *testing.T) {
		// Index n-1 (last participant)
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)
		n := 5
		state, msg, shares, err := FROSTDKGParticipantRound1(cs, seed, 2, n, n-1)
		if err != nil {
			t.Errorf("Index n-1 should be valid: %v", err)
		}
		if state.Index != n-1 {
			t.Errorf("State index = %d, want %d", state.Index, n-1)
		}
		if state == nil || msg == nil || shares == nil {
			t.Error("Index n-1 should produce valid outputs")
		}
	})

	t.Run("max_participants_boundary", func(t *testing.T) {
		// Test at MaxParticipants boundary
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)
		n := MaxParticipants
		state, msg, shares, err := FROSTDKGParticipantRound1(cs, seed, 2, n, 0)
		if err != nil {
			t.Errorf("MaxParticipants should be valid: %v", err)
		}
		if len(shares) != n {
			t.Errorf("Should generate %d shares", n)
		}
		if state == nil || msg == nil {
			t.Error("MaxParticipants should produce valid outputs")
		}
	})

	t.Run("exceeds_max_participants", func(t *testing.T) {
		// Test exceeding MaxParticipants
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)
		_, _, _, err := FROSTDKGParticipantRound1(cs, seed, 2, MaxParticipants+1, 0)
		if err != ErrFROSTDKGInvalidParticipantCount {
			t.Errorf("Expected ErrFROSTDKGInvalidParticipantCount, got %v", err)
		}
	})
}

// TestFROSTDKGParticipantRound1AllIndexes verifies all participant indexes work.
func TestFROSTDKGParticipantRound1AllIndexes(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold, n := 3, 7
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)

	states := make([]*FROSTDKGParticipantState, n)
	msgs := make([]*FROSTDKGParticipantMsg, n)
	allShares := make([][]group.Scalar, n)

	// Generate for all participants
	for index := 0; index < n; index++ {
		state, msg, shares, err := FROSTDKGParticipantRound1(cs, seed, threshold, n, index)
		if err != nil {
			t.Fatalf("Round1 failed for index %d: %v", index, err)
		}

		states[index] = state
		msgs[index] = msg
		allShares[index] = shares

		// Verify index is set correctly
		if state.Index != index {
			t.Errorf("Index %d: state.Index = %d, want %d", index, state.Index, index)
		}
	}

	// Verify each participant can verify all shares
	grp := cs.Group()
	for senderIdx := 0; senderIdx < n; senderIdx++ {
		commitment := msgs[senderIdx].Commitment

		for receiverIdx := 0; receiverIdx < n; receiverIdx++ {
			share := allShares[senderIdx][receiverIdx]

			// Verify share against commitment
			x := scalarFromInt(grp, receiverIdx+1)
			expectedPub := grp.Identity()
			xPower := scalarFromInt(grp, 1) // x^0 = 1

			for _, coeff := range commitment.Coefficients {
				term := grp.ScalarMult(coeff, xPower)
				expectedPub = expectedPub.Add(term)
				xPower = xPower.Mul(x)
			}

			actualPub := grp.ScalarBaseMult(share)
			if !actualPub.Equal(expectedPub) {
				t.Errorf("Share verification failed: sender=%d, receiver=%d",
					senderIdx, receiverIdx)
			}
		}
	}
}

// TestFROSTDKGCoordinatorRound1Errors tests error handling in Coordinator Round 1.
func TestFROSTDKGCoordinatorRound1Errors(t *testing.T) {
	cs := ed25519_sha512.New()

	t.Run("nil_message_in_list", func(t *testing.T) {
		msgs := []*FROSTDKGParticipantMsg{nil, nil, nil}
		_, err := FROSTDKGCoordinatorRound1(cs, msgs, 2, 3)
		if err != ErrFROSTDKGInvalidPOP {
			t.Errorf("Expected ErrFROSTDKGInvalidPOP, got %v", err)
		}
	})

	t.Run("wrong_message_count", func(t *testing.T) {
		msgs := []*FROSTDKGParticipantMsg{{}, {}} // only 2 messages for n=3
		_, err := FROSTDKGCoordinatorRound1(cs, msgs, 2, 3)
		if err != ErrFROSTDKGInvalidParticipantCount {
			t.Errorf("Expected ErrFROSTDKGInvalidParticipantCount, got %v", err)
		}
	})

	t.Run("threshold_below_min", func(t *testing.T) {
		// Zcash FROST: min_signers must be at least 2
		_, err := FROSTDKGCoordinatorRound1(cs, nil, 1, 3)
		if err != ErrInvalidMinSigners {
			t.Errorf("Expected ErrInvalidMinSigners, got %v", err)
		}
	})

	t.Run("invalid_threshold", func(t *testing.T) {
		_, err := FROSTDKGCoordinatorRound1(cs, nil, 0, 3)
		if err != ErrInvalidMinSigners {
			t.Errorf("Expected ErrInvalidMinSigners, got %v", err)
		}
	})

	t.Run("invalid_n", func(t *testing.T) {
		// Zcash FROST: max_signers must be at least 2
		_, err := FROSTDKGCoordinatorRound1(cs, nil, 2, 0)
		if err != ErrInvalidMaxSigners {
			t.Errorf("Expected ErrInvalidMaxSigners, got %v", err)
		}
	})
}

// TestFROSTDKGParticipantRound2Errors tests error handling in Round 2.
func TestFROSTDKGParticipantRound2Errors(t *testing.T) {
	cs := ed25519_sha512.New()

	t.Run("nil_state", func(t *testing.T) {
		_, _, err := FROSTDKGParticipantRound2(cs, nil, &FROSTDKGCoordinatorMsg{}, nil)
		if err != ErrInvalidParticipantIndex {
			t.Errorf("Expected ErrInvalidParticipantIndex, got %v", err)
		}
	})

	t.Run("nil_coordMsg", func(t *testing.T) {
		state := &FROSTDKGParticipantState{NumParticipants: 3}
		_, _, err := FROSTDKGParticipantRound2(cs, state, nil, nil)
		if err != ErrFROSTDKGCommitmentMismatch {
			t.Errorf("Expected ErrFROSTDKGCommitmentMismatch, got %v", err)
		}
	})

	t.Run("wrong_shares_count", func(t *testing.T) {
		state := &FROSTDKGParticipantState{NumParticipants: 3, Threshold: 2}
		coordMsg := &FROSTDKGCoordinatorMsg{
			AllCommitments: make([]*VSSCommitment, 3),
			AllPOPs:        make([][]byte, 3),
		}
		shares := make([]group.Scalar, 2) // wrong count
		_, _, err := FROSTDKGParticipantRound2(cs, state, coordMsg, shares)
		if err != ErrFROSTDKGInvalidParticipantCount {
			t.Errorf("Expected ErrFROSTDKGInvalidParticipantCount, got %v", err)
		}
	})
}

// TestFROSTDKGInvalidPOPRejected tests that invalid POPs are rejected.
func TestFROSTDKGInvalidPOPRejected(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold, n := 2, 3

	// Generate valid Round 1 data
	seeds := make([][]byte, n)
	msgs := make([]*FROSTDKGParticipantMsg, n)
	for i := 0; i < n; i++ {
		seeds[i] = make([]byte, 32)
		_, _ = rand.Read(seeds[i])
		_, msg, _, _ := FROSTDKGParticipantRound1(cs, seeds[i], threshold, n, i)
		msgs[i] = msg
	}

	// Corrupt one POP
	msgs[1].POP[0] ^= 0xFF

	// Coordinator should reject the corrupted POP
	_, err := FROSTDKGCoordinatorRound1(cs, msgs, threshold, n)
	if err != ErrFROSTDKGInvalidPOP {
		t.Errorf("Expected ErrFROSTDKGInvalidPOP for corrupted POP, got %v", err)
	}
}

// TestFROSTDKGCommitmentMismatchRejected tests commitment mismatch detection.
func TestFROSTDKGCommitmentMismatchRejected(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()
	threshold, n := 2, 3

	// Generate valid Round 1 data
	seeds := make([][]byte, n)
	states := make([]*FROSTDKGParticipantState, n)
	msgs := make([]*FROSTDKGParticipantMsg, n)
	allShares := make([][]group.Scalar, n)

	for i := 0; i < n; i++ {
		seeds[i] = make([]byte, 32)
		_, _ = rand.Read(seeds[i])
		state, msg, shares, _ := FROSTDKGParticipantRound1(cs, seeds[i], threshold, n, i)
		states[i] = state
		msgs[i] = msg
		allShares[i] = shares
	}

	coordMsg, _ := FROSTDKGCoordinatorRound1(cs, msgs, threshold, n)

	// Modify one commitment in the coordinator message
	// This will be detected as either commitment mismatch or invalid POP
	// depending on which check runs first (commitment mismatch check is first,
	// but if we're not participant 0, the POP check for modified commitment fails)
	wrongScalar, _ := grp.RandomScalar()
	coordMsg.AllCommitments[0].Coefficients[0] = grp.ScalarBaseMult(wrongScalar)

	// Participant 0 should detect the attack (as commitment mismatch for their own commitment)
	receivedShares := make([]group.Scalar, n)
	for sender := 0; sender < n; sender++ {
		receivedShares[sender] = allShares[sender][0]
	}

	_, _, err := FROSTDKGParticipantRound2(cs, states[0], coordMsg, receivedShares)
	// The commitment modification is detected - could be either error depending on
	// whether it's detected as a mismatch for our commitment or an invalid POP
	if err != ErrFROSTDKGCommitmentMismatch && err != ErrFROSTDKGInvalidPOP {
		t.Errorf("Expected commitment mismatch or invalid POP error, got %v", err)
	}
}

// TestFROSTDKGShareVerificationFailed tests that invalid shares are rejected.
func TestFROSTDKGShareVerificationFailed(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()
	threshold, n := 2, 3

	// Generate valid Round 1 data
	seeds := make([][]byte, n)
	states := make([]*FROSTDKGParticipantState, n)
	msgs := make([]*FROSTDKGParticipantMsg, n)
	allShares := make([][]group.Scalar, n)

	for i := 0; i < n; i++ {
		seeds[i] = make([]byte, 32)
		_, _ = rand.Read(seeds[i])
		state, msg, shares, _ := FROSTDKGParticipantRound1(cs, seeds[i], threshold, n, i)
		states[i] = state
		msgs[i] = msg
		allShares[i] = shares
	}

	coordMsg, _ := FROSTDKGCoordinatorRound1(cs, msgs, threshold, n)

	// Corrupt one share for participant 0
	wrongShare, _ := grp.RandomScalar()
	allShares[1][0] = wrongShare

	receivedShares := make([]group.Scalar, n)
	for sender := 0; sender < n; sender++ {
		receivedShares[sender] = allShares[sender][0]
	}

	_, _, err := FROSTDKGParticipantRound2(cs, states[0], coordMsg, receivedShares)
	if err != ErrFROSTDKGShareVerificationFailed {
		t.Errorf("Expected ErrFROSTDKGShareVerificationFailed, got %v", err)
	}
}

// TestFROSTDKGDeterministicWithSameSeed verifies deterministic output with same seed.
func TestFROSTDKGDeterministicWithSameSeed(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold, n := 2, 3

	// Use fixed seeds
	seed := []byte("deterministic-test-seed-1234567890")
	seeds := make([][]byte, n)
	for i := 0; i < n; i++ {
		seeds[i] = append(seed, byte(i))
	}

	// Run DKG twice
	var outputs1, outputs2 []*FROSTDKGOutput

	for run := 0; run < 2; run++ {
		states := make([]*FROSTDKGParticipantState, n)
		msgs := make([]*FROSTDKGParticipantMsg, n)
		allShares := make([][]group.Scalar, n)

		for i := 0; i < n; i++ {
			state, msg, shares, _ := FROSTDKGParticipantRound1(cs, seeds[i], threshold, n, i)
			states[i] = state
			msgs[i] = msg
			allShares[i] = shares
		}

		coordMsg, _ := FROSTDKGCoordinatorRound1(cs, msgs, threshold, n)

		outputs := make([]*FROSTDKGOutput, n)
		for i := 0; i < n; i++ {
			receivedShares := make([]group.Scalar, n)
			for sender := 0; sender < n; sender++ {
				receivedShares[sender] = allShares[sender][i]
			}
			output, _, _ := FROSTDKGParticipantRound2(cs, states[i], coordMsg, receivedShares)
			outputs[i] = output
		}

		if run == 0 {
			outputs1 = outputs
		} else {
			outputs2 = outputs
		}
	}

	// Verify outputs are identical
	for i := 0; i < n; i++ {
		if !outputs1[i].ThresholdPubkey.Equal(outputs2[i].ThresholdPubkey) {
			t.Error("Threshold pubkey should be deterministic")
		}
		if !outputs1[i].SecretShare.Equal(outputs2[i].SecretShare) {
			t.Errorf("Participant %d secret share should be deterministic", i)
		}
	}
}

// TestPedersenVulnerabilityFix tests that commitments with wrong coefficient count are rejected.
// This prevents the Trail of Bits 2024 Pedersen DKG vulnerability where a malicious
// participant could silently increase the threshold by sending more coefficients.
func TestPedersenVulnerabilityFix(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()
	threshold, n := 2, 3

	// Generate valid Round 1 data
	seeds := make([][]byte, n)
	msgs := make([]*FROSTDKGParticipantMsg, n)

	for i := 0; i < n; i++ {
		seeds[i] = make([]byte, 32)
		_, _ = rand.Read(seeds[i])
		_, msg, _, _ := FROSTDKGParticipantRound1(cs, seeds[i], threshold, n, i)
		msgs[i] = msg
	}

	t.Run("coordinator_rejects_extra_coefficients", func(t *testing.T) {
		// Create a malicious commitment with extra coefficients (t+1 instead of t)
		maliciousCoeffs := make([]group.Element, threshold+1)
		for i := 0; i <= threshold; i++ {
			scalar, _ := grp.RandomScalar()
			maliciousCoeffs[i] = grp.ScalarBaseMult(scalar)
		}
		maliciousCommitment := &VSSCommitment{Coefficients: maliciousCoeffs}

		// Replace participant 1's commitment with malicious one
		maliciousMsgs := make([]*FROSTDKGParticipantMsg, n)
		copy(maliciousMsgs, msgs)
		maliciousMsgs[1] = &FROSTDKGParticipantMsg{
			Commitment: maliciousCommitment,
			POP:        msgs[1].POP, // Keep original POP (will fail anyway)
		}

		// Coordinator should reject this
		_, err := FROSTDKGCoordinatorRound1(cs, maliciousMsgs, threshold, n)
		if err == nil {
			t.Error("Coordinator should reject commitment with wrong coefficient count")
		}
		// Should be a FaultyParticipantError for participant 1
		if fpe, ok := err.(*FaultyParticipantError); ok {
			if fpe.ParticipantIndex != 1 {
				t.Errorf("Expected faulty participant 1, got %d", fpe.ParticipantIndex)
			}
		} else {
			// Could also be rejected by POP verification if that runs first
			t.Logf("Error type: %T, error: %v", err, err)
		}
	})

	t.Run("coordinator_rejects_fewer_coefficients", func(t *testing.T) {
		// Create a malicious commitment with fewer coefficients (t-1 instead of t)
		maliciousCoeffs := make([]group.Element, threshold-1)
		for i := 0; i < threshold-1; i++ {
			scalar, _ := grp.RandomScalar()
			maliciousCoeffs[i] = grp.ScalarBaseMult(scalar)
		}
		maliciousCommitment := &VSSCommitment{Coefficients: maliciousCoeffs}

		// Replace participant 1's commitment with malicious one
		maliciousMsgs := make([]*FROSTDKGParticipantMsg, n)
		copy(maliciousMsgs, msgs)
		maliciousMsgs[1] = &FROSTDKGParticipantMsg{
			Commitment: maliciousCommitment,
			POP:        msgs[1].POP,
		}

		// Coordinator should reject this
		_, err := FROSTDKGCoordinatorRound1(cs, maliciousMsgs, threshold, n)
		if err == nil {
			t.Error("Coordinator should reject commitment with wrong coefficient count")
		}
	})
}

// TestDeriveHostScalarValidation tests that deriveHostScalar validates key lengths.
func TestDeriveHostScalarValidation(t *testing.T) {
	testCases := []struct {
		name           string
		cs             ciphersuite.Ciphersuite
		validKeyLen    int
		invalidKeyLens []int
	}{
		{"Ed25519", ed25519_sha512.New(), 32, []int{0, 16, 31, 33, 64}},
		{"P256", p256_sha256.New(), 32, []int{0, 16, 31, 33, 64}},
		{"Ristretto255", ristretto255_sha512.New(), 32, []int{0, 16, 31, 33, 64}},
		{"Secp256k1", secp256k1_sha256.New(), 32, []int{0, 16, 31, 33, 64}},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_valid_key", func(t *testing.T) {
			validKey := make([]byte, tc.validKeyLen)
			_, _ = rand.Read(validKey)
			scalar, err := deriveHostScalar(tc.cs, validKey)
			if err != nil {
				t.Errorf("Valid key should not error: %v", err)
			}
			if scalar == nil {
				t.Error("Valid key should return non-nil scalar")
			}
		})

		for _, invalidLen := range tc.invalidKeyLens {
			t.Run(tc.name+"_invalid_key_len_"+string(rune('0'+invalidLen)), func(t *testing.T) {
				invalidKey := make([]byte, invalidLen)
				_, err := deriveHostScalar(tc.cs, invalidKey)
				if err != ErrInvalidSecretKey {
					t.Errorf("Expected ErrInvalidSecretKey for length %d, got %v", invalidLen, err)
				}
			})
		}
	}
}
