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
)

// TestFROSTDKGEncryptedFullProtocol tests the encrypted DKG protocol end-to-end.
func TestFROSTDKGEncryptedFullProtocol(t *testing.T) {
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
			runEncryptedDKGTest(t, tc.cs, 2, 3)
		})
	}
}

// TestFROSTDKGEncryptedDifferentThresholds tests encrypted DKG with various configurations.
func TestFROSTDKGEncryptedDifferentThresholds(t *testing.T) {
	cs := ed25519_sha512.New()

	testCases := []struct {
		name string
		t, n int
	}{
		{"t2_n2", 2, 2},
		{"t2_n3", 2, 3},
		{"t3_n4", 3, 4},
		{"t3_n5", 3, 5},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runEncryptedDKGTest(t, cs, tc.t, tc.n)
		})
	}
}

// runEncryptedDKGTest runs a complete encrypted DKG protocol.
func runEncryptedDKGTest(t *testing.T, cs ciphersuite.Ciphersuite, threshold, n int) {
	t.Helper()

	grp := cs.Group()

	// Get the signer for this ciphersuite to generate compatible host keys
	signer, err := GetSigner(cs)
	if err != nil {
		t.Fatalf("GetSigner failed: %v", err)
	}

	// Generate host keypairs using the signer - this ensures the pubkey
	// matches the scalar that ECDH will derive from the secret key
	hostSeckeys := make([][]byte, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		seckey, pubkey, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		hostSeckeys[i] = seckey
		hostPubkeys[i] = pubkey
	}

	// Generate seeds and random for each participant
	seeds := make([][]byte, n)
	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		seeds[i] = make([]byte, 32)
		_, _ = rand.Read(seeds[i])
		randoms[i] = make([]byte, 32)
		_, _ = rand.Read(randoms[i])
	}

	// Round 1: Each participant generates encrypted state and message
	states := make([]*FROSTDKGEncParticipantState, n)
	msgs := make([]*FROSTDKGEncParticipantMsg, n)

	for i := 0; i < n; i++ {
		state, msg, err := FROSTDKGEncParticipantRound1(
			cs, seeds[i], hostSeckeys[i], hostPubkeys, threshold, i, randoms[i],
		)
		if err != nil {
			t.Fatalf("Participant %d Encrypted Round1 failed: %v", i, err)
		}
		states[i] = state
		msgs[i] = msg
	}

	// Coordinator processes encrypted Round 1 messages
	coordMsg, coordOutput, eqInput, participantShares, err := FROSTDKGEncCoordinatorRound1(
		cs, msgs, threshold, hostPubkeys,
	)
	if err != nil {
		t.Fatalf("Coordinator Encrypted Round1 failed: %v", err)
	}

	// Verify coordinator output is valid
	if coordOutput.ThresholdPubkey == nil {
		t.Error("Coordinator output should have threshold pubkey")
	}
	if len(coordOutput.PublicShares) != n {
		t.Errorf("Expected %d public shares, got %d", n, len(coordOutput.PublicShares))
	}
	if len(eqInput) == 0 {
		t.Error("eqInput should not be empty")
	}

	// Round 2: Each participant decrypts and processes
	outputs := make([]*FROSTDKGOutput, n)
	eqInputs := make([][]byte, n)

	for i := 0; i < n; i++ {
		output, eq, err := FROSTDKGEncParticipantRound2(
			cs, states[i], coordMsg, participantShares[i],
		)
		if err != nil {
			t.Fatalf("Participant %d Encrypted Round2 failed: %v", i, err)
		}
		outputs[i] = output
		eqInputs[i] = eq
	}

	// Verify all participants got the same threshold public key
	for i := 1; i < n; i++ {
		if !outputs[0].ThresholdPubkey.Equal(outputs[i].ThresholdPubkey) {
			t.Errorf("Participant %d has different threshold pubkey than participant 0", i)
		}
	}

	// Verify threshold pubkey matches coordinator output
	if !outputs[0].ThresholdPubkey.Equal(coordOutput.ThresholdPubkey) {
		t.Error("Participant threshold pubkey doesn't match coordinator output")
	}

	// Verify all participants got the same equality input
	for i := 1; i < n; i++ {
		if string(eqInputs[0]) != string(eqInputs[i]) {
			t.Errorf("Participant %d has different eqInput than participant 0", i)
		}
	}

	// Verify eqInput matches coordinator
	if string(eqInputs[0]) != string(eqInput) {
		t.Error("Participant eqInput doesn't match coordinator")
	}

	// Verify secret share corresponds to public share for each participant
	for i := 0; i < n; i++ {
		expectedPub := grp.ScalarBaseMult(outputs[i].SecretShare)
		if !expectedPub.Equal(outputs[i].PublicShares[i]) {
			t.Errorf("Participant %d secret share doesn't match public share", i)
		}
	}

	t.Logf("Encrypted DKG successful: threshold=%d, participants=%d", threshold, n)
}

// TestFROSTDKGEncParticipantRound1Errors tests error handling in encrypted Round 1.
func TestFROSTDKGEncParticipantRound1Errors(t *testing.T) {
	cs := ed25519_sha512.New()

	// Get the signer for compatible key generation
	signer, _ := GetSigner(cs)

	// Generate valid keypairs
	n := 3
	hostSeckeys := make([][]byte, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		seckey, pubkey, _ := signer.GenerateKey()
		hostSeckeys[i] = seckey
		hostPubkeys[i] = pubkey
	}

	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	random := make([]byte, 32)
	_, _ = rand.Read(random)

	t.Run("invalid_threshold", func(t *testing.T) {
		_, _, err := FROSTDKGEncParticipantRound1(cs, seed, hostSeckeys[0], hostPubkeys, 0, 0, random)
		if err == nil {
			t.Error("Expected error for invalid threshold")
		}
	})

	t.Run("threshold_below_min", func(t *testing.T) {
		_, _, err := FROSTDKGEncParticipantRound1(cs, seed, hostSeckeys[0], hostPubkeys, 1, 0, random)
		if err != ErrInvalidMinSigners {
			t.Errorf("Expected ErrInvalidMinSigners, got %v", err)
		}
	})

	t.Run("invalid_index", func(t *testing.T) {
		_, _, err := FROSTDKGEncParticipantRound1(cs, seed, hostSeckeys[0], hostPubkeys, 2, 5, random)
		if err != ErrInvalidParticipantIndex {
			t.Errorf("Expected ErrInvalidParticipantIndex, got %v", err)
		}
	})

	t.Run("negative_index", func(t *testing.T) {
		_, _, err := FROSTDKGEncParticipantRound1(cs, seed, hostSeckeys[0], hostPubkeys, 2, -1, random)
		if err != ErrInvalidParticipantIndex {
			t.Errorf("Expected ErrInvalidParticipantIndex, got %v", err)
		}
	})

	t.Run("invalid_secret_key", func(t *testing.T) {
		badKey := []byte{0x01, 0x02, 0x03} // Wrong length
		_, _, err := FROSTDKGEncParticipantRound1(cs, seed, badKey, hostPubkeys, 2, 0, random)
		if err == nil {
			t.Error("Expected error for invalid secret key")
		}
	})
}

// TestFROSTDKGEncCoordinatorRound1Errors tests coordinator error handling.
func TestFROSTDKGEncCoordinatorRound1Errors(t *testing.T) {
	cs := ed25519_sha512.New()

	// Get the signer for compatible key generation
	signer, _ := GetSigner(cs)

	n := 3
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		_, pubkey, _ := signer.GenerateKey()
		hostPubkeys[i] = pubkey
	}

	t.Run("mismatched_counts", func(t *testing.T) {
		msgs := make([]*FROSTDKGEncParticipantMsg, 2) // Wrong count
		_, _, _, _, err := FROSTDKGEncCoordinatorRound1(cs, msgs, 2, hostPubkeys)
		if err != ErrFROSTDKGInvalidParticipantCount {
			t.Errorf("Expected ErrFROSTDKGInvalidParticipantCount, got %v", err)
		}
	})
}

// TestFROSTDKGEncParticipantRound2Errors tests encrypted Round 2 error handling.
// Tests error paths for FROSTDKGEncParticipantRound2 (non-HostKey version).
func TestFROSTDKGEncParticipantRound2Errors(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Get the signer for compatible key generation
	signer, _ := GetSigner(cs)

	// Generate valid host keys
	n := 3
	hostSeckeys := make([][]byte, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		seckey, pubkey, _ := signer.GenerateKey()
		hostSeckeys[i] = seckey
		hostPubkeys[i] = pubkey
	}

	// Generate valid Round 1 states
	seed1 := make([]byte, 32)
	seed2 := make([]byte, 32)
	seed3 := make([]byte, 32)
	_, _ = rand.Read(seed1)
	_, _ = rand.Read(seed2)
	_, _ = rand.Read(seed3)

	random1 := make([]byte, 32)
	random2 := make([]byte, 32)
	random3 := make([]byte, 32)
	_, _ = rand.Read(random1)
	_, _ = rand.Read(random2)
	_, _ = rand.Read(random3)

	state1, msg1, err := FROSTDKGEncParticipantRound1(cs, seed1, hostSeckeys[0], hostPubkeys, 2, 0, random1)
	if err != nil {
		t.Fatalf("Round1 failed: %v", err)
	}
	_, msg2, err := FROSTDKGEncParticipantRound1(cs, seed2, hostSeckeys[1], hostPubkeys, 2, 1, random2)
	if err != nil {
		t.Fatalf("Round1 for participant 2 failed: %v", err)
	}
	_, msg3, err := FROSTDKGEncParticipantRound1(cs, seed3, hostSeckeys[2], hostPubkeys, 2, 2, random3)
	if err != nil {
		t.Fatalf("Round1 for participant 3 failed: %v", err)
	}

	// Create coordinator message with valid data
	msgs := []*FROSTDKGEncParticipantMsg{msg1, msg2, msg3}
	allCommitments := []*VSSCommitment{
		msg1.Commitment,
		msg2.Commitment,
		msg3.Commitment,
	}
	allPOPs := [][]byte{
		msg1.POP,
		msg2.POP,
		msg3.POP,
	}
	allPubnonces := [][]byte{msg1.Pubnonce, msg2.Pubnonce, msg3.Pubnonce}

	validCoordMsg := &FROSTDKGEncCoordinatorMsg{
		FROSTDKGCoordinatorMsg: &FROSTDKGCoordinatorMsg{
			AllCommitments: allCommitments,
			AllPOPs:        allPOPs,
		},
		AllPubnonces: allPubnonces,
	}

	// Create valid encrypted shares for participant 0
	scalarLen := len(grp.SerializeScalar(grp.NewScalar()))
	validEncryptedShares := make([]byte, 3*scalarLen)
	for i := 0; i < 3; i++ {
		copy(validEncryptedShares[i*scalarLen:], msgs[i].EncryptedShares[0])
	}

	t.Run("truncated_shares", func(t *testing.T) {
		// Test error path at line 928-930: shareEnd > len(encryptedSharesForMe)
		truncatedShares := make([]byte, 10) // Way too short

		_, _, err := FROSTDKGEncParticipantRound2(cs, state1, validCoordMsg, truncatedShares)
		if err != ErrFROSTDKGDecryptionFailed {
			t.Errorf("Expected ErrFROSTDKGDecryptionFailed, got %v", err)
		}
	})

	t.Run("invalid_encrypted_data_length", func(t *testing.T) {
		// Test error path at line 928-930: shareEnd > len(encryptedSharesForMe)
		wrongLengthData := make([]byte, scalarLen) // Too short, should be 3*scalarLen

		_, _, err := FROSTDKGEncParticipantRound2(cs, state1, validCoordMsg, wrongLengthData)
		if err != ErrFROSTDKGDecryptionFailed {
			t.Errorf("Expected ErrFROSTDKGDecryptionFailed for wrong length, got %v", err)
		}
	})

	t.Run("deserialization_error_own_share", func(t *testing.T) {
		// Test error path at line 935-938: own share deserialization fails
		// Create corrupted data where our own share (index 0) is invalid
		corruptedShares := make([]byte, len(validEncryptedShares))
		copy(corruptedShares, validEncryptedShares)

		// Corrupt our own share at index 0
		for i := 0; i < scalarLen; i++ {
			corruptedShares[i] = 0xFF // Invalid scalar bytes
		}

		_, _, err := FROSTDKGEncParticipantRound2(cs, state1, validCoordMsg, corruptedShares)
		if err == nil {
			t.Error("Expected error for invalid own share deserialization")
		}
	})

	t.Run("deserialization_error_their_pubkey", func(t *testing.T) {
		// Test error path at line 944-947: theirPubkey deserialization fails
		// Create state with invalid host pubkey for participant 1
		corruptedState := &FROSTDKGEncParticipantState{
			FROSTDKGParticipantState: state1.FROSTDKGParticipantState,
			HostSeckey:               state1.HostSeckey,
			HostPubkeys: [][]byte{
				hostPubkeys[0],
				[]byte{0xFF, 0xFF, 0xFF}, // Invalid pubkey for participant 1
				hostPubkeys[2],
			},
			Pubnonce: state1.Pubnonce,
		}

		_, _, err := FROSTDKGEncParticipantRound2(cs, corruptedState, validCoordMsg, validEncryptedShares)
		if err == nil {
			t.Error("Expected error for invalid pubkey deserialization")
		}
	})

	t.Run("deserialization_error_their_pubnonce", func(t *testing.T) {
		// Test error path at line 948-951: theirPubnonce deserialization fails
		// Create coordinator message with invalid pubnonce
		corruptedCoordMsg := &FROSTDKGEncCoordinatorMsg{
			FROSTDKGCoordinatorMsg: validCoordMsg.FROSTDKGCoordinatorMsg,
			AllPubnonces: [][]byte{
				allPubnonces[0],
				[]byte{0xFF, 0xFF, 0xFF}, // Invalid pubnonce for participant 1
				allPubnonces[2],
			},
		}

		_, _, err := FROSTDKGEncParticipantRound2(cs, state1, corruptedCoordMsg, validEncryptedShares)
		if err == nil {
			t.Error("Expected error for invalid pubnonce deserialization")
		}
	})

	t.Run("ecdh_failure", func(t *testing.T) {
		// Test error path at line 956-959: ECDH fails
		// Create state with invalid host secret key that will cause ECDH to fail
		corruptedState := &FROSTDKGEncParticipantState{
			FROSTDKGParticipantState: state1.FROSTDKGParticipantState,
			HostSeckey:               []byte{0xFF}, // Invalid seckey length
			HostPubkeys:              hostPubkeys,
			Pubnonce:                 state1.Pubnonce,
		}

		_, _, err := FROSTDKGEncParticipantRound2(cs, corruptedState, validCoordMsg, validEncryptedShares)
		if err == nil {
			t.Error("Expected error for ECDH failure")
		}
	})

	t.Run("share_deserialization_error", func(t *testing.T) {
		// Test error path at line 967-970: decrypted share deserialization fails
		// Create encrypted shares where decrypted share is invalid
		corruptedShares := make([]byte, len(validEncryptedShares))
		copy(corruptedShares, validEncryptedShares)

		// For participant 1 (not our own share), corrupt the encrypted data
		// Setting all 0xFF which should decrypt to invalid scalar
		for i := scalarLen; i < 2*scalarLen; i++ {
			corruptedShares[i] = 0xFF
		}

		_, _, err := FROSTDKGEncParticipantRound2(cs, state1, validCoordMsg, corruptedShares)
		// This should eventually fail either at deserialization or share verification
		if err == nil {
			t.Error("Expected error for corrupted encrypted shares")
		}
	})

	t.Run("valid_round2_success", func(t *testing.T) {
		// Test the success path to ensure our setup is correct
		output, eqInput, err := FROSTDKGEncParticipantRound2(cs, state1, validCoordMsg, validEncryptedShares)
		if err != nil {
			t.Fatalf("Valid Round2 should succeed, got error: %v", err)
		}
		if output == nil {
			t.Fatal("Expected non-nil output")
		}
		if len(eqInput) == 0 {
			t.Error("Expected non-empty eqInput")
		}
		if output.SecretShare == nil {
			t.Error("Expected non-nil secret share")
		}
		if output.ThresholdPubkey == nil {
			t.Error("Expected non-nil threshold pubkey")
		}
		if len(output.PublicShares) != 3 {
			t.Errorf("Expected 3 public shares, got %d", len(output.PublicShares))
		}
	})
}

// TestFROSTDKGEncryptedDeterministic verifies deterministic output with same inputs.
func TestFROSTDKGEncryptedDeterministic(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()
	threshold, n := 2, 3

	// Fixed host keys - use a deterministic seed and derive pubkey like the signer does.
	// For Ed25519, the signer uses H3(seed) to get the scalar, so pubkey = H3(seed) * G
	hostSeckeys := make([][]byte, n)
	hostPubkeys := make([][]byte, n)
	baseSecret := []byte("deterministic-host-key-seed-1234")
	for i := 0; i < n; i++ {
		// Derive deterministic seed (this is the signer's secret key format)
		keyInput := append(baseSecret, byte(i))
		seed := hashToBytes(cs, "host key seed", keyInput)[:32]
		hostSeckeys[i] = seed
		// Derive pubkey the same way the signer does: H3(seed) * G
		scalar := cs.H3(seed)
		pubkey := grp.ScalarBaseMult(scalar)
		hostPubkeys[i], _ = grp.SerializeElement(pubkey)
	}

	// Fixed seeds and randoms
	seeds := make([][]byte, n)
	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		seeds[i] = append([]byte("dkg-seed-"), byte(i))
		randoms[i] = append([]byte("dkg-random-"), byte(i))
	}

	// Run DKG twice
	var outputs1, outputs2 []*FROSTDKGOutput

	for run := 0; run < 2; run++ {
		states := make([]*FROSTDKGEncParticipantState, n)
		msgs := make([]*FROSTDKGEncParticipantMsg, n)

		for i := 0; i < n; i++ {
			state, msg, _ := FROSTDKGEncParticipantRound1(
				cs, seeds[i], hostSeckeys[i], hostPubkeys, threshold, i, randoms[i],
			)
			states[i] = state
			msgs[i] = msg
		}

		coordMsg, _, _, participantShares, _ := FROSTDKGEncCoordinatorRound1(
			cs, msgs, threshold, hostPubkeys,
		)

		outputs := make([]*FROSTDKGOutput, n)
		for i := 0; i < n; i++ {
			output, _, _ := FROSTDKGEncParticipantRound2(
				cs, states[i], coordMsg, participantShares[i],
			)
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
			t.Error("Encrypted DKG threshold pubkey should be deterministic")
		}
		if !outputs1[i].SecretShare.Equal(outputs2[i].SecretShare) {
			t.Errorf("Participant %d secret share should be deterministic", i)
		}
	}
}
