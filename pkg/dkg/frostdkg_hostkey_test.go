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

// TestFROSTDKGFullWithHostKey tests the complete FROST-DKG protocol with HostKey for all 5 ciphersuites.
func TestFROSTDKGFullWithHostKey(t *testing.T) {
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
			runFullDKGWithHostKeyTest(t, tc.cs, 2, 3)
		})
	}
}

// TestFROSTDKGFullWithHostKeyDifferentThresholds tests Full DKG with HostKey.
func TestFROSTDKGFullWithHostKeyDifferentThresholds(t *testing.T) {
	cs := ed25519_sha512.New()

	testCases := []struct {
		name string
		t, n int
	}{
		{"t2_n2", 2, 2},
		{"t2_n3", 2, 3},
		{"t3_n4", 3, 4},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runFullDKGWithHostKeyTest(t, cs, tc.t, tc.n)
		})
	}
}

func runFullDKGWithHostKeyTest(t *testing.T, cs ciphersuite.Ciphersuite, threshold, n int) {
	t.Helper()

	grp := cs.Group()

	// Generate HostKeys for each participant
	hostKeys := make([]HostKey, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		key, err := GenerateSoftwareHostKey(cs)
		if err != nil {
			t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
		}
		hostKeys[i] = key
		hostPubkeys[i] = key.PublicKey()
	}

	// Generate random for each participant
	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		randoms[i] = make([]byte, 32)
		_, _ = rand.Read(randoms[i])
	}

	// Step 1: Participants generate their first messages
	states1 := make([]*FROSTDKGFullParticipantStateHK1, n)
	msgs1 := make([]*FROSTDKGFullParticipantMsg1, n)

	for i := 0; i < n; i++ {
		state, msg, err := FROSTDKGFullParticipantStep1WithHostKey(cs, hostKeys[i], hostPubkeys, threshold, i, randoms[i])
		if err != nil {
			t.Fatalf("Participant %d Step1 failed: %v", i, err)
		}
		states1[i] = state
		msgs1[i] = msg
	}

	// Coordinator Step 1: Process all participant messages
	coordState, coordMsg1, err := FROSTDKGFullCoordinatorStep1WithHostKey(cs, msgs1, threshold, hostPubkeys)
	if err != nil {
		t.Fatalf("Coordinator Step1 failed: %v", err)
	}

	// Step 2: Participants process coordinator message and sign
	states2 := make([]*FROSTDKGFullParticipantStateHK2, n)
	msgs2 := make([]*FROSTDKGFullParticipantMsg2, n)

	for i := 0; i < n; i++ {
		state2, msg2, err := FROSTDKGFullParticipantStep2WithHostKey(cs, states1[i], coordMsg1)
		if err != nil {
			t.Fatalf("Participant %d Step2 failed: %v", i, err)
		}
		states2[i] = state2
		msgs2[i] = msg2
	}

	// Coordinator Finalize: Collect signatures and create certificate
	coordMsg2, coordOutput, err := FROSTDKGFullCoordinatorFinalizeWithHostKey(coordState, msgs2)
	if err != nil {
		t.Fatalf("Coordinator Finalize failed: %v", err)
	}

	// Verify coordinator output
	if coordOutput.ThresholdPubkey == nil {
		t.Error("Coordinator output should have threshold pubkey")
	}

	// Participant Finalize: Verify certificate
	outputs := make([]*FROSTDKGOutput, n)
	for i := 0; i < n; i++ {
		output, err := FROSTDKGFullParticipantFinalizeWithHostKey(states2[i], coordMsg2, hostPubkeys)
		if err != nil {
			t.Fatalf("Participant %d Finalize failed: %v", i, err)
		}
		outputs[i] = output
	}

	// Verify all participants have the same threshold public key
	for i := 1; i < n; i++ {
		if !outputs[0].ThresholdPubkey.Equal(outputs[i].ThresholdPubkey) {
			t.Errorf("Participant %d has different threshold pubkey", i)
		}
	}

	// Verify threshold pubkey matches coordinator
	if !outputs[0].ThresholdPubkey.Equal(coordOutput.ThresholdPubkey) {
		t.Error("Participant threshold pubkey doesn't match coordinator")
	}

	// Verify each participant's secret share corresponds to their public share
	for i := 0; i < n; i++ {
		expectedPub := grp.ScalarBaseMult(outputs[i].SecretShare)
		if !expectedPub.Equal(outputs[i].PublicShares[i]) {
			t.Errorf("Participant %d secret share doesn't match public share", i)
		}
	}

	t.Logf("Full DKG with HostKey successful: threshold=%d, participants=%d", threshold, n)
}

// TestFROSTDKGEncWithHostKey tests encrypted DKG with HostKey for all 5 ciphersuites.
func TestFROSTDKGEncWithHostKey(t *testing.T) {
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
			runEncryptedDKGWithHostKeyTest(t, tc.cs, 2, 3)
		})
	}
}

func runEncryptedDKGWithHostKeyTest(t *testing.T, cs ciphersuite.Ciphersuite, threshold, n int) {
	t.Helper()

	grp := cs.Group()

	// Generate HostKeys for each participant
	hostKeys := make([]HostKey, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		key, err := GenerateSoftwareHostKey(cs)
		if err != nil {
			t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
		}
		hostKeys[i] = key
		hostPubkeys[i] = key.PublicKey()
	}

	// Generate seeds and randoms
	seeds := make([][]byte, n)
	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		seeds[i] = make([]byte, 32)
		_, _ = rand.Read(seeds[i])
		randoms[i] = make([]byte, 32)
		_, _ = rand.Read(randoms[i])
	}

	// Round 1: Each participant generates state and message
	states := make([]*FROSTDKGEncParticipantStateHK, n)
	msgs := make([]*FROSTDKGEncParticipantMsg, n)

	for i := 0; i < n; i++ {
		state, msg, err := FROSTDKGEncParticipantRound1WithHostKey(
			cs, seeds[i], hostKeys[i], hostPubkeys, threshold, i, randoms[i],
		)
		if err != nil {
			t.Fatalf("Participant %d Round1 failed: %v", i, err)
		}
		states[i] = state
		msgs[i] = msg
	}

	// Coordinator Round 1
	coordMsg, coordOutput, eqInput, participantShares, err := FROSTDKGEncCoordinatorRound1(
		cs, msgs, threshold, hostPubkeys,
	)
	if err != nil {
		t.Fatalf("Coordinator Round1 failed: %v", err)
	}

	if coordOutput.ThresholdPubkey == nil {
		t.Error("Coordinator output should have threshold pubkey")
	}

	// Round 2: Participants decrypt and process
	outputs := make([]*FROSTDKGOutput, n)
	eqInputs := make([][]byte, n)

	for i := 0; i < n; i++ {
		output, eq, err := FROSTDKGEncParticipantRound2WithHostKey(
			cs, states[i], coordMsg, participantShares[i],
		)
		if err != nil {
			t.Fatalf("Participant %d Round2 failed: %v", i, err)
		}
		outputs[i] = output
		eqInputs[i] = eq
	}

	// Verify all participants got the same threshold public key
	for i := 1; i < n; i++ {
		if !outputs[0].ThresholdPubkey.Equal(outputs[i].ThresholdPubkey) {
			t.Errorf("Participant %d has different threshold pubkey", i)
		}
	}

	// Verify threshold pubkey matches coordinator
	if !outputs[0].ThresholdPubkey.Equal(coordOutput.ThresholdPubkey) {
		t.Error("Participant threshold pubkey doesn't match coordinator")
	}

	// Verify all participants got the same equality input
	for i := 1; i < n; i++ {
		if string(eqInputs[0]) != string(eqInputs[i]) {
			t.Errorf("Participant %d has different eqInput", i)
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

	t.Logf("Encrypted DKG with HostKey successful: threshold=%d, participants=%d", threshold, n)
}

// TestFROSTDKGEncWithHostKeyErrors tests error handling.
func TestFROSTDKGEncWithHostKeyErrors(t *testing.T) {
	cs := ed25519_sha512.New()

	hostKeys := make([]HostKey, 3)
	hostPubkeys := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		key, _ := GenerateSoftwareHostKey(cs)
		hostKeys[i] = key
		hostPubkeys[i] = key.PublicKey()
	}

	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	random := make([]byte, 32)
	_, _ = rand.Read(random)

	t.Run("invalid_threshold", func(t *testing.T) {
		_, _, err := FROSTDKGEncParticipantRound1WithHostKey(cs, seed, hostKeys[0], hostPubkeys, 0, 0, random)
		if err != ErrFROSTDKGInvalidThreshold {
			t.Errorf("Expected ErrFROSTDKGInvalidThreshold, got %v", err)
		}
	})

	t.Run("invalid_index", func(t *testing.T) {
		_, _, err := FROSTDKGEncParticipantRound1WithHostKey(cs, seed, hostKeys[0], hostPubkeys, 2, 5, random)
		if err != ErrInvalidParticipantIndex {
			t.Errorf("Expected ErrInvalidParticipantIndex, got %v", err)
		}
	})

	t.Run("negative_index", func(t *testing.T) {
		_, _, err := FROSTDKGEncParticipantRound1WithHostKey(cs, seed, hostKeys[0], hostPubkeys, 2, -1, random)
		if err != ErrInvalidParticipantIndex {
			t.Errorf("Expected ErrInvalidParticipantIndex, got %v", err)
		}
	})
}

// TestFROSTDKGFullWithHostKeyCoordinatorErrors tests coordinator error handling.
func TestFROSTDKGFullWithHostKeyCoordinatorErrors(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold, n := 2, 3

	hostKeys := make([]HostKey, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		key, _ := GenerateSoftwareHostKey(cs)
		hostKeys[i] = key
		hostPubkeys[i] = key.PublicKey()
	}

	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		randoms[i] = make([]byte, 32)
		_, _ = rand.Read(randoms[i])
	}

	states1 := make([]*FROSTDKGFullParticipantStateHK1, n)
	msgs1 := make([]*FROSTDKGFullParticipantMsg1, n)
	for i := 0; i < n; i++ {
		state, msg, _ := FROSTDKGFullParticipantStep1WithHostKey(cs, hostKeys[i], hostPubkeys, threshold, i, randoms[i])
		states1[i] = state
		msgs1[i] = msg
	}

	coordState, coordMsg1, _ := FROSTDKGFullCoordinatorStep1WithHostKey(cs, msgs1, threshold, hostPubkeys)

	states2 := make([]*FROSTDKGFullParticipantStateHK2, n)
	msgs2 := make([]*FROSTDKGFullParticipantMsg2, n)
	for i := 0; i < n; i++ {
		state2, msg2, _ := FROSTDKGFullParticipantStep2WithHostKey(cs, states1[i], coordMsg1)
		states2[i] = state2
		msgs2[i] = msg2
	}

	t.Run("wrong_message_count", func(t *testing.T) {
		wrongMsgs := msgs2[:2]
		_, _, err := FROSTDKGFullCoordinatorFinalizeWithHostKey(coordState, wrongMsgs)
		if err != ErrFROSTDKGInvalidParticipantCount {
			t.Errorf("Expected ErrFROSTDKGInvalidParticipantCount, got %v", err)
		}
	})

	t.Run("invalid_signature", func(t *testing.T) {
		corruptMsgs := make([]*FROSTDKGFullParticipantMsg2, n)
		copy(corruptMsgs, msgs2)
		corruptMsgs[1] = &FROSTDKGFullParticipantMsg2{
			Signature: []byte("invalid signature"),
		}

		_, _, err := FROSTDKGFullCoordinatorFinalizeWithHostKey(coordState, corruptMsgs)
		if err == nil {
			t.Error("Expected error for invalid signature")
		}
	})
}

// TestFROSTDKGFullWithHostKeyParticipantFinalizeErrors tests participant finalize errors.
func TestFROSTDKGFullWithHostKeyParticipantFinalizeErrors(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold, n := 2, 3

	hostKeys := make([]HostKey, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		key, _ := GenerateSoftwareHostKey(cs)
		hostKeys[i] = key
		hostPubkeys[i] = key.PublicKey()
	}

	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		randoms[i] = make([]byte, 32)
		_, _ = rand.Read(randoms[i])
	}

	states1 := make([]*FROSTDKGFullParticipantStateHK1, n)
	msgs1 := make([]*FROSTDKGFullParticipantMsg1, n)
	for i := 0; i < n; i++ {
		state, msg, _ := FROSTDKGFullParticipantStep1WithHostKey(cs, hostKeys[i], hostPubkeys, threshold, i, randoms[i])
		states1[i] = state
		msgs1[i] = msg
	}

	_, coordMsg1, _ := FROSTDKGFullCoordinatorStep1WithHostKey(cs, msgs1, threshold, hostPubkeys)

	states2 := make([]*FROSTDKGFullParticipantStateHK2, n)
	for i := 0; i < n; i++ {
		state2, _, _ := FROSTDKGFullParticipantStep2WithHostKey(cs, states1[i], coordMsg1)
		states2[i] = state2
	}

	t.Run("empty_certificate", func(t *testing.T) {
		invalidCert := &FROSTDKGFullCoordinatorMsg2{
			Certificate: []byte{},
		}
		_, err := FROSTDKGFullParticipantFinalizeWithHostKey(states2[0], invalidCert, hostPubkeys)
		if err != ErrInvalidCertificateLength {
			t.Errorf("Expected ErrInvalidCertificateLength, got %v", err)
		}
	})

	t.Run("invalid_certificate", func(t *testing.T) {
		invalidCert := &FROSTDKGFullCoordinatorMsg2{
			Certificate: []byte("invalid certificate data"),
		}
		_, err := FROSTDKGFullParticipantFinalizeWithHostKey(states2[0], invalidCert, hostPubkeys)
		if err == nil {
			t.Error("Expected error for invalid certificate")
		}
	})
}

// TestFROSTDKGHostKeyDeterministic verifies deterministic output with same inputs.
func TestFROSTDKGHostKeyDeterministic(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()
	threshold, n := 2, 3

	// Generate fixed host keys
	hostKeys := make([]HostKey, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		// Use deterministic secret keys
		secretKey := hashToBytes(cs, "hostkey", []byte{byte(i)})[:32]
		key, err := NewSoftwareHostKey(cs, secretKey)
		if err != nil {
			t.Fatalf("NewSoftwareHostKey failed: %v", err)
		}
		hostKeys[i] = key
		hostPubkeys[i] = key.PublicKey()
	}

	// Fixed randoms
	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		randoms[i] = hashToBytes(cs, "random", []byte{byte(i)})[:32]
	}

	// Run DKG twice
	var outputs1, outputs2 []*FROSTDKGOutput

	for run := 0; run < 2; run++ {
		states1 := make([]*FROSTDKGFullParticipantStateHK1, n)
		msgs1 := make([]*FROSTDKGFullParticipantMsg1, n)

		for i := 0; i < n; i++ {
			state, msg, _ := FROSTDKGFullParticipantStep1WithHostKey(cs, hostKeys[i], hostPubkeys, threshold, i, randoms[i])
			states1[i] = state
			msgs1[i] = msg
		}

		coordState, coordMsg1, _ := FROSTDKGFullCoordinatorStep1WithHostKey(cs, msgs1, threshold, hostPubkeys)

		states2 := make([]*FROSTDKGFullParticipantStateHK2, n)
		msgs2 := make([]*FROSTDKGFullParticipantMsg2, n)
		for i := 0; i < n; i++ {
			state2, msg2, _ := FROSTDKGFullParticipantStep2WithHostKey(cs, states1[i], coordMsg1)
			states2[i] = state2
			msgs2[i] = msg2
		}

		coordMsg2, _, _ := FROSTDKGFullCoordinatorFinalizeWithHostKey(coordState, msgs2)

		outputs := make([]*FROSTDKGOutput, n)
		for i := 0; i < n; i++ {
			output, _ := FROSTDKGFullParticipantFinalizeWithHostKey(states2[i], coordMsg2, hostPubkeys)
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
			t.Error("HostKey DKG threshold pubkey should be deterministic")
		}
		if !outputs1[i].SecretShare.Equal(outputs2[i].SecretShare) {
			t.Errorf("Participant %d secret share should be deterministic", i)
		}
		for j := 0; j < n; j++ {
			expectedPub := grp.ScalarBaseMult(outputs1[i].SecretShare)
			if j == i && !expectedPub.Equal(outputs1[i].PublicShares[i]) {
				t.Errorf("Participant %d public share mismatch", i)
			}
		}
	}
}
