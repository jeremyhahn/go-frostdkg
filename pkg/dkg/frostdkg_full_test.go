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

// TestFROSTDKGFullProtocolWithCertEq tests the complete FROST-DKG protocol with CertEq for all 5 ciphersuites.
func TestFROSTDKGFullProtocolWithCertEq(t *testing.T) {
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
			runFullDKGWithCertEqTest(t, tc.cs, 2, 3)
		})
	}
}

// TestFROSTDKGFullDifferentThresholds tests Full DKG with CertEq across thresholds.
func TestFROSTDKGFullDifferentThresholds(t *testing.T) {
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
			runFullDKGWithCertEqTest(t, cs, tc.t, tc.n)
		})
	}
}

func runFullDKGWithCertEqTest(t *testing.T, cs ciphersuite.Ciphersuite, threshold, n int) {
	t.Helper()

	grp := cs.Group()

	// Get the signer for this ciphersuite
	signer, err := GetSigner(cs)
	if err != nil {
		t.Fatalf("GetSigner failed: %v", err)
	}

	// Generate host keypairs using the signer (proper format for signatures)
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

	// Generate random for each participant
	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		randoms[i] = make([]byte, 32)
		_, _ = rand.Read(randoms[i])
	}

	// Step 1: Participants generate their first messages
	states1 := make([]*FROSTDKGFullParticipantState1, n)
	msgs1 := make([]*FROSTDKGFullParticipantMsg1, n)

	for i := 0; i < n; i++ {
		state, msg, err := FROSTDKGFullParticipantStep1(cs, hostSeckeys[i], hostPubkeys, threshold, i, randoms[i])
		if err != nil {
			t.Fatalf("Participant %d Step1 failed: %v", i, err)
		}
		states1[i] = state
		msgs1[i] = msg
	}

	// Coordinator Step 1: Process all participant messages
	coordState, coordMsg1, err := FROSTDKGFullCoordinatorStep1(cs, msgs1, threshold, hostPubkeys)
	if err != nil {
		t.Fatalf("Coordinator Step1 failed: %v", err)
	}

	// Step 2: Participants process coordinator message and sign
	states2 := make([]*FROSTDKGFullParticipantState2, n)
	msgs2 := make([]*FROSTDKGFullParticipantMsg2, n)

	for i := 0; i < n; i++ {
		state2, msg2, err := FROSTDKGFullParticipantStep2(cs, states1[i], coordMsg1)
		if err != nil {
			t.Fatalf("Participant %d Step2 failed: %v", i, err)
		}
		states2[i] = state2
		msgs2[i] = msg2
	}

	// Coordinator Finalize: Collect signatures and create certificate
	coordMsg2, coordOutput, err := FROSTDKGFullCoordinatorFinalize(coordState, msgs2)
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
		output, err := FROSTDKGFullParticipantFinalize(states2[i], coordMsg2, hostPubkeys)
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

	t.Logf("Full DKG with CertEq successful: threshold=%d, participants=%d", threshold, n)
}

// TestFROSTDKGFullParticipantStep1Errors tests error handling in participant step 1.
func TestFROSTDKGFullParticipantStep1Errors(t *testing.T) {
	cs := ed25519_sha512.New()

	// Get the signer for key generation
	signer, _ := GetSigner(cs)
	_, pubkey, _ := signer.GenerateKey()
	hostPubkeys := [][]byte{pubkey, pubkey, pubkey}

	t.Run("invalid_threshold_too_low", func(t *testing.T) {
		random := make([]byte, 32)
		_, _ = rand.Read(random)
		seckey := make([]byte, 32)
		_, _ = rand.Read(seckey)

		_, _, err := FROSTDKGFullParticipantStep1(cs, seckey, hostPubkeys, 1, 0, random)
		if err != ErrInvalidMinSigners {
			t.Errorf("Expected ErrInvalidMinSigners, got %v", err)
		}
	})

	t.Run("invalid_index_negative", func(t *testing.T) {
		random := make([]byte, 32)
		_, _ = rand.Read(random)
		seckey := make([]byte, 32)
		_, _ = rand.Read(seckey)

		_, _, err := FROSTDKGFullParticipantStep1(cs, seckey, hostPubkeys, 2, -1, random)
		if err != ErrInvalidParticipantIndex {
			t.Errorf("Expected ErrInvalidParticipantIndex, got %v", err)
		}
	})

	t.Run("invalid_index_too_large", func(t *testing.T) {
		random := make([]byte, 32)
		_, _ = rand.Read(random)
		seckey := make([]byte, 32)
		_, _ = rand.Read(seckey)

		_, _, err := FROSTDKGFullParticipantStep1(cs, seckey, hostPubkeys, 2, 10, random)
		if err != ErrInvalidParticipantIndex {
			t.Errorf("Expected ErrInvalidParticipantIndex, got %v", err)
		}
	})
}

// TestFROSTDKGFullCoordinatorStep1Errors tests error handling in coordinator step 1.
func TestFROSTDKGFullCoordinatorStep1Errors(t *testing.T) {
	cs := ed25519_sha512.New()

	// Get the signer for key generation
	signer, _ := GetSigner(cs)

	t.Run("mismatched_message_count", func(t *testing.T) {
		// Generate one message but expect more participants
		seckey, pubkey, _ := signer.GenerateKey()
		hostPubkeys := [][]byte{pubkey, pubkey}

		random := make([]byte, 32)
		_, _ = rand.Read(random)
		_, msg, _ := FROSTDKGFullParticipantStep1(cs, seckey, hostPubkeys, 2, 0, random)

		// Only 1 message but 3 pubkeys expected
		hostPubkeys3 := [][]byte{pubkey, pubkey, pubkey}
		msgs := []*FROSTDKGFullParticipantMsg1{msg}
		_, _, err := FROSTDKGFullCoordinatorStep1(cs, msgs, 2, hostPubkeys3)
		if err != ErrFROSTDKGInvalidParticipantCount {
			t.Errorf("Expected ErrFROSTDKGInvalidParticipantCount, got %v", err)
		}
	})
}

// TestFROSTDKGFullCoordinatorFinalizeErrors tests error handling in coordinator finalize.
func TestFROSTDKGFullCoordinatorFinalizeErrors(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold, n := 2, 3

	// Get the signer for key generation
	signer, err := GetSigner(cs)
	if err != nil {
		t.Fatalf("GetSigner failed: %v", err)
	}

	// Generate host keypairs using the signer
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

	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		randoms[i] = make([]byte, 32)
		_, _ = rand.Read(randoms[i])
	}

	states1 := make([]*FROSTDKGFullParticipantState1, n)
	msgs1 := make([]*FROSTDKGFullParticipantMsg1, n)
	for i := 0; i < n; i++ {
		state, msg, err := FROSTDKGFullParticipantStep1(cs, hostSeckeys[i], hostPubkeys, threshold, i, randoms[i])
		if err != nil {
			t.Fatalf("Participant %d Step1 failed: %v", i, err)
		}
		states1[i] = state
		msgs1[i] = msg
	}

	coordState, coordMsg1, err := FROSTDKGFullCoordinatorStep1(cs, msgs1, threshold, hostPubkeys)
	if err != nil {
		t.Fatalf("Coordinator Step1 failed: %v", err)
	}

	states2 := make([]*FROSTDKGFullParticipantState2, n)
	msgs2 := make([]*FROSTDKGFullParticipantMsg2, n)
	for i := 0; i < n; i++ {
		state2, msg2, err := FROSTDKGFullParticipantStep2(cs, states1[i], coordMsg1)
		if err != nil {
			t.Fatalf("Participant %d Step2 failed: %v", i, err)
		}
		states2[i] = state2
		msgs2[i] = msg2
	}

	t.Run("wrong_message_count", func(t *testing.T) {
		wrongMsgs := msgs2[:2] // Only 2 messages instead of 3
		_, _, err := FROSTDKGFullCoordinatorFinalize(coordState, wrongMsgs)
		if err != ErrFROSTDKGInvalidParticipantCount {
			t.Errorf("Expected ErrFROSTDKGInvalidParticipantCount, got %v", err)
		}
	})

	t.Run("invalid_signature", func(t *testing.T) {
		// Corrupt one signature
		corruptMsgs := make([]*FROSTDKGFullParticipantMsg2, n)
		copy(corruptMsgs, msgs2)
		corruptMsgs[1] = &FROSTDKGFullParticipantMsg2{
			Signature: []byte("invalid signature"),
		}

		_, _, err := FROSTDKGFullCoordinatorFinalize(coordState, corruptMsgs)
		if err == nil {
			t.Error("Expected error for invalid signature")
		}
	})
}

// TestFROSTDKGFullParticipantFinalizeErrors tests error handling in participant finalize.
func TestFROSTDKGFullParticipantFinalizeErrors(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold, n := 2, 3

	// Get the signer for key generation
	signer, err := GetSigner(cs)
	if err != nil {
		t.Fatalf("GetSigner failed: %v", err)
	}

	// Generate host keypairs using the signer
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

	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		randoms[i] = make([]byte, 32)
		_, _ = rand.Read(randoms[i])
	}

	states1 := make([]*FROSTDKGFullParticipantState1, n)
	msgs1 := make([]*FROSTDKGFullParticipantMsg1, n)
	for i := 0; i < n; i++ {
		state, msg, err := FROSTDKGFullParticipantStep1(cs, hostSeckeys[i], hostPubkeys, threshold, i, randoms[i])
		if err != nil {
			t.Fatalf("Participant %d Step1 failed: %v", i, err)
		}
		states1[i] = state
		msgs1[i] = msg
	}

	coordState, coordMsg1, err := FROSTDKGFullCoordinatorStep1(cs, msgs1, threshold, hostPubkeys)
	if err != nil {
		t.Fatalf("Coordinator Step1 failed: %v", err)
	}

	states2 := make([]*FROSTDKGFullParticipantState2, n)
	msgs2 := make([]*FROSTDKGFullParticipantMsg2, n)
	for i := 0; i < n; i++ {
		state2, msg2, err := FROSTDKGFullParticipantStep2(cs, states1[i], coordMsg1)
		if err != nil {
			t.Fatalf("Participant %d Step2 failed: %v", i, err)
		}
		states2[i] = state2
		msgs2[i] = msg2
	}

	coordMsg2, _, err := FROSTDKGFullCoordinatorFinalize(coordState, msgs2)
	if err != nil {
		t.Fatalf("FROSTDKGFullCoordinatorFinalize failed: %v", err)
	}

	t.Run("invalid_certificate", func(t *testing.T) {
		invalidCert := &FROSTDKGFullCoordinatorMsg2{
			Certificate: []byte("invalid certificate"),
		}
		_, err := FROSTDKGFullParticipantFinalize(states2[0], invalidCert, hostPubkeys)
		if err == nil {
			t.Error("Expected error for invalid certificate")
		}
	})

	t.Run("wrong_pubkeys", func(t *testing.T) {
		// Use different pubkeys for verification
		wrongPubkeys := make([][]byte, n)
		for i := 0; i < n; i++ {
			_, pubkey, err := signer.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			wrongPubkeys[i] = pubkey
		}

		_, err := FROSTDKGFullParticipantFinalize(states2[0], coordMsg2, wrongPubkeys)
		if err == nil {
			t.Error("Expected error for wrong pubkeys")
		}
	})
}
