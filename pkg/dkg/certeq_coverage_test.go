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
)

// TestCertEqParticipantStepErrorPaths tests error paths in CertEqParticipantStep.
func TestCertEqParticipantStepErrorPaths(t *testing.T) {
	signer := &Ed25519Signer{}

	// Generate valid host pubkeys for session context
	_, hostPubkey, _ := signer.GenerateKey()
	hostPubkeys := [][]byte{hostPubkey}
	threshold := 1

	// Test with invalid secret key length
	t.Run("invalid secret key length", func(t *testing.T) {
		invalidKey := []byte{0x01, 0x02, 0x03}
		transcript := []byte("test transcript")

		_, err := CertEqParticipantStep(signer, invalidKey, 0, hostPubkeys, threshold, transcript, nil)
		if err != ErrInvalidSecretKey {
			t.Fatalf("Expected ErrInvalidSecretKey, got %v", err)
		}
	})

	// Test with nil secret key
	t.Run("nil secret key", func(t *testing.T) {
		transcript := []byte("test transcript")

		_, err := CertEqParticipantStep(signer, nil, 0, hostPubkeys, threshold, transcript, nil)
		if err != ErrInvalidSecretKey {
			t.Fatalf("Expected ErrInvalidSecretKey, got %v", err)
		}
	})

	// Test with empty secret key
	t.Run("empty secret key", func(t *testing.T) {
		emptyKey := []byte{}
		transcript := []byte("test transcript")

		_, err := CertEqParticipantStep(signer, emptyKey, 0, hostPubkeys, threshold, transcript, nil)
		if err != ErrInvalidSecretKey {
			t.Fatalf("Expected ErrInvalidSecretKey, got %v", err)
		}
	})

	// Test with nil signer
	t.Run("nil signer", func(t *testing.T) {
		secretKey, _, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		transcript := []byte("test transcript")

		_, err = CertEqParticipantStep(nil, secretKey, 0, hostPubkeys, threshold, transcript, nil)
		if err != ErrSignerRequired {
			t.Fatalf("Expected ErrSignerRequired, got %v", err)
		}
	})
}

// TestCertEqParticipantStepWithSigners tests CertEqParticipantStep with different signers.
func TestCertEqParticipantStepWithSigners(t *testing.T) {
	testCases := []struct {
		name   string
		signer Signer
	}{
		{"Ed25519Signer", &Ed25519Signer{}},
		{"P256Signer", &P256Signer{}},
		{"Ristretto255Signer", &Ristretto255Signer{}},
		{"Ed448Signer", &Ed448Signer{}},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			secretKey, publicKey, err := tc.signer.GenerateKey()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			hostPubkeys := [][]byte{publicKey}
			threshold := 1
			transcript := []byte("test transcript for signing")
			signature, err := CertEqParticipantStep(tc.signer, secretKey, 0, hostPubkeys, threshold, transcript, nil)
			if err != nil {
				t.Fatalf("CertEqParticipantStep failed: %v", err)
			}

			if len(signature) != tc.signer.SignatureSize() {
				t.Fatalf("Expected signature size %d, got %d", tc.signer.SignatureSize(), len(signature))
			}
		})
	}

	// Test with different participant indices
	t.Run("different participant indices", func(t *testing.T) {
		signer := &P256Signer{}
		secretKey, publicKey, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		hostPubkeys := [][]byte{publicKey, publicKey} // 2 participants
		threshold := 2
		transcript := []byte("test transcript")

		sig0, err := CertEqParticipantStep(signer, secretKey, 0, hostPubkeys, threshold, transcript, nil)
		if err != nil {
			t.Fatalf("Failed for index 0: %v", err)
		}

		sig1, err := CertEqParticipantStep(signer, secretKey, 1, hostPubkeys, threshold, transcript, nil)
		if err != nil {
			t.Fatalf("Failed for index 1: %v", err)
		}

		// Signatures should be different for different indices
		if len(sig0) == len(sig1) {
			allSame := true
			for i := range sig0 {
				if sig0[i] != sig1[i] {
					allSame = false
					break
				}
			}
			if allSame {
				t.Fatal("Signatures should be different for different participant indices")
			}
		}
	})
}

// TestCertEqWithMultipleCiphersuites tests CertEq with different ciphersuites.
func TestCertEqWithMultipleCiphersuites(t *testing.T) {
	testCases := []struct {
		name   string
		signer Signer
	}{
		{"Ed25519Signer", &Ed25519Signer{}},
		{"P256Signer", &P256Signer{}},
		{"Ristretto255Signer", &Ristretto255Signer{}},
		{"Ed448Signer", &Ed448Signer{}},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			n := 3
			threshold := 2
			transcript := []byte("test transcript for " + tc.name)

			// Generate host keys
			hostSeckeys := make([][]byte, n)
			hostPubkeys := make([][]byte, n)
			for i := 0; i < n; i++ {
				sec, pub, err := tc.signer.GenerateKey()
				if err != nil {
					t.Fatalf("Failed to generate key %d: %v", i, err)
				}
				hostSeckeys[i] = sec
				hostPubkeys[i] = pub
			}

			// All participants sign
			signatures := make([][]byte, n)
			for i := 0; i < n; i++ {
				sig, err := CertEqParticipantStep(tc.signer, hostSeckeys[i], i, hostPubkeys, threshold, transcript, nil)
				if err != nil {
					t.Fatalf("Participant %d failed to sign: %v", i, err)
				}
				signatures[i] = sig
			}

			// Coordinator assembles certificate
			certificate := CertEqCoordinatorStep(signatures)

			// Verify certificate
			err := CertEqVerify(tc.signer, hostPubkeys, threshold, transcript, certificate)
			if err != nil {
				t.Fatalf("Certificate verification failed: %v", err)
			}
		})
	}
}

// TestCertEqVerifyErrorPaths tests error paths in CertEqVerify.
func TestCertEqVerifyErrorPaths(t *testing.T) {
	signer := &P256Signer{}
	n := 3
	threshold := 2

	// Generate host keys
	hostSeckeys := make([][]byte, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		sec, pub, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}
		hostSeckeys[i] = sec
		hostPubkeys[i] = pub
	}

	transcript := []byte("test transcript")

	// Generate valid certificate
	signatures := make([][]byte, n)
	for i := 0; i < n; i++ {
		sig, err := CertEqParticipantStep(signer, hostSeckeys[i], i, hostPubkeys, threshold, transcript, nil)
		if err != nil {
			t.Fatalf("Participant %d failed to sign: %v", i, err)
		}
		signatures[i] = sig
	}
	certificate := CertEqCoordinatorStep(signatures)

	// Test with nil signer
	t.Run("nil signer", func(t *testing.T) {
		err := CertEqVerify(nil, hostPubkeys, threshold, transcript, certificate)
		if err != ErrSignerRequired {
			t.Fatalf("Expected ErrSignerRequired, got %v", err)
		}
	})

	// Test with invalid certificate length - too short
	t.Run("invalid certificate length - too short", func(t *testing.T) {
		invalidCert := certificate[:len(certificate)-1]
		err := CertEqVerify(signer, hostPubkeys, threshold, transcript, invalidCert)
		if err == nil {
			t.Fatal("Expected error for invalid certificate length")
		}
	})

	// Test with invalid certificate length - too long
	t.Run("invalid certificate length - too long", func(t *testing.T) {
		invalidCert := append(certificate, 0x00)
		err := CertEqVerify(signer, hostPubkeys, threshold, transcript, invalidCert)
		if err == nil {
			t.Fatal("Expected error for invalid certificate length")
		}
	})

	// Test with corrupted signature
	t.Run("corrupted signature", func(t *testing.T) {
		corruptedCert := make([]byte, len(certificate))
		copy(corruptedCert, certificate)
		// Corrupt the first signature
		corruptedCert[0] ^= 0xFF

		err := CertEqVerify(signer, hostPubkeys, threshold, transcript, corruptedCert)
		if err == nil {
			t.Fatal("Expected error for corrupted signature")
		}
	})

	// Test with wrong transcript
	t.Run("wrong transcript", func(t *testing.T) {
		wrongTranscript := []byte("wrong transcript")
		err := CertEqVerify(signer, hostPubkeys, threshold, wrongTranscript, certificate)
		if err == nil {
			t.Fatal("Expected error for wrong transcript")
		}
	})

	// Test with wrong public keys
	t.Run("wrong public keys", func(t *testing.T) {
		wrongPubkeys := make([][]byte, n)
		for i := 0; i < n; i++ {
			_, pub, _ := signer.GenerateKey()
			wrongPubkeys[i] = pub
		}

		err := CertEqVerify(signer, wrongPubkeys, threshold, transcript, certificate)
		if err == nil {
			t.Fatal("Expected error for wrong public keys")
		}
	})

	// Test with invalid public key
	t.Run("invalid public key", func(t *testing.T) {
		invalidPubkeys := make([][]byte, n)
		copy(invalidPubkeys, hostPubkeys)
		invalidPubkeys[0] = []byte{0xFF} // Invalid public key

		err := CertEqVerify(signer, invalidPubkeys, threshold, transcript, certificate)
		if err == nil {
			t.Fatal("Expected error for invalid public key")
		}
	})

	// Test with wrong threshold
	t.Run("wrong threshold", func(t *testing.T) {
		wrongThreshold := threshold + 1
		err := CertEqVerify(signer, hostPubkeys, wrongThreshold, transcript, certificate)
		if err == nil {
			t.Fatal("Expected error for wrong threshold")
		}
	})
}

// TestCertEqFullFlow tests the complete CertEq flow with different scenarios.
func TestCertEqFullFlow(t *testing.T) {
	n := 5
	threshold := 3

	// Test CertEq with Ed25519
	t.Run("CertEq with Ed25519", func(t *testing.T) {
		signer := &Ed25519Signer{}

		// Generate host keys using the signer
		hostSeckeys := make([][]byte, n)
		hostPubkeys := make([][]byte, n)
		for i := 0; i < n; i++ {
			sk, pk, err := signer.GenerateKey()
			if err != nil {
				t.Fatalf("Failed to generate key for participant %d: %v", i, err)
			}
			hostSeckeys[i] = sk
			hostPubkeys[i] = pk
		}

		eqInput := []byte("test equality input for certificate verification")

		signatures := make([][]byte, n)
		for i := 0; i < n; i++ {
			sig, err := CertEqParticipantStep(signer, hostSeckeys[i], i, hostPubkeys, threshold, eqInput, nil)
			if err != nil {
				t.Fatalf("Participant %d failed CertEq: %v", i, err)
			}
			signatures[i] = sig
		}

		certificate := CertEqCoordinatorStep(signatures)
		err := CertEqVerify(signer, hostPubkeys, threshold, eqInput, certificate)
		if err != nil {
			t.Fatalf("CertEq verification failed: %v", err)
		}
	})

	// Test CertEq with P256
	t.Run("CertEq with P256", func(t *testing.T) {
		signer := &P256Signer{}

		// Generate host keys using the signer
		hostSeckeys := make([][]byte, n)
		hostPubkeys := make([][]byte, n)
		for i := 0; i < n; i++ {
			sk, pk, err := signer.GenerateKey()
			if err != nil {
				t.Fatalf("Failed to generate key for participant %d: %v", i, err)
			}
			hostSeckeys[i] = sk
			hostPubkeys[i] = pk
		}

		eqInput := []byte("test equality input for certificate verification")

		signatures := make([][]byte, n)
		for i := 0; i < n; i++ {
			sig, err := CertEqParticipantStep(signer, hostSeckeys[i], i, hostPubkeys, threshold, eqInput, nil)
			if err != nil {
				t.Fatalf("Participant %d failed CertEq: %v", i, err)
			}
			signatures[i] = sig
		}

		certificate := CertEqCoordinatorStep(signatures)
		err := CertEqVerify(signer, hostPubkeys, threshold, eqInput, certificate)
		if err != nil {
			t.Fatalf("CertEq verification failed: %v", err)
		}
	})
}

// TestCertEqWithDifferentTranscripts tests that different transcripts produce different signatures.
func TestCertEqWithDifferentTranscripts(t *testing.T) {
	signer := &Ed25519Signer{}
	secretKey, publicKey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	hostPubkeys := [][]byte{publicKey}
	threshold := 1

	transcript1 := []byte("transcript 1")
	transcript2 := []byte("transcript 2")

	sig1, err := CertEqParticipantStep(signer, secretKey, 0, hostPubkeys, threshold, transcript1, nil)
	if err != nil {
		t.Fatalf("Failed to sign transcript 1: %v", err)
	}

	sig2, err := CertEqParticipantStep(signer, secretKey, 0, hostPubkeys, threshold, transcript2, nil)
	if err != nil {
		t.Fatalf("Failed to sign transcript 2: %v", err)
	}

	// Signatures should be different
	if len(sig1) == len(sig2) {
		allSame := true
		for i := range sig1 {
			if sig1[i] != sig2[i] {
				allSame = false
				break
			}
		}
		if allSame {
			t.Fatal("Signatures should be different for different transcripts")
		}
	}

	// Verify each signature with correct transcript
	cert1 := CertEqCoordinatorStep([][]byte{sig1})
	err = CertEqVerify(signer, hostPubkeys, threshold, transcript1, cert1)
	if err != nil {
		t.Fatalf("Failed to verify signature 1: %v", err)
	}

	cert2 := CertEqCoordinatorStep([][]byte{sig2})
	err = CertEqVerify(signer, hostPubkeys, threshold, transcript2, cert2)
	if err != nil {
		t.Fatalf("Failed to verify signature 2: %v", err)
	}

	// Cross-verification should fail
	err = CertEqVerify(signer, hostPubkeys, threshold, transcript1, cert2)
	if err == nil {
		t.Fatal("Cross-verification should fail")
	}

	err = CertEqVerify(signer, hostPubkeys, threshold, transcript2, cert1)
	if err == nil {
		t.Fatal("Cross-verification should fail")
	}
}

// TestCertEqMessageConstruction tests CertEqMessage construction.
func TestCertEqMessageConstruction(t *testing.T) {
	signer := &Ed25519Signer{}
	_, publicKey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	hostPubkeys := [][]byte{publicKey}
	threshold := 1
	transcript := []byte("test transcript")

	// Test different participant indices
	msg0 := CertEqMessage(transcript, 0, hostPubkeys, threshold)
	msg1 := CertEqMessage(transcript, 1, hostPubkeys, threshold)

	// Messages should be different for different indices
	if len(msg0) == len(msg1) && len(msg0) > 0 {
		allSame := true
		for i := range msg0 {
			if msg0[i] != msg1[i] {
				allSame = false
				break
			}
		}
		if allSame {
			t.Fatal("Messages should be different for different indices")
		}
	}

	// Verify structure: should contain transcript and index
	if len(msg0) < len(transcript) {
		t.Fatal("Message should contain at least the transcript")
	}

	// Test with empty transcript
	emptyMsg := CertEqMessage([]byte{}, 0, hostPubkeys, threshold)
	if len(emptyMsg) == 0 {
		t.Fatal("Message should not be empty even with empty transcript")
	}

	// Test with different transcripts
	transcript2 := []byte("different transcript")
	msg0_t2 := CertEqMessage(transcript2, 0, hostPubkeys, threshold)

	if len(msg0) == len(msg0_t2) {
		allSame := true
		for i := range msg0 {
			if msg0[i] != msg0_t2[i] {
				allSame = false
				break
			}
		}
		if allSame {
			t.Fatal("Messages should be different for different transcripts")
		}
	}

	// Test with different thresholds
	msg_t1 := CertEqMessage(transcript, 0, hostPubkeys, 1)
	msg_t2 := CertEqMessage(transcript, 0, hostPubkeys, 2)

	allSame := true
	for i := range msg_t1 {
		if msg_t1[i] != msg_t2[i] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatal("Messages should be different for different thresholds")
	}

	// Test with different hostPubkeys
	_, publicKey2, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	hostPubkeys2 := [][]byte{publicKey2}

	msg_pk1 := CertEqMessage(transcript, 0, hostPubkeys, threshold)
	msg_pk2 := CertEqMessage(transcript, 0, hostPubkeys2, threshold)

	allSame = true
	for i := range msg_pk1 {
		if msg_pk1[i] != msg_pk2[i] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatal("Messages should be different for different hostPubkeys")
	}
}

// TestCertEqCertificateLengthFunctions tests certificate length helper functions.
func TestCertEqCertificateLengthFunctions(t *testing.T) {
	// Test CertEqCertificateLength with different signers
	t.Run("CertEqCertificateLength", func(t *testing.T) {
		signers := []Signer{
			&Ed25519Signer{},
			&P256Signer{},
			&Ristretto255Signer{},
			&Ed448Signer{},
		}

		for _, signer := range signers {
			n := 5
			expectedLen := n * signer.SignatureSize()
			actualLen := CertEqCertificateLength(signer, n)
			if actualLen != expectedLen {
				t.Fatalf("For signer type, expected length %d, got %d", expectedLen, actualLen)
			}
		}
	})

	// Test with zero participants
	t.Run("zero participants", func(t *testing.T) {
		signer := &Ed25519Signer{}
		len0 := CertEqCertificateLength(signer, 0)
		if len0 != 0 {
			t.Fatalf("Expected length 0 for 0 participants, got %d", len0)
		}
	})

	// Test with large number of participants
	t.Run("large number of participants", func(t *testing.T) {
		signer := &Ed25519Signer{}
		n := 1000
		expectedLen := n * signer.SignatureSize()
		actualLen := CertEqCertificateLength(signer, n)
		if actualLen != expectedLen {
			t.Fatalf("Expected length %d, got %d", expectedLen, actualLen)
		}
	})
}
