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
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
)

// TestCertEqMessage verifies that CertEqMessage creates the correct message format.
func TestCertEqMessage(t *testing.T) {
	signer := &Ed25519Signer{}
	_, hostPubkey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	hostPubkeys := [][]byte{hostPubkey}
	threshold := 1

	tests := []struct {
		name             string
		transcript       []byte
		participantIndex int
		wantPrefixLen    int
		wantIndexOffset  int
	}{
		{
			name:             "participant 0 with empty transcript",
			transcript:       []byte{},
			participantIndex: 0,
			wantPrefixLen:    33,
			wantIndexOffset:  33,
		},
		{
			name:             "participant 1 with data",
			transcript:       []byte("test transcript"),
			participantIndex: 1,
			wantPrefixLen:    33,
			wantIndexOffset:  33,
		},
		{
			name:             "participant 99 with large transcript",
			transcript:       make([]byte, 1000),
			participantIndex: 99,
			wantPrefixLen:    33,
			wantIndexOffset:  33,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := CertEqMessage(tt.transcript, tt.participantIndex, hostPubkeys, threshold)

			// Verify minimum structure - prefix + index + threshold + n + hostpubkeys + transcript
			// prefix (33) + index (4) + threshold (4) + n (4) + hostpubkeys (32) + transcript
			minLen := tt.wantPrefixLen + 4 + 4 + 4 + len(hostPubkey) + len(tt.transcript)
			if len(msg) != minLen {
				t.Errorf("CertEqMessage() length = %d, want %d", len(msg), minLen)
			}

			// Verify prefix contains the tag
			prefix := msg[:tt.wantPrefixLen]
			expectedPrefix := FROSTDKGTag + "certeq"
			if !bytes.HasPrefix(prefix, []byte(expectedPrefix)) {
				t.Errorf("CertEqMessage() prefix does not start with expected tag")
			}

			// Verify remaining prefix bytes are zero
			for i := len(expectedPrefix); i < tt.wantPrefixLen; i++ {
				if prefix[i] != 0 {
					t.Errorf("CertEqMessage() prefix[%d] = %d, want 0", i, prefix[i])
				}
			}

			// Verify participant index is encoded correctly
			idxBytes := msg[tt.wantIndexOffset : tt.wantIndexOffset+4]
			idx := binary.BigEndian.Uint32(idxBytes)
			if int(idx) != tt.participantIndex {
				t.Errorf("CertEqMessage() participant index = %d, want %d", idx, tt.participantIndex)
			}
		})
	}
}

// TestCertEqMessage_DifferentIndices verifies that different participant indices
// produce different messages even with the same transcript.
func TestCertEqMessage_DifferentIndices(t *testing.T) {
	signer := &Ed25519Signer{}
	_, hostPubkey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	hostPubkeys := [][]byte{hostPubkey}
	threshold := 1

	transcript := []byte("common transcript")

	msg0 := CertEqMessage(transcript, 0, hostPubkeys, threshold)
	msg1 := CertEqMessage(transcript, 1, hostPubkeys, threshold)
	msg2 := CertEqMessage(transcript, 2, hostPubkeys, threshold)

	if bytes.Equal(msg0, msg1) {
		t.Error("CertEqMessage() produced identical messages for different participant indices")
	}
	if bytes.Equal(msg1, msg2) {
		t.Error("CertEqMessage() produced identical messages for different participant indices")
	}
	if bytes.Equal(msg0, msg2) {
		t.Error("CertEqMessage() produced identical messages for different participant indices")
	}
}

// mockSigner is a test signer that can be configured to fail on demand.
type mockSigner struct {
	secretKeySize int
	publicKeySize int
	signatureSize int
	signError     error
	verifyError   error
}

func (m *mockSigner) Sign(secretKey []byte, message []byte, auxRand []byte) ([]byte, error) {
	if m.signError != nil {
		return nil, m.signError
	}
	return make([]byte, m.signatureSize), nil
}

func (m *mockSigner) Verify(publicKey []byte, message []byte, signature []byte) error {
	if m.verifyError != nil {
		return m.verifyError
	}
	return nil
}

func (m *mockSigner) SecretKeySize() int {
	return m.secretKeySize
}

func (m *mockSigner) PublicKeySize() int {
	return m.publicKeySize
}

func (m *mockSigner) SignatureSize() int {
	return m.signatureSize
}

func (m *mockSigner) GenerateKey() (secretKey []byte, publicKey []byte, err error) {
	return make([]byte, m.secretKeySize), make([]byte, m.publicKeySize), nil
}

// TestCertEqParticipantStep verifies that participants can sign transcripts.
func TestCertEqParticipantStep(t *testing.T) {
	// Generate a valid secret key using Ed25519
	signer := &Ed25519Signer{}
	seckey, pubkey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	hostPubkeys := [][]byte{pubkey}
	threshold := 1
	transcript := []byte("test transcript for signing")
	participantIndex := 0

	tests := []struct {
		name        string
		signer      Signer
		seckey      []byte
		index       int
		transcript  []byte
		auxRand     []byte
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid signature with random aux",
			signer:     signer,
			seckey:     seckey,
			index:      participantIndex,
			transcript: transcript,
			auxRand:    nil, // Will use random
			wantErr:    false,
		},
		{
			name:       "valid signature with provided aux",
			signer:     signer,
			seckey:     seckey,
			index:      participantIndex,
			transcript: transcript,
			auxRand:    make([]byte, 32),
			wantErr:    false,
		},
		{
			name:        "invalid secret key length",
			signer:      signer,
			seckey:      make([]byte, 16),
			index:       participantIndex,
			transcript:  transcript,
			auxRand:     nil,
			wantErr:     true,
			errContains: "invalid secret key",
		},
		{
			name:       "empty transcript",
			signer:     signer,
			seckey:     seckey,
			index:      participantIndex,
			transcript: []byte{},
			auxRand:    nil,
			wantErr:    false,
		},
		{
			name:       "large participant index",
			signer:     signer,
			seckey:     seckey,
			index:      9999,
			transcript: transcript,
			auxRand:    nil,
			wantErr:    false,
		},
		{
			name:        "nil signer",
			signer:      nil,
			seckey:      seckey,
			index:       participantIndex,
			transcript:  transcript,
			auxRand:     nil,
			wantErr:     true,
			errContains: "signer is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := CertEqParticipantStep(tt.signer, tt.seckey, tt.index, hostPubkeys, threshold, tt.transcript, tt.auxRand)

			if tt.wantErr {
				if err == nil {
					t.Error("CertEqParticipantStep() expected error, got nil")
				}
				if tt.errContains != "" && err != nil {
					if !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
						t.Errorf("CertEqParticipantStep() error = %v, should contain %s", err, tt.errContains)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("CertEqParticipantStep() unexpected error: %v", err)
				return
			}

			// Verify signature length
			expectedSize := tt.signer.SignatureSize()
			if len(sig) != expectedSize {
				t.Errorf("CertEqParticipantStep() signature length = %d, want %d", len(sig), expectedSize)
			}

			// Verify signature is valid
			message := CertEqMessage(tt.transcript, tt.index, hostPubkeys, threshold)
			if err := tt.signer.Verify(pubkey, message, sig); err != nil {
				t.Errorf("CertEqParticipantStep() produced invalid signature: %v", err)
			}
		})
	}
}

// TestCertEqParticipantStep_AllCiphersuites verifies that all supported
// ciphersuites work correctly with CertEqParticipantStep.
func TestCertEqParticipantStep_AllCiphersuites(t *testing.T) {
	transcript := []byte("test transcript for all ciphersuites")
	participantIndex := 0
	threshold := 1

	signers := []struct {
		name   string
		signer Signer
	}{
		{"Ed25519", &Ed25519Signer{}},
		{"P256", &P256Signer{}},
		{"Ristretto255", &Ristretto255Signer{}},
		{"Ed448", &Ed448Signer{}},
		{"Secp256k1", &Secp256k1Signer{}},
	}

	for _, tc := range signers {
		t.Run(tc.name, func(t *testing.T) {
			// Generate key
			seckey, pubkey, err := tc.signer.GenerateKey()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			hostPubkeys := [][]byte{pubkey}

			// Sign
			sig, err := CertEqParticipantStep(tc.signer, seckey, participantIndex, hostPubkeys, threshold, transcript, nil)
			if err != nil {
				t.Errorf("CertEqParticipantStep() failed: %v", err)
				return
			}

			// Verify signature size
			expectedSize := tc.signer.SignatureSize()
			if len(sig) != expectedSize {
				t.Errorf("Signature length = %d, want %d", len(sig), expectedSize)
			}

			// Verify signature
			message := CertEqMessage(transcript, participantIndex, hostPubkeys, threshold)
			if err := tc.signer.Verify(pubkey, message, sig); err != nil {
				t.Errorf("Signature verification failed: %v", err)
			}
		})
	}
}

// TestCertEqParticipantStep_NilTranscript verifies behavior with nil transcript.
func TestCertEqParticipantStep_NilTranscript(t *testing.T) {
	signer := &Ed25519Signer{}
	seckey, pubkey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	hostPubkeys := [][]byte{pubkey}
	threshold := 1

	// Sign with nil transcript
	sig, err := CertEqParticipantStep(signer, seckey, 0, hostPubkeys, threshold, nil, nil)
	if err != nil {
		t.Errorf("CertEqParticipantStep() with nil transcript failed: %v", err)
		return
	}

	// Verify signature
	message := CertEqMessage(nil, 0, hostPubkeys, threshold)
	if err := signer.Verify(pubkey, message, sig); err != nil {
		t.Errorf("Signature verification with nil transcript failed: %v", err)
	}
}

// TestCertEqParticipantStep_SigningError verifies that signing errors are properly wrapped.
func TestCertEqParticipantStep_SigningError(t *testing.T) {
	// Create a mock signer that fails on Sign
	expectedErr := errors.New("mock signing failure")
	mockSgn := &mockSigner{
		secretKeySize: 32,
		publicKeySize: 32,
		signatureSize: 64,
		signError:     expectedErr,
	}

	seckey := make([]byte, 32)
	pubkey := make([]byte, 32)
	hostPubkeys := [][]byte{pubkey}
	threshold := 1
	transcript := []byte("test transcript")

	_, err := CertEqParticipantStep(mockSgn, seckey, 0, hostPubkeys, threshold, transcript, nil)
	if err == nil {
		t.Fatal("CertEqParticipantStep() expected error, got nil")
	}

	// Verify error is wrapped correctly
	if !bytes.Contains([]byte(err.Error()), []byte("failed to sign message")) {
		t.Errorf("Error message should contain 'failed to sign message', got: %v", err)
	}

	// Verify original error is in the chain
	if !bytes.Contains([]byte(err.Error()), []byte(expectedErr.Error())) {
		t.Errorf("Error should contain original error, got: %v", err)
	}
}

// TestCertEqParticipantStep_EmptySecretKey verifies behavior with empty secret key.
func TestCertEqParticipantStep_EmptySecretKey(t *testing.T) {
	signer := &Ed25519Signer{}
	_, pubkey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	hostPubkeys := [][]byte{pubkey}
	threshold := 1
	transcript := []byte("test transcript")

	// Empty secret key
	_, err = CertEqParticipantStep(signer, []byte{}, 0, hostPubkeys, threshold, transcript, nil)
	if err == nil {
		t.Error("CertEqParticipantStep() with empty secret key should fail")
		return
	}

	if !bytes.Contains([]byte(err.Error()), []byte("invalid secret key")) {
		t.Errorf("Error should contain 'invalid secret key', got: %v", err)
	}
}

// TestCertEqParticipantStep_Deterministic verifies that signatures with the same
// aux randomness are deterministic.
func TestCertEqParticipantStep_Deterministic(t *testing.T) {
	signer := &Ed25519Signer{}
	seckey, pubkey, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	hostPubkeys := [][]byte{pubkey}
	threshold := 1
	transcript := []byte("test transcript")
	participantIndex := 0
	auxRand := make([]byte, 32)
	copy(auxRand, []byte("fixed randomness for testing"))

	sig1, err := CertEqParticipantStep(signer, seckey, participantIndex, hostPubkeys, threshold, transcript, auxRand)
	if err != nil {
		t.Fatalf("CertEqParticipantStep() failed: %v", err)
	}

	sig2, err := CertEqParticipantStep(signer, seckey, participantIndex, hostPubkeys, threshold, transcript, auxRand)
	if err != nil {
		t.Fatalf("CertEqParticipantStep() failed: %v", err)
	}

	if !bytes.Equal(sig1, sig2) {
		t.Error("CertEqParticipantStep() produced different signatures with same inputs")
	}
}

// TestCertEqVerify verifies certificate verification with valid and invalid inputs.
func TestCertEqVerify(t *testing.T) {
	signer := &Ed25519Signer{}

	// Setup: Generate keys and signatures for 3 participants
	n := 3
	threshold := 2
	seckeys := make([][]byte, n)
	pubkeys := make([][]byte, n)
	transcript := []byte("test transcript for verification")

	for i := 0; i < n; i++ {
		sk, pk, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key for participant %d: %v", i, err)
		}
		seckeys[i] = sk
		pubkeys[i] = pk
	}

	signatures := make([][]byte, n)
	for i := 0; i < n; i++ {
		sig, err := CertEqParticipantStep(signer, seckeys[i], i, pubkeys, threshold, transcript, nil)
		if err != nil {
			t.Fatalf("Failed to sign for participant %d: %v", i, err)
		}
		signatures[i] = sig
	}

	validCert := CertEqCoordinatorStep(signatures)

	tests := []struct {
		name        string
		signer      Signer
		pubkeys     [][]byte
		threshold   int
		transcript  []byte
		cert        []byte
		wantErr     bool
		errType     error
		errContains string
	}{
		{
			name:       "valid certificate",
			signer:     signer,
			pubkeys:    pubkeys,
			threshold:  threshold,
			transcript: transcript,
			cert:       validCert,
			wantErr:    false,
		},
		{
			name:        "nil signer",
			signer:      nil,
			pubkeys:     pubkeys,
			threshold:   threshold,
			transcript:  transcript,
			cert:        validCert,
			wantErr:     true,
			errType:     ErrSignerRequired,
			errContains: "signer is required",
		},
		{
			name:        "invalid certificate length - too short",
			signer:      signer,
			pubkeys:     pubkeys,
			threshold:   threshold,
			transcript:  transcript,
			cert:        validCert[:len(validCert)-1],
			wantErr:     true,
			errType:     ErrInvalidCertificateLength,
			errContains: "invalid certificate length",
		},
		{
			name:        "invalid certificate length - too long",
			signer:      signer,
			pubkeys:     pubkeys,
			threshold:   threshold,
			transcript:  transcript,
			cert:        append(validCert, 0x00),
			wantErr:     true,
			errType:     ErrInvalidCertificateLength,
			errContains: "invalid certificate length",
		},
		{
			name:        "wrong transcript",
			signer:      signer,
			pubkeys:     pubkeys,
			threshold:   threshold,
			transcript:  []byte("different transcript"),
			cert:        validCert,
			wantErr:     true,
			errContains: "invalid signature",
		},
		{
			name:        "corrupted signature",
			signer:      signer,
			pubkeys:     pubkeys,
			threshold:   threshold,
			transcript:  transcript,
			cert:        corruptSignature(validCert, 1, signer.SignatureSize()),
			wantErr:     true,
			errContains: "invalid signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CertEqVerify(tt.signer, tt.pubkeys, tt.threshold, tt.transcript, tt.cert)

			if tt.wantErr {
				if err == nil {
					t.Error("CertEqVerify() expected error, got nil")
					return
				}

				if tt.errContains != "" {
					if !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
						t.Errorf("CertEqVerify() error = %v, should contain %s", err, tt.errContains)
					}
				}

				if tt.errType != nil {
					if !bytes.Contains([]byte(err.Error()), []byte(tt.errType.Error())) {
						t.Errorf("CertEqVerify() error type mismatch, got %v, want %v", err, tt.errType)
					}
				}
			} else {
				if err != nil {
					t.Errorf("CertEqVerify() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestCertEqVerify_InvalidParticipantIndex verifies that InvalidSignatureError
// contains the correct participant index.
func TestCertEqVerify_InvalidParticipantIndex(t *testing.T) {
	signer := &Ed25519Signer{}
	n := 3
	threshold := 2
	seckeys := make([][]byte, n)
	pubkeys := make([][]byte, n)
	transcript := []byte("test transcript")

	for i := 0; i < n; i++ {
		sk, pk, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		seckeys[i] = sk
		pubkeys[i] = pk
	}

	signatures := make([][]byte, n)
	for i := 0; i < n; i++ {
		sig, err := CertEqParticipantStep(signer, seckeys[i], i, pubkeys, threshold, transcript, nil)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}
		signatures[i] = sig
	}

	// Corrupt participant 1's signature
	signatures[1][0] ^= 0xFF
	cert := CertEqCoordinatorStep(signatures)

	err := CertEqVerify(signer, pubkeys, threshold, transcript, cert)
	if err == nil {
		t.Fatal("CertEqVerify() expected error, got nil")
	}

	var sigErr *InvalidSignatureError
	if !bytes.Contains([]byte(err.Error()), []byte("participant 1")) {
		t.Errorf("Expected error to mention participant 1, got: %v", err)
	}

	// Check if we can extract the participant index
	if sigErr != nil && sigErr.ParticipantIndex != 1 {
		t.Errorf("InvalidSignatureError.ParticipantIndex = %d, want 1", sigErr.ParticipantIndex)
	}
}

// TestCertEqVerify_CompressedPublicKeys verifies that P256 compressed (33-byte)
// public keys work correctly.
func TestCertEqVerify_CompressedPublicKeys(t *testing.T) {
	n := 2
	threshold := 2
	transcript := []byte("test transcript")

	// Generate separate keys for each participant
	seckeys := make([][]byte, n)
	compressedPubkeys := make([][]byte, n)

	// Use P256 which supports compressed public keys
	signer := &P256Signer{}

	for i := 0; i < n; i++ {
		seckey, compressedPubkey, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key for participant %d: %v", i, err)
		}
		seckeys[i] = seckey
		compressedPubkeys[i] = compressedPubkey
	}

	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		// Create signature for this participant's index
		sig, err := CertEqParticipantStep(signer, seckeys[i], i, compressedPubkeys, threshold, transcript, nil)
		if err != nil {
			t.Fatalf("Failed to sign for participant %d: %v", i, err)
		}
		sigs[i] = sig
	}

	// Assemble certificate from all signatures
	cert := CertEqCoordinatorStep(sigs)

	// Test compressed format
	err := CertEqVerify(signer, compressedPubkeys, threshold, transcript, cert)
	if err != nil {
		t.Errorf("CertEqVerify() with compressed pubkeys failed: %v", err)
	}
}

func TestCertEqCoordinatorStep(t *testing.T) {
	tests := []struct {
		name       string
		signatures [][]byte
		wantLen    int
	}{
		{
			name: "single signature",
			signatures: [][]byte{
				make([]byte, 64),
			},
			wantLen: 64,
		},
		{
			name: "three signatures",
			signatures: [][]byte{
				make([]byte, 64),
				make([]byte, 64),
				make([]byte, 64),
			},
			wantLen: 192,
		},
		{
			name:       "empty list",
			signatures: [][]byte{},
			wantLen:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := CertEqCoordinatorStep(tt.signatures)

			if len(cert) != tt.wantLen {
				t.Errorf("CertEqCoordinatorStep() length = %d, want %d", len(cert), tt.wantLen)
			}

			// Verify signatures are in correct order
			offset := 0
			for i, sig := range tt.signatures {
				if !bytes.Equal(cert[offset:offset+len(sig)], sig) {
					t.Errorf("CertEqCoordinatorStep() signature %d mismatch", i)
				}
				offset += len(sig)
			}
		})
	}
}

// TestCertEqCertificateLength verifies the certificate length calculation.
func TestCertEqCertificateLength(t *testing.T) {
	signer := &Ed25519Signer{}
	sigSize := signer.SignatureSize()

	tests := []struct {
		name    string
		n       int
		wantLen int
	}{
		{"1 participant", 1, sigSize},
		{"2 participants", 2, 2 * sigSize},
		{"3 participants", 3, 3 * sigSize},
		{"10 participants", 10, 10 * sigSize},
		{"100 participants", 100, 100 * sigSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CertEqCertificateLength(signer, tt.n)
			if got != tt.wantLen {
				t.Errorf("CertEqCertificateLength(%d) = %d, want %d", tt.n, got, tt.wantLen)
			}
		})
	}
}

// TestCertEqProtocol_EndToEnd performs an end-to-end test of the CertEq protocol.
func TestCertEqProtocol_EndToEnd(t *testing.T) {
	tests := []struct {
		name            string
		numParticipants int
		threshold       int
	}{
		{"2 participants", 2, 2},
		{"3 participants", 3, 2},
		{"5 participants", 5, 3},
		{"10 participants", 10, 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := &Ed25519Signer{}
			n := tt.numParticipants
			threshold := tt.threshold
			transcript := []byte("end-to-end test transcript")

			// Step 1: Each participant generates keys
			seckeys := make([][]byte, n)
			pubkeys := make([][]byte, n)
			for i := 0; i < n; i++ {
				sk, pk, err := signer.GenerateKey()
				if err != nil {
					t.Fatalf("Participant %d: key generation failed: %v", i, err)
				}
				seckeys[i] = sk
				pubkeys[i] = pk
			}

			// Step 2: Each participant signs the transcript
			signatures := make([][]byte, n)
			for i := 0; i < n; i++ {
				sig, err := CertEqParticipantStep(signer, seckeys[i], i, pubkeys, threshold, transcript, nil)
				if err != nil {
					t.Fatalf("Participant %d: signing failed: %v", i, err)
				}
				signatures[i] = sig
			}

			// Step 3: Coordinator assembles the certificate
			cert := CertEqCoordinatorStep(signatures)

			// Verify certificate length
			expectedLen := CertEqCertificateLength(signer, n)
			if len(cert) != expectedLen {
				t.Errorf("Certificate length = %d, want %d", len(cert), expectedLen)
			}

			// Step 4: Each participant verifies the certificate
			for i := 0; i < n; i++ {
				if err := CertEqVerify(signer, pubkeys, threshold, transcript, cert); err != nil {
					t.Errorf("Participant %d: verification failed: %v", i, err)
				}
			}
		})
	}
}

// TestCertEqProtocol_DifferentTranscripts verifies that participants signing
// different transcripts produces an invalid certificate.
func TestCertEqProtocol_DifferentTranscripts(t *testing.T) {
	signer := &Ed25519Signer{}
	n := 3
	threshold := 2
	transcript1 := []byte("transcript 1")
	transcript2 := []byte("transcript 2")

	seckeys := make([][]byte, n)
	pubkeys := make([][]byte, n)

	for i := 0; i < n; i++ {
		sk, pk, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		seckeys[i] = sk
		pubkeys[i] = pk
	}

	signatures := make([][]byte, n)
	for i := 0; i < n; i++ {
		// Participant 1 signs a different transcript
		transcript := transcript1
		if i == 1 {
			transcript = transcript2
		}

		sig, err := CertEqParticipantStep(signer, seckeys[i], i, pubkeys, threshold, transcript, nil)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}
		signatures[i] = sig
	}

	cert := CertEqCoordinatorStep(signatures)

	// Verification should fail with transcript1
	err := CertEqVerify(signer, pubkeys, threshold, transcript1, cert)
	if err == nil {
		t.Error("CertEqVerify() should fail when participants sign different transcripts")
	}

	// Verification should also fail with transcript2
	err = CertEqVerify(signer, pubkeys, threshold, transcript2, cert)
	if err == nil {
		t.Error("CertEqVerify() should fail when participants sign different transcripts")
	}
}

// Helper function to corrupt a signature in a certificate.
func corruptSignature(cert []byte, participantIndex int, sigSize int) []byte {
	corrupted := make([]byte, len(cert))
	copy(corrupted, cert)
	// Flip a byte in the specified participant's signature
	offset := participantIndex * sigSize
	corrupted[offset] ^= 0xFF
	return corrupted
}

// TestInvalidSignatureError_Error verifies the error message format.
func TestInvalidSignatureError_Error(t *testing.T) {
	underlyingErr := ErrVerificationFailed
	err := &InvalidSignatureError{
		ParticipantIndex: 5,
		Err:              underlyingErr,
	}

	msg := err.Error()
	if !bytes.Contains([]byte(msg), []byte("participant 5")) {
		t.Errorf("Error message should contain participant index, got: %s", msg)
	}
	if !bytes.Contains([]byte(msg), []byte("certeq")) {
		t.Errorf("Error message should contain 'certeq', got: %s", msg)
	}
}

// TestInvalidSignatureError_Unwrap verifies error unwrapping.
func TestInvalidSignatureError_Unwrap(t *testing.T) {
	underlyingErr := ErrVerificationFailed
	err := &InvalidSignatureError{
		ParticipantIndex: 0,
		Err:              underlyingErr,
	}

	unwrapped := err.Unwrap()
	if unwrapped != underlyingErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, underlyingErr)
	}
}

// BenchmarkCertEqMessage benchmarks message creation.
func BenchmarkCertEqMessage(b *testing.B) {
	signer := &Ed25519Signer{}
	_, pubkey, _ := signer.GenerateKey()
	hostPubkeys := [][]byte{pubkey}
	threshold := 1

	transcript := make([]byte, 1000)
	if _, err := rand.Read(transcript); err != nil {
		b.Fatalf("rand.Read failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CertEqMessage(transcript, i%100, hostPubkeys, threshold)
	}
}

// BenchmarkCertEqParticipantStep benchmarks signature creation.
func BenchmarkCertEqParticipantStep(b *testing.B) {
	signer := &Ed25519Signer{}
	seckey, pubkey, _ := signer.GenerateKey()
	hostPubkeys := [][]byte{pubkey}
	threshold := 1

	transcript := make([]byte, 1000)
	if _, err := rand.Read(transcript); err != nil {
		b.Fatalf("rand.Read failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CertEqParticipantStep(signer, seckey, 0, hostPubkeys, threshold, transcript, nil)
	}
}

// BenchmarkCertEqVerify benchmarks certificate verification.
func BenchmarkCertEqVerify(b *testing.B) {
	signer := &Ed25519Signer{}
	n := 5
	threshold := 3
	transcript := make([]byte, 1000)
	if _, err := rand.Read(transcript); err != nil {
		b.Fatalf("rand.Read failed: %v", err)
	}

	seckeys := make([][]byte, n)
	pubkeys := make([][]byte, n)

	for i := 0; i < n; i++ {
		sk, pk, _ := signer.GenerateKey()
		seckeys[i] = sk
		pubkeys[i] = pk
	}

	signatures := make([][]byte, n)
	for i := 0; i < n; i++ {
		sig, _ := CertEqParticipantStep(signer, seckeys[i], i, pubkeys, threshold, transcript, nil)
		signatures[i] = sig
	}

	cert := CertEqCoordinatorStep(signatures)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CertEqVerify(signer, pubkeys, threshold, transcript, cert)
	}
}
