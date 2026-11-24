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

// Package dkg implements the FROST-DKG distributed key generation protocol.
package dkg

import (
	"encoding/binary"
)

const (
	// FROSTDKGTag is the domain separation tag for FROST-DKG operations.
	FROSTDKGTag = "FROST-DKG/"

	// CertEqPrefixLen is the length of the CertEq message prefix.
	// Format: FROST-DKG-TAG + "certeq" padded to 33 bytes.
	CertEqPrefixLen = 33

	// ParticipantIndexSize is the size of the participant index in bytes.
	ParticipantIndexSize = 4
)

// safeUint32 safely converts a non-negative int to uint32.
// Returns 0 if the input is negative or exceeds MaxUint32.
func safeUint32(n int) uint32 {
	if n < 0 || n > int(^uint32(0)) {
		return 0
	}
	return uint32(n)
}

// CertEqMessage builds the CertEq message: prefix || participant_index || threshold || n || hostpubkeys || transcript, binding the session per ChillDKG.
func CertEqMessage(transcript []byte, participantIndex int, hostPubkeys [][]byte, threshold int) []byte {
	// Create the domain separation prefix:
	// FROST-DKG-TAG + "certeq" padded with zeros to 33 bytes
	prefix := make([]byte, CertEqPrefixLen)
	tag := FROSTDKGTag + "certeq"
	copy(prefix, tag)
	// Remaining bytes are already zero from make()

	// Encode participant index as 4-byte big-endian
	idxBytes := make([]byte, ParticipantIndexSize)
	binary.BigEndian.PutUint32(idxBytes, safeUint32(participantIndex))

	// Encode session parameters as 4-byte big-endian values
	n := len(hostPubkeys)
	thresholdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(thresholdBytes, safeUint32(threshold))
	nBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nBytes, safeUint32(n))

	// Calculate total size for hostpubkeys concatenation
	hostPubkeysLen := 0
	for _, pk := range hostPubkeys {
		hostPubkeysLen += len(pk)
	}

	// Concatenate: prefix || index || threshold || n || hostpubkeys || transcript
	messageLen := len(prefix) + len(idxBytes) + 4 + 4 + hostPubkeysLen + len(transcript)
	message := make([]byte, 0, messageLen)
	message = append(message, prefix...)
	message = append(message, idxBytes...)
	message = append(message, thresholdBytes...)
	message = append(message, nBytes...)
	for _, pk := range hostPubkeys {
		message = append(message, pk...)
	}
	message = append(message, transcript...)

	return message
}

// CertEqParticipantStep signs the transcript bound to hostPubkeys, threshold and n; auxRand nil means random.
func CertEqParticipantStep(signer Signer, hostSeckey []byte, participantIndex int, hostPubkeys [][]byte, threshold int, transcript []byte, auxRand []byte) ([]byte, error) {
	if signer == nil {
		return nil, ErrSignerRequired
	}
	if len(hostSeckey) != signer.SecretKeySize() {
		return nil, ErrInvalidSecretKey
	}

	// Create the message to sign with session context binding
	message := CertEqMessage(transcript, participantIndex, hostPubkeys, threshold)

	// Sign the message using the provided signer
	signature, err := signer.Sign(hostSeckey, message, auxRand)
	if err != nil {
		return nil, &CertEqSigningError{Err: err}
	}

	return signature, nil
}

// CertEqVerify checks a certificate of n signatures, each against its participant's host key and the session-bound transcript.
func CertEqVerify(signer Signer, hostPubkeys [][]byte, threshold int, transcript []byte, certificate []byte) error {
	if signer == nil {
		return ErrSignerRequired
	}

	n := len(hostPubkeys)
	sigSize := signer.SignatureSize()

	// Verify certificate length
	expectedLen := n * sigSize
	if len(certificate) != expectedLen {
		return &CertificateLengthError{
			Expected:     expectedLen,
			Got:          len(certificate),
			Participants: n,
		}
	}

	// Verify every signature before returning so timing does not reveal which one failed.
	var firstError error
	firstErrorIndex := -1

	// Verify each participant's signature
	for i := 0; i < n; i++ {
		// Extract the signature for participant i
		sigStart := i * sigSize
		sigEnd := sigStart + sigSize
		signature := certificate[sigStart:sigEnd]

		// Get the host public key for participant i
		hostPubkey := hostPubkeys[i]

		// Create the message that participant i should have signed with session context
		message := CertEqMessage(transcript, i, hostPubkeys, threshold)

		// Verify the signature using the provided signer
		if err := signer.Verify(hostPubkey, message, signature); err != nil {
			// Record first error but continue verifying remaining signatures
			if firstError == nil {
				firstError = err
				firstErrorIndex = i
			}
		}
	}

	// Return the first error after all verifications are complete
	if firstError != nil {
		return &InvalidSignatureError{
			ParticipantIndex: firstErrorIndex,
			Err:              firstError,
		}
	}

	return nil
}

// CertEqCoordinatorStep concatenates participant signatures in session order; it does not validate them (use CertEqVerify).
func CertEqCoordinatorStep(signatures [][]byte) []byte {
	// Calculate total size
	totalSize := 0
	for _, sig := range signatures {
		totalSize += len(sig)
	}

	// Concatenate all signatures
	certificate := make([]byte, 0, totalSize)
	for _, sig := range signatures {
		certificate = append(certificate, sig...)
	}

	return certificate
}

// CertEqCertificateLength returns the certificate length for n participants with signer.
func CertEqCertificateLength(signer Signer, n int) int {
	return n * signer.SignatureSize()
}
