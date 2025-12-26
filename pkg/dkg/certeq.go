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

// CertEqMessage creates the message to be signed in the CertEq protocol.
//
// The message format uses FROST-DKG domain separation and includes session
// context binding to prevent cross-session replay attacks per ChillDKG spec:
//
//	prefix = (FROST-DKG-TAG + "certeq") padded with zeros to 33 bytes
//	session_context = threshold || n || hostpubkeys_concat
//	message = prefix || participant_index || session_context || transcript
//
// where:
//   - participant_index is a 4-byte big-endian unsigned integer
//   - threshold is a 4-byte big-endian unsigned integer
//   - n is a 4-byte big-endian unsigned integer (number of participants)
//   - hostpubkeys_concat is the concatenation of all host public keys
//
// This ensures that:
//  1. Each participant signs a unique message (via participant_index)
//  2. Signatures cannot be replayed across sessions with different parameters
//  3. Signatures are bound to the specific set of participants (via hostpubkeys)
//
// Parameters:
//   - transcript: The session transcript to be signed (eq_input from FROST-DKG).
//   - participantIndex: The zero-based index of the participant in the session.
//   - hostPubkeys: Ordered list of all participants' host public keys.
//   - threshold: The signing threshold (t in t-of-n).
//
// Returns:
//
//	The complete message to be signed by the participant.
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

// CertEqParticipantStep performs a participant's step in the CertEq protocol.
//
// This function creates a signature on the session transcript using the provided
// signer, which allows using different signature schemes for different ciphersuites.
//
// The signature includes session context binding (hostpubkeys, threshold, n) to
// prevent cross-session replay attacks per the ChillDKG specification.
//
// Parameters:
//   - signer: The signer to use for creating the signature.
//   - hostSeckey: The participant's long-term host secret key.
//   - participantIndex: The zero-based index of the participant in the session.
//   - hostPubkeys: Ordered list of all participants' host public keys for session binding.
//   - threshold: The signing threshold (t in t-of-n) for session binding.
//   - transcript: The session transcript to sign (eq_input from FROST-DKG).
//   - auxRand: Optional auxiliary randomness for signing. If nil, random data
//     will be generated automatically.
//
// Returns:
//
//	A signature of the size specified by the signer.
//
// Errors:
//   - ErrSignerRequired: If signer is nil.
//   - ErrInvalidSecretKey: If the host secret key is invalid or wrong length.
//   - Signature errors: If signature generation fails.
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

// CertEqVerify verifies a success certificate from the CertEq protocol.
//
// A certificate is a concatenation of signatures from all n participants.
// This function verifies that each signature is valid for the corresponding
// participant's public key and the session transcript.
//
// The verification includes session context binding (hostpubkeys, threshold, n)
// to ensure signatures cannot be replayed across different DKG sessions.
//
// The verification ensures:
//  1. The certificate has the correct length (n * signatureSize bytes).
//  2. Each participant's signature is valid for their host public key.
//  3. All participants signed the same transcript with the same session context.
//
// Parameters:
//   - signer: The signer to use for verifying signatures.
//   - hostPubkeys: Ordered list of all participants' host public keys.
//   - threshold: The signing threshold (t in t-of-n) for session binding.
//   - transcript: The session transcript that was signed (eq_input from FROST-DKG).
//   - certificate: The certificate containing all n signatures.
//
// Returns:
//
//	nil if the certificate is valid, otherwise an error describing the failure.
//
// Errors:
//   - ErrSignerRequired: If signer is nil.
//   - ErrInvalidCertificateLength: If the certificate length is incorrect.
//   - InvalidSignatureError: If a specific participant's signature is invalid.
//   - ErrInvalidHostPubkey: If a host public key is invalid.
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

	// SECURITY: Verify ALL signatures before returning to prevent timing attacks.
	// Early return would leak information about which signature is invalid.
	// We collect errors and return the first one after all verifications complete.
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

// CertEqCoordinatorStep assembles a certificate from participant signatures.
//
// The coordinator collects signatures from all participants and concatenates
// them to form the certificate. This is a simple concatenation operation.
//
// The order of signatures in the certificate must match the order of participants
// in the session, as the certificate will be verified against the ordered list
// of host public keys.
//
// Parameters:
//   - signatures: List of signatures from all participants, in order.
//
// Returns:
//
//	The assembled certificate (concatenation of all signatures).
//
// Note:
//
//	This function does not perform validation. The coordinator should verify
//	signatures before including them in the certificate using CertEqVerify.
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

// CertEqCertificateLength returns the expected length of a certificate
// for n participants using a specific signer.
//
// Parameters:
//   - signer: The signer to use for determining signature size.
//   - n: The number of participants in the session.
//
// Returns:
//
//	The expected certificate length in bytes.
func CertEqCertificateLength(signer Signer, n int) int {
	return n * signer.SignatureSize()
}
