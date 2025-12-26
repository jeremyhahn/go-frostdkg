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
	"errors"
	"fmt"
)

// Validation constants aligned with Zcash FROST reference implementation.
// These follow RFC 9591 and Zcash FROST security requirements.
const (
	// MinThreshold is the minimum allowed threshold value.
	// Per Zcash FROST: min_signers must be at least 2.
	// A threshold of 1 provides no threshold security.
	MinThreshold = 2

	// MinParticipants is the minimum allowed number of participants.
	// Per Zcash FROST: max_signers must be at least 2.
	MinParticipants = 2

	// MaxParticipants is the maximum allowed number of participants.
	// This prevents DoS attacks from excessive memory allocation.
	// Aligned with Zcash FROST's use of u16 (65535 max).
	MaxParticipants = 65535
)

// Core DKG errors for VSS, polynomial, and share operations.
var (
	// ErrInvalidParticipantIndex indicates that a participant index is invalid.
	// Participant indices must be non-negative.
	ErrInvalidParticipantIndex = errors.New("dkg: invalid participant index")

	// ErrInvalidThreshold indicates that the threshold value is invalid.
	// The threshold must be at least MinThreshold and at most equal to the number of participants.
	ErrInvalidThreshold = errors.New("dkg: invalid threshold")

	// ErrInvalidMinSigners indicates threshold is below minimum (must be >= 2).
	// Aligned with Zcash FROST: min_signers must be at least 2.
	ErrInvalidMinSigners = errors.New("dkg: min_signers must be at least 2")

	// ErrInvalidMaxSigners indicates participant count is below minimum (must be >= 2).
	// Aligned with Zcash FROST: max_signers must be at least 2.
	ErrInvalidMaxSigners = errors.New("dkg: max_signers must be at least 2")

	// ErrInvalidCommitmentLength indicates that a VSS commitment has an invalid length.
	// The commitment must have exactly t * element_length bytes.
	ErrInvalidCommitmentLength = errors.New("dkg: invalid commitment length")

	// ErrInvalidShare indicates that a secret share verification failed.
	// This occurs when the share does not match its corresponding public share.
	ErrInvalidShare = errors.New("dkg: invalid share")

	// ErrZeroScalar indicates that a scalar is zero in a context where it is not allowed.
	// This occurs when attempting to compute the multiplicative inverse of zero.
	ErrZeroScalar = errors.New("dkg: zero scalar")

	// ErrMismatchedThreshold indicates that two VSS commitments have different thresholds.
	// Operations like addition require both commitments to have the same threshold.
	ErrMismatchedThreshold = errors.New("dkg: mismatched threshold")

	// ErrInvalidPolynomial indicates that a polynomial is invalid.
	// This occurs when the polynomial has no coefficients or invalid structure.
	ErrInvalidPolynomial = errors.New("dkg: invalid polynomial")

	// ErrInvalidSeed indicates that the seed is invalid.
	ErrInvalidSeed = errors.New("dkg: invalid seed")

	// ErrInvalidMessageLength indicates that a message has incorrect length.
	ErrInvalidMessageLength = errors.New("dkg: invalid message length")

	// ErrSecShareSum indicates that the sum of partial secret shares does not match expected.
	ErrSecShareSum = errors.New("dkg: secret share sum error")

	// ErrDuplicateHelper indicates that duplicate helper indices were provided.
	// Helper indices must be unique in the Repairable Threshold Scheme.
	ErrDuplicateHelper = errors.New("dkg: duplicate helper index")

	// ErrIdentityElementInCommitment indicates that an identity element was found
	// in a VSS commitment. Identity elements in commitments are not allowed as
	// they could indicate a maliciously crafted input (e.g., zero secret).
	ErrIdentityElementInCommitment = errors.New("dkg: identity element in commitment")
)

// FROST-DKG protocol errors for the distributed key generation protocol.
var (
	// ErrFROSTDKGInvalidThreshold indicates an invalid threshold value in FROST-DKG.
	ErrFROSTDKGInvalidThreshold = errors.New("frostdkg: invalid threshold")

	// ErrFROSTDKGInvalidParticipantCount indicates an invalid participant count.
	ErrFROSTDKGInvalidParticipantCount = errors.New("frostdkg: invalid participant count")

	// ErrFROSTDKGShareVerificationFailed indicates a share verification failure.
	ErrFROSTDKGShareVerificationFailed = errors.New("frostdkg: share verification failed")

	// ErrFROSTDKGCommitmentMismatch indicates a commitment mismatch.
	ErrFROSTDKGCommitmentMismatch = errors.New("frostdkg: commitment mismatch")

	// ErrFROSTDKGInvalidPOP indicates an invalid proof of possession.
	ErrFROSTDKGInvalidPOP = errors.New("frostdkg: invalid proof of possession")

	// ErrFROSTDKGDecryptionFailed indicates decryption failure.
	ErrFROSTDKGDecryptionFailed = errors.New("frostdkg: decryption failed")

	// ErrUnsupportedCiphersuite indicates an unknown or unsupported ciphersuite.
	ErrUnsupportedCiphersuite = errors.New("frostdkg: unsupported ciphersuite")
)

// Signer errors for signature operations.
var (
	// ErrUnknownCiphersuite indicates an unknown or unsupported ciphersuite for signing.
	ErrUnknownCiphersuite = errors.New("signer: unknown ciphersuite")

	// ErrSigningFailed indicates that signing operation failed.
	ErrSigningFailed = errors.New("signer: signing failed")

	// ErrVerificationFailed indicates that signature verification failed.
	ErrVerificationFailed = errors.New("signer: verification failed")

	// ErrInvalidPublicKey indicates an invalid public key.
	ErrInvalidPublicKey = errors.New("signer: invalid public key")

	// ErrInvalidSignature indicates an invalid signature format.
	ErrInvalidSignature = errors.New("signer: invalid signature")
)

// CertEq protocol errors for certificate equality verification.
var (
	// ErrInvalidCertificateLength indicates that a certificate has invalid length.
	// The certificate must be exactly n * signatureSize bytes where n is the number of participants.
	ErrInvalidCertificateLength = errors.New("certeq: invalid certificate length")

	// ErrInvalidSignatureInCertificate indicates that a signature in the certificate is invalid.
	// This error wraps InvalidSignatureError which includes the participant index.
	ErrInvalidSignatureInCertificate = errors.New("certeq: invalid signature in certificate")

	// ErrInvalidHostPubkey indicates that a host public key is invalid.
	ErrInvalidHostPubkey = errors.New("certeq: invalid host public key")

	// ErrInvalidSecretKey indicates that a host secret key is invalid.
	ErrInvalidSecretKey = errors.New("certeq: invalid secret key")

	// ErrSignerRequired indicates that a signer is required but not provided.
	ErrSignerRequired = errors.New("certeq: signer is required")
)

// HostKey errors for host key operations.
var (
	// ErrHostKeyECDHFailed indicates that ECDH key agreement failed.
	ErrHostKeyECDHFailed = errors.New("hostkey: ECDH failed")

	// ErrHostKeySignFailed indicates that signing failed.
	ErrHostKeySignFailed = errors.New("hostkey: signing failed")
)

// InvalidSignatureError represents an error where a specific participant's
// signature in a certificate is invalid.
type InvalidSignatureError struct {
	// ParticipantIndex is the index of the participant with the invalid signature.
	ParticipantIndex int
	// Err is the underlying error from signature verification.
	Err error
}

// Error implements the error interface.
func (e *InvalidSignatureError) Error() string {
	return fmt.Sprintf("certeq: invalid signature from participant %d: %v", e.ParticipantIndex, e.Err)
}

// Unwrap returns the underlying error for error chain unwrapping.
func (e *InvalidSignatureError) Unwrap() error {
	return e.Err
}

// CertEqSigningError wraps an underlying signing error during CertEq operations.
type CertEqSigningError struct {
	Err error
}

func (e *CertEqSigningError) Error() string {
	return fmt.Sprintf("certeq: failed to sign message: %v", e.Err)
}

func (e *CertEqSigningError) Unwrap() error {
	return e.Err
}

// CertificateLengthError provides details about a certificate length mismatch.
type CertificateLengthError struct {
	Expected     int
	Got          int
	Participants int
}

func (e *CertificateLengthError) Error() string {
	return fmt.Sprintf("certeq: invalid certificate length: expected %d bytes for %d participants, got %d bytes",
		e.Expected, e.Participants, e.Got)
}

func (e *CertificateLengthError) Is(target error) bool {
	return target == ErrInvalidCertificateLength
}

// FaultyParticipantError indicates that a participant has deviated from the protocol.
type FaultyParticipantError struct {
	ParticipantIndex int
	Reason           string
}

func (e *FaultyParticipantError) Error() string {
	return fmt.Sprintf("dkg: participant %d is faulty: %s", e.ParticipantIndex, e.Reason)
}

// NewFaultyParticipantError creates a new FaultyParticipantError.
func NewFaultyParticipantError(index int, reason string) *FaultyParticipantError {
	return &FaultyParticipantError{
		ParticipantIndex: index,
		Reason:           reason,
	}
}

// FaultyCoordinatorError indicates that the coordinator has deviated from the protocol.
type FaultyCoordinatorError struct {
	Reason string
}

func (e *FaultyCoordinatorError) Error() string {
	return fmt.Sprintf("dkg: coordinator is faulty: %s", e.Reason)
}

// NewFaultyCoordinatorError creates a new FaultyCoordinatorError.
func NewFaultyCoordinatorError(reason string) *FaultyCoordinatorError {
	return &FaultyCoordinatorError{
		Reason: reason,
	}
}

// UnknownFaultyPartyError indicates that either a participant or coordinator is faulty,
// but investigation is required to determine which.
type UnknownFaultyPartyError struct {
	InvestigationData *ParticipantInvestigationData
	Reason            string
}

func (e *UnknownFaultyPartyError) Error() string {
	return fmt.Sprintf("dkg: unknown faulty party: %s", e.Reason)
}

// NewUnknownFaultyPartyError creates a new UnknownFaultyPartyError.
func NewUnknownFaultyPartyError(invData *ParticipantInvestigationData, reason string) *UnknownFaultyPartyError {
	return &UnknownFaultyPartyError{
		InvestigationData: invData,
		Reason:            reason,
	}
}
