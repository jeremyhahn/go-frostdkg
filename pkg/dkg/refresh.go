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

// Package dkg implements share refresh functionality for FROST.
//
// Share refreshing has two purposes:
// - Mitigate against share compromise
// - Remove participants from a group
//
// This package supports refreshing shares using either a Trusted Dealer
// or DKG approach. You should use the same approach as the original
// share generation.
//
// For the Trusted Dealer approach, the trusted dealer calls
// ComputeRefreshingShares and sends the returned refreshing shares to
// the participants. Each participant then calls RefreshShare.
//
// For the DKG approach, the flow is similar to DKG itself. Each participant
// calls RefreshDKGPart1, keeps the returned secret package and sends the
// returned package to other participants. Then each participant calls
// RefreshDKGPart2 and sends the returned packages to other participants.
// Finally each participant calls RefreshDKGShares.

package dkg

import (
	"crypto/rand"
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen/dkg"
)

// RefreshingShare represents a secret share used to refresh an existing share.
// This is similar to a SecretShare but with the identity commitment removed.
type RefreshingShare struct {
	// Identifier is the participant's unique identifier
	Identifier frost.Identifier

	// SigningShare is the refreshing share value
	SigningShare group.Scalar

	// Commitment is the VSS commitment (without the identity element)
	Commitment *VSSCommitment
}

// PublicKeyPackage contains public key information for all participants.
type PublicKeyPackage struct {
	// VerifyingShares maps each participant to their public share
	VerifyingShares map[frost.Identifier]group.Element

	// VerifyingKey is the group's threshold public key
	VerifyingKey group.Element

	// MinSigners is the threshold (may be nil if not set)
	MinSigners *uint32
}

// ComputeRefreshingShares computes refreshing shares for the Trusted Dealer approach.
//
// This function creates new shares that can be added to existing shares to refresh them.
// The refreshing shares are based on a zero secret, so adding them doesn't change
// the group public key.
//
// Parameters:
//   - pubKeyPackage: The current public key package
//   - maxSigners: Number of participants refreshing their shares (can be smaller than original)
//   - minSigners: Threshold needed to sign (must equal original value)
//   - identifiers: Identifiers of all participants refreshing (must have length maxSigners)
//   - cs: The ciphersuite to use
//
// Returns:
//   - A slice of RefreshingShare to send to participants (in same order as identifiers)
//   - The refreshed PublicKeyPackage
//
// Errors:
//   - Returns error if minSigners doesn't match the package's value
//   - Returns error if number of identifiers doesn't match maxSigners
//   - Returns error if parameters are invalid
func ComputeRefreshingShares(
	pubKeyPackage *PublicKeyPackage,
	maxSigners uint32,
	minSigners uint32,
	identifiers []frost.Identifier,
	cs ciphersuite.Ciphersuite,
) ([]RefreshingShare, *PublicKeyPackage, error) {
	grp := cs.Group()

	// Validate minSigners matches the package's value
	if pubKeyPackage.MinSigners != nil && *pubKeyPackage.MinSigners != minSigners {
		return nil, nil, ErrInvalidThreshold
	}

	// Validate inputs
	if len(identifiers) != int(maxSigners) {
		return nil, nil, NewFaultyParticipantError(0, "incorrect number of identifiers")
	}

	if err := validateNumOfSigners(minSigners, maxSigners); err != nil {
		return nil, nil, err
	}

	// Build refreshing shares using a zero secret
	// This ensures the group public key doesn't change
	zeroSecret := grp.NewScalar() // Zero scalar

	// Generate random coefficients for a polynomial with zero constant term
	seed, err := generateRandomSeed(32)
	if err != nil {
		return nil, nil, err
	}

	vss, err := Generate(cs, seed, int(minSigners))
	if err != nil {
		return nil, nil, err
	}

	// Replace the constant term with zero
	coeffs := vss.f.Coefficients()
	coeffs[0] = zeroSecret
	poly, err := NewPolynomial(grp, coeffs)
	if err != nil {
		return nil, nil, err
	}
	vss.f = poly

	// Generate secret shares for all participants
	shares, err := generateSecretShares(grp, vss, identifiers)
	if err != nil {
		return nil, nil, err
	}

	// Compute refreshed verifying shares
	refreshedVerifyingShares := make(map[frost.Identifier]group.Element)
	refreshingShares := make([]RefreshingShare, len(shares))

	for i, share := range shares {
		// Compute the refreshing verifying share (public share)
		refreshingVerifyingShare := grp.ScalarBaseMult(share.SigningShare)

		// Get the existing verifying share
		existingShare, exists := pubKeyPackage.VerifyingShares[share.Identifier]
		if !exists {
			return nil, nil, NewFaultyParticipantError(int(share.Identifier), "unknown identifier")
		}

		// Add the refreshing share to the existing share
		refreshedVerifyingShare := existingShare.Add(refreshingVerifyingShare)
		refreshedVerifyingShares[share.Identifier] = refreshedVerifyingShare

		// Remove the identity element from the commitment for the refreshing share
		commitmentCoeffs := share.Commitment.Coefficients
		if len(commitmentCoeffs) > 0 {
			// Skip the first coefficient (identity)
			newCoeffs := make([]group.Element, len(commitmentCoeffs)-1)
			copy(newCoeffs, commitmentCoeffs[1:])
			share.Commitment.Coefficients = newCoeffs
		}

		refreshingShares[i] = share
	}

	// Create refreshed public key package
	minSignersValue := minSigners
	refreshedPubKeyPackage := &PublicKeyPackage{
		VerifyingShares: refreshedVerifyingShares,
		VerifyingKey:    pubKeyPackage.VerifyingKey, // Group key unchanged
		MinSigners:      &minSignersValue,
	}

	return refreshingShares, refreshedPubKeyPackage, nil
}

// RefreshShare refreshes a participant's share in the Trusted Dealer approach.
//
// This must be called by each participant with the refreshing share received
// from the trusted dealer and their current key package.
//
// Parameters:
//   - refreshingShare: The refreshing share received from the trusted dealer
//   - currentKeyPackage: The participant's current key package
//   - cs: The ciphersuite to use
//
// Returns:
//   - The refreshed KeyPackage
//
// Errors:
//   - Returns error if the refreshing share is invalid
//   - Returns error if minSigners doesn't match
func RefreshShare(
	refreshingShare RefreshingShare,
	currentKeyPackage *frost.KeyPackage,
	cs ciphersuite.Ciphersuite,
) (*frost.KeyPackage, error) {
	grp := cs.Group()

	// Add identity commitment to the VSS commitment
	identityCommitment := grp.Identity()
	newCoeffs := make([]group.Element, len(refreshingShare.Commitment.Coefficients)+1)
	newCoeffs[0] = identityCommitment
	copy(newCoeffs[1:], refreshingShare.Commitment.Coefficients)

	commitment := &VSSCommitment{
		Coefficients: newCoeffs,
	}

	// Verify the refreshing share
	expectedPubshare, err := commitment.Pubshare(grp, int(refreshingShare.Identifier)-1)
	if err != nil {
		return nil, err
	}

	if !VerifySecshare(grp, refreshingShare.SigningShare, expectedPubshare) {
		return nil, ErrInvalidShare
	}

	// Verify minSigners matches
	if currentKeyPackage.MinSigners != safeUint32(commitment.Threshold()) {
		return nil, ErrInvalidThreshold
	}

	// Add the refreshing share to the current share
	newSigningShare := currentKeyPackage.SecretShare.Add(refreshingShare.SigningShare)

	// Create the new key package
	newKeyPackage := &frost.KeyPackage{
		Identifier:         currentKeyPackage.Identifier,
		SecretShare:        newSigningShare,
		GroupPublicKey:     currentKeyPackage.GroupPublicKey,
		VerificationShares: currentKeyPackage.VerificationShares,
		MinSigners:         currentKeyPackage.MinSigners,
		MaxSigners:         currentKeyPackage.MaxSigners,
	}

	return newKeyPackage, nil
}

// RefreshDKGPart1 executes part 1 of refresh share with DKG.
//
// Each participant generates a polynomial with zero constant term and
// broadcasts commitments to other participants.
//
// Parameters:
//   - identifier: The participant's unique identifier
//   - maxSigners: Number of participants refreshing (can be smaller than original)
//   - minSigners: Threshold needed to sign (must equal original value)
//   - cs: The ciphersuite to use
//
// Returns:
//   - Round1SecretPackage to keep in memory for part 2
//   - Round1Package to broadcast to all other participants
//
// Errors:
//   - Returns error if parameters are invalid
//   - Returns error if random generation fails
func RefreshDKGPart1(
	identifier frost.Identifier,
	maxSigners uint32,
	minSigners uint32,
	cs ciphersuite.Ciphersuite,
) (*dkg.Round1SecretPackage, *dkg.Round1Package, error) {
	grp := cs.Group()

	// Validate parameters
	if err := validateNumOfSigners(minSigners, maxSigners); err != nil {
		return nil, nil, err
	}

	if identifier == 0 {
		return nil, nil, NewFaultyParticipantError(0, "identifier cannot be zero")
	}

	// Build refreshing polynomial with zero constant term
	zeroSecret := grp.NewScalar()

	// Generate random coefficients (except constant term)
	coefficients := make([]group.Scalar, minSigners)
	coefficients[0] = zeroSecret

	for i := uint32(1); i < minSigners; i++ {
		scalar, err := grp.RandomScalar()
		if err != nil {
			return nil, nil, err
		}
		coefficients[i] = scalar
	}

	// Compute commitments
	commitment := make([]group.Element, minSigners)
	for i, coeff := range coefficients {
		commitment[i] = grp.ScalarBaseMult(coeff)
	}

	// Remove identity element from commitment for the package
	packageCommitment := make([]group.Element, minSigners-1)
	copy(packageCommitment, commitment[1:])

	// Compute proof of knowledge
	// Note: We still prove knowledge of the zero secret for consistency
	proof, err := computeProofOfKnowledge(identifier, coefficients[0], commitment[0], cs)
	if err != nil {
		return nil, nil, err
	}

	// Create secret package with full commitment (including identity)
	secretPackage := &dkg.Round1SecretPackage{
		Identifier:   identifier,
		Coefficients: coefficients,
		Commitment:   commitment,
		MinSigners:   minSigners,
		MaxSigners:   maxSigners,
	}

	// Create public package without identity element
	publicPackage := &dkg.Round1Package{
		Commitment:       packageCommitment,
		ProofOfKnowledge: *proof,
	}

	return secretPackage, publicPackage, nil
}

// RefreshDKGPart2 performs the second part of the refresh procedure.
//
// Each participant verifies received packages and computes shares to send
// to other participants.
//
// Parameters:
//   - secretPackage: The secret package from RefreshDKGPart1
//   - round1Packages: Map of Round1Package from other participants
//   - cs: The ciphersuite to use
//
// Returns:
//   - Round2SecretPackage to keep for part 3
//   - Map of Round2Package to send to each other participant
//
// Errors:
//   - Returns error if incorrect number of packages
//   - Returns error if verification fails
func RefreshDKGPart2(
	secretPackage *dkg.Round1SecretPackage,
	round1Packages map[frost.Identifier]*dkg.Round1Package,
	cs ciphersuite.Ciphersuite,
) (*dkg.Round2SecretPackage, map[frost.Identifier]*dkg.Round2Package, error) {
	grp := cs.Group()

	// Validate package count
	if len(round1Packages) != int(secretPackage.MaxSigners-1) {
		return nil, nil, NewFaultyParticipantError(0, "incorrect number of packages")
	}

	// The identity commitment needs to be added to the VSS commitment for secret package
	// (it was removed for transmission)
	identityElement := grp.Identity()

	// Prepare round 2 packages
	round2Packages := make(map[frost.Identifier]*dkg.Round2Package)

	for senderID, round1Package := range round1Packages {
		// Add identity commitment back to verify
		fullCommitment := make([]group.Element, len(round1Package.Commitment)+1)
		fullCommitment[0] = identityElement
		copy(fullCommitment[1:], round1Package.Commitment)

		// Verify commitment length
		if len(fullCommitment) != int(secretPackage.MinSigners) {
			return nil, nil, NewFaultyParticipantError(int(senderID), "incorrect commitment length")
		}

		// Note: We don't verify the proof of knowledge in refresh
		// because the secret is always zero

		// Compute share for this participant: f_i(senderID)
		share := evaluatePolynomialAtIdentifier(
			grp,
			secretPackage.Coefficients,
			senderID,
		)

		round2Packages[senderID] = &dkg.Round2Package{
			SigningShare: share,
		}
	}

	// Compute our own share: f_i(i)
	ownShare := evaluatePolynomialAtIdentifier(
		grp,
		secretPackage.Coefficients,
		secretPackage.Identifier,
	)

	// Create round 2 secret package
	// Remove identity element from commitment for storage
	commitmentWithoutIdentity := make([]group.Element, len(secretPackage.Commitment)-1)
	copy(commitmentWithoutIdentity, secretPackage.Commitment[1:])

	round2SecretPackage := &dkg.Round2SecretPackage{
		Identifier:  secretPackage.Identifier,
		Commitment:  commitmentWithoutIdentity,
		SecretShare: ownShare,
		MinSigners:  secretPackage.MinSigners,
		MaxSigners:  secretPackage.MaxSigners,
	}

	return round2SecretPackage, round2Packages, nil
}

// RefreshDKGShares performs the third and final part of the refresh procedure.
//
// Each participant verifies received shares, accumulates them, and adds to
// their existing share to create the refreshed share.
//
// Parameters:
//   - round2SecretPackage: The secret package from RefreshDKGPart2
//   - round1Packages: The same packages used in RefreshDKGPart2
//   - round2Packages: Map of Round2Package from other participants
//   - oldPubKeyPackage: The old public key package being refreshed
//   - oldKeyPackage: The old key package being refreshed
//   - cs: The ciphersuite to use
//
// Returns:
//   - The refreshed KeyPackage with new signing share
//   - The refreshed PublicKeyPackage with new verifying shares
//
// Errors:
//   - Returns error if minSigners doesn't match
//   - Returns error if share verification fails
//   - Returns error if package counts are incorrect
func RefreshDKGShares(
	round2SecretPackage *dkg.Round2SecretPackage,
	round1Packages map[frost.Identifier]*dkg.Round1Package,
	round2Packages map[frost.Identifier]*dkg.Round2Package,
	oldPubKeyPackage *PublicKeyPackage,
	oldKeyPackage *frost.KeyPackage,
	cs ciphersuite.Ciphersuite,
) (*frost.KeyPackage, *PublicKeyPackage, error) {
	grp := cs.Group()

	// Validate minSigners
	if round2SecretPackage.MinSigners != oldKeyPackage.MinSigners {
		return nil, nil, ErrInvalidThreshold
	}

	// Add identity commitment back to round2SecretPackage
	identityElement := grp.Identity()
	fullSecretCommitment := make([]group.Element, len(round2SecretPackage.Commitment)+1)
	fullSecretCommitment[0] = identityElement
	copy(fullSecretCommitment[1:], round2SecretPackage.Commitment)

	// Validate package counts
	if len(round1Packages) != int(round2SecretPackage.MaxSigners-1) {
		return nil, nil, NewFaultyParticipantError(0, "incorrect number of round1 packages")
	}
	if len(round2Packages) != len(round1Packages) {
		return nil, nil, NewFaultyParticipantError(0, "package count mismatch")
	}

	// Verify all identifiers match
	for id := range round1Packages {
		if _, exists := round2Packages[id]; !exists {
			return nil, nil, NewFaultyParticipantError(int(id), "missing round2 package")
		}
	}

	// Accumulate signing shares
	signingShare := grp.NewScalar() // Start with zero

	for senderID, round2Package := range round2Packages {
		// Get the corresponding round1 package
		round1Package, exists := round1Packages[senderID]
		if !exists {
			return nil, nil, NewFaultyParticipantError(int(senderID), "missing round1 package")
		}

		// Add identity commitment back for verification
		fullCommitment := make([]group.Element, len(round1Package.Commitment)+1)
		fullCommitment[0] = identityElement
		copy(fullCommitment[1:], round1Package.Commitment)

		// Verify the share using VSS
		vssCommitment := &VSSCommitment{Coefficients: fullCommitment}
		expectedPubshare, err := vssCommitment.Pubshare(grp, int(round2SecretPackage.Identifier)-1)
		if err != nil {
			return nil, nil, err
		}

		if !VerifySecshare(grp, round2Package.SigningShare, expectedPubshare) {
			return nil, nil, NewFaultyParticipantError(int(senderID), "invalid share")
		}

		// Accumulate the share
		signingShare = signingShare.Add(round2Package.SigningShare)
	}

	// Add our own share
	signingShare = signingShare.Add(round2SecretPackage.SecretShare)

	// Add the old signing share
	signingShare = signingShare.Add(oldKeyPackage.SecretShare)

	// Build verifying shares map from commitments
	allCommitments := make(map[frost.Identifier][]group.Element)

	// Add our commitment
	allCommitments[round2SecretPackage.Identifier] = fullSecretCommitment

	// Add all other commitments
	for senderID, round1Package := range round1Packages {
		fullCommitment := make([]group.Element, len(round1Package.Commitment)+1)
		fullCommitment[0] = identityElement
		copy(fullCommitment[1:], round1Package.Commitment)
		allCommitments[senderID] = fullCommitment
	}

	// Compute zero-shares public key package
	zeroSharesVerifyingShares := make(map[frost.Identifier]group.Element)

	for _, id := range getAllIdentifiers(allCommitments) {
		// Sum commitments for this participant across all polynomials
		pubshare := grp.Identity()

		for _, commitment := range allCommitments {
			vssCommitment := &VSSCommitment{Coefficients: commitment}
			participantPubshare, err := vssCommitment.Pubshare(grp, int(id)-1)
			if err != nil {
				return nil, nil, err
			}
			pubshare = pubshare.Add(participantPubshare)
		}

		zeroSharesVerifyingShares[id] = pubshare
	}

	// Compute new verifying shares by adding to old shares
	newVerifyingShares := make(map[frost.Identifier]group.Element)

	for id, zeroShare := range zeroSharesVerifyingShares {
		oldShare, exists := oldPubKeyPackage.VerifyingShares[id]
		if !exists {
			return nil, nil, NewFaultyParticipantError(int(id), "unknown identifier in old package")
		}
		newVerifyingShares[id] = oldShare.Add(zeroShare)
	}

	// Create refreshed public key package
	minSignersValue := round2SecretPackage.MinSigners
	publicKeyPackage := &PublicKeyPackage{
		VerifyingShares: newVerifyingShares,
		VerifyingKey:    oldPubKeyPackage.VerifyingKey,
		MinSigners:      &minSignersValue,
	}

	// Convert new verifying shares to frost.VerificationShare format
	verificationShares := make([]frost.VerificationShare, 0, len(newVerifyingShares))
	for id, share := range newVerifyingShares {
		verificationShares = append(verificationShares, frost.VerificationShare{
			Identifier:      id,
			VerificationKey: share,
		})
	}

	// Compute participant's verifying share
	participantVerifyingShare := grp.ScalarBaseMult(signingShare)

	// Create refreshed key package
	keyPackage := &frost.KeyPackage{
		Identifier:         round2SecretPackage.Identifier,
		SecretShare:        signingShare,
		GroupPublicKey:     oldKeyPackage.GroupPublicKey,
		VerificationShares: verificationShares,
		MinSigners:         round2SecretPackage.MinSigners,
		MaxSigners:         round2SecretPackage.MaxSigners,
	}

	// Verify our new signing share matches our verifying share
	if !participantVerifyingShare.Equal(newVerifyingShares[round2SecretPackage.Identifier]) {
		return nil, nil, NewFaultyParticipantError(
			int(round2SecretPackage.Identifier),
			"computed signing share doesn't match verifying share",
		)
	}

	return keyPackage, publicKeyPackage, nil
}

// Helper functions

// generateSecretShares generates secret shares for all participants.
func generateSecretShares(
	grp group.Group,
	vss *VSS,
	identifiers []frost.Identifier,
) ([]RefreshingShare, error) {
	shares := make([]RefreshingShare, len(identifiers))

	for i, id := range identifiers {
		// Compute share value: f(id)
		// VSS uses 0-based indexing, so we pass i directly
		shareValue, err := vss.SecshareFor(int(id) - 1)
		if err != nil {
			return nil, err
		}

		commitment := vss.Commit()

		shares[i] = RefreshingShare{
			Identifier:   id,
			SigningShare: shareValue,
			Commitment:   commitment,
		}
	}

	return shares, nil
}

// validateNumOfSigners validates the minSigners and maxSigners parameters.
func validateNumOfSigners(minSigners, maxSigners uint32) error {
	if minSigners == 0 {
		return ErrInvalidThreshold
	}
	if maxSigners < minSigners {
		return ErrInvalidThreshold
	}
	if minSigners < 2 {
		return ErrInvalidThreshold
	}
	return nil
}

// generateRandomSeed generates a random seed of the specified length.
func generateRandomSeed(length int) ([]byte, error) {
	seed := make([]byte, length)
	// Use crypto/rand for secure random generation
	n, err := cryptoRandRead(seed)
	if err != nil {
		return nil, err
	}
	if n != length {
		return nil, ErrInvalidSeed
	}
	return seed, nil
}

// cryptoRandRead is a wrapper around crypto/rand.Read for testing purposes.
var cryptoRandRead = func(b []byte) (int, error) {
	// Import crypto/rand inline to avoid import cycle
	return cryptoRead(b)
}

// evaluatePolynomialAtIdentifier evaluates a polynomial at a given identifier.
// Identifiers are converted to scalars for evaluation.
func evaluatePolynomialAtIdentifier(
	grp group.Group,
	coefficients []group.Scalar,
	identifier frost.Identifier,
) group.Scalar {
	// Convert identifier to scalar
	x := identifierToScalar(grp, identifier)

	// Evaluate using Horner's method
	result := grp.NewScalar()
	for i := len(coefficients) - 1; i >= 0; i-- {
		result = result.Mul(x)
		result = result.Add(coefficients[i])
	}

	return result
}

// identifierToScalar converts a FROST identifier to a scalar.
func identifierToScalar(grp group.Group, id frost.Identifier) group.Scalar {
	// Create a byte slice with the identifier value
	bytes := make([]byte, grp.ScalarLength())

	idValue := uint32(id)

	// Use the group's byte order
	if grp.ByteOrder() == group.BigEndian {
		// Big-endian: most significant byte first
		for i := grp.ScalarLength() - 1; i >= 0 && idValue > 0; i-- {
			bytes[i] = byte(idValue & 0xff)
			idValue >>= 8
		}
	} else {
		// Little-endian: least significant byte first
		for i := 0; i < grp.ScalarLength() && idValue > 0; i++ {
			bytes[i] = byte(idValue & 0xff)
			idValue >>= 8
		}
	}

	// Deserialize to scalar
	// Error ignored: small integers always deserialize successfully
	scalar, _ := grp.DeserializeScalar(bytes)
	return scalar
}

// getAllIdentifiers extracts all unique identifiers from a commitment map.
func getAllIdentifiers(commitments map[frost.Identifier][]group.Element) []frost.Identifier {
	ids := make([]frost.Identifier, 0, len(commitments))
	for id := range commitments {
		ids = append(ids, id)
	}
	return ids
}

// computeProofOfKnowledge creates a Schnorr proof of knowledge.
// This is used in the DKG refresh protocol.
func computeProofOfKnowledge(
	identifier frost.Identifier,
	secret group.Scalar,
	commitment group.Element,
	cs ciphersuite.Ciphersuite,
) (*dkg.Signature, error) {
	grp := cs.Group()

	// Generate random nonce
	k, err := grp.RandomScalar()
	if err != nil {
		return nil, err
	}

	// Compute R = g^k
	R := grp.ScalarBaseMult(k)

	// Compute challenge
	challenge := computeChallenge(identifier, commitment, R, cs)

	// Compute response: z = k + secret * challenge
	z := k.Add(secret.Mul(challenge))

	return &dkg.Signature{R: R, Z: z}, nil
}

// computeChallenge computes the DKG challenge hash.
func computeChallenge(
	identifier frost.Identifier,
	commitment group.Element,
	R group.Element,
	cs ciphersuite.Ciphersuite,
) group.Scalar {
	grp := cs.Group()

	// Build challenge input
	var challengeInput []byte

	// Serialize identifier
	idBytes := make([]byte, grp.ScalarLength())
	idValue := uint32(identifier)

	if grp.ByteOrder() == group.BigEndian {
		idBytes[len(idBytes)-1] = byte(idValue)
		idBytes[len(idBytes)-2] = byte(idValue >> 8)
		idBytes[len(idBytes)-3] = byte(idValue >> 16)
		idBytes[len(idBytes)-4] = byte(idValue >> 24)
	} else {
		for j := 0; j < 4 && j < len(idBytes); j++ {
			idBytes[j] = byte(idValue >> (8 * j))
		}
	}

	challengeInput = append(challengeInput, idBytes...)
	challengeInput = append(challengeInput, commitment.Bytes()...)
	challengeInput = append(challengeInput, R.Bytes()...)

	return cs.HDKG(challengeInput)
}

// cryptoRead provides access to crypto/rand.Read
func cryptoRead(b []byte) (int, error) {
	// Use a local import to avoid circular dependencies
	// This is safe because crypto/rand is a standard library package
	return randRead(b)
}

// randRead is an indirection for crypto/rand.Read to enable testing
var randRead = defaultRandRead

// defaultRandRead uses crypto/rand.Read
func defaultRandRead(b []byte) (int, error) {

	return rand.Read(b)
}
