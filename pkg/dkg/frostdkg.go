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

// Package dkg provides FROST-DKG, a modular distributed key generation protocol
// that works with any FROST ciphersuite from RFC 9591.
//
// This implementation is aligned with the Zcash FROST reference implementation
// (https://github.com/ZcashFoundation/frost) and follows RFC 9591 requirements.
//
// # Supported Ciphersuites
//
// FROST-DKG uses the ciphersuite's hash functions (H1-H5) for all cryptographic
// operations, enabling support for all RFC 9591 curves:
//   - P-256
//   - Ed25519
//   - ristretto255
//   - Ed448
//   - secp256k1
//
// # Security Requirements
//
// Per Zcash FROST and RFC 9591, this implementation enforces:
//   - Minimum threshold (min_signers) of 2 - a threshold of 1 provides no security
//   - Minimum participants (max_signers) of 2
//   - Maximum participants limited to prevent DoS attacks
//
// # Transport Security
//
// IMPORTANT: This implementation follows Zcash FROST's security model:
//
// Round 1 packages (commitments and proofs) can be sent over a public broadcast
// channel as they contain no secret information.
//
// Round 2 packages (secret shares) MUST be sent over a CONFIDENTIAL and
// AUTHENTICATED channel. The recommended approach is to use TLS 1.3, QUIC,
// or another secure transport protocol. Application-level encryption is NOT
// provided by default - transport security is delegated to the network layer.
//
// # Memory Security
//
// Use the Zeroize functions (ZeroBytes, SecretPackage.Zeroize) to clear
// sensitive data from memory when no longer needed. This is aligned with
// Zcash FROST's Zeroize trait pattern.
package dkg

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// Domain separation prefix for FROST-DKG operations.
// This ensures hash outputs are unique to this protocol and don't collide
// with FROST signing operations or other protocols.
const FROSTDKGPrefix = "FROST-DKG/"

// hashToScalar uses the ciphersuite's H3 function with FROST-DKG domain separation.
// H3 is designed for nonce generation and produces uniformly distributed scalars.
func hashToScalar(cs ciphersuite.Ciphersuite, tag string, data []byte) group.Scalar {
	// Construct input with domain separation: "FROST-DKG/" + tag + data
	input := make([]byte, len(FROSTDKGPrefix)+len(tag)+len(data))
	copy(input, FROSTDKGPrefix)
	copy(input[len(FROSTDKGPrefix):], tag)
	copy(input[len(FROSTDKGPrefix)+len(tag):], data)
	return cs.H3(input)
}

// hashToBytes uses the ciphersuite's H4 function with FROST-DKG domain separation.
// H4 produces fixed-length byte output for message hashing.
func hashToBytes(cs ciphersuite.Ciphersuite, tag string, data []byte) []byte {
	// Construct input with domain separation: "FROST-DKG/" + tag + data
	input := make([]byte, len(FROSTDKGPrefix)+len(tag)+len(data))
	copy(input, FROSTDKGPrefix)
	copy(input[len(FROSTDKGPrefix):], tag)
	copy(input[len(FROSTDKGPrefix)+len(tag):], data)
	return cs.H4(input)
}

// FROSTDKGOutput represents the output of a FROST-DKG session.
type FROSTDKGOutput struct {
	// SecretShare is this participant's share of the threshold secret key.
	SecretShare group.Scalar

	// ThresholdPubkey is the group's threshold public key.
	ThresholdPubkey group.Element

	// PublicShares are the public key shares for all participants.
	PublicShares []group.Element
}

// Zeroize clears sensitive data from the output.
//
// SECURITY NOTE: Due to Go's type system, this cannot directly zero the memory
// holding scalar/element values. The group interfaces don't expose internal
// byte storage. This method sets all references to nil to make them GC-eligible.
//
// For more thorough zeroization, use ZeroizeWithGroup which attempts to
// overwrite scalar data before niling references.
//
// For maximum security in high-assurance environments:
//   - Use group implementations that support secure zeroization
//   - Call runtime.GC() after Zeroize() if needed
//   - Consider memory isolation techniques (mlock, etc.)
func (o *FROSTDKGOutput) Zeroize() {
	if o == nil {
		return
	}
	// Set references to nil to make them GC-eligible
	o.SecretShare = nil
	o.ThresholdPubkey = nil
	for i := range o.PublicShares {
		o.PublicShares[i] = nil
	}
	o.PublicShares = nil
}

// ZeroizeWithGroup clears sensitive data with explicit overwriting using the group.
// This is more thorough than Zeroize as it attempts to overwrite scalar data
// with zero values before niling references.
func (o *FROSTDKGOutput) ZeroizeWithGroup(grp group.Group) {
	if o == nil || grp == nil {
		return
	}
	// Attempt to overwrite the secret share with a zero scalar
	if o.SecretShare != nil {
		o.SecretShare = grp.NewScalar()
	}
	// Overwrite public shares with identity elements
	if o.PublicShares != nil {
		identity := grp.Identity()
		for i := range o.PublicShares {
			if o.PublicShares[i] != nil {
				o.PublicShares[i] = identity
			}
		}
	}
	// Now nil all references
	o.Zeroize()
}

// FROSTDKGParticipantState holds state for a FROST-DKG participant.
type FROSTDKGParticipantState struct {
	Ciphersuite     ciphersuite.Ciphersuite
	Index           int
	Threshold       int
	NumParticipants int
	VSS             *VSS
	Commitment      *VSSCommitment
	Seed            []byte
}

// Zeroize clears sensitive data from the participant state.
// This includes the seed and the VSS polynomial coefficients.
func (s *FROSTDKGParticipantState) Zeroize() {
	if s == nil {
		return
	}
	ZeroBytes(s.Seed)
	s.Seed = nil
	if s.VSS != nil {
		s.VSS.Zeroize()
	}
	s.VSS = nil
}

// FROSTDKGParticipantMsg is a participant's round 1 message.
type FROSTDKGParticipantMsg struct {
	// Commitment to the participant's VSS polynomial
	Commitment *VSSCommitment
	// Proof of possession (Schnorr signature proving knowledge of secret)
	POP []byte
}

// FROSTDKGCoordinatorMsg is the coordinator's message to participants.
type FROSTDKGCoordinatorMsg struct {
	// AllCommitments contains commitments from all participants
	AllCommitments []*VSSCommitment
	// AllPOPs contains proofs of possession from all participants
	AllPOPs [][]byte
}

// FROSTDKGGenerateVSS creates a VSS polynomial using the ciphersuite's hash functions.
// This is the ciphersuite-aware replacement for Generate().
func FROSTDKGGenerateVSS(cs ciphersuite.Ciphersuite, seed []byte, t int) (*VSS, error) {
	grp := cs.Group()
	if t <= 0 {
		return nil, ErrFROSTDKGInvalidThreshold
	}

	coeffs := make([]group.Scalar, t)
	for i := 0; i < t; i++ {
		// Create input: seed || i (i as 4-byte big-endian)
		// Loop index i is bounded by threshold t, safe for uint32
		input := make([]byte, len(seed)+4)
		copy(input, seed)
		binary.BigEndian.PutUint32(input[len(seed):], safeUint32(i))

		// Use ciphersuite's hash-to-scalar with domain separation
		coeffs[i] = hashToScalar(cs, "vss coeffs", input)
	}

	poly, err := NewPolynomial(grp, coeffs)
	if err != nil {
		return nil, err
	}

	return NewVSS(grp, poly)
}

// FROSTDKGProveKnowledge creates a proof of possession (Schnorr signature)
// proving knowledge of the secret key corresponding to a public key.
//
// This implementation follows the RFC 9591 FROST DKG specification:
// - Challenge: c = HDKG(identifier || verifying_key || R)
// - Response: μ = k + a_0 * c
// - Proof: σ = (R, μ)
//
// Parameters:
//   - cs: The ciphersuite to use for cryptographic operations.
//   - secret: The secret value (a_0, first coefficient of the polynomial).
//   - pubkey: The public key corresponding to the secret (g^a_0).
//   - index: The participant's 0-indexed index (converted to 1-indexed identifier internally).
func FROSTDKGProveKnowledge(cs ciphersuite.Ciphersuite, secret group.Scalar, pubkey group.Element, index int) ([]byte, error) {
	grp := cs.Group()

	// Convert 0-indexed index to 1-indexed RFC 9591 identifier scalar
	identifierScalar := indexToIdentifierScalar(grp, index)
	identifierBytes := grp.SerializeScalar(identifierScalar)

	// Generate deterministic nonce following RFC 6979 pattern for reproducibility:
	// k = H3("FROST-DKG/pop nonce" || secret || pubkey || identifier)
	// Including pubkey provides additional domain separation and follows
	// RFC 6979 best practices for deterministic signature nonces.
	secretBytes := grp.SerializeScalar(secret)
	pubkeyBytes, err := grp.SerializeElement(pubkey)
	if err != nil {
		return nil, err
	}

	nonceInput := make([]byte, len(secretBytes)+len(pubkeyBytes)+len(identifierBytes))
	copy(nonceInput, secretBytes)
	copy(nonceInput[len(secretBytes):], pubkeyBytes)
	copy(nonceInput[len(secretBytes)+len(pubkeyBytes):], identifierBytes)
	k := hashToScalar(cs, "pop nonce", nonceInput)

	// R = k * G
	R := grp.ScalarBaseMult(k)

	// Serialize R for challenge (pubkeyBytes already serialized above)
	RBytes, err := grp.SerializeElement(R)
	if err != nil {
		return nil, err
	}

	// RFC 9591 Challenge: c = HDKG(identifier || verifying_key || R)
	// where identifier is serialized as a scalar
	challengeInput := make([]byte, len(identifierBytes)+len(pubkeyBytes)+len(RBytes))
	copy(challengeInput, identifierBytes)
	copy(challengeInput[len(identifierBytes):], pubkeyBytes)
	copy(challengeInput[len(identifierBytes)+len(pubkeyBytes):], RBytes)
	c := cs.HDKG(challengeInput)

	// Response: μ = k + a_0 * c
	mu := c.Mul(secret)
	mu = k.Add(mu)

	// POP = R || μ (Schnorr signature format)
	muBytes := grp.SerializeScalar(mu)
	pop := make([]byte, len(RBytes)+len(muBytes))
	copy(pop, RBytes)
	copy(pop[len(RBytes):], muBytes)

	return pop, nil
}

// indexToIdentifierScalar converts a 0-indexed participant index to a
// 1-indexed RFC 9591 identifier scalar.
//
// In RFC 9591, identifiers are 1-indexed non-zero scalars. This function
// takes a 0-indexed participant index (0, 1, 2, ...) and converts it to
// the corresponding RFC 9591 identifier (1, 2, 3, ...) as a scalar.
func indexToIdentifierScalar(grp group.Group, index int) group.Scalar {
	// Convert 0-indexed to 1-indexed: identifier = index + 1
	identifier := index + 1
	return scalarFromInt(grp, identifier)
}

// FROSTDKGVerifyPOP verifies a proof of possession.
//
// This implementation follows the RFC 9591 FROST DKG specification:
// - Recompute challenge: c = HDKG(identifier || verifying_key || R)
// - Verify: R == g^μ - verifying_key * c (equivalently: g^μ == R + c * pubkey)
//
// Parameters:
//   - cs: The ciphersuite to use for cryptographic operations.
//   - pop: The proof of possession (R || μ).
//   - pubkey: The public key (verifying key) to verify against.
//   - index: The participant's 0-indexed index (converted to 1-indexed identifier internally).
func FROSTDKGVerifyPOP(cs ciphersuite.Ciphersuite, pop []byte, pubkey group.Element, index int) bool {
	grp := cs.Group()

	elemLen := grp.ElementLength()
	scalarLen := grp.ScalarLength()

	if len(pop) != elemLen+scalarLen {
		return false
	}

	// Parse R and μ from the proof
	R, err := grp.DeserializeElement(pop[:elemLen])
	if err != nil {
		return false
	}
	mu, err := grp.DeserializeScalar(pop[elemLen:])
	if err != nil {
		return false
	}

	// Serialize pubkey (verifying_key)
	pubkeyBytes, err := grp.SerializeElement(pubkey)
	if err != nil {
		return false
	}

	// Convert 0-indexed index to 1-indexed RFC 9591 identifier scalar
	identifierScalar := indexToIdentifierScalar(grp, index)
	identifierBytes := grp.SerializeScalar(identifierScalar)

	// RFC 9591 Challenge: c = HDKG(identifier || verifying_key || R)
	challengeInput := make([]byte, len(identifierBytes)+len(pubkeyBytes)+elemLen)
	copy(challengeInput, identifierBytes)
	copy(challengeInput[len(identifierBytes):], pubkeyBytes)
	copy(challengeInput[len(identifierBytes)+len(pubkeyBytes):], pop[:elemLen])
	c := cs.HDKG(challengeInput)

	// Verify: R == g^μ - pubkey * c
	// Which is equivalent to: g^μ == R + c * pubkey
	muG := grp.ScalarBaseMult(mu)
	cPubkey := grp.ScalarMult(pubkey, c)
	RcPubkey := R.Add(cPubkey)

	// Use constant-time comparison to prevent timing attacks
	muGBytes, err := grp.SerializeElement(muG)
	if err != nil {
		return false
	}
	RcPubkeyBytes, err := grp.SerializeElement(RcPubkey)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(muGBytes, RcPubkeyBytes) == 1
}

// FROSTDKGParticipantRound1 performs the first round of FROST-DKG for a participant.
// Returns the participant's state, message, and secret shares for other participants.
//
// Parameters are validated per Zcash FROST requirements:
// - t (threshold/min_signers) must be >= MinThreshold (2)
// - n (max_signers) must be >= MinParticipants (2) and <= MaxParticipants
// - t must be <= n
// - index must be in range [0, n)
func FROSTDKGParticipantRound1(cs ciphersuite.Ciphersuite, seed []byte, t, n, index int) (*FROSTDKGParticipantState, *FROSTDKGParticipantMsg, []group.Scalar, error) {
	// Validate min_signers (threshold) per Zcash FROST
	if t < MinThreshold {
		return nil, nil, nil, ErrInvalidMinSigners
	}
	// Validate max_signers (participant count) per Zcash FROST
	if n < MinParticipants {
		return nil, nil, nil, ErrInvalidMaxSigners
	}
	if n > MaxParticipants {
		return nil, nil, nil, ErrFROSTDKGInvalidParticipantCount
	}
	// Validate threshold <= participant count
	if t > n {
		return nil, nil, nil, ErrFROSTDKGInvalidThreshold
	}
	// Validate participant index
	if index < 0 || index >= n {
		return nil, nil, nil, ErrInvalidParticipantIndex
	}

	// Generate VSS polynomial using ciphersuite hash functions
	vss, err := FROSTDKGGenerateVSS(cs, seed, t)
	if err != nil {
		return nil, nil, nil, err
	}

	// Compute commitment
	commitment := vss.Commit()

	// Generate shares for all participants
	shares, err := vss.Secshares(n)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create proof of possession for our constant term commitment
	secret := vss.Secret()
	pubkey := commitment.CommitmentToSecret()
	pop, err := FROSTDKGProveKnowledge(cs, secret, pubkey, index)
	if err != nil {
		return nil, nil, nil, err
	}

	state := &FROSTDKGParticipantState{
		Ciphersuite:     cs,
		Index:           index,
		Threshold:       t,
		NumParticipants: n,
		VSS:             vss,
		Commitment:      commitment,
		Seed:            seed,
	}

	msg := &FROSTDKGParticipantMsg{
		Commitment: commitment,
		POP:        pop,
	}

	return state, msg, shares, nil
}

// FROSTDKGCoordinatorRound1 processes round 1 messages from all participants.
// Returns the coordinator's message for round 2.
//
// Parameters are validated per Zcash FROST requirements:
// - t (threshold/min_signers) must be >= MinThreshold (2)
// - n (max_signers) must be >= MinParticipants (2) and <= MaxParticipants
// - t must be <= n
// - len(msgs) must equal n
func FROSTDKGCoordinatorRound1(cs ciphersuite.Ciphersuite, msgs []*FROSTDKGParticipantMsg, t, n int) (*FROSTDKGCoordinatorMsg, error) {
	// Validate min_signers (threshold) per Zcash FROST
	if t < MinThreshold {
		return nil, ErrInvalidMinSigners
	}
	// Validate max_signers (participant count) per Zcash FROST
	if n < MinParticipants {
		return nil, ErrInvalidMaxSigners
	}
	if n > MaxParticipants {
		return nil, ErrFROSTDKGInvalidParticipantCount
	}
	// Validate threshold <= participant count
	if t > n {
		return nil, ErrFROSTDKGInvalidThreshold
	}
	// Validate message count
	if len(msgs) != n {
		return nil, ErrFROSTDKGInvalidParticipantCount
	}

	// Verify all POPs and check for nil messages
	// Also validate commitment coefficient count to prevent Pedersen DKG vulnerability
	// (Trail of Bits 2024: malicious participants could silently increase threshold)
	for i, msg := range msgs {
		if msg == nil || msg.Commitment == nil {
			return nil, ErrFROSTDKGInvalidPOP
		}
		// Validate commitment has exactly t coefficients (Pedersen vulnerability fix)
		if msg.Commitment.Threshold() != t {
			return nil, NewFaultyParticipantError(i, "commitment has wrong number of coefficients")
		}
		pubkey := msg.Commitment.CommitmentToSecret()
		if !FROSTDKGVerifyPOP(cs, msg.POP, pubkey, i) {
			return nil, ErrFROSTDKGInvalidPOP
		}
	}

	// Collect all commitments and POPs
	allCommitments := make([]*VSSCommitment, n)
	allPOPs := make([][]byte, n)
	for i, msg := range msgs {
		allCommitments[i] = msg.Commitment
		allPOPs[i] = msg.POP
	}

	return &FROSTDKGCoordinatorMsg{
		AllCommitments: allCommitments,
		AllPOPs:        allPOPs,
	}, nil
}

// FROSTDKGParticipantRound2 performs the second round of FROST-DKG.
// The participant verifies all commitments and POPs, then computes their output.
func FROSTDKGParticipantRound2(
	cs ciphersuite.Ciphersuite,
	state *FROSTDKGParticipantState,
	coordMsg *FROSTDKGCoordinatorMsg,
	receivedShares []group.Scalar, // shares[j] is the share from participant j for this participant
) (*FROSTDKGOutput, []byte, error) {
	// Input validation
	if state == nil {
		return nil, nil, ErrInvalidParticipantIndex
	}
	if coordMsg == nil {
		return nil, nil, ErrFROSTDKGCommitmentMismatch
	}

	grp := cs.Group()
	n := state.NumParticipants
	t := state.Threshold
	myIndex := state.Index

	// Validate received shares count
	if len(receivedShares) != n {
		return nil, nil, ErrFROSTDKGInvalidParticipantCount
	}
	if len(coordMsg.AllCommitments) != n {
		return nil, nil, ErrFROSTDKGInvalidParticipantCount
	}
	if len(coordMsg.AllPOPs) != n {
		return nil, nil, ErrFROSTDKGInvalidParticipantCount
	}

	// Verify our commitment was included correctly
	if !commitmentsEqual(grp, state.Commitment, coordMsg.AllCommitments[myIndex]) {
		return nil, nil, ErrFROSTDKGCommitmentMismatch
	}

	// Verify all POPs and validate commitment coefficient counts
	// (Pedersen vulnerability fix: prevent silently increased threshold)
	for i := 0; i < n; i++ {
		commitment := coordMsg.AllCommitments[i]
		if commitment == nil {
			return nil, nil, NewFaultyParticipantError(i, "nil commitment")
		}
		// Validate commitment has exactly t coefficients
		if commitment.Threshold() != t {
			return nil, nil, NewFaultyParticipantError(i, "commitment has wrong number of coefficients")
		}
		pubkey := commitment.CommitmentToSecret()
		if !FROSTDKGVerifyPOP(cs, coordMsg.AllPOPs[i], pubkey, i) {
			return nil, nil, ErrFROSTDKGInvalidPOP
		}
	}

	// Sum the commitments to get the aggregated commitment
	sumCommitment := coordMsg.AllCommitments[0]
	for i := 1; i < n; i++ {
		var err error
		sumCommitment, err = sumCommitment.Add(coordMsg.AllCommitments[i])
		if err != nil {
			return nil, nil, err
		}
	}

	// Note: FROST-DKG does not apply any tweak to the threshold public key.
	// This makes it compatible with all RFC 9591 curves.

	// Sum all received shares to get our secret share
	secretShare := grp.NewScalar()
	for _, share := range receivedShares {
		secretShare = secretShare.Add(share)
	}

	// Compute our expected public share
	expectedPubshare, err := sumCommitment.Pubshare(grp, myIndex)
	if err != nil {
		return nil, nil, err
	}

	// Verify our secret share
	if !VerifySecshare(grp, secretShare, expectedPubshare) {
		return nil, nil, ErrFROSTDKGShareVerificationFailed
	}

	// Compute threshold public key
	thresholdPubkey := sumCommitment.CommitmentToSecret()

	// Compute all public shares
	publicShares := make([]group.Element, n)
	for i := 0; i < n; i++ {
		publicShares[i], err = sumCommitment.Pubshare(grp, i)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create equality input for CertEq (hash of all commitments)
	eqInput, err := createEqInput(cs, coordMsg.AllCommitments, t, n)
	if err != nil {
		return nil, nil, err
	}

	output := &FROSTDKGOutput{
		SecretShare:     secretShare,
		ThresholdPubkey: thresholdPubkey,
		PublicShares:    publicShares,
	}

	return output, eqInput, nil
}

// commitmentsEqual compares two VSS commitments for equality using constant-time
// comparison to prevent timing attacks.
func commitmentsEqual(grp group.Group, a, b *VSSCommitment) bool {
	if len(a.Coefficients) != len(b.Coefficients) {
		return false
	}
	// Use constant-time comparison to prevent timing attacks
	equal := 1
	for i := range a.Coefficients {
		aBytes, err := grp.SerializeElement(a.Coefficients[i])
		if err != nil {
			return false
		}
		bBytes, err := grp.SerializeElement(b.Coefficients[i])
		if err != nil {
			return false
		}
		equal &= subtle.ConstantTimeCompare(aBytes, bBytes)
	}
	return equal == 1
}

// createEqInput creates the equality check input by hashing all commitments.
func createEqInput(cs ciphersuite.Ciphersuite, commitments []*VSSCommitment, t, n int) ([]byte, error) {
	grp := cs.Group()

	// Serialize all commitments
	var data []byte
	for _, comm := range commitments {
		commBytes, err := comm.ToBytes(grp)
		if err != nil {
			return nil, err
		}
		data = append(data, commBytes...)
	}

	// Add threshold and participant count
	tBytes := make([]byte, 4)
	nBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tBytes, safeUint32(t))
	binary.BigEndian.PutUint32(nBytes, safeUint32(n))
	data = append(data, tBytes...)
	data = append(data, nBytes...)

	return hashToBytes(cs, "eq input", data), nil
}

// FROSTDKGCoordinatorOutput returns the coordinator's view of the DKG output.
func FROSTDKGCoordinatorOutput(cs ciphersuite.Ciphersuite, commitments []*VSSCommitment, t, n int) (*FROSTDKGOutput, []byte, error) {
	grp := cs.Group()

	// Sum the commitments
	sumCommitment := commitments[0]
	for i := 1; i < n; i++ {
		var err error
		sumCommitment, err = sumCommitment.Add(commitments[i])
		if err != nil {
			return nil, nil, err
		}
	}

	// Note: FROST-DKG does not apply any tweak to the threshold public key.
	// This makes it compatible with all RFC 9591 curves.

	// Compute threshold public key
	thresholdPubkey := sumCommitment.CommitmentToSecret()

	// Compute all public shares
	publicShares := make([]group.Element, n)
	var err error
	for i := 0; i < n; i++ {
		publicShares[i], err = sumCommitment.Pubshare(grp, i)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create equality input
	eqInput, err := createEqInput(cs, commitments, t, n)
	if err != nil {
		return nil, nil, err
	}

	output := &FROSTDKGOutput{
		SecretShare:     nil, // Coordinator doesn't have a secret share
		ThresholdPubkey: thresholdPubkey,
		PublicShares:    publicShares,
	}

	return output, eqInput, nil
}

// =============================================================================
// Encrypted FROST-DKG (EncPedPop equivalent)
// =============================================================================

// FROSTDKGEncParticipantState holds state for encrypted FROST-DKG.
type FROSTDKGEncParticipantState struct {
	*FROSTDKGParticipantState
	HostSeckey  []byte
	HostPubkeys [][]byte
	Pubnonce    group.Element
}

// Zeroize clears sensitive data from the encrypted participant state.
// This includes the host secret key and the embedded participant state.
func (s *FROSTDKGEncParticipantState) Zeroize() {
	if s == nil {
		return
	}
	ZeroBytes(s.HostSeckey)
	s.HostSeckey = nil
	if s.FROSTDKGParticipantState != nil {
		s.FROSTDKGParticipantState.Zeroize()
	}
	s.FROSTDKGParticipantState = nil
	s.Pubnonce = nil
}

// FROSTDKGEncParticipantMsg is a participant's encrypted round 1 message.
type FROSTDKGEncParticipantMsg struct {
	*FROSTDKGParticipantMsg
	// Pubnonce is the public nonce for ECDH
	Pubnonce []byte
	// EncryptedShares contains encrypted shares for all other participants
	EncryptedShares [][]byte
}

// FROSTDKGEncCoordinatorMsg is the coordinator's encrypted message.
type FROSTDKGEncCoordinatorMsg struct {
	*FROSTDKGCoordinatorMsg
	// AllPubnonces contains public nonces from all participants
	AllPubnonces [][]byte
}

// deriveHostScalar derives the ECDH scalar from the host secret key.
// This must be consistent with how the corresponding Signer derives its internal scalar.
// - P256: uses the key bytes directly as the scalar (ECDSA private key format)
// - Ed25519, Ristretto255, Ed448, Secp256k1: use H3(secretKey) to derive the scalar
func deriveHostScalar(cs ciphersuite.Ciphersuite, hostSeckey []byte) (group.Scalar, error) {
	grp := cs.Group()

	switch cs.ID() {
	case CiphersuiteP256:
		// P256 uses the secret key directly as the scalar (32-byte ECDSA D value)
		if len(hostSeckey) != 32 {
			return nil, ErrInvalidSecretKey
		}
		return grp.DeserializeScalar(hostSeckey)
	case CiphersuiteEd25519, CiphersuiteRistretto255:
		// Ed25519 and Ristretto255 use 32-byte seeds
		if len(hostSeckey) != 32 {
			return nil, ErrInvalidSecretKey
		}
		return cs.H3(hostSeckey), nil
	case CiphersuiteEd448:
		// Ed448 uses 57-byte seeds
		if len(hostSeckey) != 57 {
			return nil, ErrInvalidSecretKey
		}
		return cs.H3(hostSeckey), nil
	case CiphersuiteSecp256k1:
		// Secp256k1 uses 32-byte seeds
		if len(hostSeckey) != 32 {
			return nil, ErrInvalidSecretKey
		}
		return cs.H3(hostSeckey), nil
	default:
		// Unknown ciphersuite - return error to prevent silent failures
		return nil, ErrUnsupportedCiphersuite
	}
}

// frostDKGECDH performs ECDH using the ciphersuite's group operations.
func frostDKGECDH(cs ciphersuite.Ciphersuite, mySeckey []byte, myPubnonce, theirPubkey, theirPubnonce group.Element, encrypt bool) ([]byte, error) {
	grp := cs.Group()

	// Derive the scalar consistently with how the signer derives its internal scalar.
	// This ensures ECDH and CertEq signing use the same effective key.
	mySecret, err := deriveHostScalar(cs, mySeckey)
	if err != nil {
		return nil, err
	}

	// Compute shared secret: mySecret * theirPubkey
	sharedPoint := grp.ScalarMult(theirPubkey, mySecret)

	// Serialize all components for hashing
	sharedBytes, err := grp.SerializeElement(sharedPoint)
	if err != nil {
		return nil, err
	}
	myNonceBytes, err := grp.SerializeElement(myPubnonce)
	if err != nil {
		return nil, err
	}
	theirNonceBytes, err := grp.SerializeElement(theirPubnonce)
	if err != nil {
		return nil, err
	}

	// Order the nonces consistently (sender first for encryption, receiver first for decryption)
	var data []byte
	if encrypt {
		data = append(data, myNonceBytes...)
		data = append(data, theirNonceBytes...)
	} else {
		data = append(data, theirNonceBytes...)
		data = append(data, myNonceBytes...)
	}
	data = append(data, sharedBytes...)

	// Derive pad using ciphersuite hash
	return hashToBytes(cs, "ecdh pad", data), nil
}

// FROSTDKGEncParticipantRound1 performs encrypted round 1 of FROST-DKG.
func FROSTDKGEncParticipantRound1(
	cs ciphersuite.Ciphersuite,
	seed []byte,
	hostSeckey []byte,
	hostPubkeys [][]byte,
	t, index int,
	random []byte,
) (*FROSTDKGEncParticipantState, *FROSTDKGEncParticipantMsg, error) {
	grp := cs.Group()
	n := len(hostPubkeys)

	if t <= 0 || t > n {
		return nil, nil, ErrFROSTDKGInvalidThreshold
	}
	if index < 0 || index >= n {
		return nil, nil, ErrInvalidParticipantIndex
	}

	// First do the basic FROST-DKG round 1
	baseState, baseMsg, shares, err := FROSTDKGParticipantRound1(cs, seed, t, n, index)
	if err != nil {
		return nil, nil, err
	}

	// Generate nonce for ECDH: secnonce = H3("secnonce" || seed || random)
	nonceInput := make([]byte, len(seed)+len(random))
	copy(nonceInput, seed)
	copy(nonceInput[len(seed):], random)
	secnonce := hashToScalar(cs, "secnonce", nonceInput)

	// Compute public nonce
	pubnonce := grp.ScalarBaseMult(secnonce)
	pubnonceBytes, err := grp.SerializeElement(pubnonce)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt shares for each participant
	encryptedShares := make([][]byte, n)
	for j := 0; j < n; j++ {
		shareBytes := grp.SerializeScalar(shares[j])

		if j == index {
			// Don't encrypt our own share
			encryptedShares[j] = shareBytes
			continue
		}

		// Deserialize their public key
		theirPubkey, err := grp.DeserializeElement(hostPubkeys[j])
		if err != nil {
			return nil, nil, err
		}

		// For encryption, we use our own pubnonce for both positions since
		// the receiver doesn't have their pubnonce yet. The receiver will
		// use our pubnonce (from coordinator) for both positions to match.
		pad, err := frostDKGECDH(cs, hostSeckey, pubnonce, theirPubkey, pubnonce, true)
		if err != nil {
			return nil, nil, err
		}

		// XOR the share with the pad (truncated to share length)
		if len(pad) < len(shareBytes) {
			return nil, nil, ErrFROSTDKGDecryptionFailed
		}
		encryptedShares[j] = xorBytes(shareBytes, pad[:len(shareBytes)])
	}

	state := &FROSTDKGEncParticipantState{
		FROSTDKGParticipantState: baseState,
		HostSeckey:               hostSeckey,
		HostPubkeys:              hostPubkeys,
		Pubnonce:                 pubnonce,
	}

	msg := &FROSTDKGEncParticipantMsg{
		FROSTDKGParticipantMsg: baseMsg,
		Pubnonce:               pubnonceBytes,
		EncryptedShares:        encryptedShares,
	}

	return state, msg, nil
}

// FROSTDKGEncCoordinatorRound1 processes encrypted round 1 messages.
func FROSTDKGEncCoordinatorRound1(
	cs ciphersuite.Ciphersuite,
	msgs []*FROSTDKGEncParticipantMsg,
	t int,
	hostPubkeys [][]byte,
) (*FROSTDKGEncCoordinatorMsg, *FROSTDKGOutput, []byte, [][]byte, error) {
	n := len(msgs)
	if n != len(hostPubkeys) {
		return nil, nil, nil, nil, ErrFROSTDKGInvalidParticipantCount
	}

	// Extract base messages
	baseMsgs := make([]*FROSTDKGParticipantMsg, n)
	for i, msg := range msgs {
		baseMsgs[i] = msg.FROSTDKGParticipantMsg
	}

	// Process base round 1
	baseCoordMsg, err := FROSTDKGCoordinatorRound1(cs, baseMsgs, t, n)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Collect all pubnonces
	allPubnonces := make([][]byte, n)
	for i, msg := range msgs {
		allPubnonces[i] = msg.Pubnonce
	}

	// Collect encrypted shares for each participant
	// participantShares[i] contains all encrypted shares destined for participant i
	participantShares := make([][]byte, n)
	for i := 0; i < n; i++ {
		// Concatenate all shares destined for participant i
		var shares []byte
		for j := 0; j < n; j++ {
			shares = append(shares, msgs[j].EncryptedShares[i]...)
		}
		participantShares[i] = shares
	}

	// Get coordinator output
	coordOutput, eqInput, err := FROSTDKGCoordinatorOutput(cs, baseCoordMsg.AllCommitments, t, n)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	coordMsg := &FROSTDKGEncCoordinatorMsg{
		FROSTDKGCoordinatorMsg: baseCoordMsg,
		AllPubnonces:           allPubnonces,
	}

	return coordMsg, coordOutput, eqInput, participantShares, nil
}

// FROSTDKGEncParticipantRound2 performs encrypted round 2 of FROST-DKG.
func FROSTDKGEncParticipantRound2(
	cs ciphersuite.Ciphersuite,
	state *FROSTDKGEncParticipantState,
	coordMsg *FROSTDKGEncCoordinatorMsg,
	encryptedSharesForMe []byte, // All encrypted shares destined for this participant
) (*FROSTDKGOutput, []byte, error) {
	grp := cs.Group()
	n := state.NumParticipants
	myIndex := state.Index
	scalarLen := grp.ScalarLength()

	// Decrypt shares from each participant
	receivedShares := make([]group.Scalar, n)
	for j := 0; j < n; j++ {
		// Extract encrypted share from participant j
		shareStart := j * scalarLen
		shareEnd := shareStart + scalarLen
		if shareEnd > len(encryptedSharesForMe) {
			return nil, nil, ErrFROSTDKGDecryptionFailed
		}
		encShare := encryptedSharesForMe[shareStart:shareEnd]

		if j == myIndex {
			// Our own share is not encrypted
			share, err := grp.DeserializeScalar(encShare)
			if err != nil {
				return nil, nil, err
			}
			receivedShares[j] = share
			continue
		}

		// Deserialize their public key and nonce
		theirPubkey, err := grp.DeserializeElement(state.HostPubkeys[j])
		if err != nil {
			return nil, nil, err
		}
		theirPubnonce, err := grp.DeserializeElement(coordMsg.AllPubnonces[j])
		if err != nil {
			return nil, nil, err
		}

		// Compute ECDH pad using sender's pubnonce for both positions to match encryption.
		// The sender used (senderNonce, senderNonce) order, and with encrypt=false
		// the order becomes (theirNonce, myNonce) = (senderNonce, senderNonce).
		pad, err := frostDKGECDH(cs, state.HostSeckey, theirPubnonce, theirPubkey, theirPubnonce, false)
		if err != nil {
			return nil, nil, err
		}

		// Decrypt the share
		if len(pad) < scalarLen {
			return nil, nil, ErrFROSTDKGDecryptionFailed
		}
		shareBytes := xorBytes(encShare, pad[:scalarLen])

		share, err := grp.DeserializeScalar(shareBytes)
		if err != nil {
			return nil, nil, ErrFROSTDKGDecryptionFailed
		}
		receivedShares[j] = share
	}

	// Complete round 2 with decrypted shares
	return FROSTDKGParticipantRound2(cs, state.FROSTDKGParticipantState, coordMsg.FROSTDKGCoordinatorMsg, receivedShares)
}

// =============================================================================
// Full FROST-DKG with CertEq for consensus
// =============================================================================

// FROSTDKGFullParticipantState1 holds state after round 1.
type FROSTDKGFullParticipantState1 struct {
	EncState    *FROSTDKGEncParticipantState
	Signer      Signer
	HostSeckey  []byte
	HostPubkeys [][]byte
	Threshold   int
}

// Zeroize clears sensitive data from the state.
func (s *FROSTDKGFullParticipantState1) Zeroize() {
	if s == nil {
		return
	}
	ZeroBytes(s.HostSeckey)
	s.HostSeckey = nil
	if s.EncState != nil {
		s.EncState.Zeroize()
	}
	s.EncState = nil
}

// FROSTDKGFullParticipantState2 holds state after round 2.
type FROSTDKGFullParticipantState2 struct {
	Output      *FROSTDKGOutput
	EqInput     []byte
	Signer      Signer
	Index       int
	HostPubkeys [][]byte
	Threshold   int
}

// Zeroize clears sensitive data from the state.
func (s *FROSTDKGFullParticipantState2) Zeroize() {
	if s == nil {
		return
	}
	if s.Output != nil {
		s.Output.Zeroize()
	}
	s.Output = nil
}

// FROSTDKGFullParticipantMsg1 is the participant's first message.
type FROSTDKGFullParticipantMsg1 struct {
	EncMsg *FROSTDKGEncParticipantMsg
}

// FROSTDKGFullParticipantMsg2 is the participant's second message (CertEq signature).
type FROSTDKGFullParticipantMsg2 struct {
	Signature []byte
}

// FROSTDKGFullCoordinatorState holds coordinator state.
type FROSTDKGFullCoordinatorState struct {
	EncCoordMsg *FROSTDKGEncCoordinatorMsg
	Output      *FROSTDKGOutput
	EqInput     []byte
	Signer      Signer
	HostPubkeys [][]byte
	EncShares   [][]byte
	Threshold   int
}

// Zeroize clears sensitive data from the coordinator state.
func (s *FROSTDKGFullCoordinatorState) Zeroize() {
	if s == nil {
		return
	}
	if s.Output != nil {
		s.Output.Zeroize()
	}
	s.Output = nil
	// Clear encrypted shares which contain sensitive share data
	for i := range s.EncShares {
		ZeroBytes(s.EncShares[i])
	}
	s.EncShares = nil
}

// FROSTDKGFullCoordinatorMsg1 is the coordinator's first message.
type FROSTDKGFullCoordinatorMsg1 struct {
	EncCoordMsg *FROSTDKGEncCoordinatorMsg
	EncShares   [][]byte
}

// FROSTDKGFullCoordinatorMsg2 is the coordinator's second message (certificate).
type FROSTDKGFullCoordinatorMsg2 struct {
	Certificate []byte
}

// FROSTDKGFullParticipantStep1 performs the first step of full FROST-DKG.
func FROSTDKGFullParticipantStep1(
	cs ciphersuite.Ciphersuite,
	hostSeckey []byte,
	hostPubkeys [][]byte,
	t int,
	index int,
	random []byte,
) (*FROSTDKGFullParticipantState1, *FROSTDKGFullParticipantMsg1, error) {
	// Get the signer for this ciphersuite
	signer, err := GetSigner(cs)
	if err != nil {
		return nil, nil, err
	}

	// Derive seed from host secret key and random
	seedInput := make([]byte, len(hostSeckey)+len(random))
	copy(seedInput, hostSeckey)
	copy(seedInput[len(hostSeckey):], random)
	seedScalar := hashToScalar(cs, "participant seed", seedInput)
	seed := cs.Group().SerializeScalar(seedScalar)

	// Perform encrypted round 1
	encState, encMsg, err := FROSTDKGEncParticipantRound1(cs, seed, hostSeckey, hostPubkeys, t, index, random)
	if err != nil {
		return nil, nil, err
	}

	state := &FROSTDKGFullParticipantState1{
		EncState:    encState,
		Signer:      signer,
		HostSeckey:  hostSeckey,
		HostPubkeys: hostPubkeys,
		Threshold:   t,
	}

	msg := &FROSTDKGFullParticipantMsg1{
		EncMsg: encMsg,
	}

	return state, msg, nil
}

// FROSTDKGFullCoordinatorStep1 performs the coordinator's first step.
func FROSTDKGFullCoordinatorStep1(
	cs ciphersuite.Ciphersuite,
	msgs []*FROSTDKGFullParticipantMsg1,
	t int,
	hostPubkeys [][]byte,
) (*FROSTDKGFullCoordinatorState, *FROSTDKGFullCoordinatorMsg1, error) {
	// Get the signer for this ciphersuite
	signer, err := GetSigner(cs)
	if err != nil {
		return nil, nil, err
	}

	// Extract encrypted messages
	encMsgs := make([]*FROSTDKGEncParticipantMsg, len(msgs))
	for i, msg := range msgs {
		encMsgs[i] = msg.EncMsg
	}

	// Process encrypted round 1
	encCoordMsg, output, eqInput, encShares, err := FROSTDKGEncCoordinatorRound1(cs, encMsgs, t, hostPubkeys)
	if err != nil {
		return nil, nil, err
	}

	state := &FROSTDKGFullCoordinatorState{
		EncCoordMsg: encCoordMsg,
		Output:      output,
		EqInput:     eqInput,
		Signer:      signer,
		HostPubkeys: hostPubkeys,
		EncShares:   encShares,
		Threshold:   t,
	}

	msg := &FROSTDKGFullCoordinatorMsg1{
		EncCoordMsg: encCoordMsg,
		EncShares:   encShares,
	}

	return state, msg, nil
}

// FROSTDKGFullParticipantStep2 performs the participant's second step.
func FROSTDKGFullParticipantStep2(
	cs ciphersuite.Ciphersuite,
	state1 *FROSTDKGFullParticipantState1,
	coordMsg1 *FROSTDKGFullCoordinatorMsg1,
) (*FROSTDKGFullParticipantState2, *FROSTDKGFullParticipantMsg2, error) {
	index := state1.EncState.Index

	// Perform encrypted round 2
	output, eqInput, err := FROSTDKGEncParticipantRound2(cs, state1.EncState, coordMsg1.EncCoordMsg, coordMsg1.EncShares[index])
	if err != nil {
		return nil, nil, err
	}

	// Sign the equality input using CertEq with session context binding
	signature, err := CertEqParticipantStep(state1.Signer, state1.HostSeckey, index, state1.HostPubkeys, state1.Threshold, eqInput, nil)
	if err != nil {
		return nil, nil, err
	}

	state2 := &FROSTDKGFullParticipantState2{
		Output:      output,
		EqInput:     eqInput,
		Signer:      state1.Signer,
		Index:       index,
		HostPubkeys: state1.HostPubkeys,
		Threshold:   state1.Threshold,
	}

	msg2 := &FROSTDKGFullParticipantMsg2{
		Signature: signature,
	}

	return state2, msg2, nil
}

// FROSTDKGFullCoordinatorFinalize finalizes the coordinator's role.
func FROSTDKGFullCoordinatorFinalize(
	state *FROSTDKGFullCoordinatorState,
	msgs2 []*FROSTDKGFullParticipantMsg2,
) (*FROSTDKGFullCoordinatorMsg2, *FROSTDKGOutput, error) {
	n := len(msgs2)
	if n != len(state.HostPubkeys) {
		return nil, nil, ErrFROSTDKGInvalidParticipantCount
	}

	// Collect all signatures
	signatures := make([][]byte, n)
	for i, msg := range msgs2 {
		signatures[i] = msg.Signature
	}

	// Assemble the certificate
	certificate := CertEqCoordinatorStep(signatures)

	// Verify the certificate with session context binding
	if err := CertEqVerify(state.Signer, state.HostPubkeys, state.Threshold, state.EqInput, certificate); err != nil {
		return nil, nil, err
	}

	msg2 := &FROSTDKGFullCoordinatorMsg2{
		Certificate: certificate,
	}

	return msg2, state.Output, nil
}

// FROSTDKGFullParticipantFinalize finalizes the participant's role.
func FROSTDKGFullParticipantFinalize(
	state2 *FROSTDKGFullParticipantState2,
	coordMsg2 *FROSTDKGFullCoordinatorMsg2,
	hostPubkeys [][]byte,
) (*FROSTDKGOutput, error) {
	// Verify the certificate with session context binding
	if err := CertEqVerify(state2.Signer, hostPubkeys, state2.Threshold, state2.EqInput, coordMsg2.Certificate); err != nil {
		return nil, err
	}

	return state2.Output, nil
}

// =============================================================================
// HostKey-based FROST-DKG (Hardware Key Support)
// =============================================================================

// frostDKGECDHWithHostKey computes the ECDH pad using a HostKey interface.
// This enables hardware-backed keys (TPM, HSM) where the private key
// never leaves the secure element.
func frostDKGECDHWithHostKey(cs ciphersuite.Ciphersuite, hostKey HostKey, myPubnonce group.Element, theirPubkey []byte, theirPubnonce group.Element, encrypt bool) ([]byte, error) {
	grp := cs.Group()

	// Compute shared secret using HostKey.ECDH()
	sharedBytes, err := hostKey.ECDH(theirPubkey)
	if err != nil {
		return nil, err
	}

	// Serialize nonces
	myNonceBytes, err := grp.SerializeElement(myPubnonce)
	if err != nil {
		return nil, err
	}

	theirNonceBytes, err := grp.SerializeElement(theirPubnonce)
	if err != nil {
		return nil, err
	}

	// Order the nonces consistently (sender first for encryption, receiver first for decryption)
	var data []byte
	if encrypt {
		data = append(data, myNonceBytes...)
		data = append(data, theirNonceBytes...)
	} else {
		data = append(data, theirNonceBytes...)
		data = append(data, myNonceBytes...)
	}
	data = append(data, sharedBytes...)

	// Derive pad using ciphersuite hash
	return hashToBytes(cs, "ecdh pad", data), nil
}

// FROSTDKGEncParticipantStateHK holds encrypted DKG state with HostKey support.
type FROSTDKGEncParticipantStateHK struct {
	*FROSTDKGParticipantState
	HostKey     HostKey
	HostPubkeys [][]byte
	Pubnonce    group.Element
}

// Zeroize clears sensitive data from the state.
// Note: HostKey is an interface and may be hardware-backed; it cannot be zeroized here.
func (s *FROSTDKGEncParticipantStateHK) Zeroize() {
	if s == nil {
		return
	}
	if s.FROSTDKGParticipantState != nil {
		s.FROSTDKGParticipantState.Zeroize()
	}
	s.FROSTDKGParticipantState = nil
	s.HostKey = nil
	s.Pubnonce = nil
}

// FROSTDKGEncParticipantRound1WithHostKey performs encrypted round 1 using HostKey.
func FROSTDKGEncParticipantRound1WithHostKey(
	cs ciphersuite.Ciphersuite,
	seed []byte,
	hostKey HostKey,
	hostPubkeys [][]byte,
	t, index int,
	random []byte,
) (*FROSTDKGEncParticipantStateHK, *FROSTDKGEncParticipantMsg, error) {
	grp := cs.Group()
	n := len(hostPubkeys)

	if t <= 0 || t > n {
		return nil, nil, ErrFROSTDKGInvalidThreshold
	}
	if index < 0 || index >= n {
		return nil, nil, ErrInvalidParticipantIndex
	}

	// First do the basic FROST-DKG round 1
	baseState, baseMsg, shares, err := FROSTDKGParticipantRound1(cs, seed, t, n, index)
	if err != nil {
		return nil, nil, err
	}

	// Generate nonce for ECDH: secnonce = H3("secnonce" || seed || random)
	nonceInput := make([]byte, len(seed)+len(random))
	copy(nonceInput, seed)
	copy(nonceInput[len(seed):], random)
	secnonce := hashToScalar(cs, "secnonce", nonceInput)

	// Compute public nonce
	pubnonce := grp.ScalarBaseMult(secnonce)
	pubnonceBytes, err := grp.SerializeElement(pubnonce)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt shares for each participant
	encryptedShares := make([][]byte, n)
	for j := 0; j < n; j++ {
		shareBytes := grp.SerializeScalar(shares[j])

		if j == index {
			// Don't encrypt our own share
			encryptedShares[j] = shareBytes
			continue
		}

		// For encryption, we use our own pubnonce for both positions
		pad, err := frostDKGECDHWithHostKey(cs, hostKey, pubnonce, hostPubkeys[j], pubnonce, true)
		if err != nil {
			return nil, nil, err
		}

		// XOR the share with the pad (truncated to share length)
		if len(pad) < len(shareBytes) {
			return nil, nil, ErrFROSTDKGDecryptionFailed
		}
		encryptedShares[j] = xorBytes(shareBytes, pad[:len(shareBytes)])
	}

	state := &FROSTDKGEncParticipantStateHK{
		FROSTDKGParticipantState: baseState,
		HostKey:                  hostKey,
		HostPubkeys:              hostPubkeys,
		Pubnonce:                 pubnonce,
	}

	msg := &FROSTDKGEncParticipantMsg{
		FROSTDKGParticipantMsg: baseMsg,
		Pubnonce:               pubnonceBytes,
		EncryptedShares:        encryptedShares,
	}

	return state, msg, nil
}

// FROSTDKGEncParticipantRound2WithHostKey performs encrypted round 2 using HostKey.
func FROSTDKGEncParticipantRound2WithHostKey(
	cs ciphersuite.Ciphersuite,
	state *FROSTDKGEncParticipantStateHK,
	coordMsg *FROSTDKGEncCoordinatorMsg,
	encryptedSharesForMe []byte,
) (*FROSTDKGOutput, []byte, error) {
	grp := cs.Group()
	n := state.NumParticipants
	myIndex := state.Index

	// Determine scalar length based on ciphersuite
	scalarLen := len(grp.SerializeScalar(grp.NewScalar()))

	// Verify we have the right amount of encrypted data
	expectedLen := n * scalarLen
	if len(encryptedSharesForMe) != expectedLen {
		return nil, nil, ErrFROSTDKGDecryptionFailed
	}

	// Decrypt shares from each participant
	receivedShares := make([]group.Scalar, n)

	for j := 0; j < n; j++ {
		// Extract encrypted share from participant j
		encShare := encryptedSharesForMe[j*scalarLen : (j+1)*scalarLen]

		if j == myIndex {
			// Our own share isn't encrypted
			share, err := grp.DeserializeScalar(encShare)
			if err != nil {
				return nil, nil, ErrFROSTDKGDecryptionFailed
			}
			receivedShares[j] = share
			continue
		}

		// Deserialize their public nonce
		theirPubnonce, err := grp.DeserializeElement(coordMsg.AllPubnonces[j])
		if err != nil {
			return nil, nil, ErrFROSTDKGDecryptionFailed
		}

		// Compute ECDH pad using sender's pubnonce for both positions to match encryption.
		// The sender used (senderNonce, senderNonce) order, and with encrypt=false
		// the order becomes (theirNonce, myNonce) = (senderNonce, senderNonce).
		pad, err := frostDKGECDHWithHostKey(cs, state.HostKey, theirPubnonce, state.HostPubkeys[j], theirPubnonce, false)
		if err != nil {
			return nil, nil, ErrFROSTDKGDecryptionFailed
		}

		// Decrypt the share
		if len(pad) < scalarLen {
			return nil, nil, ErrFROSTDKGDecryptionFailed
		}
		shareBytes := xorBytes(encShare, pad[:scalarLen])

		share, err := grp.DeserializeScalar(shareBytes)
		if err != nil {
			return nil, nil, ErrFROSTDKGDecryptionFailed
		}
		receivedShares[j] = share
	}

	// Complete round 2 with decrypted shares
	return FROSTDKGParticipantRound2(cs, state.FROSTDKGParticipantState, coordMsg.FROSTDKGCoordinatorMsg, receivedShares)
}

// =============================================================================
// Full FROST-DKG with HostKey Support
// =============================================================================

// FROSTDKGFullParticipantStateHK1 holds state after round 1 with HostKey.
type FROSTDKGFullParticipantStateHK1 struct {
	EncState    *FROSTDKGEncParticipantStateHK
	HostKey     HostKey
	HostPubkeys [][]byte
	Threshold   int
}

// Zeroize clears sensitive data from the state.
func (s *FROSTDKGFullParticipantStateHK1) Zeroize() {
	if s == nil {
		return
	}
	if s.EncState != nil {
		s.EncState.Zeroize()
	}
	s.EncState = nil
	s.HostKey = nil
}

// FROSTDKGFullParticipantStateHK2 holds state after round 2 with HostKey.
type FROSTDKGFullParticipantStateHK2 struct {
	Output      *FROSTDKGOutput
	EqInput     []byte
	HostKey     HostKey
	Index       int
	CS          ciphersuite.Ciphersuite
	HostPubkeys [][]byte
	Threshold   int
}

// Zeroize clears sensitive data from the state.
func (s *FROSTDKGFullParticipantStateHK2) Zeroize() {
	if s == nil {
		return
	}
	if s.Output != nil {
		s.Output.Zeroize()
	}
	s.Output = nil
	s.HostKey = nil
}

// FROSTDKGFullParticipantStep1WithHostKey performs the first step using HostKey.
func FROSTDKGFullParticipantStep1WithHostKey(
	cs ciphersuite.Ciphersuite,
	hostKey HostKey,
	hostPubkeys [][]byte,
	t int,
	index int,
	random []byte,
) (*FROSTDKGFullParticipantStateHK1, *FROSTDKGFullParticipantMsg1, error) {
	// Derive seed from host public key and random
	pubkey := hostKey.PublicKey()
	seedInput := make([]byte, len(pubkey)+len(random))
	copy(seedInput, pubkey)
	copy(seedInput[len(pubkey):], random)
	seedScalar := hashToScalar(cs, "participant seed", seedInput)
	seed := cs.Group().SerializeScalar(seedScalar)

	// Perform encrypted round 1
	encState, encMsg, err := FROSTDKGEncParticipantRound1WithHostKey(cs, seed, hostKey, hostPubkeys, t, index, random)
	if err != nil {
		return nil, nil, err
	}

	state := &FROSTDKGFullParticipantStateHK1{
		EncState:    encState,
		HostKey:     hostKey,
		HostPubkeys: hostPubkeys,
		Threshold:   t,
	}

	msg := &FROSTDKGFullParticipantMsg1{
		EncMsg: encMsg,
	}

	return state, msg, nil
}

// FROSTDKGFullParticipantStep2WithHostKey performs the participant's second step.
func FROSTDKGFullParticipantStep2WithHostKey(
	cs ciphersuite.Ciphersuite,
	state1 *FROSTDKGFullParticipantStateHK1,
	coordMsg1 *FROSTDKGFullCoordinatorMsg1,
) (*FROSTDKGFullParticipantStateHK2, *FROSTDKGFullParticipantMsg2, error) {
	index := state1.EncState.Index

	// Perform encrypted round 2
	output, eqInput, err := FROSTDKGEncParticipantRound2WithHostKey(cs, state1.EncState, coordMsg1.EncCoordMsg, coordMsg1.EncShares[index])
	if err != nil {
		return nil, nil, err
	}

	// Sign the equality input using HostKey with session context binding
	message := CertEqMessage(eqInput, index, state1.HostPubkeys, state1.Threshold)
	signature, err := state1.HostKey.Sign(message)
	if err != nil {
		return nil, nil, err
	}

	state2 := &FROSTDKGFullParticipantStateHK2{
		Output:      output,
		EqInput:     eqInput,
		HostKey:     state1.HostKey,
		Index:       index,
		CS:          cs,
		HostPubkeys: state1.HostPubkeys,
		Threshold:   state1.Threshold,
	}

	msg2 := &FROSTDKGFullParticipantMsg2{
		Signature: signature,
	}

	return state2, msg2, nil
}

// FROSTDKGFullCoordinatorStateHK holds coordinator state with HostKey support.
type FROSTDKGFullCoordinatorStateHK struct {
	EncCoordMsg *FROSTDKGEncCoordinatorMsg
	Output      *FROSTDKGOutput
	EqInput     []byte
	HostPubkeys [][]byte
	EncShares   [][]byte
	CS          ciphersuite.Ciphersuite
	Threshold   int
}

// Zeroize clears sensitive data from the coordinator state.
func (s *FROSTDKGFullCoordinatorStateHK) Zeroize() {
	if s == nil {
		return
	}
	if s.Output != nil {
		s.Output.Zeroize()
	}
	s.Output = nil
	// Clear encrypted shares which contain sensitive share data
	for i := range s.EncShares {
		ZeroBytes(s.EncShares[i])
	}
	s.EncShares = nil
}

// FROSTDKGFullCoordinatorStep1WithHostKey performs the coordinator's first step.
// Note: The coordinator doesn't need a HostKey for step 1, it just processes messages.
func FROSTDKGFullCoordinatorStep1WithHostKey(
	cs ciphersuite.Ciphersuite,
	msgs []*FROSTDKGFullParticipantMsg1,
	t int,
	hostPubkeys [][]byte,
) (*FROSTDKGFullCoordinatorStateHK, *FROSTDKGFullCoordinatorMsg1, error) {
	// Extract encrypted messages
	encMsgs := make([]*FROSTDKGEncParticipantMsg, len(msgs))
	for i, msg := range msgs {
		encMsgs[i] = msg.EncMsg
	}

	// Process encrypted round 1
	encCoordMsg, output, eqInput, encShares, err := FROSTDKGEncCoordinatorRound1(cs, encMsgs, t, hostPubkeys)
	if err != nil {
		return nil, nil, err
	}

	state := &FROSTDKGFullCoordinatorStateHK{
		EncCoordMsg: encCoordMsg,
		Output:      output,
		EqInput:     eqInput,
		HostPubkeys: hostPubkeys,
		EncShares:   encShares,
		CS:          cs,
		Threshold:   t,
	}

	msg := &FROSTDKGFullCoordinatorMsg1{
		EncCoordMsg: encCoordMsg,
		EncShares:   encShares,
	}

	return state, msg, nil
}

// FROSTDKGFullCoordinatorFinalizeWithHostKey finalizes the coordinator's role.
func FROSTDKGFullCoordinatorFinalizeWithHostKey(
	state *FROSTDKGFullCoordinatorStateHK,
	msgs2 []*FROSTDKGFullParticipantMsg2,
) (*FROSTDKGFullCoordinatorMsg2, *FROSTDKGOutput, error) {
	n := len(msgs2)
	if n != len(state.HostPubkeys) {
		return nil, nil, ErrFROSTDKGInvalidParticipantCount
	}

	// Collect all signatures
	signatures := make([][]byte, n)
	for i, msg := range msgs2 {
		if msg == nil {
			return nil, nil, ErrInvalidSignature
		}
		signatures[i] = msg.Signature
	}

	// Assemble the certificate
	certificate := CertEqCoordinatorStep(signatures)

	// Verify the certificate using HostKey signature verification with session context
	for i := 0; i < n; i++ {
		message := CertEqMessage(state.EqInput, i, state.HostPubkeys, state.Threshold)
		if err := VerifyHostKeySignature(state.CS, state.HostPubkeys[i], message, signatures[i]); err != nil {
			return nil, nil, err
		}
	}

	msg2 := &FROSTDKGFullCoordinatorMsg2{
		Certificate: certificate,
	}

	return msg2, state.Output, nil
}

// FROSTDKGFullParticipantFinalizeWithHostKey finalizes the participant's role.
func FROSTDKGFullParticipantFinalizeWithHostKey(
	state2 *FROSTDKGFullParticipantStateHK2,
	coordMsg2 *FROSTDKGFullCoordinatorMsg2,
	hostPubkeys [][]byte,
) (*FROSTDKGOutput, error) {
	n := len(hostPubkeys)

	// Determine signature size from certificate length
	if len(coordMsg2.Certificate) == 0 {
		return nil, ErrInvalidCertificateLength
	}
	sigSize := len(coordMsg2.Certificate) / n
	if sigSize*n != len(coordMsg2.Certificate) {
		return nil, ErrInvalidCertificateLength
	}

	// Verify each signature in the certificate with session context
	for i := 0; i < n; i++ {
		message := CertEqMessage(state2.EqInput, i, hostPubkeys, state2.Threshold)
		signature := coordMsg2.Certificate[i*sigSize : (i+1)*sigSize]
		if err := VerifyHostKeySignature(state2.CS, hostPubkeys[i], message, signature); err != nil {
			return nil, err
		}
	}

	return state2.Output, nil
}
