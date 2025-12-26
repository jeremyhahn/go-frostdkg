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
//
// This file implements the Repairable Threshold Scheme (RTS) from
// https://eprint.iacr.org/2017/1155
//
// The RTS allows a participant to recover their lost share with help from a
// threshold of other participants, without reconstructing the group secret.
//
// Protocol Overview:
//
//  1. Step 1 (Each Helper): Generate random delta values that sum to their
//     Lagrange-weighted share contribution for the recovering participant.
//
//  2. Step 2 (Each Helper): Sum all received delta values from other helpers
//     to compute a sigma value.
//
//  3. Step 3 (Recovering Participant): Sum all sigma values from helpers to
//     recover their lost share.
//
// Security Requirements:
//   - At least 2 helpers are required (the threshold)
//   - Delta values between helpers must be transmitted on secure channels
//   - Sigma values to the recovering participant must be on secure channels
//   - All helper identifiers must be unique
package dkg

import (
	"crypto/rand"

	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// RepairShareStep1 generates delta values for share repair.
//
// Each helper executes this function to generate delta values that will be
// distributed to all other helpers (including themselves). The delta values
// are constructed such that their sum equals the helper's Lagrange-weighted
// contribution to the recovering participant's share.
//
// The function generates (numHelpers-1) random delta values, with the last
// delta computed to ensure: sum(deltas) = L_i(x_participant) * share_i
// where L_i is the Lagrange basis polynomial for this helper.
//
// Parameters:
//   - helpers: Slice of all helper participant indices (including self)
//   - myHelperIndex: This helper's index in the helpers slice
//   - shareI: This helper's secret share
//   - grp: The group being used (for scalar operations)
//   - participantIndex: The index of the participant being recovered
//
// Returns:
//   - A map from helper index to their delta value
//   - An error if validation fails
//
// Errors:
//   - ErrInvalidThreshold: Fewer than 2 helpers provided
//   - ErrInvalidParticipantIndex: Helper indices contain invalid values
//   - ErrDuplicateHelper: Duplicate helper indices detected
func RepairShareStep1(
	helpers []int,
	myHelperIndex int,
	shareI group.Scalar,
	grp group.Group,
	participantIndex int,
) (map[int]group.Scalar, error) {
	// Validate inputs
	if len(helpers) < 2 {
		return nil, ErrInvalidThreshold
	}

	if myHelperIndex < 0 || myHelperIndex >= len(helpers) {
		return nil, ErrInvalidParticipantIndex
	}

	// Check for duplicates and validate indices
	seen := make(map[int]bool)
	for _, idx := range helpers {
		if idx < 0 {
			return nil, ErrInvalidParticipantIndex
		}
		if seen[idx] {
			return nil, ErrDuplicateHelper
		}
		seen[idx] = true
	}

	if participantIndex < 0 {
		return nil, ErrInvalidParticipantIndex
	}

	// Convert helper indices to scalars for Lagrange computation
	// Use idx+1 to match VSS evaluation points (avoiding x=0)
	helperScalars := make([]group.Scalar, len(helpers))
	for i, idx := range helpers {
		helperScalars[i] = scalarFromInt(grp, idx+1)
	}

	// Convert participant index to scalar
	participantScalar := scalarFromInt(grp, participantIndex+1)

	// Compute Lagrange coefficient for this helper at the recovery point
	// zeta_i = L_i(participantScalar) where L_i is the Lagrange basis polynomial
	lambda, err := computeLagrangeCoefficientForHelper(
		helperScalars,
		participantScalar,
		myHelperIndex,
		grp,
	)
	if err != nil {
		return nil, err
	}

	// Compute this helper's Lagrange-weighted contribution
	// contribution = lambda * shareI
	contribution := lambda.Mul(shareI)

	// Generate random delta values for all helpers except the last
	numHelpers := len(helpers)
	deltas := make(map[int]group.Scalar)
	randomSum := grp.NewScalar() // Initialize to zero

	// Generate random deltas for first (n-1) helpers
	for i := 0; i < numHelpers-1; i++ {
		// Use the group's RandomScalar for proper random scalar generation
		delta, err := grp.RandomScalar()
		if err != nil {
			// Fallback: generate random bytes and deserialize
			deltaBytes := make([]byte, grp.ScalarLength())
			if _, err := rand.Read(deltaBytes); err != nil {
				return nil, err
			}
			delta, err = grp.DeserializeScalar(deltaBytes)
			if err != nil {
				return nil, err
			}
		}
		deltas[helpers[i]] = delta
		randomSum = randomSum.Add(delta)
	}

	// Last delta = contribution - sum(random deltas)
	// This ensures sum(all deltas) = contribution
	lastDelta := contribution.Sub(randomSum)
	deltas[helpers[numHelpers-1]] = lastDelta

	return deltas, nil
}

// RepairShareStep2 computes sigma from received delta values.
//
// Each helper executes this function after receiving delta values from all
// other helpers (including their own delta for themselves). The sigma value
// is simply the sum of all received deltas.
//
// Parameters:
//   - deltas: All delta values received from helpers (including self)
//
// Returns:
//   - The sigma value (sum of all deltas)
func RepairShareStep2(deltas []group.Scalar) group.Scalar {
	if len(deltas) == 0 {
		return nil
	}

	// Sum all deltas
	sigma := deltas[0].Copy()
	for i := 1; i < len(deltas); i++ {
		sigma = sigma.Add(deltas[i])
	}

	return sigma
}

// RepairShareStep3 reconstructs the lost share from sigma values.
//
// The recovering participant executes this function after receiving sigma
// values from all helpers. The recovered share is the sum of all sigmas.
//
// If a VSS commitment is provided, the function verifies that the recovered
// share is valid by checking: share*G == Pubshare(participantIndex)
//
// Parameters:
//   - sigmas: All sigma values received from helpers
//   - participantIndex: This participant's index
//   - commitment: VSS commitment for verification (optional, can be nil)
//   - grp: The group being used
//
// Returns:
//   - The recovered secret share
//   - An error if verification fails or inputs are invalid
//
// Errors:
//   - ErrInvalidShare: Share verification failed (if commitment provided)
//   - ErrInvalidParticipantIndex: Invalid participant index
func RepairShareStep3(
	sigmas []group.Scalar,
	participantIndex int,
	commitment *VSSCommitment,
	grp group.Group,
) (group.Scalar, error) {
	if len(sigmas) == 0 {
		return nil, ErrInvalidShare
	}

	if participantIndex < 0 {
		return nil, ErrInvalidParticipantIndex
	}

	// Sum all sigmas to recover the share
	recoveredShare := sigmas[0].Copy()
	for i := 1; i < len(sigmas); i++ {
		recoveredShare = recoveredShare.Add(sigmas[i])
	}

	// Verify the recovered share if commitment is provided
	if commitment != nil {
		pubshare, err := commitment.Pubshare(grp, participantIndex)
		if err != nil {
			return nil, err
		}

		if !VerifySecshare(grp, recoveredShare, pubshare) {
			return nil, ErrInvalidShare
		}
	}

	return recoveredShare, nil
}

// computeLagrangeCoefficientForHelper computes the Lagrange coefficient for a
// specific helper at a given evaluation point.
//
// This computes L_i(x) for helper at index helperIdx, where:
//
//	L_i(x) = product((x - x_j) / (x_i - x_j)) for all j != i
//
// The Lagrange basis polynomial allows interpolation: given values f(x_0), f(x_1), ..., f(x_n),
// we can compute f(x) = sum(f(x_i) * L_i(x)) for any x.
//
// In the RTS context, this is used to compute each helper's contribution to the
// recovering participant's share:
//
//	share_participant = sum(L_i(x_participant) * share_i) for all helpers i
//
// Parameters:
//   - xCoords: All helper x-coordinates (as scalars)
//   - x: The evaluation point (recovering participant's x-coordinate)
//   - helperIdx: The index of the helper in xCoords
//   - grp: The group for scalar operations
//
// Returns:
//   - The Lagrange coefficient L_i(x)
//   - An error if computation fails
//
// Errors:
//   - ErrInvalidParticipantIndex: Invalid helper index
//   - ErrZeroScalar: Division by zero (duplicate x-coordinates)
func computeLagrangeCoefficientForHelper(
	xCoords []group.Scalar,
	x group.Scalar,
	helperIdx int,
	grp group.Group,
) (group.Scalar, error) {
	if helperIdx < 0 || helperIdx >= len(xCoords) {
		return nil, ErrInvalidParticipantIndex
	}

	xi := xCoords[helperIdx]

	// Initialize numerator and denominator to 1
	numerator := scalarFromInt(grp, 1)
	denominator := scalarFromInt(grp, 1)

	// Compute the Lagrange basis polynomial L_i(x)
	for j := 0; j < len(xCoords); j++ {
		if j == helperIdx {
			continue
		}
		xj := xCoords[j]

		// numerator *= (x - xj)
		xMinusXj := x.Sub(xj)
		numerator = numerator.Mul(xMinusXj)

		// denominator *= (xi - xj)
		xiMinusXj := xi.Sub(xj)
		denominator = denominator.Mul(xiMinusXj)
	}

	// Check for zero denominator (would indicate duplicate x-coordinates)
	zero := grp.NewScalar()
	if denominator.Equal(zero) {
		return nil, ErrZeroScalar
	}

	// Result = numerator / denominator = numerator * denominator^(-1)
	denominatorInv, err := denominator.Inv()
	if err != nil {
		return nil, err
	}

	return numerator.Mul(denominatorInv), nil
}
