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

// Repairable Threshold Scheme (https://eprint.iacr.org/2017/1155): at least 2 helpers recover a lost share over secure channels without the group secret.
package dkg

import (
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// RepairShareStep1 returns per-helper random deltas summing to L_i(x_participant) * share_i.
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
	defer lambda.Zeroize()

	// Compute this helper's Lagrange-weighted contribution
	// contribution = lambda * shareI
	contribution := lambda.Mul(shareI)
	defer contribution.Zeroize()

	// Generate random delta values for all helpers except the last
	numHelpers := len(helpers)
	deltas := make(map[int]group.Scalar)
	randomSum := grp.NewScalar() // Initialize to zero

	// Generate random deltas for first (n-1) helpers
	for i := 0; i < numHelpers-1; i++ {
		// Use the group's RandomScalar for proper random scalar generation
		delta, err := grp.RandomScalar()
		if err != nil {
			return nil, err
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

// RepairShareStep2 returns sigma, the sum of the received deltas.
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

// RepairShareStep3 sums the sigmas into the recovered share and, when commitment is non-nil, verifies share*G against it.
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

// computeLagrangeCoefficientForHelper returns L_i(x) = prod((x - x_j) / (x_i - x_j)) for j != i.
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
	defer numerator.Zeroize()
	denominator := scalarFromInt(grp, 1)
	defer denominator.Zeroize()

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
	defer denominatorInv.Zeroize()

	return numerator.Mul(denominatorInv), nil
}
