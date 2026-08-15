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

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/stretchr/testify/require"
)

// computeProofOfKnowledge returns the scalar it computed, so it must not
// zeroize it on the way out. group.Scalar.Add returns a fresh scalar, which
// makes the returned z the very value stored in Signature.Z — a deferred
// z.Zeroize() there emitted an all-zero proof to every caller.
func TestComputeProofOfKnowledge_ReturnedZIsNotZeroized(t *testing.T) {
	cs := ristretto255_sha512.New()
	grp := cs.Group()

	// Refresh proves knowledge of the zero secret, which is the case that
	// regressed; z is then k alone and must survive.
	secret := grp.NewScalar()
	commitment := grp.ScalarBaseMult(secret)

	proof, err := computeProofOfKnowledge(1, secret, commitment, cs)
	require.NoError(t, err)
	require.NotNil(t, proof)
	require.NotNil(t, proof.Z)
	require.False(t, proof.Z.IsZero(), "returned proof-of-knowledge Z must not be the zero scalar")
	require.NotNil(t, proof.R)
	require.False(t, proof.R.IsIdentity(), "returned proof-of-knowledge R must not be the identity element")
}

// The Schnorr proof must actually verify: g^z == R + c*commitment. With the
// zero secret this reduces to g^z == R, which is exactly what a zeroized z
// breaks.
func TestComputeProofOfKnowledge_VerifiesAgainstR(t *testing.T) {
	cs := ristretto255_sha512.New()
	grp := cs.Group()

	secret := grp.NewScalar()
	commitment := grp.ScalarBaseMult(secret)

	proof, err := computeProofOfKnowledge(7, secret, commitment, cs)
	require.NoError(t, err)

	// secret is zero, so z = k and g^z must equal R.
	require.True(t, grp.ScalarBaseMult(proof.Z).Equal(proof.R),
		"g^z must equal R for a proof of knowledge of the zero secret")
}

// The non-zero secret path must satisfy the full relation g^z == R + c*A.
func TestComputeProofOfKnowledge_NonZeroSecretVerifies(t *testing.T) {
	cs := secp256k1_sha256.New()
	grp := cs.Group()

	secret, err := grp.RandomScalar()
	require.NoError(t, err)
	commitment := grp.ScalarBaseMult(secret)

	proof, err := computeProofOfKnowledge(3, secret, commitment, cs)
	require.NoError(t, err)
	require.False(t, proof.Z.IsZero())

	challenge := computeChallenge(3, commitment, proof.R, cs)
	expected := proof.R.Add(grp.ScalarMult(commitment, challenge))
	require.True(t, grp.ScalarBaseMult(proof.Z).Equal(expected),
		"g^z must equal R + c*A")
}

// The input secret belongs to the caller and must come back unchanged.
func TestComputeProofOfKnowledge_DoesNotMutateSecret(t *testing.T) {
	cs := ristretto255_sha512.New()
	grp := cs.Group()

	secret, err := grp.RandomScalar()
	require.NoError(t, err)
	before := grp.SerializeScalar(secret)

	commitment := grp.ScalarBaseMult(secret)
	_, err = computeProofOfKnowledge(2, secret, commitment, cs)
	require.NoError(t, err)

	require.Equal(t, before, grp.SerializeScalar(secret),
		"caller's secret scalar must not be mutated or zeroized")
}
