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

// Zeroize nils both the secret key bytes and the derived scalar, and the
// private-key operations dereference them. Using a zeroized key must fail
// closed with a typed error; it previously panicked with a nil dereference
// inside the group arithmetic.
func TestSoftwareHostKey_Sign_AfterZeroizeReturnsError(t *testing.T) {
	hostKey, err := GenerateSoftwareHostKey(ristretto255_sha512.New())
	require.NoError(t, err)

	// Works before zeroization.
	sig, err := hostKey.Sign([]byte("message"))
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	hostKey.Zeroize()

	require.NotPanics(t, func() {
		_, err = hostKey.Sign([]byte("message"))
	})
	require.ErrorIs(t, err, ErrHostKeyZeroized)
}

func TestSoftwareHostKey_ECDH_AfterZeroizeReturnsError(t *testing.T) {
	cs := ristretto255_sha512.New()

	alice, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)
	bob, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)

	shared, err := alice.ECDH(bob.PublicKey())
	require.NoError(t, err)
	require.NotEmpty(t, shared)

	alice.Zeroize()

	require.NotPanics(t, func() {
		_, err = alice.ECDH(bob.PublicKey())
	})
	require.ErrorIs(t, err, ErrHostKeyZeroized)
}

// The P-256 path signs from the raw key bytes rather than the scalar, so it
// needs the same guard.
func TestSoftwareHostKey_Sign_AfterZeroizeReturnsErrorSecp256k1(t *testing.T) {
	hostKey, err := GenerateSoftwareHostKey(secp256k1_sha256.New())
	require.NoError(t, err)

	hostKey.Zeroize()

	require.NotPanics(t, func() {
		_, err = hostKey.Sign([]byte("message"))
	})
	require.ErrorIs(t, err, ErrHostKeyZeroized)
}

// Zeroize must be safe to call more than once and on a nil receiver.
func TestSoftwareHostKey_Zeroize_IsIdempotent(t *testing.T) {
	hostKey, err := GenerateSoftwareHostKey(ristretto255_sha512.New())
	require.NoError(t, err)

	require.NotPanics(t, func() {
		hostKey.Zeroize()
		hostKey.Zeroize()
		var nilKey *SoftwareHostKey
		nilKey.Zeroize()
	})
}
