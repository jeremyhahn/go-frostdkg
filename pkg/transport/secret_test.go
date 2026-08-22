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

package transport

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
	"github.com/stretchr/testify/require"
)

func TestSealSecret_SealsTheContent(t *testing.T) {
	original := []byte("a 32-byte host secret key ......")
	require.Len(t, original, 32)

	sealed := SealSecret(original)
	require.NotNil(t, sealed)
	require.Equal(t, 32, sealed.Size())

	require.NoError(t, secmem.WithSecret(sealed, func(secret []byte) error {
		require.True(t, bytes.Equal(original, secret), "the sealed content must be what was handed in")
		return nil
	}))
}

// TestSealSecret_LeavesTheCallerSlice is the borrow rule at the transport
// boundary. secmem.NewSecretBytes ZEROES the slice it is given, so sealing a
// caller's buffer directly would wipe memory the caller still owns — a caller
// reading several participants' keys out of one decoded document would find
// the rest of it destroyed. SealSecret copies for exactly that reason.
func TestSealSecret_LeavesTheCallerSlice(t *testing.T) {
	original := []byte("a 32-byte host secret key ......")
	before := append([]byte(nil), original...)

	sealed := SealSecret(original)
	t.Cleanup(sealed.Destroy)

	require.True(t, bytes.Equal(before, original),
		"SealSecret must not zero the caller's slice; use secmem.NewSecretBytes when that IS what you want")
}

func TestSealSecret_EmptyInput(t *testing.T) {
	require.Nil(t, SealSecret(nil))
	require.Nil(t, SealSecret([]byte{}))
}

// TestDKGParamsZeroize_DestroysTheSecret proves the host secret is not
// reachable at all after release — not merely zeroed in a slice that still
// exists, which is what the plain []byte field left behind.
func TestDKGParamsZeroize_DestroysTheSecret(t *testing.T) {
	params := &DKGParams{
		HostSeckey:     SealSecret([]byte("a 32-byte host secret key ......")),
		HostPubkeys:    [][]byte{make([]byte, PublicKeySize)},
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         SealSecret([]byte("32 bytes of session randomness..")),
	}
	sealed := params.HostSeckey

	params.Zeroize()

	require.Nil(t, params.HostSeckey, "the field must not point at a destroyed enclave")
	require.Nil(t, params.Random)

	err := secmem.WithSecret(sealed, func([]byte) error {
		t.Fatal("the destroyed secret must not open")
		return nil
	})
	require.Error(t, err, "opening a destroyed enclave must fail rather than yield bytes")
}

// TestDKGParamsZeroize_DestroysTheRandomness covers the session randomness,
// which is a secret rather than a nonce: combined with the host key it derives
// the participant seed, so holding both reproduces the share.
func TestDKGParamsZeroize_DestroysTheRandomness(t *testing.T) {
	params := &DKGParams{
		HostSeckey: SealSecret([]byte("a 32-byte host secret key ......")),
		Random:     SealSecret([]byte("32 bytes of session randomness..")),
	}
	sealed := params.Random

	params.Zeroize()

	require.Nil(t, params.Random)
	require.Error(t, secmem.WithSecret(sealed, func([]byte) error { return nil }),
		"the destroyed randomness must not open")
}

func TestDKGParamsZeroize_NilAndEmpty(t *testing.T) {
	var nilParams *DKGParams
	nilParams.Zeroize() // must not panic

	empty := &DKGParams{}
	empty.Zeroize() // no secret to destroy
	require.Nil(t, empty.HostSeckey)
}

// TestDKGResultZeroize_DestroysTheShare is the same property for the one
// secret a DKG produces.
func TestDKGResultZeroize_DestroysTheShare(t *testing.T) {
	result := &DKGResult{
		SecretShare:     SealSecret([]byte("a 32-byte threshold share ......")),
		ThresholdPubkey: make([]byte, PublicKeySize),
		SessionID:       "session",
	}
	sealed := result.SecretShare

	result.Zeroize()

	require.Nil(t, result.SecretShare)

	err := secmem.WithSecret(sealed, func([]byte) error {
		t.Fatal("the destroyed share must not open")
		return nil
	})
	require.Error(t, err)
}

func TestDKGResultZeroize_NilAndEmpty(t *testing.T) {
	var nilResult *DKGResult
	nilResult.Zeroize() // must not panic

	empty := &DKGResult{}
	empty.Zeroize()
	require.Nil(t, empty.SecretShare)
}

// TestSecretBytesSizeIsNilSafe covers the shape every transport's
// validateParams relies on: a missing host key must fail the length check
// rather than panic.
func TestSecretBytesSizeIsNilSafe(t *testing.T) {
	params := &DKGParams{}
	require.Equal(t, 0, params.HostSeckey.Size())
	require.Equal(t, 0, params.Random.Size())
}
