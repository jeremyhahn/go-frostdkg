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
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
	"github.com/stretchr/testify/require"
)

// TestSoftwareHostKey_SecretIsNotReachableAfterZeroize is the property the
// enclave migration exists for: after release the secret is gone, not merely
// zeroed inside a slice that still exists and can still be read.
func TestSoftwareHostKey_SecretIsNotReachableAfterZeroize(t *testing.T) {
	cs := testCiphersuite()
	key, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)

	require.NotNil(t, key.SecretKey(), "the key must be usable before release")

	// Hold the enclave itself, not just the field: dropping the reference is
	// not the same as destroying the secret, and only this distinguishes them.
	sealed := key.secret

	key.Zeroize()

	require.Nil(t, key.secret, "the field must not point at a destroyed enclave")
	require.Error(t, secmem.WithSecret(sealed, func([]byte) error { return nil }),
		"Zeroize must DESTROY the enclave, not merely stop referencing it")

	require.Nil(t, key.SecretKey(), "the secret must not be exportable after release")

	_, err = key.Sign([]byte("message"))
	require.ErrorIs(t, err, ErrHostKeyZeroized)

	other, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)
	_, err = key.ECDH(other.PublicKey())
	require.ErrorIs(t, err, ErrHostKeyZeroized)
}

// TestSoftwareHostKey_LeavesTheCallerSecretSlice pins the borrow rule at the
// constructor. secmem.NewSecretBytes zeroes what it is handed, so the
// constructor seals a COPY: a caller loading several host keys from one
// decoded document must not find the rest of its buffer wiped.
func TestSoftwareHostKey_LeavesTheCallerSecretSlice(t *testing.T) {
	cs := testCiphersuite()
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	before := append([]byte(nil), secret...)

	key, err := NewSoftwareHostKey(cs, secret)
	require.NoError(t, err)
	t.Cleanup(key.Zeroize)

	require.True(t, bytes.Equal(before, secret),
		"constructing a host key must not zero the caller's secret slice")
}

// TestSoftwareHostKey_SignRoundTripsThroughTheEnclave proves the operations
// still work when the key material only exists sealed — the enclave is opened
// per operation rather than the secret being held decrypted.
func TestSoftwareHostKey_SignRoundTripsThroughTheEnclave(t *testing.T) {
	suites := []ciphersuite.Ciphersuite{
		ed25519_sha512.New(),
		ristretto255_sha512.New(),
		ed448_shake256.New(),
		secp256k1_sha256.New(),
		p256_sha256.New(),
	}

	for _, cs := range suites {
		t.Run(cs.ID(), func(t *testing.T) {
			key, err := GenerateSoftwareHostKey(cs)
			require.NoError(t, err)
			t.Cleanup(key.Zeroize)

			message := []byte("certeq input")

			// Twice: the second call proves the enclave was resealed and can be
			// reopened, which a one-shot open would not catch.
			for i := 0; i < 2; i++ {
				sig, err := key.Sign(message)
				require.NoError(t, err)
				require.NoError(t, VerifyHostKeySignature(cs, key.PublicKey(), message, sig))
			}
		})
	}
}

func TestSoftwareHostKey_ECDHRoundTripsThroughTheEnclave(t *testing.T) {
	cs := testCiphersuite()
	alice, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)
	t.Cleanup(alice.Zeroize)
	bob, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)
	t.Cleanup(bob.Zeroize)

	aliceShared, err := alice.ECDH(bob.PublicKey())
	require.NoError(t, err)
	bobShared, err := bob.ECDH(alice.PublicKey())
	require.NoError(t, err)

	require.True(t, bytes.Equal(aliceShared, bobShared), "ECDH must agree")
	require.NotEmpty(t, aliceShared)
}

// TestSealCopy_LeavesTheCallerSlice is the pkg/dkg half of the same borrow
// rule the transport layer's SealSecret carries.
func TestSealCopy_LeavesTheCallerSlice(t *testing.T) {
	secret := []byte("a 32-byte host secret key ......")
	before := append([]byte(nil), secret...)

	sealed := sealCopy(secret)
	require.NotNil(t, sealed)
	t.Cleanup(sealed.Destroy)

	require.True(t, bytes.Equal(before, secret), "sealCopy must not zero the caller's slice")
	require.NoError(t, secmem.WithSecret(sealed, func(got []byte) error {
		require.True(t, bytes.Equal(before, got))
		return nil
	}))
}

func TestSealCopy_EmptyInput(t *testing.T) {
	require.Nil(t, sealCopy(nil))
	require.Nil(t, sealCopy([]byte{}))
}

// TestParticipantStateZeroize_DestroysTheOwnedSeed covers the state secrets:
// the state OWNS what it sealed, so releasing it destroys the enclave, while
// the caller's original slice is untouched.
func TestParticipantStateZeroize_DestroysTheOwnedSeed(t *testing.T) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	before := append([]byte(nil), seed...)

	state := &FROSTDKGParticipantState{Seed: sealCopy(seed)}
	sealed := state.Seed

	state.Zeroize()

	require.Nil(t, state.Seed)
	require.True(t, bytes.Equal(before, seed), "the caller's seed slice is not the state's to wipe")
	require.Error(t, secmem.WithSecret(sealed, func([]byte) error { return nil }),
		"the state's own sealed seed must be destroyed")
}

func TestEncParticipantStateZeroize_DestroysTheOwnedHostSeckey(t *testing.T) {
	hostSeckey := make([]byte, 32)
	_, err := rand.Read(hostSeckey)
	require.NoError(t, err)
	before := append([]byte(nil), hostSeckey...)

	state := &FROSTDKGEncParticipantState{
		FROSTDKGParticipantState: &FROSTDKGParticipantState{},
		HostSeckey:               sealCopy(hostSeckey),
	}
	sealed := state.HostSeckey

	state.Zeroize()

	require.Nil(t, state.HostSeckey)
	require.True(t, bytes.Equal(before, hostSeckey), "the caller's key slice is not the state's to wipe")
	require.Error(t, secmem.WithSecret(sealed, func([]byte) error { return nil }))
}

// capturingRNG fills the buffer it is handed and keeps a reference to it. That
// makes the generator's own scratch buffer observable from a test: io.ReadFull
// passes the real slice to Read, so whatever this retains IS the buffer the
// raw host key was generated into.
type capturingRNG struct {
	fill byte
	buf  []byte
	// err, when set, is returned after the buffer has been filled, so the
	// failure path can be exercised with the key material already written.
	err error
}

func (r *capturingRNG) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.fill
	}
	if r.buf == nil {
		r.buf = p // the first read is the key material
	}
	if r.err != nil {
		return 0, r.err
	}
	return len(p), nil
}

// TestGenerateSoftwareHostKey_ZeroesItsOwnBuffer covers the producer side of
// the borrow rule, and it is the case the CLI fix in this PR missed.
//
// NewSoftwareHostKeyWithRNG seals a COPY and leaves its input alone, because
// the key it is usually handed belongs to its caller. A caller that generated
// the buffer itself therefore has to zero it — otherwise a freshly generated
// host key sits in plain heap memory until the GC gets to it, which is what the
// enclave exists to prevent.
//
// Unlike the CLI's function-local, this one IS observable: the RNG is injected,
// so the test can hold the exact slice the key was generated into.
func TestGenerateSoftwareHostKey_ZeroesItsOwnBuffer(t *testing.T) {
	rng := &capturingRNG{fill: 0xA5}

	key, err := GenerateSoftwareHostKeyWithRNG(testCiphersuite(), rng)
	require.NoError(t, err)
	require.NotNil(t, key)
	t.Cleanup(key.Zeroize)

	require.NotNil(t, rng.buf, "the RNG should have been asked for key material")
	require.NotEmpty(t, rng.buf)
	for i, b := range rng.buf {
		require.Zerof(t, b, "byte %d of the generator's buffer still holds key material", i)
	}

	// And the key itself still works — zeroing the source must not have
	// reached through into the sealed copy.
	sig, err := key.Sign([]byte("message"))
	require.NoError(t, err)
	require.NotEmpty(t, sig)
}

// TestGenerateSoftwareHostKey_ZeroesItsBufferOnFailure covers the path that was
// already correct, so a refactor cannot quietly drop it. The RNG fills the
// buffer and THEN fails, so there is real key material to leave behind.
func TestGenerateSoftwareHostKey_ZeroesItsBufferOnFailure(t *testing.T) {
	rng := &capturingRNG{fill: 0xA5, err: io.ErrUnexpectedEOF}

	key, err := GenerateSoftwareHostKeyWithRNG(testCiphersuite(), rng)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Nil(t, key)

	require.NotNil(t, rng.buf, "the RNG should have been asked for key material")
	for i, b := range rng.buf {
		require.Zerof(t, b, "byte %d survived the failure path", i)
	}
}
