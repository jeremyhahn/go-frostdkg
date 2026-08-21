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

package main

import (
	"testing"

	"github.com/jeremyhahn/go-frostdkg/pkg/dkg"
	"github.com/stretchr/testify/require"
)

// TestValidCiphersuites_ResolveInTheLibrary is the test the secp256k1 casing
// drift would have failed: the CLI spelled the identifier
// FROST-SECP256K1-SHA256-v1 while the library spells it
// FROST-secp256k1-SHA256-v1, so --ciphersuite could offer a value that
// resolved to no ciphersuite at all. Every identifier the CLI advertises must
// be one the library can build a generator for.
func TestValidCiphersuites_ResolveInTheLibrary(t *testing.T) {
	suites := ValidCiphersuites()
	require.NotEmpty(t, suites)

	for _, id := range suites {
		t.Run(id, func(t *testing.T) {
			cs, err := dkg.CiphersuiteByID(id)
			require.NoError(t, err, "the CLI offers %q but the library does not know it", id)
			require.Equal(t, id, cs.ID())

			gen, err := dkg.GetHostKeyGenerator(cs)
			require.NoError(t, err)
			require.NotNil(t, gen)
		})
	}
}

// TestCiphersuiteConstants_MatchTheLibrary pins each alias to its source, so a
// literal reintroduced here fails rather than drifting silently.
func TestCiphersuiteConstants_MatchTheLibrary(t *testing.T) {
	require.Equal(t, dkg.CiphersuiteEd25519, CiphersuiteEd25519)
	require.Equal(t, dkg.CiphersuiteRistretto255, CiphersuiteRistretto255)
	require.Equal(t, dkg.CiphersuiteP256, CiphersuiteP256)
	require.Equal(t, dkg.CiphersuiteSecp256k1, CiphersuiteSecp256k1)
	require.Equal(t, dkg.CiphersuiteEd448, CiphersuiteEd448)
}

// TestCiphersuiteKeySize covers the sizes the CLI reports for a generated
// share, including the P256 and secp256k1 compressed-point case.
func TestCiphersuiteKeySize(t *testing.T) {
	tests := []struct {
		id   string
		want int
	}{
		{CiphersuiteEd25519, 32},
		{CiphersuiteRistretto255, 32},
		{CiphersuiteP256, 33},
		{CiphersuiteSecp256k1, 33},
		{CiphersuiteEd448, 57},
		{"unknown-suite", 32},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			require.Equal(t, tt.want, CiphersuiteKeySize(tt.id))
		})
	}
}
