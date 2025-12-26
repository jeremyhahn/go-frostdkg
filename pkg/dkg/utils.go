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
	"crypto/subtle"

	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// Ciphersuite ID constants for supported FROST ciphersuites per RFC 9591.
const (
	// CiphersuiteP256 is the FROST-P256-SHA256-v1 ciphersuite ID.
	CiphersuiteP256 = "FROST-P256-SHA256-v1"

	// CiphersuiteEd25519 is the FROST-ED25519-SHA512-v1 ciphersuite ID.
	CiphersuiteEd25519 = "FROST-ED25519-SHA512-v1"

	// CiphersuiteRistretto255 is the FROST-RISTRETTO255-SHA512-v1 ciphersuite ID.
	CiphersuiteRistretto255 = "FROST-RISTRETTO255-SHA512-v1"

	// CiphersuiteEd448 is the FROST-ED448-SHAKE256-v1 ciphersuite ID.
	CiphersuiteEd448 = "FROST-ED448-SHAKE256-v1"

	// CiphersuiteSecp256k1 is the FROST-secp256k1-SHA256-v1 ciphersuite ID.
	CiphersuiteSecp256k1 = "FROST-secp256k1-SHA256-v1"
)

// scalarFromInt creates a scalar from an integer value.
// This is a helper to simplify creating small scalar values.
//
// Panics if n is negative or if deserialization fails (indicating a bug).
func scalarFromInt(grp group.Group, n int) group.Scalar {
	if n < 0 {
		panic("scalarFromInt: negative integer not allowed")
	}

	bytes := make([]byte, grp.ScalarLength())

	// Handle byte order based on group
	if grp.ByteOrder() == group.LittleEndian {
		// Little-endian: least significant byte first
		for i := 0; i < len(bytes) && n > 0; i++ {
			bytes[i] = byte(n & 0xff)
			n >>= 8
		}
	} else {
		// Big-endian: most significant byte first
		for i := grp.ScalarLength() - 1; i >= 0 && n > 0; i-- {
			bytes[i] = byte(n & 0xff)
			n >>= 8
		}
	}

	scalar, err := grp.DeserializeScalar(bytes)
	if err != nil {
		// This should never happen for small non-negative integers
		// as they are well below the group order for all supported curves
		panic("scalarFromInt: unexpected deserialization failure: " + err.Error())
	}
	return scalar
}

// constantTimeElementEqual compares two group elements in constant time.
// This prevents timing side-channel attacks during signature verification.
// It serializes both elements and uses crypto/subtle.ConstantTimeCompare.
func constantTimeElementEqual(grp group.Group, a, b group.Element) bool {
	// Serialize both elements to canonical byte representation
	aBytes := a.Bytes()
	bBytes := b.Bytes()

	// Constant-time comparison
	if len(aBytes) != len(bBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

// xorBytes XORs two byte slices of equal length.
// Caller must ensure both slices have equal length.
func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}
