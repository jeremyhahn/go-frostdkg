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
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// RFC 9591 Appendix E test vectors for trusted dealer key generation.
// These verify our VSS polynomial evaluation matches the reference implementation.

// rfc9591TestVector contains test data from RFC 9591 Appendix E
type rfc9591TestVector struct {
	name                        string
	groupSecretKey              string // a_0, the constant term
	sharePolynomialCoefficient1 string // a_1, the coefficient of x
	p1Share                     string // f(1)
	p2Share                     string // f(2)
	p3Share                     string // f(3)
	groupPublicKey              string // G * a_0
}

// RFC 9591 test vectors (cleaned up from line-wrapped format in RFC)
var rfc9591Ed25519Vectors = rfc9591TestVector{
	name:                        "Ed25519",
	groupSecretKey:              "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304",
	sharePolynomialCoefficient1: "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204",
	p1Share:                     "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
	p2Share:                     "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d",
	p3Share:                     "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
	groupPublicKey:              "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673",
}

var rfc9591Ed448Vectors = rfc9591TestVector{
	name:                        "Ed448",
	groupSecretKey:              "6298e1eef3c379392caaed061ed8a31033c9e9e3420726f23b404158a401cd9df24632adfe6b418dc942d8a091817dd8bd70e1c72ba52f3c00",
	sharePolynomialCoefficient1: "dbd7a514f7a731976620f0436bd135fe8dddc3fadd6e0d13dbd58a1981e587d377d48e0b7ce4e0092967c5e85884d0275a7a740b6abdcd0500",
	p1Share:                     "4a2b2f5858a932ad3d3b18bd16e76ced3070d72fd79ae4402df201f525e754716a1bc1b87a502297f2a99d89ea054e0018eb55d39562fd0100",
	p2Share:                     "2503d56c4f516444a45b080182b8a2ebbe4d9b2ab509f25308c88c0ea7ccdc44e2ef4fc4f63403a11b116372438a1e287265cadeff1fcb0700",
	p3Share:                     "00db7a8146f995db0a7cf844ed89d8e94c2b5f259378ff66e39d172828b264185ac4decf7219e4aa4478285b9c0eef4fccdf3eea69dd980d00",
	groupPublicKey:              "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000",
}

var rfc9591Ristretto255Vectors = rfc9591TestVector{
	name:                        "Ristretto255",
	groupSecretKey:              "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b",
	sharePolynomialCoefficient1: "410f8b744b19325891d73736923525a4f596c805d060dfb9c98009d34e3fec02",
	p1Share:                     "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e",
	p2Share:                     "b06fc5eac20b4f6e1b271d9df2343d843e1e1fb03c4cbb673f2872d459ce6f01",
	p3Share:                     "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04",
	groupPublicKey:              "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57",
}

var rfc9591P256Vectors = rfc9591TestVector{
	name:                        "P256",
	groupSecretKey:              "8ba9bba2e0fd8c4767154d35a0b7562244a4aaf6f36c8fb8735fa48b301bd8de",
	sharePolynomialCoefficient1: "80f25e6c0709353e46bfbe882a11bdbb1f8097e46340eb8673b7e14556e6c3a4",
	p1Share:                     "0c9c1a0fe806c184add50bbdcac913dda73e482daf95dcb9f35dbb0d8a9f7731",
	p2Share:                     "8d8e787bef0ff6c2f494ca45f4dad198c6bee01212d6c84067159c52e1863ad5",
	p3Share:                     "0e80d6e8f6192c003b5488ce1eec8f5429587d48cf001541e713b2d53c09d928",
	groupPublicKey:              "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70",
}

var rfc9591Secp256k1Vectors = rfc9591TestVector{
	name:                        "Secp256k1",
	groupSecretKey:              "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114",
	sharePolynomialCoefficient1: "fbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579",
	p1Share:                     "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c",
	p2Share:                     "04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984",
	p3Share:                     "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc",
	groupPublicKey:              "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f",
}

// TestRFC9591_ShareGeneration verifies that polynomial evaluation produces
// the same shares as the RFC 9591 test vectors.
func TestRFC9591_ShareGeneration(t *testing.T) {
	tests := []struct {
		name    string
		grp     group.Group
		vectors rfc9591TestVector
	}{
		{"Ed25519", ed25519_sha512.New().Group(), rfc9591Ed25519Vectors},
		{"Ed448", ed448_shake256.New().Group(), rfc9591Ed448Vectors},
		{"Ristretto255", ristretto255_sha512.New().Group(), rfc9591Ristretto255Vectors},
		{"P256", p256_sha256.New().Group(), rfc9591P256Vectors},
		{"Secp256k1", secp256k1_sha256.New().Group(), rfc9591Secp256k1Vectors},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grp := tt.grp
			v := tt.vectors

			// Decode scalars
			a0Bytes := mustDecodeHex(t, v.groupSecretKey)
			a1Bytes := mustDecodeHex(t, v.sharePolynomialCoefficient1)

			a0, err := grp.DeserializeScalar(a0Bytes)
			if err != nil {
				t.Fatalf("Failed to deserialize a0: %v", err)
			}
			a1, err := grp.DeserializeScalar(a1Bytes)
			if err != nil {
				t.Fatalf("Failed to deserialize a1: %v", err)
			}

			// Create polynomial f(x) = a_0 + a_1 * x
			coeffs := []group.Scalar{a0, a1}
			poly, err := NewPolynomial(grp, coeffs)
			if err != nil {
				t.Fatalf("Failed to create polynomial: %v", err)
			}

			// Create VSS
			vss, err := NewVSS(grp, poly)
			if err != nil {
				t.Fatalf("Failed to create VSS: %v", err)
			}

			// Generate shares
			shares, err := vss.Secshares(3)
			if err != nil {
				t.Fatalf("Failed to generate shares: %v", err)
			}

			// Verify each share
			expectedShares := []string{v.p1Share, v.p2Share, v.p3Share}
			for i, expectedHex := range expectedShares {
				expectedBytes := mustDecodeHex(t, expectedHex)
				actualBytes := grp.SerializeScalar(shares[i])

				if !bytes.Equal(actualBytes, expectedBytes) {
					t.Errorf("P%d share mismatch:\n  got:  %x\n  want: %x",
						i+1, actualBytes, expectedBytes)
				}
			}
		})
	}
}

// TestRFC9591_GroupPublicKey verifies that the commitment to the secret
// produces the correct group public key.
func TestRFC9591_GroupPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		grp     group.Group
		vectors rfc9591TestVector
	}{
		{"Ed25519", ed25519_sha512.New().Group(), rfc9591Ed25519Vectors},
		{"Ed448", ed448_shake256.New().Group(), rfc9591Ed448Vectors},
		{"Ristretto255", ristretto255_sha512.New().Group(), rfc9591Ristretto255Vectors},
		{"P256", p256_sha256.New().Group(), rfc9591P256Vectors},
		{"Secp256k1", secp256k1_sha256.New().Group(), rfc9591Secp256k1Vectors},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grp := tt.grp
			v := tt.vectors

			// Decode scalars
			a0Bytes := mustDecodeHex(t, v.groupSecretKey)
			a1Bytes := mustDecodeHex(t, v.sharePolynomialCoefficient1)

			a0, err := grp.DeserializeScalar(a0Bytes)
			if err != nil {
				t.Fatalf("Failed to deserialize a0: %v", err)
			}
			a1, err := grp.DeserializeScalar(a1Bytes)
			if err != nil {
				t.Fatalf("Failed to deserialize a1: %v", err)
			}

			// Create polynomial and VSS
			coeffs := []group.Scalar{a0, a1}
			poly, err := NewPolynomial(grp, coeffs)
			if err != nil {
				t.Fatalf("Failed to create polynomial: %v", err)
			}
			vss, err := NewVSS(grp, poly)
			if err != nil {
				t.Fatalf("Failed to create VSS: %v", err)
			}

			// Get commitment (VSS commitment C_0 = G * a_0 is the group public key)
			commitment := vss.Commit()
			groupPubkey := commitment.CommitmentToSecret()

			expectedBytes := mustDecodeHex(t, v.groupPublicKey)
			actualBytes, err := grp.SerializeElement(groupPubkey)
			if err != nil {
				t.Fatalf("Failed to serialize group pubkey: %v", err)
			}

			if !bytes.Equal(actualBytes, expectedBytes) {
				t.Errorf("Group public key mismatch:\n  got:  %x\n  want: %x",
					actualBytes, expectedBytes)
			}
		})
	}
}

// TestRFC9591_ShareVerification verifies that shares can be verified against
// the VSS commitment.
func TestRFC9591_ShareVerification(t *testing.T) {
	tests := []struct {
		name    string
		grp     group.Group
		vectors rfc9591TestVector
	}{
		{"Ed25519", ed25519_sha512.New().Group(), rfc9591Ed25519Vectors},
		{"Ed448", ed448_shake256.New().Group(), rfc9591Ed448Vectors},
		{"Ristretto255", ristretto255_sha512.New().Group(), rfc9591Ristretto255Vectors},
		{"P256", p256_sha256.New().Group(), rfc9591P256Vectors},
		{"Secp256k1", secp256k1_sha256.New().Group(), rfc9591Secp256k1Vectors},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grp := tt.grp
			v := tt.vectors

			// Decode scalars
			a0Bytes := mustDecodeHex(t, v.groupSecretKey)
			a1Bytes := mustDecodeHex(t, v.sharePolynomialCoefficient1)

			a0, err := grp.DeserializeScalar(a0Bytes)
			if err != nil {
				t.Fatalf("Failed to deserialize a0: %v", err)
			}
			a1, err := grp.DeserializeScalar(a1Bytes)
			if err != nil {
				t.Fatalf("Failed to deserialize a1: %v", err)
			}

			// Create polynomial and VSS
			coeffs := []group.Scalar{a0, a1}
			poly, err := NewPolynomial(grp, coeffs)
			if err != nil {
				t.Fatalf("Failed to create polynomial: %v", err)
			}
			vss, err := NewVSS(grp, poly)
			if err != nil {
				t.Fatalf("Failed to create VSS: %v", err)
			}

			// Get commitment
			commitment := vss.Commit()

			// Verify each share from RFC vectors
			shareHexes := []string{v.p1Share, v.p2Share, v.p3Share}
			for i, shareHex := range shareHexes {
				shareBytes := mustDecodeHex(t, shareHex)
				share, err := grp.DeserializeScalar(shareBytes)
				if err != nil {
					t.Fatalf("P%d: failed to deserialize share: %v", i+1, err)
				}

				// Compute expected public share from commitment
				pubshare, err := commitment.Pubshare(grp, i)
				if err != nil {
					t.Fatalf("P%d: failed to compute pubshare: %v", i+1, err)
				}

				// Verify share
				if !VerifySecshare(grp, share, pubshare) {
					t.Errorf("P%d: share verification failed", i+1)
				}
			}
		})
	}
}

// mustDecodeHex decodes a hex string, handling line-wrapped RFC format
func mustDecodeHex(t *testing.T, s string) []byte {
	// Remove any whitespace (for line-wrapped RFC values)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("Failed to decode hex %q: %v", s, err)
	}
	return b
}
