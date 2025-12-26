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
	"encoding/binary"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// VSS represents a Verifiable Secret Sharing scheme using a polynomial.
//
// VSS allows a dealer to share a secret among n participants such that:
// - Any t participants can reconstruct the secret
// - Fewer than t participants learn nothing about the secret
// - Each participant can verify their share is correct
//
// The secret is the constant term of a polynomial f(x) of degree t-1.
// Each participant i receives f(i+1) as their secret share.
type VSS struct {
	f   *Polynomial
	grp group.Group
}

// Zeroize clears sensitive data from the VSS.
// This zeros the polynomial coefficients which contain secret data.
func (v *VSS) Zeroize() {
	if v == nil {
		return
	}
	if v.f != nil {
		v.f.Zeroize()
	}
	v.f = nil
}

// NewVSS creates a new VSS instance with the given polynomial.
func NewVSS(grp group.Group, f *Polynomial) (*VSS, error) {
	if f == nil {
		return nil, ErrInvalidPolynomial
	}

	return &VSS{
		f:   f,
		grp: grp,
	}, nil
}

// Generate creates a new VSS instance using a ciphersuite's hash-to-scalar.
// This is compatible with all FROST ciphersuites (Ed25519, ristretto255, P-256, etc.)
// as it uses the ciphersuite's H3 function which properly handles scalar encoding.
//
// The polynomial coefficients are derived from the seed using the ciphersuite's H3 function.
// coeffs[i] = H3("FROST-DKG/vss coeffs" || seed || i) for i in 0..t-1
func Generate(cs ciphersuite.Ciphersuite, seed []byte, t int) (*VSS, error) {
	grp := cs.Group()
	if t <= 0 {
		return nil, ErrInvalidThreshold
	}

	coeffs := make([]group.Scalar, t)
	for i := 0; i < t; i++ {
		// Create input: "FROST-DKG/vss coeffs" || seed || i (i as 4-byte big-endian)
		// Loop index i is bounded by threshold t, safe for uint32
		prefix := []byte("FROST-DKG/vss coeffs")
		input := make([]byte, len(prefix)+len(seed)+4)
		copy(input, prefix)
		copy(input[len(prefix):], seed)
		binary.BigEndian.PutUint32(input[len(prefix)+len(seed):], safeUint32(i))

		// Use ciphersuite's H3 function for hash-to-scalar
		// H3 properly handles scalar encoding for all groups
		scalar := cs.H3(input)
		coeffs[i] = scalar
	}

	poly, err := NewPolynomial(grp, coeffs)
	if err != nil {
		return nil, err
	}

	return NewVSS(grp, poly)
}

// SecshareFor returns the secret share for participant with index i.
//
// This computes f(i+1) where i is the participant index (0-based).
// The participant index must be non-negative.
// We use i+1 to ensure we never evaluate f(0), which is the secret.
func (v *VSS) SecshareFor(i int) (group.Scalar, error) {
	if i < 0 {
		return nil, ErrInvalidParticipantIndex
	}

	// Compute x = i + 1 to avoid evaluating at 0
	x := scalarFromInt(v.grp, i+1)
	return v.f.Eval(x), nil
}

// Secshares returns the secret shares for participants with indices 0..n-1.
//
// This computes [f(1), f(2), ..., f(n)].
func (v *VSS) Secshares(n int) ([]group.Scalar, error) {
	if n <= 0 {
		return nil, ErrInvalidParticipantIndex
	}

	shares := make([]group.Scalar, n)
	for i := 0; i < n; i++ {
		share, err := v.SecshareFor(i)
		if err != nil {
			return nil, err
		}
		shares[i] = share
	}

	return shares, nil
}

// Commit returns the VSS commitment to the polynomial.
//
// The commitment consists of group elements C_j = f_j * G for each coefficient f_j,
// where G is the group generator. This allows participants to verify their shares
// without revealing the polynomial coefficients.
func (v *VSS) Commit() *VSSCommitment {
	coeffs := v.f.Coefficients()
	elements := make([]group.Element, len(coeffs))

	for i, coeff := range coeffs {
		elements[i] = v.grp.ScalarBaseMult(coeff)
	}

	return &VSSCommitment{
		Coefficients: elements,
	}
}

// Secret returns the secret being shared (the constant term f(0)).
func (v *VSS) Secret() group.Scalar {
	return v.f.ConstantTerm()
}

// VSSCommitment methods

// Threshold returns the threshold value t (the number of coefficients).
func (c *VSSCommitment) Threshold() int {
	return len(c.Coefficients)
}

// Pubshare computes the public share for participant i.
//
// The public share is computed as:
// pubshare(i) = C_0 + (i+1)*C_1 + (i+1)^2*C_2 + ... + (i+1)^(t-1)*C_(t-1)
//
// This is the public key corresponding to the secret share f(i+1).
func (c *VSSCommitment) Pubshare(grp group.Group, i int) (group.Element, error) {
	if i < 0 {
		return nil, ErrInvalidParticipantIndex
	}

	// Compute x = i + 1
	x := scalarFromInt(grp, i+1)

	// Compute sum of (x^j * Coefficients[j]) for j = 0 to t-1
	result := grp.Identity()
	xPower := scalarFromInt(grp, 1) // Start with x^0 = 1

	for j := 0; j < len(c.Coefficients); j++ {
		// Compute (x^j * Coefficients[j])
		term := grp.ScalarMult(c.Coefficients[j], xPower)
		result = result.Add(term)

		// Update x^j to x^(j+1) for next iteration
		if j < len(c.Coefficients)-1 {
			xPower = xPower.Mul(x)
		}
	}

	return result, nil
}

// VerifySecshare verifies that a secret share matches its public share.
//
// Verification checks that secshare * G == pubshare, where G is the generator.
// The caller must provide the correct public share for participant i using Pubshare(i).
//
// Uses constant-time comparison to prevent timing side-channel attacks.
// Returns true if the share is valid, false otherwise.
func VerifySecshare(grp group.Group, secshare group.Scalar, pubshare group.Element) bool {
	actual := grp.ScalarBaseMult(secshare)

	// Use constant-time comparison to prevent timing attacks
	actualBytes, err := grp.SerializeElement(actual)
	if err != nil {
		return false
	}
	expectedBytes, err := grp.SerializeElement(pubshare)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(actualBytes, expectedBytes) == 1
}

// ToBytes serializes the VSS commitment to bytes.
//
// The commitment is serialized as the concatenation of all group elements
// in compressed form. The total length is t * element_length bytes.
func (c *VSSCommitment) ToBytes(grp group.Group) ([]byte, error) {
	totalLen := len(c.Coefficients) * grp.ElementLength()
	result := make([]byte, 0, totalLen)

	for _, ge := range c.Coefficients {
		var elemBytes []byte
		if ge.IsIdentity() {
			// Serialize identity element as all zeros
			elemBytes = make([]byte, grp.ElementLength())
		} else {
			var err error
			elemBytes, err = grp.SerializeElement(ge)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, elemBytes...)
	}

	return result, nil
}

// FromBytes deserializes a VSS commitment from bytes.
//
// The input must have exactly t * element_length bytes, where element_length
// is the serialized size of a group element.
//
// SECURITY NOTE: This function allows identity elements in commitments because:
//   - Zero polynomial coefficients result in identity elements when committed
//   - Valid polynomials can have zero higher-degree coefficients
//   - DeserializeElement validates curve point encoding (subgroup checks, etc.)
//
// Callers concerned about zero secrets should separately validate that
// the first coefficient (C_0 = commitment to secret) is not identity.
func VSSCommitmentFromBytes(grp group.Group, b []byte, t int) (*VSSCommitment, error) {
	elemLen := grp.ElementLength()
	expectedLen := t * elemLen

	if len(b) != expectedLen {
		return nil, ErrInvalidCommitmentLength
	}

	elements := make([]group.Element, t)
	for i := 0; i < t; i++ {
		start := i * elemLen
		end := start + elemLen
		elemBytes := b[start:end]

		// Check if this is the zero/identity element (all zeros)
		// This is needed for proper round-trip serialization since
		// some groups serialize identity as all zeros
		isZero := true
		for _, by := range elemBytes {
			if by != 0 {
				isZero = false
				break
			}
		}

		if isZero {
			elements[i] = grp.Identity()
		} else {
			elem, err := grp.DeserializeElement(elemBytes)
			if err != nil {
				return nil, err
			}
			elements[i] = elem
		}
	}

	return &VSSCommitment{
		Coefficients: elements,
	}, nil
}

// CommitmentToSecret returns the commitment to the secret (the first coefficient).
//
// This is C_0 = f_0 * G, which is the public key corresponding to the shared secret.
func (c *VSSCommitment) CommitmentToSecret() group.Element {
	if len(c.Coefficients) == 0 {
		return nil
	}
	return c.Coefficients[0].Copy()
}

// CommitmentToNonconstTerms returns the commitments to non-constant polynomial terms.
//
// This returns [C_1, C_2, ..., C_(t-1)], excluding the constant term commitment C_0.
func (c *VSSCommitment) CommitmentToNonconstTerms() []group.Element {
	if len(c.Coefficients) <= 1 {
		return []group.Element{}
	}

	result := make([]group.Element, len(c.Coefficients)-1)
	for i := 1; i < len(c.Coefficients); i++ {
		result[i-1] = c.Coefficients[i].Copy()
	}
	return result
}

// Add adds two VSS commitments element-wise.
//
// This operation combines two VSS instances:
// (C + D)[i] = C[i] + D[i] for each coefficient commitment.
//
// Both commitments must have the same threshold.
// Returns ErrMismatchedThreshold if thresholds differ.
func (c *VSSCommitment) Add(other *VSSCommitment) (*VSSCommitment, error) {
	if c.Threshold() != other.Threshold() {
		return nil, ErrMismatchedThreshold
	}

	elements := make([]group.Element, len(c.Coefficients))
	for i := 0; i < len(c.Coefficients); i++ {
		elements[i] = c.Coefficients[i].Add(other.Coefficients[i])
	}

	return &VSSCommitment{
		Coefficients: elements,
	}, nil
}
