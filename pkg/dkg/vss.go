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
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// VSS is verifiable secret sharing: the secret is f(0) of a degree t-1 polynomial and participant i gets f(i+1).
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

// Generate creates a VSS with coeffs[i] = H3("FROST-DKG/vss coeffs" || seed || i).
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
		secmem.ZeroBytes(input)
		coeffs[i] = scalar
	}

	// Defer zeroization of intermediate coefficients
	defer func() {
		for _, c := range coeffs {
			if c != nil {
				c.Zeroize()
			}
		}
	}()

	poly, err := NewPolynomial(grp, coeffs)
	if err != nil {
		return nil, err
	}

	return NewVSS(grp, poly)
}

// SecshareFor returns f(i+1) for 0-based participant index i, never f(0).
func (v *VSS) SecshareFor(i int) (group.Scalar, error) {
	if i < 0 {
		return nil, ErrInvalidParticipantIndex
	}

	// Compute x = i + 1 to avoid evaluating at 0
	x := scalarFromInt(v.grp, i+1)
	return v.f.Eval(x)
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

// Commit returns the commitment C_j = f_j * G for each coefficient.
func (v *VSS) Commit() *VSSCommitment {
	coeffs := v.f.Coefficients()

	// Zeroize the coefficient copies
	defer func() {
		for _, coeff := range coeffs {
			if coeff != nil {
				coeff.Zeroize()
			}
		}
	}()

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

// Pubshare returns sum((i+1)^j * C_j), the public key of share f(i+1).
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

// VerifySecshare reports whether secshare * G == pubshare, in constant time.
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

// ToBytes serializes the commitment as t compressed elements.
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

// FromBytes parses t elements; identity elements are allowed, so callers check C_0 themselves if a zero secret matters.
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

		// Some groups serialize identity as all zeros; detect it in constant time.
		isZero := subtle.ConstantTimeCompare(elemBytes, make([]byte, len(elemBytes))) == 1

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

// Add adds two commitments element-wise; ErrMismatchedThreshold if thresholds differ.
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
