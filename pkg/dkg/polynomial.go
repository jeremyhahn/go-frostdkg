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
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// Polynomial represents a scalar polynomial over a prime-order group.
//
// A polynomial f of degree at most t-1 is represented by a list of t coefficients:
// f(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ... + coeffs[t-1]*x^(t-1)
//
// The polynomial is curve-agnostic and works with any group.Group implementation.
type Polynomial struct {
	coeffs []group.Scalar
	grp    group.Group
}

// Zeroize clears the polynomial coefficients.
//
// SECURITY NOTE: Due to Go's type system, this cannot directly zero the memory
// holding scalar values. The group.Scalar interface doesn't expose internal
// byte storage. This method:
//  1. Overwrites each coefficient with a zero scalar (may help if implementation
//     caches byte representations)
//  2. Sets all coefficient references to nil to make them GC-eligible
//
// For maximum security in high-assurance environments:
//   - Use group implementations that support secure zeroization
//   - Call runtime.GC() after Zeroize() if needed
//   - Consider memory isolation techniques (mlock, etc.)
func (p *Polynomial) Zeroize() {
	if p == nil {
		return
	}
	// Overwrite with zero scalars before niling references
	if p.grp != nil {
		zeroScalar := p.grp.NewScalar()
		for i := range p.coeffs {
			if p.coeffs[i] != nil {
				// Attempt to overwrite by re-assigning
				// (effectiveness depends on group implementation)
				p.coeffs[i] = zeroScalar
			}
		}
	}
	// Nil all references to make them GC-eligible
	for i := range p.coeffs {
		p.coeffs[i] = nil
	}
	p.coeffs = nil
}

// NewPolynomial creates a new polynomial with the given coefficients.
// The coefficients are ordered from the constant term (coeffs[0]) to the
// highest degree term (coeffs[t-1]).
//
// Returns ErrInvalidPolynomial if coeffs is empty.
func NewPolynomial(grp group.Group, coeffs []group.Scalar) (*Polynomial, error) {
	if len(coeffs) == 0 {
		return nil, ErrInvalidPolynomial
	}

	// Create deep copies of all coefficients to ensure immutability
	copiedCoeffs := make([]group.Scalar, len(coeffs))
	for i, c := range coeffs {
		copiedCoeffs[i] = c.Copy()
	}

	return &Polynomial{
		coeffs: copiedCoeffs,
		grp:    grp,
	}, nil
}

// Degree returns the degree of the polynomial (t-1 where t is the number of coefficients).
func (p *Polynomial) Degree() int {
	return len(p.coeffs) - 1
}

// Threshold returns the threshold value t (the number of coefficients).
func (p *Polynomial) Threshold() int {
	return len(p.coeffs)
}

// Eval evaluates the polynomial at position x using Horner's method.
//
// Horner's method is efficient and numerically stable:
// f(x) = a0 + x(a1 + x(a2 + x(a3 + ... + x(an))))
//
// This method reverses the coefficient array and evaluates from the highest
// degree term down to the constant term.
//
// SECURITY: This function panics if x is zero because evaluating at zero
// reveals the secret (constant term). Use ConstantTerm() for explicit access.
func (p *Polynomial) Eval(x group.Scalar) group.Scalar {
	if len(p.coeffs) == 0 {
		return p.grp.NewScalar() // Return zero scalar
	}

	// Security check: never evaluate at zero - reveals the secret!
	if x.IsZero() {
		panic("Polynomial.Eval: evaluation at zero would reveal secret - use ConstantTerm()")
	}

	// Start with zero
	value := p.grp.NewScalar()

	// Horner's method: reverse iteration through coefficients
	// For f(x) = a0 + a1*x + a2*x^2 + a3*x^3
	// Compute as: a0 + x*(a1 + x*(a2 + x*a3))
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		value = value.Mul(x)
		value = value.Add(p.coeffs[i])
	}

	return value
}

// ConstantTerm returns the constant term of the polynomial (coeffs[0]).
// This is the secret in VSS schemes (the value f(0)).
func (p *Polynomial) ConstantTerm() group.Scalar {
	if len(p.coeffs) == 0 {
		return p.grp.NewScalar()
	}
	return p.coeffs[0].Copy()
}

// Coefficients returns a deep copy of the polynomial coefficients.
func (p *Polynomial) Coefficients() []group.Scalar {
	result := make([]group.Scalar, len(p.coeffs))
	for i, c := range p.coeffs {
		result[i] = c.Copy()
	}
	return result
}
