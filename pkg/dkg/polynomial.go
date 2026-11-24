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

// Polynomial is f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[t-1]*x^(t-1) over any group.
type Polynomial struct {
	coeffs []group.Scalar
	grp    group.Group
}

// Zeroize overwrites and drops the coefficients; best effort, as the GC may hold copies.
func (p *Polynomial) Zeroize() {
	if p == nil {
		return
	}
	// Zeroize each coefficient's internal memory in place
	for i := range p.coeffs {
		if p.coeffs[i] != nil {
			p.coeffs[i].Zeroize()
		}
	}
	// Nil all references to make them GC-eligible
	for i := range p.coeffs {
		p.coeffs[i] = nil
	}
	p.coeffs = nil
}

// NewPolynomial creates a polynomial from constant-term-first coefficients; ErrInvalidPolynomial if empty.
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

// Eval evaluates the polynomial at x by Horner's method; x == 0 is refused because f(0) is the secret.
func (p *Polynomial) Eval(x group.Scalar) (group.Scalar, error) {
	if len(p.coeffs) == 0 {
		return p.grp.NewScalar(), nil // Return zero scalar
	}

	// Security check: never evaluate at zero - reveals the secret!
	if x.IsZero() {
		return nil, ErrEvalAtZero
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

	return value, nil
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
