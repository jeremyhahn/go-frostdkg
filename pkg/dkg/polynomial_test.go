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

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

func TestNewPolynomial(t *testing.T) {
	grp := ed25519_sha512.New().Group()

	t.Run("ValidPolynomial", func(t *testing.T) {
		coeffs := make([]group.Scalar, 3)
		for i := range coeffs {
			scalar, err := grp.RandomScalar()
			if err != nil {
				t.Fatalf("Failed to generate random scalar: %v", err)
			}
			coeffs[i] = scalar
		}

		poly, err := NewPolynomial(grp, coeffs)
		if err != nil {
			t.Fatalf("NewPolynomial failed: %v", err)
		}
		if poly == nil {
			t.Fatal("Expected non-nil polynomial")
		}
		if poly.Threshold() != 3 {
			t.Errorf("Expected threshold 3, got %d", poly.Threshold())
		}
		if poly.Degree() != 2 {
			t.Errorf("Expected degree 2, got %d", poly.Degree())
		}
	})

	t.Run("EmptyCoefficients", func(t *testing.T) {
		coeffs := []group.Scalar{}
		poly, err := NewPolynomial(grp, coeffs)
		if err != ErrInvalidPolynomial {
			t.Errorf("Expected ErrInvalidPolynomial, got %v", err)
		}
		if poly != nil {
			t.Error("Expected nil polynomial for empty coefficients")
		}
	})

	t.Run("SingleCoefficient", func(t *testing.T) {
		scalar, err := grp.RandomScalar()
		if err != nil {
			t.Fatalf("Failed to generate random scalar: %v", err)
		}
		coeffs := []group.Scalar{scalar}

		poly, err := NewPolynomial(grp, coeffs)
		if err != nil {
			t.Fatalf("NewPolynomial failed: %v", err)
		}
		if poly.Threshold() != 1 {
			t.Errorf("Expected threshold 1, got %d", poly.Threshold())
		}
		if poly.Degree() != 0 {
			t.Errorf("Expected degree 0, got %d", poly.Degree())
		}
	})
}

func TestPolynomialEval(t *testing.T) {
	grp := ed25519_sha512.New().Group()

	t.Run("ConstantPolynomial", func(t *testing.T) {
		five := scalarFromInt(grp, 5)
		coeffs := []group.Scalar{five}
		poly, _ := NewPolynomial(grp, coeffs)

		for i := 1; i <= 3; i++ {
			x := scalarFromInt(grp, i)
			result := poly.Eval(x)
			if !result.Equal(five) {
				t.Errorf("Expected f(%d) = 5, got different value", i)
			}
		}
	})

	t.Run("LinearPolynomial", func(t *testing.T) {
		two := scalarFromInt(grp, 2)
		three := scalarFromInt(grp, 3)
		coeffs := []group.Scalar{two, three}
		poly, _ := NewPolynomial(grp, coeffs)

		// f(1) = 2 + 3*1 = 5
		one := scalarFromInt(grp, 1)
		five := scalarFromInt(grp, 5)
		result := poly.Eval(one)
		if !result.Equal(five) {
			t.Error("Expected f(1) = 5")
		}

		// f(2) = 2 + 3*2 = 8
		twoScalar := scalarFromInt(grp, 2)
		eight := scalarFromInt(grp, 8)
		result = poly.Eval(twoScalar)
		if !result.Equal(eight) {
			t.Error("Expected f(2) = 8")
		}
	})

	t.Run("QuadraticPolynomial", func(t *testing.T) {
		one := scalarFromInt(grp, 1)
		two := scalarFromInt(grp, 2)
		three := scalarFromInt(grp, 3)
		coeffs := []group.Scalar{one, two, three}
		poly, _ := NewPolynomial(grp, coeffs)

		// f(0) = 1 (use ConstantTerm() for security - Eval(0) would reveal secret)
		result := poly.ConstantTerm()
		if !result.Equal(one) {
			t.Error("Expected f(0) = 1")
		}

		// f(1) = 1 + 2*1 + 3*1 = 6
		six := scalarFromInt(grp, 6)
		result = poly.Eval(one)
		if !result.Equal(six) {
			t.Error("Expected f(1) = 6")
		}
	})

	t.Run("ConstantTermEqualsSecret", func(t *testing.T) {
		coeffs := make([]group.Scalar, 5)
		for i := range coeffs {
			scalar, _ := grp.RandomScalar()
			coeffs[i] = scalar
		}
		poly, _ := NewPolynomial(grp, coeffs)

		// ConstantTerm() should return coeffs[0]
		constant := poly.ConstantTerm()
		if !constant.Equal(coeffs[0]) {
			t.Error("ConstantTerm() should return coeffs[0]")
		}
	})

	t.Run("EvalAtZeroPanics", func(t *testing.T) {
		// Security check: evaluating at zero would reveal the secret
		coeffs := make([]group.Scalar, 3)
		for i := range coeffs {
			scalar, _ := grp.RandomScalar()
			coeffs[i] = scalar
		}
		poly, _ := NewPolynomial(grp, coeffs)

		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when evaluating at zero")
			}
		}()

		zero := grp.NewScalar()
		poly.Eval(zero) // Should panic
	})
}

func TestPolynomialConstantTerm(t *testing.T) {
	grp := ed25519_sha512.New().Group()

	t.Run("ReturnsFirstCoefficient", func(t *testing.T) {
		secret, _ := grp.RandomScalar()
		coeffs := make([]group.Scalar, 3)
		coeffs[0] = secret
		for i := 1; i < len(coeffs); i++ {
			coeffs[i], _ = grp.RandomScalar()
		}
		poly, _ := NewPolynomial(grp, coeffs)

		constant := poly.ConstantTerm()
		if !constant.Equal(secret) {
			t.Error("Constant term should equal first coefficient")
		}
	})
}

func TestPolynomialCoefficients(t *testing.T) {
	grp := ed25519_sha512.New().Group()

	t.Run("ReturnsAllCoefficients", func(t *testing.T) {
		original := make([]group.Scalar, 5)
		for i := range original {
			scalar, _ := grp.RandomScalar()
			original[i] = scalar
		}
		poly, _ := NewPolynomial(grp, original)

		returned := poly.Coefficients()
		if len(returned) != len(original) {
			t.Fatalf("Expected %d coefficients, got %d", len(original), len(returned))
		}
		for i := range returned {
			if !returned[i].Equal(original[i]) {
				t.Errorf("Coefficient %d does not match", i)
			}
		}
	})
}

func TestPolynomialEvalZeroCoefficients(t *testing.T) {
	grp := ed25519_sha512.New().Group()

	t.Run("ConstantTermEqualsFirstCoeff", func(t *testing.T) {
		one := scalarFromInt(grp, 1)
		two := scalarFromInt(grp, 2)
		three := scalarFromInt(grp, 3)
		poly, _ := NewPolynomial(grp, []group.Scalar{one, two, three})

		// Use ConstantTerm() instead of Eval(zero) for security
		result := poly.ConstantTerm()
		if !result.Equal(one) {
			t.Error("ConstantTerm() should equal first coefficient")
		}
	})

	t.Run("SingleCoefficientPolynomial", func(t *testing.T) {
		constant := scalarFromInt(grp, 42)
		poly, _ := NewPolynomial(grp, []group.Scalar{constant})

		// Start at 1, not 0 (evaluating at 0 would panic for security)
		for i := 1; i < 10; i++ {
			x := scalarFromInt(grp, i)
			result := poly.Eval(x)
			if !result.Equal(constant) {
				t.Errorf("Constant polynomial should always return constant")
			}
		}
	})
}

// TestPolynomialConstantTermEmptyCoeffs tests the edge case where polynomial has empty coefficients.
// This tests the defensive code path in ConstantTerm().
func TestPolynomialConstantTermEmptyCoeffs(t *testing.T) {
	grp := ed25519_sha512.New().Group()

	// Manually create a polynomial with empty coefficients to test defensive code
	poly := &Polynomial{
		grp:    grp,
		coeffs: []group.Scalar{},
	}

	result := poly.ConstantTerm()
	if result == nil {
		t.Error("ConstantTerm should return zero scalar, not nil")
	}

	// Should return zero scalar
	zero := grp.NewScalar()
	if !result.Equal(zero) {
		t.Error("ConstantTerm of empty polynomial should be zero")
	}
}

// TestPolynomialEvalNilX tests nil input handling.
func TestPolynomialEvalNilX(t *testing.T) {
	grp := ed25519_sha512.New().Group()

	one := scalarFromInt(grp, 1)
	two := scalarFromInt(grp, 2)
	poly, _ := NewPolynomial(grp, []group.Scalar{one, two})

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when evaluating with nil x")
		}
	}()

	poly.Eval(nil)
}
