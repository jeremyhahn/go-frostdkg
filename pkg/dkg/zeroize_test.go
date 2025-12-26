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
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// testCiphersuite returns a default ciphersuite for testing.
func testCiphersuite() ciphersuite.Ciphersuite {
	return ed25519_sha512.New()
}

func TestZeroBytes(t *testing.T) {
	t.Run("zeros_non_empty_slice", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		ZeroBytes(data)

		for i, b := range data {
			if b != 0 {
				t.Errorf("Byte at index %d is not zero: %x", i, b)
			}
		}
	})

	t.Run("handles_empty_slice", func(t *testing.T) {
		data := []byte{}
		ZeroBytes(data) // Should not panic
	})

	t.Run("handles_nil_slice", func(t *testing.T) {
		var data []byte
		ZeroBytes(data) // Should not panic
	})

	t.Run("zeros_large_slice", func(t *testing.T) {
		data := make([]byte, 1024)
		_, _ = rand.Read(data)

		ZeroBytes(data)

		zeros := make([]byte, 1024)
		if !bytes.Equal(data, zeros) {
			t.Error("Large slice was not zeroed")
		}
	})
}

func TestZeroSlices(t *testing.T) {
	t.Run("zeros_multiple_slices", func(t *testing.T) {
		slice1 := []byte{0x01, 0x02, 0x03}
		slice2 := []byte{0x04, 0x05, 0x06, 0x07}
		slice3 := []byte{0x08}

		ZeroSlices(slice1, slice2, slice3)

		for i, b := range slice1 {
			if b != 0 {
				t.Errorf("slice1[%d] not zero", i)
			}
		}
		for i, b := range slice2 {
			if b != 0 {
				t.Errorf("slice2[%d] not zero", i)
			}
		}
		for i, b := range slice3 {
			if b != 0 {
				t.Errorf("slice3[%d] not zero", i)
			}
		}
	})

	t.Run("handles_no_slices", func(t *testing.T) {
		ZeroSlices() // Should not panic
	})
}

func TestSecretPackageZeroize(t *testing.T) {
	t.Run("zeroizes_all_fields", func(t *testing.T) {
		pkg := &SecretPackage{
			Coefficients: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
			},
			SecretShare: []byte{0x07, 0x08, 0x09, 0x0A},
			Seed:        []byte{0x0B, 0x0C, 0x0D},
		}

		pkg.Zeroize()

		// Check all coefficients zeroed
		for i, coeff := range pkg.Coefficients {
			for j, b := range coeff {
				if b != 0 {
					t.Errorf("Coefficient[%d][%d] not zero", i, j)
				}
			}
		}

		// Check secret share zeroed
		for i, b := range pkg.SecretShare {
			if b != 0 {
				t.Errorf("SecretShare[%d] not zero", i)
			}
		}

		// Check seed zeroed
		for i, b := range pkg.Seed {
			if b != 0 {
				t.Errorf("Seed[%d] not zero", i)
			}
		}
	})

	t.Run("handles_nil_package", func(t *testing.T) {
		var pkg *SecretPackage
		pkg.Zeroize() // Should not panic
	})

	t.Run("handles_empty_fields", func(t *testing.T) {
		pkg := &SecretPackage{
			Coefficients: [][]byte{},
			SecretShare:  []byte{},
			Seed:         []byte{},
		}
		pkg.Zeroize() // Should not panic
	})
}

func TestSecureScalar(t *testing.T) {
	t.Run("stores_and_returns_data", func(t *testing.T) {
		original := []byte{0x01, 0x02, 0x03, 0x04}
		ss := NewSecureScalar(original)

		if !bytes.Equal(ss.Bytes(), original) {
			t.Error("Bytes() should return stored data")
		}

		// Verify it's a copy
		original[0] = 0xFF
		if ss.Bytes()[0] == 0xFF {
			t.Error("SecureScalar should store a copy, not reference")
		}
	})

	t.Run("zeroizes_data", func(t *testing.T) {
		ss := NewSecureScalar([]byte{0x01, 0x02, 0x03, 0x04})
		ss.Zeroize()

		for i, b := range ss.Bytes() {
			if b != 0 {
				t.Errorf("Byte at index %d not zero", i)
			}
		}
	})

	t.Run("handles_nil", func(t *testing.T) {
		var ss *SecureScalar
		ss.Zeroize() // Should not panic
	})
}

func TestPolynomialZeroize(t *testing.T) {
	t.Run("zeroizes_coefficients", func(t *testing.T) {
		cs := testCiphersuite()
		grp := cs.Group()

		// Create a polynomial with some coefficients
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
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		// Verify it has coefficients
		if len(poly.Coefficients()) != 3 {
			t.Fatal("Polynomial should have 3 coefficients")
		}

		poly.Zeroize()

		// Verify coefficients are nil
		if poly.coeffs != nil {
			t.Error("Polynomial coefficients should be nil after zeroize")
		}
	})

	t.Run("handles_nil_polynomial", func(t *testing.T) {
		var poly *Polynomial
		poly.Zeroize() // Should not panic
	})
}

func TestVSSZeroize(t *testing.T) {
	t.Run("zeroizes_polynomial", func(t *testing.T) {
		cs := testCiphersuite()
		grp := cs.Group()

		// Create a polynomial
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
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		vss, err := NewVSS(grp, poly)
		if err != nil {
			t.Fatalf("Failed to create VSS: %v", err)
		}

		vss.Zeroize()

		if vss.f != nil {
			t.Error("VSS polynomial should be nil after zeroize")
		}
	})

	t.Run("handles_nil_vss", func(t *testing.T) {
		var vss *VSS
		vss.Zeroize() // Should not panic
	})
}

func TestFROSTDKGOutputZeroize(t *testing.T) {
	t.Run("zeroizes_all_fields", func(t *testing.T) {
		cs := testCiphersuite()
		grp := cs.Group()

		secretShare, err := grp.RandomScalar()
		if err != nil {
			t.Fatalf("Failed to generate random scalar: %v", err)
		}

		output := &FROSTDKGOutput{
			SecretShare:     secretShare,
			ThresholdPubkey: grp.ScalarBaseMult(secretShare),
			PublicShares:    []group.Element{grp.ScalarBaseMult(secretShare)},
		}

		output.Zeroize()

		if output.SecretShare != nil {
			t.Error("SecretShare should be nil after zeroize")
		}
		if output.ThresholdPubkey != nil {
			t.Error("ThresholdPubkey should be nil after zeroize")
		}
		if output.PublicShares != nil {
			t.Error("PublicShares should be nil after zeroize")
		}
	})

	t.Run("handles_nil_output", func(t *testing.T) {
		var output *FROSTDKGOutput
		output.Zeroize() // Should not panic
	})
}

func TestFROSTDKGParticipantStateZeroize(t *testing.T) {
	t.Run("zeroizes_seed_and_vss", func(t *testing.T) {
		cs := testCiphersuite()
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)

		vss, err := Generate(cs, seed, 3)
		if err != nil {
			t.Fatalf("Failed to generate VSS: %v", err)
		}

		state := &FROSTDKGParticipantState{
			Seed: seed,
			VSS:  vss,
		}

		state.Zeroize()

		if state.Seed != nil {
			t.Error("Seed should be nil after zeroize")
		}
		if state.VSS != nil {
			t.Error("VSS should be nil after zeroize")
		}
	})

	t.Run("handles_nil_state", func(t *testing.T) {
		var state *FROSTDKGParticipantState
		state.Zeroize() // Should not panic
	})
}

func TestFROSTDKGEncParticipantStateZeroize(t *testing.T) {
	t.Run("zeroizes_host_seckey_and_base_state", func(t *testing.T) {
		hostSeckey := make([]byte, 32)
		_, _ = rand.Read(hostSeckey)
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)

		state := &FROSTDKGEncParticipantState{
			FROSTDKGParticipantState: &FROSTDKGParticipantState{
				Seed: seed,
			},
			HostSeckey: hostSeckey,
		}

		state.Zeroize()

		if state.HostSeckey != nil {
			t.Error("HostSeckey should be nil after zeroize")
		}
		if state.FROSTDKGParticipantState != nil {
			t.Error("FROSTDKGParticipantState should be nil after zeroize")
		}
	})

	t.Run("handles_nil_state", func(t *testing.T) {
		var state *FROSTDKGEncParticipantState
		state.Zeroize() // Should not panic
	})
}

func TestFROSTDKGFullParticipantState1Zeroize(t *testing.T) {
	t.Run("zeroizes_host_seckey_and_enc_state", func(t *testing.T) {
		hostSeckey := make([]byte, 32)
		_, _ = rand.Read(hostSeckey)
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)

		state := &FROSTDKGFullParticipantState1{
			HostSeckey: hostSeckey,
			EncState: &FROSTDKGEncParticipantState{
				FROSTDKGParticipantState: &FROSTDKGParticipantState{
					Seed: seed,
				},
			},
		}

		state.Zeroize()

		if state.HostSeckey != nil {
			t.Error("HostSeckey should be nil after zeroize")
		}
		if state.EncState != nil {
			t.Error("EncState should be nil after zeroize")
		}
	})

	t.Run("handles_nil_state", func(t *testing.T) {
		var state *FROSTDKGFullParticipantState1
		state.Zeroize() // Should not panic
	})
}

func TestFROSTDKGFullParticipantState2Zeroize(t *testing.T) {
	t.Run("zeroizes_output", func(t *testing.T) {
		cs := testCiphersuite()
		grp := cs.Group()
		secretShare, _ := grp.RandomScalar()

		state := &FROSTDKGFullParticipantState2{
			Output: &FROSTDKGOutput{
				SecretShare: secretShare,
			},
			EqInput: []byte{0x04, 0x05},
		}

		state.Zeroize()

		if state.Output != nil {
			t.Error("Output should be nil after zeroize")
		}
	})

	t.Run("handles_nil_state", func(t *testing.T) {
		var state *FROSTDKGFullParticipantState2
		state.Zeroize() // Should not panic
	})
}

func TestFROSTDKGFullCoordinatorStateZeroize(t *testing.T) {
	t.Run("zeroizes_output_and_enc_shares", func(t *testing.T) {
		cs := testCiphersuite()
		grp := cs.Group()
		secretShare, _ := grp.RandomScalar()

		encShares := [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06},
		}

		state := &FROSTDKGFullCoordinatorState{
			Output: &FROSTDKGOutput{
				SecretShare: secretShare,
			},
			EncShares: encShares,
		}

		state.Zeroize()

		if state.Output != nil {
			t.Error("Output should be nil after zeroize")
		}
		if state.EncShares != nil {
			t.Error("EncShares should be nil after zeroize")
		}

		// Verify original slice was zeroed (in-place)
		for i, share := range encShares {
			for j, b := range share {
				if b != 0 {
					t.Errorf("EncShares[%d][%d] should be zeroed", i, j)
				}
			}
		}
	})

	t.Run("handles_nil_state", func(t *testing.T) {
		var state *FROSTDKGFullCoordinatorState
		state.Zeroize() // Should not panic
	})
}

func TestFROSTDKGEncParticipantStateHKZeroize(t *testing.T) {
	t.Run("zeroizes_base_state", func(t *testing.T) {
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)

		state := &FROSTDKGEncParticipantStateHK{
			FROSTDKGParticipantState: &FROSTDKGParticipantState{
				Seed: seed,
			},
		}

		state.Zeroize()

		if state.FROSTDKGParticipantState != nil {
			t.Error("FROSTDKGParticipantState should be nil after zeroize")
		}
		if state.HostKey != nil {
			t.Error("HostKey should be nil after zeroize")
		}
	})

	t.Run("handles_nil_state", func(t *testing.T) {
		var state *FROSTDKGEncParticipantStateHK
		state.Zeroize() // Should not panic
	})
}

func TestFROSTDKGFullParticipantStateHK1Zeroize(t *testing.T) {
	t.Run("zeroizes_enc_state", func(t *testing.T) {
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)

		state := &FROSTDKGFullParticipantStateHK1{
			EncState: &FROSTDKGEncParticipantStateHK{
				FROSTDKGParticipantState: &FROSTDKGParticipantState{
					Seed: seed,
				},
			},
		}

		state.Zeroize()

		if state.EncState != nil {
			t.Error("EncState should be nil after zeroize")
		}
		if state.HostKey != nil {
			t.Error("HostKey should be nil after zeroize")
		}
	})

	t.Run("handles_nil_state", func(t *testing.T) {
		var state *FROSTDKGFullParticipantStateHK1
		state.Zeroize() // Should not panic
	})
}

func TestFROSTDKGFullParticipantStateHK2Zeroize(t *testing.T) {
	t.Run("zeroizes_output", func(t *testing.T) {
		cs := testCiphersuite()
		grp := cs.Group()
		secretShare, _ := grp.RandomScalar()

		state := &FROSTDKGFullParticipantStateHK2{
			Output: &FROSTDKGOutput{
				SecretShare: secretShare,
			},
		}

		state.Zeroize()

		if state.Output != nil {
			t.Error("Output should be nil after zeroize")
		}
		if state.HostKey != nil {
			t.Error("HostKey should be nil after zeroize")
		}
	})

	t.Run("handles_nil_state", func(t *testing.T) {
		var state *FROSTDKGFullParticipantStateHK2
		state.Zeroize() // Should not panic
	})
}

func TestFROSTDKGFullCoordinatorStateHKZeroize(t *testing.T) {
	t.Run("zeroizes_output_and_enc_shares", func(t *testing.T) {
		cs := testCiphersuite()
		grp := cs.Group()
		secretShare, _ := grp.RandomScalar()

		encShares := [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06},
		}

		state := &FROSTDKGFullCoordinatorStateHK{
			Output: &FROSTDKGOutput{
				SecretShare: secretShare,
			},
			EncShares: encShares,
		}

		state.Zeroize()

		if state.Output != nil {
			t.Error("Output should be nil after zeroize")
		}
		if state.EncShares != nil {
			t.Error("EncShares should be nil after zeroize")
		}

		// Verify original slice was zeroed (in-place)
		for i, share := range encShares {
			for j, b := range share {
				if b != 0 {
					t.Errorf("EncShares[%d][%d] should be zeroed", i, j)
				}
			}
		}
	})

	t.Run("handles_nil_state", func(t *testing.T) {
		var state *FROSTDKGFullCoordinatorStateHK
		state.Zeroize() // Should not panic
	})
}

func BenchmarkZeroBytes(b *testing.B) {
	data := make([]byte, 32) // Typical scalar size

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Refill with non-zero data
		for j := range data {
			data[j] = byte(i + j)
		}
		ZeroBytes(data)
	}
}
