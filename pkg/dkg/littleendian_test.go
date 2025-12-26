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

// TestScalarFromIntLittleEndian tests the LittleEndian branch of scalarFromInt
// by using the Ed25519 ciphersuite which uses little-endian byte order.
func TestScalarFromIntLittleEndian(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Verify we're using a LittleEndian group
	if grp.ByteOrder() != group.LittleEndian {
		t.Fatal("Expected LittleEndian byte order for Ed25519")
	}

	tests := []struct {
		name  string
		value int
	}{
		{"zero", 0},
		{"one", 1},
		{"small", 42},
		{"max byte", 255},
		{"two bytes", 256},
		{"max uint16", 65535},
		{"three bytes", 65536},
		{"max uint24", 16777215},
		{"large value", 123456789},
		{"max int24", 0xFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scalar := scalarFromInt(grp, tt.value)
			if scalar == nil {
				t.Error("Expected non-nil scalar")
			}

			if tt.value == 0 && !scalar.IsZero() {
				t.Error("Expected zero scalar for value 0")
			}

			if tt.value != 0 && scalar.IsZero() {
				t.Error("Expected non-zero scalar for non-zero value")
			}
		})
	}
}

// TestMultiGroupScalarFromInt tests scalarFromInt with both big-endian and little-endian groups.
func TestMultiGroupScalarFromInt(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	// Test values that require multiple bytes to exercise the loop
	multiByteValues := []int{
		0x0100,     // 256 - requires 2 bytes
		0x010000,   // 65536 - requires 3 bytes
		0x01000000, // 16777216 - requires 4 bytes
	}

	for _, val := range multiByteValues {
		scalar := scalarFromInt(grp, val)
		if scalar == nil {
			t.Errorf("scalarFromInt(%d) returned nil", val)
		}
		if scalar.IsZero() {
			t.Errorf("scalarFromInt(%d) returned zero scalar", val)
		}
	}
}
