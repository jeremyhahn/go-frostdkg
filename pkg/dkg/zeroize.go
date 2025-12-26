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
)

// ZeroBytes securely zeros a byte slice.
// This is aligned with Zcash FROST's Zeroize trait pattern.
// The function uses crypto/subtle to prevent compiler optimizations
// from removing the zeroing operation.
func ZeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use ConstantTimeCopy to zero the slice in a way that
	// the compiler cannot optimize away
	zeros := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zeros)
}

// ZeroSlices securely zeros multiple byte slices.
func ZeroSlices(slices ...[]byte) {
	for _, s := range slices {
		ZeroBytes(s)
	}
}

// SecretPackage wraps sensitive data and provides secure cleanup.
// This is similar to Zcash FROST's SecretPackage with ZeroizeOnDrop.
type SecretPackage struct {
	// Coefficients are the secret polynomial coefficients
	Coefficients [][]byte
	// SecretShare is the participant's secret signing share
	SecretShare []byte
	// Seed is the initial random seed
	Seed []byte
}

// Zeroize securely clears all secret data in the package.
// Call this when done using the secret package to prevent
// secrets from remaining in memory.
func (sp *SecretPackage) Zeroize() {
	if sp == nil {
		return
	}
	for _, coeff := range sp.Coefficients {
		ZeroBytes(coeff)
	}
	ZeroBytes(sp.SecretShare)
	ZeroBytes(sp.Seed)
}

// SecureScalar wraps a scalar byte representation with secure cleanup.
type SecureScalar struct {
	data []byte
}

// NewSecureScalar creates a new SecureScalar from bytes.
func NewSecureScalar(data []byte) *SecureScalar {
	copied := make([]byte, len(data))
	copy(copied, data)
	return &SecureScalar{data: copied}
}

// Bytes returns the scalar data.
func (s *SecureScalar) Bytes() []byte {
	return s.data
}

// Zeroize securely clears the scalar data.
func (s *SecureScalar) Zeroize() {
	if s != nil {
		ZeroBytes(s.data)
	}
}
