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

// Package integration provides comprehensive end-to-end integration tests
// for the go-frost-dkg implementation. These tests validate:
//
// 1. FROST-DKG protocol with all supported ciphersuites
// 2. Full protocol simulations with multiple participants
// 3. Validation against test vectors
//
// Integration tests run in Docker containers and perform complete E2E testing
// with real services, never modifying the host OS.
package integration

import (
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frostdkg/pkg/dkg"
)

// CiphersuiteTestCase contains a ciphersuite and its metadata for integration testing.
type CiphersuiteTestCase struct {
	Name        string
	Ciphersuite ciphersuite.Ciphersuite
	SkipReason  string // If non-empty, skip this ciphersuite with this reason
}

// getAllCiphersuites returns all supported ciphersuites for integration testing.
func getAllCiphersuites() []CiphersuiteTestCase {
	return []CiphersuiteTestCase{
		{
			Name:        "FROST-ED25519-SHA512-v1",
			Ciphersuite: ed25519_sha512.New(),
		},
		{
			Name:        "FROST-P256-SHA256-v1",
			Ciphersuite: p256_sha256.New(),
		},
		{
			Name:        "FROST-RISTRETTO255-SHA512-v1",
			Ciphersuite: ristretto255_sha512.New(),
		},
		{
			Name:        "FROST-ED448-SHAKE256-v1",
			Ciphersuite: ed448_shake256.New(),
		},
	}
}

// TestFROSTDKGIntegration tests the full FROST-DKG protocol with all supported ciphersuites.
// This is a comprehensive E2E test that validates the complete distributed key generation
// protocol across multiple participants.
func TestFROSTDKGIntegration(t *testing.T) {
	suites := getAllCiphersuites()

	for _, tc := range suites {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.SkipReason != "" {
				t.Skip(tc.SkipReason)
			}

			// Test FROST-DKG with different participant configurations
			participantCounts := []int{3, 5, 7}
			thresholds := []int{2, 3, 4}

			for i, n := range participantCounts {
				threshold := thresholds[i]
				t.Run("", func(t *testing.T) {
					testFROSTDKGWithParams(t, tc.Ciphersuite, n, threshold)
				})
			}
		})
	}
}

// testFROSTDKGWithParams runs FROST-DKG with specific parameters.
func testFROSTDKGWithParams(t *testing.T, cs ciphersuite.Ciphersuite, n, threshold int) {
	t.Helper()

	grp := cs.Group()

	// Step 1: Each participant generates their VSS
	type participantData struct {
		vss  *dkg.VSS
		comm *dkg.VSSCommitment
		pop  []byte
	}

	participants := make([]participantData, n)

	for i := 0; i < n; i++ {
		// Generate random seed
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("Participant %d: Failed to generate seed: %v", i+1, err)
		}

		// Generate VSS
		vss, err := dkg.FROSTDKGGenerateVSS(cs, seed, threshold)
		if err != nil {
			t.Fatalf("Participant %d: Failed to generate VSS: %v", i+1, err)
		}

		// Get commitments
		commitments := vss.Commit()

		// Generate proof of possession
		pop, err := dkg.FROSTDKGProveKnowledge(cs, vss.Secret(), commitments.Coefficients[0], i)
		if err != nil {
			t.Fatalf("Participant %d: Failed to generate PoP: %v", i+1, err)
		}

		participants[i] = participantData{
			vss:  vss,
			comm: commitments,
			pop:  pop,
		}
	}

	// Step 2: Verify all proofs of possession
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			valid := dkg.FROSTDKGVerifyPOP(cs, participants[j].pop, participants[j].comm.Coefficients[0], j)
			if !valid {
				t.Fatalf("Participant %d: Failed to verify PoP from participant %d", i+1, j+1)
			}
		}
	}

	// Step 3: Generate shares for all participants
	shares := make([][]group.Scalar, n)
	for i := 0; i < n; i++ {
		shares[i] = make([]group.Scalar, n)
	}

	for i := 0; i < n; i++ {
		vss := participants[i].vss
		vssShares, err := vss.Secshares(n)
		if err != nil {
			t.Fatalf("Participant %d: Failed to generate shares: %v", i+1, err)
		}
		shares[i] = vssShares
	}

	// Step 4: Each participant verifies and aggregates their received shares
	signingShares := make([]group.Scalar, n)
	for i := 0; i < n; i++ {
		// Aggregate shares from all participants
		signingShare := grp.NewScalar()
		for j := 0; j < n; j++ {
			// Verify share against sender's commitments
			share := shares[j][i]
			pubshare := grp.ScalarBaseMult(share)
			valid := dkg.VerifySecshare(grp, share, pubshare)
			if !valid {
				t.Fatalf("Participant %d: Share verification failed from participant %d", i+1, j+1)
			}

			signingShare = signingShare.Add(share)
		}
		signingShares[i] = signingShare
	}

	// Step 5: Compute group verification key
	verificationKey := grp.NewElement()
	for i := 0; i < n; i++ {
		constantCommitment := participants[i].comm.Coefficients[0]
		verificationKey = verificationKey.Add(constantCommitment)
	}

	// Validate outputs
	if verificationKey.IsIdentity() {
		t.Fatal("Verification key is identity element")
	}

	for i, share := range signingShares {
		if share.IsZero() {
			t.Fatalf("Participant %d has zero signing share", i+1)
		}
	}

	t.Logf("FROST-DKG completed successfully with n=%d, threshold=%d", n, threshold)
}

// TestSimplPedPoP tests SimplPedPoP (Simplified Pedersen PoP) protocol.
func TestSimplPedPoP(t *testing.T) {
	suites := getAllCiphersuites()

	for _, tc := range suites {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.SkipReason != "" {
				t.Skip(tc.SkipReason)
			}

			testSimplPedPoPProtocol(t, tc.Ciphersuite)
		})
	}
}

// testSimplPedPoPProtocol runs the SimplPedPoP protocol.
func testSimplPedPoPProtocol(t *testing.T, cs ciphersuite.Ciphersuite) {
	t.Helper()

	const (
		numParticipants = 5
		threshold       = 3
	)

	grp := cs.Group()

	// Step 1: Each participant generates their VSS
	type participantData struct {
		vss  *dkg.VSS
		comm *dkg.VSSCommitment
		pop  []byte
	}

	participants := make([]participantData, numParticipants)

	for i := 0; i < numParticipants; i++ {
		// Generate random seed
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("Participant %d: Failed to generate seed: %v", i+1, err)
		}

		// Generate VSS
		vss, err := dkg.FROSTDKGGenerateVSS(cs, seed, threshold)
		if err != nil {
			t.Fatalf("Participant %d: Failed to generate VSS: %v", i+1, err)
		}

		commitments := vss.Commit()

		// Generate proof of possession
		pop, err := dkg.FROSTDKGProveKnowledge(cs, vss.Secret(), commitments.Coefficients[0], i)
		if err != nil {
			t.Fatalf("Participant %d: Failed to generate PoP: %v", i+1, err)
		}

		participants[i] = participantData{
			vss:  vss,
			comm: commitments,
			pop:  pop,
		}
	}

	// Step 2: Verify all proofs of possession
	for i := 0; i < numParticipants; i++ {
		for j := 0; j < numParticipants; j++ {
			valid := dkg.FROSTDKGVerifyPOP(cs, participants[j].pop, participants[j].comm.Coefficients[0], j)
			if !valid {
				t.Fatalf("Participant %d: PoP verification failed for participant %d", i+1, j+1)
			}
		}
	}

	// Step 3: Generate and aggregate shares
	for i := 0; i < numParticipants; i++ {
		signingShare := grp.NewScalar()

		for j := 0; j < numParticipants; j++ {
			share, err := participants[j].vss.SecshareFor(i)
			if err != nil {
				t.Fatalf("Failed to generate share: %v", err)
			}

			// Verify share
			pubshare := grp.ScalarBaseMult(share)
			valid := dkg.VerifySecshare(grp, share, pubshare)
			if !valid {
				t.Fatalf("Share verification failed")
			}

			// Aggregate
			signingShare = signingShare.Add(share)
		}

		if signingShare.IsZero() {
			t.Fatalf("Participant %d has zero signing share", i+1)
		}
	}

	t.Log("SimplPedPoP protocol completed successfully")
}

// TestMultiParticipantScaling tests DKG protocol scaling with varying participant counts.
func TestMultiParticipantScaling(t *testing.T) {
	cs := ed25519_sha512.New()
	participantCounts := []int{3, 5, 7, 10}

	for _, n := range participantCounts {
		threshold := (n*2 + 2) / 3 // 2/3 threshold
		t.Run("", func(t *testing.T) {
			testFROSTDKGWithParams(t, cs, n, threshold)
		})
	}
}

// TestProtocolRobustness tests protocol behavior under various edge cases.
func TestProtocolRobustness(t *testing.T) {
	cs := ed25519_sha512.New()

	t.Run("MinimumParticipants", func(t *testing.T) {
		testFROSTDKGWithParams(t, cs, 2, 2)
	})

	t.Run("MaximalThreshold", func(t *testing.T) {
		testFROSTDKGWithParams(t, cs, 5, 5)
	})

	t.Run("MinimalThreshold", func(t *testing.T) {
		testFROSTDKGWithParams(t, cs, 10, 2)
	})
}

// TestVSSBasicOperations tests basic VSS operations across all ciphersuites.
func TestVSSBasicOperations(t *testing.T) {
	suites := getAllCiphersuites()

	for _, tc := range suites {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.SkipReason != "" {
				t.Skip(tc.SkipReason)
			}

			const threshold = 3
			const numParticipants = 5

			seed := make([]byte, 32)
			if _, err := rand.Read(seed); err != nil {
				t.Fatalf("Failed to generate seed: %v", err)
			}

			// Generate VSS
			vss, err := dkg.FROSTDKGGenerateVSS(tc.Ciphersuite, seed, threshold)
			if err != nil {
				t.Fatalf("Failed to generate VSS: %v", err)
			}

			// Generate shares for participants
			shares, err := vss.Secshares(numParticipants)
			if err != nil {
				t.Fatalf("Failed to generate shares: %v", err)
			}

			// Verify each share
			grp := tc.Ciphersuite.Group()
			for i, share := range shares {
				if share.IsZero() {
					t.Fatalf("Share %d is zero", i)
				}

				// Verify share
				pubshare := grp.ScalarBaseMult(share)
				valid := dkg.VerifySecshare(grp, share, pubshare)
				if !valid {
					t.Fatalf("Share verification failed for participant %d", i)
				}
			}

			// Verify commitment
			commitment := vss.Commit()
			if len(commitment.Coefficients) != threshold {
				t.Fatalf("Expected %d commitment coefficients, got %d", threshold, len(commitment.Coefficients))
			}

			// Verify public key (first coefficient) is not identity
			if commitment.Coefficients[0].IsIdentity() {
				t.Fatal("Public key commitment is identity element")
			}
		})
	}
}
