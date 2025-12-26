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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestFROSTDKGGenerateVSSComprehensive provides comprehensive test coverage for FROSTDKGGenerateVSS.
// This test ensures the function handles all edge cases and works correctly with all ciphersuites.
func TestFROSTDKGGenerateVSSComprehensive(t *testing.T) {
	t.Run("valid seed with all ciphersuites", func(t *testing.T) {
		testCases := []struct {
			name string
			cs   ciphersuite.Ciphersuite
		}{
			{"Ed25519", ed25519_sha512.New()},
			{"Ed448", ed448_shake256.New()},
			{"P256", p256_sha256.New()},
			{"Ristretto255", ristretto255_sha512.New()},
			{"Secp256k1", secp256k1_sha256.New()},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				seed := make([]byte, 32)
				if _, err := rand.Read(seed); err != nil {
					t.Fatalf("rand.Read failed: %v", err)
				}

				threshold := 3
				vss, err := FROSTDKGGenerateVSS(tc.cs, seed, threshold)
				if err != nil {
					t.Fatalf("FROSTDKGGenerateVSS failed: %v", err)
				}

				if vss == nil {
					t.Fatal("FROSTDKGGenerateVSS returned nil VSS")
				}

				// Verify the polynomial has the correct degree
				commitment := vss.Commit()
				if len(commitment.Coefficients) != threshold {
					t.Errorf("Expected %d coefficients, got %d", threshold, len(commitment.Coefficients))
				}

				// Verify we can generate shares
				share, err := vss.SecshareFor(0)
				if err != nil {
					t.Fatalf("SecshareFor failed: %v", err)
				}

				if share == nil || share.IsZero() {
					t.Error("Expected non-zero share")
				}

				// Verify share verification works
				pubshare, err := commitment.Pubshare(tc.cs.Group(), 0)
				if err != nil {
					t.Fatalf("Pubshare failed: %v", err)
				}

				if !VerifySecshare(tc.cs.Group(), share, pubshare) {
					t.Error("Share verification failed")
				}
			})
		}
	})

	t.Run("zero threshold", func(t *testing.T) {
		cs := ed25519_sha512.New()
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		vss, err := FROSTDKGGenerateVSS(cs, seed, 0)
		if err != ErrFROSTDKGInvalidThreshold {
			t.Errorf("Expected ErrFROSTDKGInvalidThreshold, got: %v", err)
		}

		if vss != nil {
			t.Error("Expected nil VSS for zero threshold")
		}
	})

	t.Run("negative threshold", func(t *testing.T) {
		cs := ed25519_sha512.New()
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		negativeThresholds := []int{-1, -10, -100, -1000}

		for _, threshold := range negativeThresholds {
			t.Run("threshold", func(t *testing.T) {
				vss, err := FROSTDKGGenerateVSS(cs, seed, threshold)
				if err != ErrFROSTDKGInvalidThreshold {
					t.Errorf("Expected ErrFROSTDKGInvalidThreshold for threshold %d, got: %v", threshold, err)
				}

				if vss != nil {
					t.Errorf("Expected nil VSS for negative threshold %d", threshold)
				}
			})
		}
	})

	t.Run("empty seed", func(t *testing.T) {
		cs := ed25519_sha512.New()
		seed := []byte{}
		threshold := 3

		vss, err := FROSTDKGGenerateVSS(cs, seed, threshold)
		if err != nil {
			t.Fatalf("FROSTDKGGenerateVSS with empty seed failed: %v", err)
		}

		if vss == nil {
			t.Fatal("FROSTDKGGenerateVSS returned nil VSS for empty seed")
		}

		// Verify the polynomial has the correct degree
		commitment := vss.Commit()
		if len(commitment.Coefficients) != threshold {
			t.Errorf("Expected %d coefficients, got %d", threshold, len(commitment.Coefficients))
		}

		// Verify we can generate shares even with empty seed
		share, err := vss.SecshareFor(0)
		if err != nil {
			t.Fatalf("SecshareFor failed: %v", err)
		}

		if share == nil || share.IsZero() {
			t.Error("Expected non-zero share even with empty seed")
		}
	})

	t.Run("nil seed", func(t *testing.T) {
		cs := ed25519_sha512.New()
		threshold := 3

		// nil seed should be handled gracefully (treated as empty seed)
		vss, err := FROSTDKGGenerateVSS(cs, nil, threshold)
		if err != nil {
			t.Fatalf("FROSTDKGGenerateVSS with nil seed failed: %v", err)
		}

		if vss == nil {
			t.Fatal("FROSTDKGGenerateVSS returned nil VSS for nil seed")
		}

		// Verify the polynomial has the correct degree
		commitment := vss.Commit()
		if len(commitment.Coefficients) != threshold {
			t.Errorf("Expected %d coefficients, got %d", threshold, len(commitment.Coefficients))
		}

		// Verify we can generate shares
		share, err := vss.SecshareFor(0)
		if err != nil {
			t.Fatalf("SecshareFor failed: %v", err)
		}

		if share == nil || share.IsZero() {
			t.Error("Expected non-zero share even with nil seed")
		}
	})

	t.Run("very large threshold", func(t *testing.T) {
		cs := ed25519_sha512.New()
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		largeThresholds := []int{100, 500, 1000}

		for _, threshold := range largeThresholds {
			t.Run("threshold", func(t *testing.T) {
				vss, err := FROSTDKGGenerateVSS(cs, seed, threshold)
				if err != nil {
					t.Fatalf("FROSTDKGGenerateVSS with threshold %d failed: %v", threshold, err)
				}

				if vss == nil {
					t.Fatalf("FROSTDKGGenerateVSS returned nil VSS for threshold %d", threshold)
				}

				// Verify the polynomial has the correct degree
				commitment := vss.Commit()
				if len(commitment.Coefficients) != threshold {
					t.Errorf("Expected %d coefficients, got %d", threshold, len(commitment.Coefficients))
				}

				// Verify we can generate shares
				share, err := vss.SecshareFor(0)
				if err != nil {
					t.Fatalf("SecshareFor failed: %v", err)
				}

				if share == nil || share.IsZero() {
					t.Errorf("Expected non-zero share for large threshold %d", threshold)
				}

				// Verify share verification works
				pubshare, err := commitment.Pubshare(cs.Group(), 0)
				if err != nil {
					t.Fatalf("Pubshare failed: %v", err)
				}

				if !VerifySecshare(cs.Group(), share, pubshare) {
					t.Errorf("Share verification failed for threshold %d", threshold)
				}
			})
		}
	})

	t.Run("deterministic generation with same seed", func(t *testing.T) {
		cs := ed25519_sha512.New()
		seed := make([]byte, 32)
		for i := range seed {
			seed[i] = byte(i)
		}
		threshold := 3

		// Generate twice with the same seed
		vss1, err := FROSTDKGGenerateVSS(cs, seed, threshold)
		if err != nil {
			t.Fatalf("First FROSTDKGGenerateVSS failed: %v", err)
		}

		vss2, err := FROSTDKGGenerateVSS(cs, seed, threshold)
		if err != nil {
			t.Fatalf("Second FROSTDKGGenerateVSS failed: %v", err)
		}

		// Verify the shares are identical (deterministic)
		share1, err := vss1.SecshareFor(0)
		if err != nil {
			t.Fatalf("First SecshareFor failed: %v", err)
		}

		share2, err := vss2.SecshareFor(0)
		if err != nil {
			t.Fatalf("Second SecshareFor failed: %v", err)
		}

		if !share1.Equal(share2) {
			t.Error("Expected identical shares for same seed (deterministic generation)")
		}

		// Verify commitments are identical
		commitment1 := vss1.Commit()
		commitment2 := vss2.Commit()

		for i := range commitment1.Coefficients {
			if !commitment1.Coefficients[i].Equal(commitment2.Coefficients[i]) {
				t.Errorf("Coefficient %d differs between identical seeds", i)
			}
		}
	})

	t.Run("different seeds produce different VSS", func(t *testing.T) {
		cs := ed25519_sha512.New()
		threshold := 3

		seed1 := make([]byte, 32)
		seed2 := make([]byte, 32)

		for i := range seed1 {
			seed1[i] = byte(i)
			seed2[i] = byte(i + 1)
		}

		vss1, err := FROSTDKGGenerateVSS(cs, seed1, threshold)
		if err != nil {
			t.Fatalf("FROSTDKGGenerateVSS with seed1 failed: %v", err)
		}

		vss2, err := FROSTDKGGenerateVSS(cs, seed2, threshold)
		if err != nil {
			t.Fatalf("FROSTDKGGenerateVSS with seed2 failed: %v", err)
		}

		// Verify the shares are different
		share1, err := vss1.SecshareFor(0)
		if err != nil {
			t.Fatalf("SecshareFor from vss1 failed: %v", err)
		}

		share2, err := vss2.SecshareFor(0)
		if err != nil {
			t.Fatalf("SecshareFor from vss2 failed: %v", err)
		}

		if share1.Equal(share2) {
			t.Error("Different seeds should produce different shares")
		}

		// Verify commitments are different
		commitment1 := vss1.Commit()
		commitment2 := vss2.Commit()

		allEqual := true
		for i := range commitment1.Coefficients {
			if !commitment1.Coefficients[i].Equal(commitment2.Coefficients[i]) {
				allEqual = false
				break
			}
		}

		if allEqual {
			t.Error("Different seeds should produce different commitments")
		}
	})

	t.Run("various threshold values", func(t *testing.T) {
		cs := ed25519_sha512.New()
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		validThresholds := []int{1, 2, 5, 10, 20, 50}

		for _, threshold := range validThresholds {
			t.Run("threshold", func(t *testing.T) {
				vss, err := FROSTDKGGenerateVSS(cs, seed, threshold)
				if err != nil {
					t.Fatalf("FROSTDKGGenerateVSS with threshold %d failed: %v", threshold, err)
				}

				commitment := vss.Commit()
				if len(commitment.Coefficients) != threshold {
					t.Errorf("Expected %d coefficients, got %d", threshold, len(commitment.Coefficients))
				}

				// Verify shares work
				numShares := threshold + 5
				shares, err := vss.Secshares(numShares)
				if err != nil {
					t.Fatalf("Secshares failed: %v", err)
				}

				if len(shares) != numShares {
					t.Errorf("Expected %d shares, got %d", numShares, len(shares))
				}

				// Verify all shares are valid
				for i := 0; i < numShares; i++ {
					if shares[i] == nil || shares[i].IsZero() {
						t.Errorf("Share %d is invalid", i)
						continue
					}

					pubshare, err := commitment.Pubshare(cs.Group(), i)
					if err != nil {
						t.Errorf("Pubshare(%d) failed: %v", i, err)
						continue
					}

					if !VerifySecshare(cs.Group(), shares[i], pubshare) {
						t.Errorf("Share %d failed verification", i)
					}
				}
			})
		}
	})

	t.Run("large seed variations", func(t *testing.T) {
		cs := ed25519_sha512.New()
		threshold := 3

		seedSizes := []int{1, 16, 32, 64, 128, 256, 512, 1024}

		for _, size := range seedSizes {
			t.Run("seed_size", func(t *testing.T) {
				seed := make([]byte, size)
				if _, err := rand.Read(seed); err != nil {
					t.Fatalf("rand.Read failed: %v", err)
				}

				vss, err := FROSTDKGGenerateVSS(cs, seed, threshold)
				if err != nil {
					t.Fatalf("FROSTDKGGenerateVSS with seed size %d failed: %v", size, err)
				}

				if vss == nil {
					t.Fatalf("FROSTDKGGenerateVSS returned nil VSS for seed size %d", size)
				}

				// Verify we can generate shares
				share, err := vss.SecshareFor(0)
				if err != nil {
					t.Fatalf("SecshareFor failed for seed size %d: %v", size, err)
				}

				if share == nil || share.IsZero() {
					t.Errorf("Expected non-zero share for seed size %d", size)
				}
			})
		}
	})

	t.Run("coefficient uniqueness", func(t *testing.T) {
		cs := ed25519_sha512.New()
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		threshold := 10
		vss, err := FROSTDKGGenerateVSS(cs, seed, threshold)
		if err != nil {
			t.Fatalf("FROSTDKGGenerateVSS failed: %v", err)
		}

		commitment := vss.Commit()

		// Check that all coefficients are unique (extremely high probability)
		for i := 0; i < len(commitment.Coefficients); i++ {
			for j := i + 1; j < len(commitment.Coefficients); j++ {
				if commitment.Coefficients[i].Equal(commitment.Coefficients[j]) {
					t.Errorf("Coefficients %d and %d are equal (should be unique)", i, j)
				}
			}
		}
	})

	t.Run("threshold degree validation", func(t *testing.T) {
		// Verify that the same seed with different thresholds produces different polynomials
		cs := ed25519_sha512.New()
		seed := make([]byte, 32)
		for i := range seed {
			seed[i] = 0x42
		}

		vss1, err := FROSTDKGGenerateVSS(cs, seed, 2)
		if err != nil {
			t.Fatalf("FROSTDKGGenerateVSS with threshold 2 failed: %v", err)
		}

		vss2, err := FROSTDKGGenerateVSS(cs, seed, 3)
		if err != nil {
			t.Fatalf("FROSTDKGGenerateVSS with threshold 3 failed: %v", err)
		}

		commitment1 := vss1.Commit()
		commitment2 := vss2.Commit()

		// Different thresholds should produce different polynomial degrees
		if len(commitment1.Coefficients) == len(commitment2.Coefficients) {
			t.Error("Different thresholds should produce different polynomial degrees")
		}

		// Verify the degrees match the thresholds
		if len(commitment1.Coefficients) != 2 {
			t.Errorf("Expected 2 coefficients for threshold 2, got %d", len(commitment1.Coefficients))
		}

		if len(commitment2.Coefficients) != 3 {
			t.Errorf("Expected 3 coefficients for threshold 3, got %d", len(commitment2.Coefficients))
		}
	})
}

// mockHostKeyECDHError is a mock HostKey that returns an error on ECDH.
type mockHostKeyECDHError struct {
	pubkey []byte
	err    error
}

func (m *mockHostKeyECDHError) ECDH(theirPubkey []byte) ([]byte, error) {
	return nil, m.err
}

func (m *mockHostKeyECDHError) Sign(message []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHostKeyECDHError) PublicKey() []byte {
	return m.pubkey
}

// TestFrostDKGECDHWithHostKeyComprehensive tests frostDKGECDHWithHostKey for all ciphersuites
// and covers all error paths.
func TestFrostDKGECDHWithHostKeyComprehensive(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grp := tc.cs.Group()

			// Generate host keys for Alice and Bob
			alice, err := GenerateSoftwareHostKey(tc.cs)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKey alice failed: %v", err)
			}

			bob, err := GenerateSoftwareHostKey(tc.cs)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKey bob failed: %v", err)
			}

			// Generate nonces for both parties
			aliceNonce, _ := grp.RandomScalar()
			aliceNonceElement := grp.ScalarBaseMult(aliceNonce)

			bobNonce, _ := grp.RandomScalar()
			bobNonceElement := grp.ScalarBaseMult(bobNonce)

			// Test 1: Valid ECDH with encrypt=true
			t.Run("encrypt_true", func(t *testing.T) {
				alicePad, err := frostDKGECDHWithHostKey(
					tc.cs,
					alice,
					aliceNonceElement,
					bob.PublicKey(),
					bobNonceElement,
					true, // encrypt
				)
				if err != nil {
					t.Fatalf("frostDKGECDHWithHostKey encrypt=true failed: %v", err)
				}

				if len(alicePad) == 0 {
					t.Error("Expected non-empty pad from encrypt=true")
				}

				// Bob should be able to decrypt using encrypt=false
				bobPad, err := frostDKGECDHWithHostKey(
					tc.cs,
					bob,
					bobNonceElement,
					alice.PublicKey(),
					aliceNonceElement,
					false, // decrypt
				)
				if err != nil {
					t.Fatalf("frostDKGECDHWithHostKey encrypt=false failed: %v", err)
				}

				// Pads should be identical for encryption/decryption
				if !bytes.Equal(alicePad, bobPad) {
					t.Error("Encrypt and decrypt pads do not match")
				}
			})

			// Test 2: Valid ECDH with encrypt=false
			t.Run("encrypt_false", func(t *testing.T) {
				pad, err := frostDKGECDHWithHostKey(
					tc.cs,
					alice,
					aliceNonceElement,
					bob.PublicKey(),
					bobNonceElement,
					false, // decrypt
				)
				if err != nil {
					t.Fatalf("frostDKGECDHWithHostKey encrypt=false failed: %v", err)
				}

				if len(pad) == 0 {
					t.Error("Expected non-empty pad from encrypt=false")
				}
			})

			// Test 3: Invalid theirPubkey causing ECDH error (error path line 1203-1205)
			t.Run("ecdh_error_invalid_pubkey", func(t *testing.T) {
				invalidPubkey := []byte{0x01, 0x02, 0x03} // Invalid public key

				_, err := frostDKGECDHWithHostKey(
					tc.cs,
					alice,
					aliceNonceElement,
					invalidPubkey,
					bobNonceElement,
					true,
				)
				if err == nil {
					t.Error("Expected error for invalid public key")
				}
			})

			// Test 4: HostKey.ECDH returns error (error path line 1203-1205)
			t.Run("ecdh_error_mock", func(t *testing.T) {
				expectedErr := errors.New("mock ECDH failure")
				mockKey := &mockHostKeyECDHError{
					pubkey: alice.PublicKey(),
					err:    expectedErr,
				}

				_, err := frostDKGECDHWithHostKey(
					tc.cs,
					mockKey,
					aliceNonceElement,
					bob.PublicKey(),
					bobNonceElement,
					true,
				)
				if err == nil {
					t.Error("Expected error from mock HostKey.ECDH")
				}
				if !errors.Is(err, expectedErr) {
					t.Errorf("Expected error %v, got %v", expectedErr, err)
				}
			})

			// Test 5: Verify that encrypt and decrypt produce same pad (symmetry test)
			t.Run("symmetry", func(t *testing.T) {
				// Alice encrypts
				padAliceEncrypt, err := frostDKGECDHWithHostKey(
					tc.cs,
					alice,
					aliceNonceElement,
					bob.PublicKey(),
					bobNonceElement,
					true,
				)
				if err != nil {
					t.Fatalf("Alice encrypt failed: %v", err)
				}

				// Bob decrypts
				padBobDecrypt, err := frostDKGECDHWithHostKey(
					tc.cs,
					bob,
					bobNonceElement,
					alice.PublicKey(),
					aliceNonceElement,
					false,
				)
				if err != nil {
					t.Fatalf("Bob decrypt failed: %v", err)
				}

				// Should produce same pad
				if !bytes.Equal(padAliceEncrypt, padBobDecrypt) {
					t.Error("Encrypt/decrypt symmetry broken")
				}

				// Bob encrypts
				padBobEncrypt, err := frostDKGECDHWithHostKey(
					tc.cs,
					bob,
					bobNonceElement,
					alice.PublicKey(),
					aliceNonceElement,
					true,
				)
				if err != nil {
					t.Fatalf("Bob encrypt failed: %v", err)
				}

				// Alice decrypts
				padAliceDecrypt, err := frostDKGECDHWithHostKey(
					tc.cs,
					alice,
					aliceNonceElement,
					bob.PublicKey(),
					bobNonceElement,
					false,
				)
				if err != nil {
					t.Fatalf("Alice decrypt failed: %v", err)
				}

				// Should produce same pad
				if !bytes.Equal(padBobEncrypt, padAliceDecrypt) {
					t.Error("Encrypt/decrypt symmetry broken (reversed)")
				}
			})

			// Test 6: Different nonces produce different pads
			t.Run("different_nonces", func(t *testing.T) {
				// Generate different nonce
				aliceNonce2, _ := grp.RandomScalar()
				aliceNonceElement2 := grp.ScalarBaseMult(aliceNonce2)

				pad1, err := frostDKGECDHWithHostKey(
					tc.cs,
					alice,
					aliceNonceElement,
					bob.PublicKey(),
					bobNonceElement,
					true,
				)
				if err != nil {
					t.Fatalf("First pad generation failed: %v", err)
				}

				pad2, err := frostDKGECDHWithHostKey(
					tc.cs,
					alice,
					aliceNonceElement2,
					bob.PublicKey(),
					bobNonceElement,
					true,
				)
				if err != nil {
					t.Fatalf("Second pad generation failed: %v", err)
				}

				// Different nonces should produce different pads
				if bytes.Equal(pad1, pad2) {
					t.Error("Different nonces produced identical pads")
				}
			})

			// Test 7: Different peer keys produce different pads
			t.Run("different_peer_keys", func(t *testing.T) {
				charlie, err := GenerateSoftwareHostKey(tc.cs)
				if err != nil {
					t.Fatalf("GenerateSoftwareHostKey charlie failed: %v", err)
				}

				padWithBob, err := frostDKGECDHWithHostKey(
					tc.cs,
					alice,
					aliceNonceElement,
					bob.PublicKey(),
					bobNonceElement,
					true,
				)
				if err != nil {
					t.Fatalf("Pad with Bob failed: %v", err)
				}

				charlieNonce, _ := grp.RandomScalar()
				charlieNonceElement := grp.ScalarBaseMult(charlieNonce)

				padWithCharlie, err := frostDKGECDHWithHostKey(
					tc.cs,
					alice,
					aliceNonceElement,
					charlie.PublicKey(),
					charlieNonceElement,
					true,
				)
				if err != nil {
					t.Fatalf("Pad with Charlie failed: %v", err)
				}

				// Different peer keys should produce different pads
				if bytes.Equal(padWithBob, padWithCharlie) {
					t.Error("Different peer keys produced identical pads")
				}
			})
		})
	}
}

// TestFrostDKGECDHWithHostKeyNonceOrdering tests that nonce ordering matters.
func TestFrostDKGECDHWithHostKeyNonceOrdering(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	alice, err := GenerateSoftwareHostKey(cs)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKey alice failed: %v", err)
	}

	bob, err := GenerateSoftwareHostKey(cs)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKey bob failed: %v", err)
	}

	aliceNonce, _ := grp.RandomScalar()
	aliceNonceElement := grp.ScalarBaseMult(aliceNonce)

	bobNonce, _ := grp.RandomScalar()
	bobNonceElement := grp.ScalarBaseMult(bobNonce)

	// Encrypt: myNonce first, theirNonce second
	padEncrypt, err := frostDKGECDHWithHostKey(
		cs,
		alice,
		aliceNonceElement,
		bob.PublicKey(),
		bobNonceElement,
		true,
	)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt: theirNonce first, myNonce second
	padDecrypt, err := frostDKGECDHWithHostKey(
		cs,
		alice,
		aliceNonceElement,
		bob.PublicKey(),
		bobNonceElement,
		false,
	)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Ordering matters - encrypt and decrypt should produce different results
	// when using the same keys but different ordering
	if bytes.Equal(padEncrypt, padDecrypt) {
		t.Error("Encrypt and decrypt with same party should produce different pads due to nonce ordering")
	}
}

// TestFrostDKGECDHWithHostKeyEmptyNonce tests behavior with identity element nonces.
func TestFrostDKGECDHWithHostKeyEmptyNonce(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	alice, err := GenerateSoftwareHostKey(cs)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKey alice failed: %v", err)
	}

	bob, err := GenerateSoftwareHostKey(cs)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKey bob failed: %v", err)
	}

	// Use identity element as nonce (edge case)
	identityNonce := grp.Identity()

	normalNonce, _ := grp.RandomScalar()
	normalNonceElement := grp.ScalarBaseMult(normalNonce)

	// Identity element causes an error (expected)
	_, err = frostDKGECDHWithHostKey(
		cs,
		alice,
		identityNonce,
		bob.PublicKey(),
		normalNonceElement,
		true,
	)
	if err == nil {
		t.Error("Expected error for identity nonce, but got none")
	}
}

// TestFrostDKGECDHWithHostKeyValidElementSerialization tests that all valid elements serialize correctly.
func TestFrostDKGECDHWithHostKeyValidElementSerialization(t *testing.T) {
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grp := tc.cs.Group()

			alice, err := GenerateSoftwareHostKey(tc.cs)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
			}

			bob, err := GenerateSoftwareHostKey(tc.cs)
			if err != nil {
				t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
			}

			// Test with various types of elements
			testElements := []struct {
				name string
				elem group.Element
			}{
				{"identity", grp.Identity()},
				{"generator", grp.Generator()},
				{"random1", func() group.Element { s, _ := grp.RandomScalar(); return grp.ScalarBaseMult(s) }()},
				{"random2", func() group.Element { s, _ := grp.RandomScalar(); return grp.ScalarBaseMult(s) }()},
			}

			for _, te1 := range testElements {
				for _, te2 := range testElements {
					t.Run(te1.name+"_"+te2.name, func(t *testing.T) {
						pad, err := frostDKGECDHWithHostKey(
							tc.cs,
							alice,
							te1.elem,
							bob.PublicKey(),
							te2.elem,
							true,
						)
						// Identity elements may cause ECDH failures, which is expected
						if te1.name == "identity" || te2.name == "identity" {
							// Identity may cause valid errors
							if err != nil {
								// This is acceptable - identity is an edge case
								return
							}
						}
						if err != nil {
							t.Errorf("ECDH failed for %s + %s: %v", te1.name, te2.name, err)
						}
						if len(pad) == 0 {
							t.Errorf("Empty pad for %s + %s", te1.name, te2.name)
						}
					})
				}
			}
		})
	}
}

// TestFrostDKGECDHWithHostKeyDeterministic tests that same inputs produce same outputs.
func TestFrostDKGECDHWithHostKeyDeterministic(t *testing.T) {
	cs := ed25519_sha512.New()
	grp := cs.Group()

	alice, err := GenerateSoftwareHostKey(cs)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKey alice failed: %v", err)
	}

	bob, err := GenerateSoftwareHostKey(cs)
	if err != nil {
		t.Fatalf("GenerateSoftwareHostKey bob failed: %v", err)
	}

	aliceNonce, _ := grp.RandomScalar()
	aliceNonceElement := grp.ScalarBaseMult(aliceNonce)

	bobNonce, _ := grp.RandomScalar()
	bobNonceElement := grp.ScalarBaseMult(bobNonce)

	// Call twice with same inputs
	pad1, err := frostDKGECDHWithHostKey(
		cs,
		alice,
		aliceNonceElement,
		bob.PublicKey(),
		bobNonceElement,
		true,
	)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	pad2, err := frostDKGECDHWithHostKey(
		cs,
		alice,
		aliceNonceElement,
		bob.PublicKey(),
		bobNonceElement,
		true,
	)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	// Should produce identical results
	if !bytes.Equal(pad1, pad2) {
		t.Error("Same inputs produced different pads - function is not deterministic")
	}
}

// TestFROSTDKGFullParticipantStep2Errors tests error handling in FROSTDKGFullParticipantStep2.
func TestFROSTDKGFullParticipantStep2Errors(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold, n := 2, 3

	// Get the signer for key generation
	signer, err := GetSigner(cs)
	if err != nil {
		t.Fatalf("GetSigner failed: %v", err)
	}

	// Generate host keypairs using the signer
	hostSeckeys := make([][]byte, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		seckey, pubkey, err := signer.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		hostSeckeys[i] = seckey
		hostPubkeys[i] = pubkey
	}

	// Generate random for each participant
	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		randoms[i] = make([]byte, 32)
		_, _ = rand.Read(randoms[i])
	}

	// Step 1: Participants generate their first messages
	states1 := make([]*FROSTDKGFullParticipantState1, n)
	msgs1 := make([]*FROSTDKGFullParticipantMsg1, n)
	for i := 0; i < n; i++ {
		state, msg, err := FROSTDKGFullParticipantStep1(cs, hostSeckeys[i], hostPubkeys, threshold, i, randoms[i])
		if err != nil {
			t.Fatalf("Participant %d Step1 failed: %v", i, err)
		}
		states1[i] = state
		msgs1[i] = msg
	}

	// Coordinator Step 1: Process all participant messages
	_, coordMsg1, err := FROSTDKGFullCoordinatorStep1(cs, msgs1, threshold, hostPubkeys)
	if err != nil {
		t.Fatalf("Coordinator Step1 failed: %v", err)
	}

	// Test 1: Error from FROSTDKGEncParticipantRound2 - corrupted encrypted shares
	t.Run("error_from_enc_participant_round2_corrupted_shares", func(t *testing.T) {
		// Create a corrupted coordinator message with truncated encrypted shares
		corruptedCoordMsg := &FROSTDKGFullCoordinatorMsg1{
			EncCoordMsg: coordMsg1.EncCoordMsg,
			EncShares:   make([][]byte, n),
		}

		// Copy valid shares but truncate one to cause decryption error
		for i := 0; i < n; i++ {
			if i == 0 {
				// Truncate the encrypted shares to cause an error in FROSTDKGEncParticipantRound2
				corruptedCoordMsg.EncShares[i] = coordMsg1.EncShares[i][:len(coordMsg1.EncShares[i])/2]
			} else {
				corruptedCoordMsg.EncShares[i] = coordMsg1.EncShares[i]
			}
		}

		_, _, err := FROSTDKGFullParticipantStep2(cs, states1[0], corruptedCoordMsg)
		if err == nil {
			t.Error("Expected error from FROSTDKGEncParticipantRound2 with corrupted shares, got nil")
		}
	})

	// Test 2: Error from FROSTDKGEncParticipantRound2 - invalid encrypted data
	t.Run("error_from_enc_participant_round2_invalid_data", func(t *testing.T) {
		// Create a coordinator message with completely invalid encrypted shares
		invalidCoordMsg := &FROSTDKGFullCoordinatorMsg1{
			EncCoordMsg: coordMsg1.EncCoordMsg,
			EncShares:   make([][]byte, n),
		}

		// Fill with random garbage data
		for i := 0; i < n; i++ {
			invalidCoordMsg.EncShares[i] = make([]byte, 10) // Too short
			_, _ = rand.Read(invalidCoordMsg.EncShares[i])
		}

		_, _, err := FROSTDKGFullParticipantStep2(cs, states1[0], invalidCoordMsg)
		if err == nil {
			t.Error("Expected error from FROSTDKGEncParticipantRound2 with invalid data, got nil")
		}
	})

	// Test 3: Error from CertEqParticipantStep - invalid host secret key
	t.Run("error_from_certeq_participant_step_invalid_seckey", func(t *testing.T) {
		// Create a state with an invalid host secret key
		invalidState := &FROSTDKGFullParticipantState1{
			EncState:    states1[0].EncState,
			Signer:      states1[0].Signer,
			HostSeckey:  []byte{0x01, 0x02, 0x03}, // Invalid length
			HostPubkeys: states1[0].HostPubkeys,
		}

		_, _, err := FROSTDKGFullParticipantStep2(cs, invalidState, coordMsg1)
		if err == nil {
			t.Error("Expected error from CertEqParticipantStep with invalid seckey, got nil")
		}
		// Should get ErrInvalidSecretKey
		if err != ErrInvalidSecretKey {
			t.Logf("Got error: %v (expected ErrInvalidSecretKey but any error from CertEqParticipantStep is valid)", err)
		}
	})

	// Test 4: Error from CertEqParticipantStep - nil signer
	t.Run("error_from_certeq_participant_step_nil_signer", func(t *testing.T) {
		// Create a state with a nil signer
		invalidState := &FROSTDKGFullParticipantState1{
			EncState:    states1[0].EncState,
			Signer:      nil, // Nil signer
			HostSeckey:  states1[0].HostSeckey,
			HostPubkeys: states1[0].HostPubkeys,
		}

		_, _, err := FROSTDKGFullParticipantStep2(cs, invalidState, coordMsg1)
		if err == nil {
			t.Error("Expected error from CertEqParticipantStep with nil signer, got nil")
		}
		// Should get ErrSignerRequired
		if err != ErrSignerRequired {
			t.Logf("Got error: %v (expected ErrSignerRequired but any error from CertEqParticipantStep is valid)", err)
		}
	})

	// Test 5: Successful operation (verify the happy path is still working)
	t.Run("successful_step2", func(t *testing.T) {
		state2, msg2, err := FROSTDKGFullParticipantStep2(cs, states1[0], coordMsg1)
		if err != nil {
			t.Fatalf("FROSTDKGFullParticipantStep2 failed: %v", err)
		}
		if state2 == nil {
			t.Error("Expected non-nil state2")
		}
		if msg2 == nil {
			t.Error("Expected non-nil msg2")
		}
		if msg2 != nil && len(msg2.Signature) == 0 {
			t.Error("Expected non-empty signature in msg2")
		}
		if state2 != nil {
			if state2.Output == nil {
				t.Error("Expected non-nil output in state2")
			}
			if state2.EqInput == nil {
				t.Error("Expected non-nil eqInput in state2")
			}
			if state2.Index != 0 {
				t.Errorf("Expected index 0, got %d", state2.Index)
			}
		}
	})
}

// mockHostKeySignError is a mock HostKey that returns an error on Sign.
type mockHostKeySignError struct {
	realKey HostKey
	err     error
}

func (m *mockHostKeySignError) ECDH(theirPubkey []byte) ([]byte, error) {
	return m.realKey.ECDH(theirPubkey)
}

func (m *mockHostKeySignError) Sign(message []byte) ([]byte, error) {
	return nil, m.err
}

func (m *mockHostKeySignError) PublicKey() []byte {
	return m.realKey.PublicKey()
}

// TestFROSTDKGFullParticipantStep2WithHostKeyErrors tests error handling in
// FROSTDKGFullParticipantStep2WithHostKey with comprehensive coverage of both error paths.
func TestFROSTDKGFullParticipantStep2WithHostKeyErrors(t *testing.T) {
	cs := ed25519_sha512.New()
	threshold, n := 2, 3

	// Generate host keys
	hostKeys := make([]HostKey, n)
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		key, err := GenerateSoftwareHostKey(cs)
		if err != nil {
			t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
		}
		hostKeys[i] = key
		hostPubkeys[i] = key.PublicKey()
	}

	// Generate random for each participant
	randoms := make([][]byte, n)
	for i := 0; i < n; i++ {
		randoms[i] = make([]byte, 32)
		_, _ = rand.Read(randoms[i])
	}

	// Step 1: Participants generate their first messages
	states1 := make([]*FROSTDKGFullParticipantStateHK1, n)
	msgs1 := make([]*FROSTDKGFullParticipantMsg1, n)
	for i := 0; i < n; i++ {
		state, msg, err := FROSTDKGFullParticipantStep1WithHostKey(cs, hostKeys[i], hostPubkeys, threshold, i, randoms[i])
		if err != nil {
			t.Fatalf("Participant %d Step1WithHostKey failed: %v", i, err)
		}
		states1[i] = state
		msgs1[i] = msg
	}

	// Coordinator Step 1: Process all participant messages
	_, coordMsg1, err := FROSTDKGFullCoordinatorStep1(cs, msgs1, threshold, hostPubkeys)
	if err != nil {
		t.Fatalf("Coordinator Step1 failed: %v", err)
	}

	// Test 1: Error from FROSTDKGEncParticipantRound2WithHostKey - corrupted encrypted shares
	t.Run("error_from_enc_participant_round2_corrupted_shares", func(t *testing.T) {
		// Create a corrupted coordinator message with truncated encrypted shares
		corruptedCoordMsg := &FROSTDKGFullCoordinatorMsg1{
			EncCoordMsg: coordMsg1.EncCoordMsg,
			EncShares:   make([][]byte, n),
		}

		// Copy valid shares but truncate one to cause decryption error
		for i := 0; i < n; i++ {
			if i == 0 {
				// Truncate to cause an error in FROSTDKGEncParticipantRound2WithHostKey
				corruptedCoordMsg.EncShares[i] = coordMsg1.EncShares[i][:len(coordMsg1.EncShares[i])/2]
			} else {
				corruptedCoordMsg.EncShares[i] = coordMsg1.EncShares[i]
			}
		}

		_, _, err := FROSTDKGFullParticipantStep2WithHostKey(cs, states1[0], corruptedCoordMsg)
		if err == nil {
			t.Error("Expected error from FROSTDKGEncParticipantRound2WithHostKey with corrupted shares, got nil")
		}
	})

	// Test 2: Error from FROSTDKGEncParticipantRound2WithHostKey - invalid encrypted data length
	t.Run("error_from_enc_participant_round2_invalid_data_length", func(t *testing.T) {
		// Create a coordinator message with completely invalid encrypted shares
		invalidCoordMsg := &FROSTDKGFullCoordinatorMsg1{
			EncCoordMsg: coordMsg1.EncCoordMsg,
			EncShares:   make([][]byte, n),
		}

		// Fill with random garbage data that's too short
		for i := 0; i < n; i++ {
			invalidCoordMsg.EncShares[i] = make([]byte, 10) // Too short
			_, _ = rand.Read(invalidCoordMsg.EncShares[i])
		}

		_, _, err := FROSTDKGFullParticipantStep2WithHostKey(cs, states1[0], invalidCoordMsg)
		if err == nil {
			t.Error("Expected error from FROSTDKGEncParticipantRound2WithHostKey with invalid data length, got nil")
		}
		if err != ErrFROSTDKGDecryptionFailed {
			t.Logf("Got error: %v (expected ErrFROSTDKGDecryptionFailed)", err)
		}
	})

	// Test 3: Error from FROSTDKGEncParticipantRound2WithHostKey - corrupted scalar deserialization
	t.Run("error_from_enc_participant_round2_invalid_scalar", func(t *testing.T) {
		// Create a coordinator message with invalid scalar data
		grp := cs.Group()
		scalarLen := len(grp.SerializeScalar(grp.NewScalar()))
		invalidCoordMsg := &FROSTDKGFullCoordinatorMsg1{
			EncCoordMsg: coordMsg1.EncCoordMsg,
			EncShares:   make([][]byte, n),
		}

		// Fill with data of correct length but invalid scalar values
		for i := 0; i < n; i++ {
			invalidCoordMsg.EncShares[i] = make([]byte, n*scalarLen)
			// Fill with 0xFF which is likely invalid for most groups
			for j := range invalidCoordMsg.EncShares[i] {
				invalidCoordMsg.EncShares[i][j] = 0xFF
			}
		}

		_, _, err := FROSTDKGFullParticipantStep2WithHostKey(cs, states1[0], invalidCoordMsg)
		if err == nil {
			t.Error("Expected error from FROSTDKGEncParticipantRound2WithHostKey with invalid scalar data, got nil")
		}
	})

	// Test 4: Error from HostKey.Sign - mock key that fails signing
	t.Run("error_from_hostkey_sign", func(t *testing.T) {
		// Create a mock HostKey that fails on Sign
		expectedErr := errors.New("mock signing failure")
		mockKey := &mockHostKeySignError{
			realKey: hostKeys[0],
			err:     expectedErr,
		}

		// Create state with the mock key
		stateWithMockKey := &FROSTDKGFullParticipantStateHK1{
			EncState:    states1[0].EncState,
			HostKey:     mockKey,
			HostPubkeys: states1[0].HostPubkeys,
		}

		_, _, err := FROSTDKGFullParticipantStep2WithHostKey(cs, stateWithMockKey, coordMsg1)
		if err == nil {
			t.Error("Expected error from HostKey.Sign, got nil")
		}
		if !errors.Is(err, expectedErr) {
			t.Errorf("Expected error %v, got %v", expectedErr, err)
		}
	})

	// Test 5: Error from HostKey.Sign - ErrHostKeySignFailed
	t.Run("error_from_hostkey_sign_standard_error", func(t *testing.T) {
		// Create a mock HostKey that fails with standard error
		mockKey := &mockHostKeySignError{
			realKey: hostKeys[0],
			err:     ErrHostKeySignFailed,
		}

		// Create state with the mock key
		stateWithMockKey := &FROSTDKGFullParticipantStateHK1{
			EncState:    states1[0].EncState,
			HostKey:     mockKey,
			HostPubkeys: states1[0].HostPubkeys,
		}

		_, _, err := FROSTDKGFullParticipantStep2WithHostKey(cs, stateWithMockKey, coordMsg1)
		if err == nil {
			t.Error("Expected ErrHostKeySignFailed from HostKey.Sign, got nil")
		}
		if !errors.Is(err, ErrHostKeySignFailed) {
			t.Errorf("Expected ErrHostKeySignFailed, got %v", err)
		}
	})

	// Test 6: Successful operation (verify the happy path still works)
	t.Run("successful_step2_with_hostkey", func(t *testing.T) {
		state2, msg2, err := FROSTDKGFullParticipantStep2WithHostKey(cs, states1[0], coordMsg1)
		if err != nil {
			t.Fatalf("FROSTDKGFullParticipantStep2WithHostKey failed: %v", err)
		}
		if state2 == nil {
			t.Error("Expected non-nil state2")
		}
		if msg2 == nil {
			t.Error("Expected non-nil msg2")
		}
		if msg2 != nil && len(msg2.Signature) == 0 {
			t.Error("Expected non-empty signature in msg2")
		}
		if state2 != nil {
			if state2.Output == nil {
				t.Error("Expected non-nil output in state2")
			}
			if state2.EqInput == nil {
				t.Error("Expected non-nil eqInput in state2")
			}
			if state2.Index != 0 {
				t.Errorf("Expected index 0, got %d", state2.Index)
			}
			if state2.HostKey == nil {
				t.Error("Expected non-nil HostKey in state2")
			}
			if state2.CS == nil {
				t.Error("Expected non-nil ciphersuite in state2")
			}
		}
	})

	// Test 7: Verify signature in successful case can be verified
	t.Run("successful_step2_signature_verification", func(t *testing.T) {
		state2, msg2, err := FROSTDKGFullParticipantStep2WithHostKey(cs, states1[1], coordMsg1)
		if err != nil {
			t.Fatalf("FROSTDKGFullParticipantStep2WithHostKey failed: %v", err)
		}

		// Verify the signature using the HostKey verification function
		message := CertEqMessage(state2.EqInput, state2.Index, hostPubkeys, threshold)
		err = VerifyHostKeySignature(cs, hostPubkeys[1], message, msg2.Signature)
		if err != nil {
			t.Errorf("Signature verification failed: %v", err)
		}
	})

	// Test 8: Multiple ciphersuites for happy path
	t.Run("successful_step2_all_ciphersuites", func(t *testing.T) {
		testCases := []struct {
			name string
			cs   ciphersuite.Ciphersuite
		}{
			{"Ed25519", ed25519_sha512.New()},
			{"P256", p256_sha256.New()},
			{"Ristretto255", ristretto255_sha512.New()},
			{"Secp256k1", secp256k1_sha256.New()},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Generate host keys for this ciphersuite
				csHostKeys := make([]HostKey, n)
				csHostPubkeys := make([][]byte, n)
				for i := 0; i < n; i++ {
					key, err := GenerateSoftwareHostKey(tc.cs)
					if err != nil {
						t.Fatalf("GenerateSoftwareHostKey failed: %v", err)
					}
					csHostKeys[i] = key
					csHostPubkeys[i] = key.PublicKey()
				}

				// Step 1
				csStates1 := make([]*FROSTDKGFullParticipantStateHK1, n)
				csMsgs1 := make([]*FROSTDKGFullParticipantMsg1, n)
				for i := 0; i < n; i++ {
					state, msg, err := FROSTDKGFullParticipantStep1WithHostKey(tc.cs, csHostKeys[i], csHostPubkeys, threshold, i, randoms[i])
					if err != nil {
						t.Fatalf("Participant %d Step1WithHostKey failed: %v", i, err)
					}
					csStates1[i] = state
					csMsgs1[i] = msg
				}

				// Coordinator Step 1
				_, csCoordMsg1, err := FROSTDKGFullCoordinatorStep1(tc.cs, csMsgs1, threshold, csHostPubkeys)
				if err != nil {
					t.Fatalf("Coordinator Step1 failed: %v", err)
				}

				// Step 2
				state2, msg2, err := FROSTDKGFullParticipantStep2WithHostKey(tc.cs, csStates1[0], csCoordMsg1)
				if err != nil {
					t.Fatalf("FROSTDKGFullParticipantStep2WithHostKey failed: %v", err)
				}
				if state2 == nil || msg2 == nil {
					t.Fatal("Expected non-nil state2 and msg2")
				}
				if len(msg2.Signature) == 0 {
					t.Error("Expected non-empty signature")
				}

				// Verify signature
				message := CertEqMessage(state2.EqInput, state2.Index, csHostPubkeys, threshold)
				err = VerifyHostKeySignature(tc.cs, csHostPubkeys[0], message, msg2.Signature)
				if err != nil {
					t.Errorf("Signature verification failed: %v", err)
				}
			})
		}
	})
}

// TestFROSTDKGParticipantRound2Validation tests error paths in FROSTDKGParticipantRound2.
// This test focuses on achieving comprehensive coverage of the function at line 449.
func TestFROSTDKGParticipantRound2Validation(t *testing.T) {
	// Test all ciphersuites
	testCases := []struct {
		name string
		cs   ciphersuite.Ciphersuite
	}{
		{"Ed25519", ed25519_sha512.New()},
		{"Ed448", ed448_shake256.New()},
		{"P256", p256_sha256.New()},
		{"Ristretto255", ristretto255_sha512.New()},
		{"Secp256k1", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cs := tc.cs
			grp := cs.Group()
			threshold := 2
			n := 3

			// Helper function to run a full valid Round 1 and get states
			setupRound1 := func() ([]*FROSTDKGParticipantState, []*FROSTDKGParticipantMsg, [][]group.Scalar, *FROSTDKGCoordinatorMsg) {
				states := make([]*FROSTDKGParticipantState, n)
				msgs := make([]*FROSTDKGParticipantMsg, n)
				allShares := make([][]group.Scalar, n)

				// Each participant generates their Round 1 state
				for i := 0; i < n; i++ {
					seed := make([]byte, 32)
					_, _ = rand.Read(seed)

					state, msg, shares, err := FROSTDKGParticipantRound1(cs, seed, threshold, n, i)
					if err != nil {
						t.Fatalf("Participant %d Round1 failed: %v", i, err)
					}
					states[i] = state
					msgs[i] = msg
					allShares[i] = shares
				}

				// Coordinator aggregates all commitments
				coordMsg, err := FROSTDKGCoordinatorRound1(cs, msgs, threshold, n)
				if err != nil {
					t.Fatalf("Coordinator Round1 failed: %v", err)
				}

				return states, msgs, allShares, coordMsg
			}

			// Test 1: Valid round 2 completion
			t.Run("valid_round2_completion", func(t *testing.T) {
				states, _, allShares, coordMsg := setupRound1()

				// Prepare received shares for participant 0
				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					receivedShares[i] = allShares[i][0]
				}

				output, eqInput, err := FROSTDKGParticipantRound2(cs, states[0], coordMsg, receivedShares)
				if err != nil {
					t.Fatalf("FROSTDKGParticipantRound2 failed: %v", err)
				}

				if output == nil {
					t.Fatal("Expected non-nil output")
				}
				if eqInput == nil {
					t.Fatal("Expected non-nil eqInput")
				}
				if output.SecretShare == nil {
					t.Error("Expected non-nil secret share")
				}
				if output.ThresholdPubkey == nil {
					t.Error("Expected non-nil threshold pubkey")
				}
				if len(output.PublicShares) != n {
					t.Errorf("Expected %d public shares, got %d", n, len(output.PublicShares))
				}
			})

			// Test 2: Nil state (error path line 456-458)
			t.Run("nil_state", func(t *testing.T) {
				_, _, allShares, coordMsg := setupRound1()

				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					receivedShares[i] = allShares[i][0]
				}

				_, _, err := FROSTDKGParticipantRound2(cs, nil, coordMsg, receivedShares)
				if err != ErrInvalidParticipantIndex {
					t.Errorf("Expected ErrInvalidParticipantIndex for nil state, got: %v", err)
				}
			})

			// Test 3: Nil coordinator message (error path line 459-461)
			t.Run("nil_coordinator_message", func(t *testing.T) {
				states, _, allShares, _ := setupRound1()

				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					receivedShares[i] = allShares[i][0]
				}

				_, _, err := FROSTDKGParticipantRound2(cs, states[0], nil, receivedShares)
				if err != ErrFROSTDKGCommitmentMismatch {
					t.Errorf("Expected ErrFROSTDKGCommitmentMismatch for nil coordMsg, got: %v", err)
				}
			})

			// Test 4: Invalid received shares count (error path line 469-471)
			t.Run("invalid_received_shares_count", func(t *testing.T) {
				states, _, _, coordMsg := setupRound1()

				// Provide wrong number of shares
				receivedShares := make([]group.Scalar, 1)
				receivedShares[0] = grp.NewScalar()

				_, _, err := FROSTDKGParticipantRound2(cs, states[0], coordMsg, receivedShares)
				if err != ErrFROSTDKGInvalidParticipantCount {
					t.Errorf("Expected ErrFROSTDKGInvalidParticipantCount for wrong shares count, got: %v", err)
				}
			})

			// Test 5: Invalid commitments count (error path line 472-474)
			t.Run("invalid_commitments_count", func(t *testing.T) {
				states, _, allShares, coordMsg := setupRound1()

				// Create coordinator message with wrong number of commitments
				corruptedCoordMsg := &FROSTDKGCoordinatorMsg{
					AllCommitments: coordMsg.AllCommitments[:1], // Only one commitment
					AllPOPs:        coordMsg.AllPOPs,
				}

				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					receivedShares[i] = allShares[i][0]
				}

				_, _, err := FROSTDKGParticipantRound2(cs, states[0], corruptedCoordMsg, receivedShares)
				if err != ErrFROSTDKGInvalidParticipantCount {
					t.Errorf("Expected ErrFROSTDKGInvalidParticipantCount for wrong commitments count, got: %v", err)
				}
			})

			// Test 6: Invalid POPs count (error path line 475-477)
			t.Run("invalid_pops_count", func(t *testing.T) {
				states, _, allShares, coordMsg := setupRound1()

				// Create coordinator message with wrong number of POPs
				corruptedCoordMsg := &FROSTDKGCoordinatorMsg{
					AllCommitments: coordMsg.AllCommitments,
					AllPOPs:        coordMsg.AllPOPs[:1], // Only one POP
				}

				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					receivedShares[i] = allShares[i][0]
				}

				_, _, err := FROSTDKGParticipantRound2(cs, states[0], corruptedCoordMsg, receivedShares)
				if err != ErrFROSTDKGInvalidParticipantCount {
					t.Errorf("Expected ErrFROSTDKGInvalidParticipantCount for wrong POPs count, got: %v", err)
				}
			})

			// Test 7: Commitment mismatch (error path line 480-482)
			t.Run("commitment_mismatch", func(t *testing.T) {
				states, _, allShares, coordMsg := setupRound1()

				// Replace our commitment with a different one
				corruptedCoordMsg := &FROSTDKGCoordinatorMsg{
					AllCommitments: make([]*VSSCommitment, n),
					AllPOPs:        coordMsg.AllPOPs,
				}
				copy(corruptedCoordMsg.AllCommitments, coordMsg.AllCommitments)

				// Create a different commitment for participant 0
				seed := make([]byte, 32)
				_, _ = rand.Read(seed)
				vss, _ := FROSTDKGGenerateVSS(cs, seed, threshold)
				corruptedCoordMsg.AllCommitments[0] = vss.Commit()

				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					receivedShares[i] = allShares[i][0]
				}

				_, _, err := FROSTDKGParticipantRound2(cs, states[0], corruptedCoordMsg, receivedShares)
				if err != ErrFROSTDKGCommitmentMismatch {
					t.Errorf("Expected ErrFROSTDKGCommitmentMismatch, got: %v", err)
				}
			})

			// Test 8: Nil commitment (error path line 488-490)
			t.Run("nil_commitment", func(t *testing.T) {
				states, _, allShares, coordMsg := setupRound1()

				// Create coordinator message with nil commitment
				corruptedCoordMsg := &FROSTDKGCoordinatorMsg{
					AllCommitments: make([]*VSSCommitment, n),
					AllPOPs:        coordMsg.AllPOPs,
				}
				copy(corruptedCoordMsg.AllCommitments, coordMsg.AllCommitments)
				corruptedCoordMsg.AllCommitments[1] = nil // Nil commitment at index 1

				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					receivedShares[i] = allShares[i][0]
				}

				_, _, err := FROSTDKGParticipantRound2(cs, states[0], corruptedCoordMsg, receivedShares)
				if err == nil {
					t.Error("Expected error for nil commitment")
				}
				// Should be a FaultyParticipantError
				var faultyErr *FaultyParticipantError
				if !errors.As(err, &faultyErr) {
					t.Errorf("Expected FaultyParticipantError, got: %v", err)
				} else if faultyErr.ParticipantIndex != 1 {
					t.Errorf("Expected faulty participant 1, got %d", faultyErr.ParticipantIndex)
				}
			})

			// Test 9: Wrong threshold in commitment (error path line 492-494)
			t.Run("wrong_threshold_in_commitment", func(t *testing.T) {
				states, _, allShares, coordMsg := setupRound1()

				// Create a commitment with wrong threshold
				seed := make([]byte, 32)
				_, _ = rand.Read(seed)
				wrongThresholdVSS, _ := FROSTDKGGenerateVSS(cs, seed, threshold+1) // Wrong threshold
				wrongCommitment := wrongThresholdVSS.Commit()

				corruptedCoordMsg := &FROSTDKGCoordinatorMsg{
					AllCommitments: make([]*VSSCommitment, n),
					AllPOPs:        coordMsg.AllPOPs,
				}
				copy(corruptedCoordMsg.AllCommitments, coordMsg.AllCommitments)
				corruptedCoordMsg.AllCommitments[1] = wrongCommitment

				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					receivedShares[i] = allShares[i][0]
				}

				_, _, err := FROSTDKGParticipantRound2(cs, states[0], corruptedCoordMsg, receivedShares)
				if err == nil {
					t.Error("Expected error for wrong threshold in commitment")
				}
				// Should be a FaultyParticipantError
				var faultyErr *FaultyParticipantError
				if !errors.As(err, &faultyErr) {
					t.Errorf("Expected FaultyParticipantError, got: %v", err)
				} else if faultyErr.ParticipantIndex != 1 {
					t.Errorf("Expected faulty participant 1, got %d", faultyErr.ParticipantIndex)
				}
			})

			// Test 10: Invalid POP (error path line 496-498)
			t.Run("invalid_pop", func(t *testing.T) {
				states, _, allShares, coordMsg := setupRound1()

				// Corrupt one POP
				corruptedCoordMsg := &FROSTDKGCoordinatorMsg{
					AllCommitments: coordMsg.AllCommitments,
					AllPOPs:        make([][]byte, n),
				}
				copy(corruptedCoordMsg.AllPOPs, coordMsg.AllPOPs)

				// Create invalid POP (random bytes)
				corruptedCoordMsg.AllPOPs[1] = make([]byte, len(coordMsg.AllPOPs[1]))
				_, _ = rand.Read(corruptedCoordMsg.AllPOPs[1])

				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					receivedShares[i] = allShares[i][0]
				}

				_, _, err := FROSTDKGParticipantRound2(cs, states[0], corruptedCoordMsg, receivedShares)
				if err != ErrFROSTDKGInvalidPOP {
					t.Errorf("Expected ErrFROSTDKGInvalidPOP, got: %v", err)
				}
			})
			// Test 11: Share verification failure (error path line 527-529)
			t.Run("share_verification_failure", func(t *testing.T) {
				states, _, allShares, coordMsg := setupRound1()

				// Provide corrupted shares that won't verify
				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					if i == 0 {
						// Corrupt our own share by adding a random scalar
						randomScalar, _ := grp.RandomScalar()
						receivedShares[i] = grp.NewScalar()
						receivedShares[i].Add(allShares[i][0])
						receivedShares[i].Add(randomScalar)
					} else {
						receivedShares[i] = allShares[i][0]
					}
				}

				_, _, err := FROSTDKGParticipantRound2(cs, states[0], coordMsg, receivedShares)
				if err != ErrFROSTDKGShareVerificationFailed {
					t.Errorf("Expected ErrFROSTDKGShareVerificationFailed, got: %v", err)
				}
			})
			// Test 12: All shares zero (edge case for share verification)
			t.Run("all_zero_shares", func(t *testing.T) {
				states, _, _, coordMsg := setupRound1()

				// Provide all zero shares
				receivedShares := make([]group.Scalar, n)
				for i := 0; i < n; i++ {
					receivedShares[i] = grp.NewScalar()
				}

				_, _, err := FROSTDKGParticipantRound2(cs, states[0], coordMsg, receivedShares)
				if err != ErrFROSTDKGShareVerificationFailed {
					t.Errorf("Expected ErrFROSTDKGShareVerificationFailed for zero shares, got: %v", err)
				}
			})

			// Test 13: Successful completion with all participants
			t.Run("full_dkg_completion", func(t *testing.T) {
				states, _, allShares, coordMsg := setupRound1()

				// Each participant runs Round 2
				outputs := make([]*FROSTDKGOutput, n)
				for i := 0; i < n; i++ {
					receivedShares := make([]group.Scalar, n)
					for j := 0; j < n; j++ {
						receivedShares[j] = allShares[j][i]
					}

					output, eqInput, err := FROSTDKGParticipantRound2(cs, states[i], coordMsg, receivedShares)
					if err != nil {
						t.Fatalf("Participant %d Round2 failed: %v", i, err)
					}

					if output == nil {
						t.Fatalf("Participant %d got nil output", i)
					}
					if eqInput == nil {
						t.Fatalf("Participant %d got nil eqInput", i)
					}

					outputs[i] = output
				}

				// Verify all participants got the same threshold public key
				for i := 1; i < n; i++ {
					if !outputs[0].ThresholdPubkey.Equal(outputs[i].ThresholdPubkey) {
						t.Errorf("Participant %d has different threshold pubkey", i)
					}
				}

				// Verify all participants got the same public shares
				for i := 1; i < n; i++ {
					for j := 0; j < n; j++ {
						if !outputs[0].PublicShares[j].Equal(outputs[i].PublicShares[j]) {
							t.Errorf("Participant %d has different public share %d", i, j)
						}
					}
				}
			})
		})
	}
}
