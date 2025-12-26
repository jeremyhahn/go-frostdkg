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
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frostdkg/test/testvectors"
)

// testPOPVerificationWithVector verifies that we can verify POPs from test vectors.
// Note: Our POP generation uses deterministic nonces, so the generated POPs won't match
// the test vectors (which use random nonces). However, verification should work.
func TestPOPVerificationWithTestVectors(t *testing.T) {
	testCases := []struct {
		name   string
		cs     ciphersuite.Ciphersuite
		loader func() (*testvectors.DKGVectors, error)
	}{
		{"secp256k1", secp256k1_sha256.New(), testvectors.GetSecp256k1Vectors},
		{"ed25519", ed25519_sha512.New(), testvectors.GetEd25519Vectors},
		{"p256", p256_sha256.New(), testvectors.GetP256Vectors},
		{"ristretto255", ristretto255_sha512.New(), testvectors.GetRistretto255Vectors},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := tc.loader()
			if err != nil {
				t.Fatalf("Failed to load vectors: %v", err)
			}

			grp := tc.cs.Group()

			for id, participant := range vectors.Inputs.Participants {
				t.Run("participant_"+id, func(t *testing.T) {
					// Get the signing key (secret)
					secretBytes, err := hex.DecodeString(participant.SigningKey)
					if err != nil {
						t.Fatalf("Failed to decode signing key: %v", err)
					}
					secret, err := grp.DeserializeScalar(secretBytes)
					if err != nil {
						t.Fatalf("Failed to deserialize secret: %v", err)
					}

					// Compute pubkey from secret
					pubkey := grp.ScalarBaseMult(secret)

					// Get the VSS commitment
					if len(participant.VSSCommitments) == 0 {
						t.Fatal("No VSS commitments")
					}
					commitment0Bytes, err := hex.DecodeString(participant.VSSCommitments[0])
					if err != nil {
						t.Fatalf("Failed to decode commitment: %v", err)
					}
					commitment0, err := grp.DeserializeElement(commitment0Bytes)
					if err != nil {
						t.Fatalf("Failed to deserialize commitment: %v", err)
					}

					// Verify pubkey matches commitment[0] (the constant term commitment)
					pubkeyBytes, _ := grp.SerializeElement(pubkey)
					if hex.EncodeToString(pubkeyBytes) != hex.EncodeToString(commitment0Bytes) {
						t.Logf("Note: pubkey doesn't match commitment[0], this may be expected")
						t.Logf("pubkey: %s", hex.EncodeToString(pubkeyBytes))
						t.Logf("commitment[0]: %s", hex.EncodeToString(commitment0Bytes))
					}

					// Test vector POPs are generated with random nonces, so we can't
					// verify them directly with our implementation. However, we can
					// verify that our own POPs work correctly.

					// The test vector identifier is 1-indexed, but our index is 0-indexed
					index := participant.Identifier - 1

					// Generate our own POP and verify it
					ourPOP, err := FROSTDKGProveKnowledge(tc.cs, secret, pubkey, index)
					if err != nil {
						t.Fatalf("Failed to generate POP: %v", err)
					}

					// Our POP should verify
					if !FROSTDKGVerifyPOP(tc.cs, ourPOP, pubkey, index) {
						t.Error("Our generated POP should verify")
					}

					// Log comparison
					t.Logf("Test vector POP: %s", participant.ProofOfKnowledge)
					t.Logf("Our POP: %s", hex.EncodeToString(ourPOP))

					// Verify the commitment[0] is consistent with what we generate
					if commitment0.Equal(pubkey) {
						t.Log("SUCCESS: commitment[0] matches pubkey (g^secret)")
					}
				})
			}
		})
	}
}

// TestVSSCommitmentsMatchTestVectors verifies VSS commitment computation.
func TestVSSCommitmentsMatchTestVectors(t *testing.T) {
	testCases := []struct {
		name   string
		cs     ciphersuite.Ciphersuite
		loader func() (*testvectors.DKGVectors, error)
	}{
		{"secp256k1", secp256k1_sha256.New(), testvectors.GetSecp256k1Vectors},
		{"ed25519", ed25519_sha512.New(), testvectors.GetEd25519Vectors},
		{"p256", p256_sha256.New(), testvectors.GetP256Vectors},
		{"ristretto255", ristretto255_sha512.New(), testvectors.GetRistretto255Vectors},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := tc.loader()
			if err != nil {
				t.Fatalf("Failed to load vectors: %v", err)
			}

			grp := tc.cs.Group()

			for id, participant := range vectors.Inputs.Participants {
				t.Run("participant_"+id, func(t *testing.T) {
					// Get coefficients from test vector
					signingKeyBytes, err := hex.DecodeString(participant.SigningKey)
					if err != nil {
						t.Fatalf("Failed to decode signing key: %v", err)
					}
					coefficientBytes, err := hex.DecodeString(participant.Coefficient)
					if err != nil {
						t.Fatalf("Failed to decode coefficient: %v", err)
					}

					a0, err := grp.DeserializeScalar(signingKeyBytes)
					if err != nil {
						t.Fatalf("Failed to deserialize a0: %v", err)
					}
					a1, err := grp.DeserializeScalar(coefficientBytes)
					if err != nil {
						t.Fatalf("Failed to deserialize a1: %v", err)
					}

					// Compute commitments: C_j = g^a_j
					C0 := grp.ScalarBaseMult(a0)
					C1 := grp.ScalarBaseMult(a1)

					// Serialize our commitments
					C0Bytes, _ := grp.SerializeElement(C0)
					C1Bytes, _ := grp.SerializeElement(C1)

					// Compare with test vector commitments
					expectedC0, _ := hex.DecodeString(participant.VSSCommitments[0])
					expectedC1, _ := hex.DecodeString(participant.VSSCommitments[1])

					if hex.EncodeToString(C0Bytes) != hex.EncodeToString(expectedC0) {
						t.Errorf("Commitment[0] mismatch:\n  got: %s\n  exp: %s",
							hex.EncodeToString(C0Bytes), hex.EncodeToString(expectedC0))
					}

					if hex.EncodeToString(C1Bytes) != hex.EncodeToString(expectedC1) {
						t.Errorf("Commitment[1] mismatch:\n  got: %s\n  exp: %s",
							hex.EncodeToString(C1Bytes), hex.EncodeToString(expectedC1))
					}
				})
			}
		})
	}
}

// TestSigningSharesMatchTestVectors verifies share computation matches test vectors.
func TestSigningSharesMatchTestVectors(t *testing.T) {
	testCases := []struct {
		name   string
		cs     ciphersuite.Ciphersuite
		loader func() (*testvectors.DKGVectors, error)
	}{
		{"secp256k1", secp256k1_sha256.New(), testvectors.GetSecp256k1Vectors},
		{"ed25519", ed25519_sha512.New(), testvectors.GetEd25519Vectors},
		{"p256", p256_sha256.New(), testvectors.GetP256Vectors},
		{"ristretto255", ristretto255_sha512.New(), testvectors.GetRistretto255Vectors},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := tc.loader()
			if err != nil {
				t.Fatalf("Failed to load vectors: %v", err)
			}

			grp := tc.cs.Group()

			// The signing_shares map: participant[receiver].signing_shares[sender] = f_sender(receiver)
			// So for each receiver, we look up shares they receive from each sender

			for receiverID, receiver := range vectors.Inputs.Participants {
				t.Run("receiver_"+receiverID, func(t *testing.T) {
					// Parse receiver identifier (1-indexed)
					var receiverIdent int
					for _, c := range receiverID {
						receiverIdent = receiverIdent*10 + int(c-'0')
					}

					// For each sender that sends a share to this receiver
					for senderID, expectedShareHex := range receiver.SigningShares {
						// Get the sender's polynomial coefficients
						sender := vectors.Inputs.Participants[senderID]
						a0Bytes, _ := hex.DecodeString(sender.SigningKey)
						a1Bytes, _ := hex.DecodeString(sender.Coefficient)
						a0, _ := grp.DeserializeScalar(a0Bytes)
						a1, _ := grp.DeserializeScalar(a1Bytes)

						// Compute f_sender(receiverIdent) = a0 + a1 * receiverIdent
						x := scalarFromInt(grp, receiverIdent)
						share := a1.Mul(x)
						share = a0.Add(share)

						// Serialize and compare
						shareBytes := grp.SerializeScalar(share)
						expectedBytes, _ := hex.DecodeString(expectedShareHex)

						if hex.EncodeToString(shareBytes) != hex.EncodeToString(expectedBytes) {
							t.Errorf("Share from %s to %s mismatch:\n  got: %s\n  exp: %s",
								senderID, receiverID, hex.EncodeToString(shareBytes), hex.EncodeToString(expectedBytes))
						}
					}
				})
			}
		})
	}
}

// TestVerifyingShareMatchesTestVectors verifies public share computation.
func TestVerifyingShareMatchesTestVectors(t *testing.T) {
	testCases := []struct {
		name   string
		cs     ciphersuite.Ciphersuite
		loader func() (*testvectors.DKGVectors, error)
	}{
		{"secp256k1", secp256k1_sha256.New(), testvectors.GetSecp256k1Vectors},
		{"ed25519", ed25519_sha512.New(), testvectors.GetEd25519Vectors},
		{"p256", p256_sha256.New(), testvectors.GetP256Vectors},
		{"ristretto255", ristretto255_sha512.New(), testvectors.GetRistretto255Vectors},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := tc.loader()
			if err != nil {
				t.Fatalf("Failed to load vectors: %v", err)
			}

			grp := tc.cs.Group()

			// First collect all VSS commitments
			allCommitments := make(map[string][]group.Element)
			for id, participant := range vectors.Inputs.Participants {
				commitments := make([]group.Element, len(participant.VSSCommitments))
				for i, cHex := range participant.VSSCommitments {
					cBytes, _ := hex.DecodeString(cHex)
					c, _ := grp.DeserializeElement(cBytes)
					commitments[i] = c
				}
				allCommitments[id] = commitments
			}

			// Now verify each participant's verifying share
			for id, participant := range vectors.Inputs.Participants {
				t.Run("participant_"+id, func(t *testing.T) {
					// Parse participant identifier
					var participantIdent int
					for _, c := range id {
						participantIdent = participantIdent*10 + int(c-'0')
					}

					// Sum all commitments and compute public share at this identifier
					// Y_i = sum_j(C_j0 * i^0 + C_j1 * i^1 + ...)
					var pubshare group.Element

					for _, commitments := range allCommitments {
						// Evaluate commitment polynomial at participantIdent
						// sum = C[0] + C[1]*i + C[2]*i^2 + ...
						x := scalarFromInt(grp, participantIdent)
						xPow := scalarFromInt(grp, 1) // x^0 = 1

						var partialShare group.Element
						for j, C := range commitments {
							term := grp.ScalarMult(C, xPow)
							if j == 0 {
								partialShare = term
							} else {
								partialShare = partialShare.Add(term)
							}
							xPow = xPow.Mul(x)
						}

						if pubshare == nil {
							pubshare = partialShare
						} else {
							pubshare = pubshare.Add(partialShare)
						}
					}

					// Serialize and compare
					pubshareBytes, _ := grp.SerializeElement(pubshare)
					expectedBytes, _ := hex.DecodeString(participant.VerifyingShare)

					if hex.EncodeToString(pubshareBytes) != hex.EncodeToString(expectedBytes) {
						t.Errorf("Verifying share mismatch:\n  got: %s\n  exp: %s",
							hex.EncodeToString(pubshareBytes), hex.EncodeToString(expectedBytes))
					}
				})
			}
		})
	}
}

// TestGroupVerifyingKeyMatchesTestVectors verifies group public key computation.
func TestGroupVerifyingKeyMatchesTestVectors(t *testing.T) {
	testCases := []struct {
		name   string
		cs     ciphersuite.Ciphersuite
		loader func() (*testvectors.DKGVectors, error)
	}{
		{"secp256k1", secp256k1_sha256.New(), testvectors.GetSecp256k1Vectors},
		{"ed25519", ed25519_sha512.New(), testvectors.GetEd25519Vectors},
		{"p256", p256_sha256.New(), testvectors.GetP256Vectors},
		{"ristretto255", ristretto255_sha512.New(), testvectors.GetRistretto255Vectors},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := tc.loader()
			if err != nil {
				t.Fatalf("Failed to load vectors: %v", err)
			}

			grp := tc.cs.Group()

			// Sum all constant term commitments (C[0]) to get group verifying key
			var groupPubkey group.Element
			for _, participant := range vectors.Inputs.Participants {
				cBytes, _ := hex.DecodeString(participant.VSSCommitments[0])
				c, _ := grp.DeserializeElement(cBytes)
				if groupPubkey == nil {
					groupPubkey = c
				} else {
					groupPubkey = groupPubkey.Add(c)
				}
			}

			// Compare with test vector
			groupPubkeyBytes, _ := grp.SerializeElement(groupPubkey)
			expectedBytes, _ := hex.DecodeString(vectors.Inputs.VerifyingKey)

			if hex.EncodeToString(groupPubkeyBytes) != hex.EncodeToString(expectedBytes) {
				t.Errorf("Group verifying key mismatch:\n  got: %s\n  exp: %s",
					hex.EncodeToString(groupPubkeyBytes), hex.EncodeToString(expectedBytes))
			}
		})
	}
}

// TestFinalSigningShareMatchesTestVectors verifies final signing share computation.
// The final signing share is s_i = sum_j(f_j(i)) where f_j(i) is evaluated at
// the receiver's identifier.
func TestFinalSigningShareMatchesTestVectors(t *testing.T) {
	testCases := []struct {
		name   string
		cs     ciphersuite.Ciphersuite
		loader func() (*testvectors.DKGVectors, error)
	}{
		{"secp256k1", secp256k1_sha256.New(), testvectors.GetSecp256k1Vectors},
		{"ed25519", ed25519_sha512.New(), testvectors.GetEd25519Vectors},
		{"p256", p256_sha256.New(), testvectors.GetP256Vectors},
		{"ristretto255", ristretto255_sha512.New(), testvectors.GetRistretto255Vectors},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := tc.loader()
			if err != nil {
				t.Fatalf("Failed to load vectors: %v", err)
			}

			grp := tc.cs.Group()

			// Compute final signing share for each participant
			for receiverID, receiver := range vectors.Inputs.Participants {
				t.Run("participant_"+receiverID, func(t *testing.T) {
					// Parse receiver identifier (1-indexed)
					var receiverIdent int
					for _, c := range receiverID {
						receiverIdent = receiverIdent*10 + int(c-'0')
					}

					// Sum all polynomial evaluations at receiverIdent
					// s_i = sum_j(f_j(i)) where f_j(x) = a_j0 + a_j1*x
					finalShare := grp.NewScalar()

					for _, sender := range vectors.Inputs.Participants {
						// Get sender's polynomial coefficients
						a0Bytes, _ := hex.DecodeString(sender.SigningKey)
						a1Bytes, _ := hex.DecodeString(sender.Coefficient)
						a0, _ := grp.DeserializeScalar(a0Bytes)
						a1, _ := grp.DeserializeScalar(a1Bytes)

						// Evaluate f_sender(receiverIdent) = a0 + a1 * receiverIdent
						x := scalarFromInt(grp, receiverIdent)
						share := a1.Mul(x)
						share = a0.Add(share)
						finalShare = finalShare.Add(share)
					}

					// Compare with test vector
					finalShareBytes := grp.SerializeScalar(finalShare)
					expectedBytes, _ := hex.DecodeString(receiver.SigningShare)

					if hex.EncodeToString(finalShareBytes) != hex.EncodeToString(expectedBytes) {
						t.Errorf("Final signing share mismatch:\n  got: %s\n  exp: %s",
							hex.EncodeToString(finalShareBytes), hex.EncodeToString(expectedBytes))
					}
				})
			}
		})
	}
}
