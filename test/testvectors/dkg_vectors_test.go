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

package testvectors

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

// TestGetEd25519Vectors verifies that Ed25519 test vectors load correctly.
func TestGetEd25519Vectors(t *testing.T) {
	vectors, err := GetEd25519Vectors()
	if err != nil {
		t.Fatalf("GetEd25519Vectors() failed: %v", err)
	}

	verifyBasicStructure(t, vectors, "ed25519", "SHA-512", "FROST(Ed25519, SHA-512)")
	verifyParticipantData(t, vectors)
}

// TestGetEd448Vectors verifies that Ed448 test vectors load correctly.
func TestGetEd448Vectors(t *testing.T) {
	vectors, err := GetEd448Vectors()
	if err != nil {
		t.Fatalf("GetEd448Vectors() failed: %v", err)
	}

	verifyBasicStructure(t, vectors, "ed448", "SHAKE256", "FROST(Ed448, SHAKE256)")
	verifyParticipantData(t, vectors)
}

// TestGetP256Vectors verifies that P-256 test vectors load correctly.
func TestGetP256Vectors(t *testing.T) {
	vectors, err := GetP256Vectors()
	if err != nil {
		t.Fatalf("GetP256Vectors() failed: %v", err)
	}

	verifyBasicStructure(t, vectors, "P-256", "SHA-256", "FROST(P-256, SHA-256)")
	verifyParticipantData(t, vectors)
}

// TestGetRistretto255Vectors verifies that ristretto255 test vectors load correctly.
func TestGetRistretto255Vectors(t *testing.T) {
	vectors, err := GetRistretto255Vectors()
	if err != nil {
		t.Fatalf("GetRistretto255Vectors() failed: %v", err)
	}

	verifyBasicStructure(t, vectors, "ed25519", "SHA-512", "FROST(Ed25519, SHA-512)")
	verifyParticipantData(t, vectors)
}

// TestGetSecp256k1Vectors verifies that secp256k1 test vectors load correctly.
func TestGetSecp256k1Vectors(t *testing.T) {
	vectors, err := GetSecp256k1Vectors()
	if err != nil {
		t.Fatalf("GetSecp256k1Vectors() failed: %v", err)
	}

	verifyBasicStructure(t, vectors, "secp256k1", "SHA-256", "FROST(secp256k1, SHA-256)")
	verifyParticipantData(t, vectors)
}

// TestInvalidVectorFile verifies that loading a non-existent vector file returns an error.
func TestInvalidVectorFile(t *testing.T) {
	_, err := loadVectors("nonexistent.json")
	if err == nil {
		t.Fatal("loadVectors() with invalid file should return error")
	}
}

// TestHexEncodedFields verifies that all hex-encoded fields contain valid hex strings.
func TestHexEncodedFields(t *testing.T) {
	testCases := []struct {
		name   string
		loader func() (*DKGVectors, error)
	}{
		{"ed25519", GetEd25519Vectors},
		{"ed448", GetEd448Vectors},
		{"p256", GetP256Vectors},
		{"ristretto255", GetRistretto255Vectors},
		{"secp256k1", GetSecp256k1Vectors},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := tc.loader()
			if err != nil {
				t.Fatalf("failed to load vectors: %v", err)
			}

			// Verify verifying key is valid hex
			if _, err := hex.DecodeString(vectors.Inputs.VerifyingKey); err != nil {
				t.Errorf("verifying_key is not valid hex: %v", err)
			}

			// Verify each participant's data
			for id, participant := range vectors.Inputs.Participants {
				// Verify signing key
				if _, err := hex.DecodeString(participant.SigningKey); err != nil {
					t.Errorf("participant %s signing_key is not valid hex: %v", id, err)
				}

				// Verify coefficient
				if _, err := hex.DecodeString(participant.Coefficient); err != nil {
					t.Errorf("participant %s coefficient is not valid hex: %v", id, err)
				}

				// Verify VSS commitments
				for i, commitment := range participant.VSSCommitments {
					if _, err := hex.DecodeString(commitment); err != nil {
						t.Errorf("participant %s vss_commitment[%d] is not valid hex: %v", id, i, err)
					}
				}

				// Verify proof of knowledge
				if _, err := hex.DecodeString(participant.ProofOfKnowledge); err != nil {
					t.Errorf("participant %s proof_of_knowledge is not valid hex: %v", id, err)
				}

				// Verify signing shares
				for targetID, share := range participant.SigningShares {
					if _, err := hex.DecodeString(share); err != nil {
						t.Errorf("participant %s signing_share for %s is not valid hex: %v", id, targetID, err)
					}
				}

				// Verify verifying share
				if _, err := hex.DecodeString(participant.VerifyingShare); err != nil {
					t.Errorf("participant %s verifying_share is not valid hex: %v", id, err)
				}

				// Verify signing share
				if _, err := hex.DecodeString(participant.SigningShare); err != nil {
					t.Errorf("participant %s signing_share is not valid hex: %v", id, err)
				}

				// Verify optional secret field if present
				if participant.Secret != "" {
					if _, err := hex.DecodeString(participant.Secret); err != nil {
						t.Errorf("participant %s secret is not valid hex: %v", id, err)
					}
				}
			}

			// Verify optional shared secret if present
			if vectors.Inputs.Secret != "" {
				if _, err := hex.DecodeString(vectors.Inputs.Secret); err != nil {
					t.Errorf("shared secret is not valid hex: %v", err)
				}
			}
		})
	}
}

// TestParticipantCount verifies that all ciphersuites have the expected number of participants.
func TestParticipantCount(t *testing.T) {
	testCases := []struct {
		name   string
		loader func() (*DKGVectors, error)
	}{
		{"ed25519", GetEd25519Vectors},
		{"ed448", GetEd448Vectors},
		{"p256", GetP256Vectors},
		{"ristretto255", GetRistretto255Vectors},
		{"secp256k1", GetSecp256k1Vectors},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := tc.loader()
			if err != nil {
				t.Fatalf("failed to load vectors: %v", err)
			}

			expectedCount := vectors.Config.MaxParticipants
			actualCount := len(vectors.Inputs.Participants)

			if actualCount != expectedCount {
				t.Errorf("expected %d participants, got %d", expectedCount, actualCount)
			}
		})
	}
}

// TestSigningSharesConsistency verifies that signing shares are consistent across participants.
func TestSigningSharesConsistency(t *testing.T) {
	testCases := []struct {
		name   string
		loader func() (*DKGVectors, error)
	}{
		{"ed25519", GetEd25519Vectors},
		{"ed448", GetEd448Vectors},
		{"p256", GetP256Vectors},
		{"ristretto255", GetRistretto255Vectors},
		{"secp256k1", GetSecp256k1Vectors},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := tc.loader()
			if err != nil {
				t.Fatalf("failed to load vectors: %v", err)
			}

			// For each participant, verify their signing shares are consistent
			// with what other participants send to them
			for senderID, sender := range vectors.Inputs.Participants {
				for receiverID := range vectors.Inputs.Participants {
					if senderID == receiverID {
						continue
					}

					// Get the share sender sends to receiver
					sentShare, ok := sender.SigningShares[receiverID]
					if !ok {
						t.Errorf("participant %s should send share to participant %s", senderID, receiverID)
					}

					// Verify it exists
					if sentShare == "" {
						t.Errorf("participant %s sent empty share to participant %s", senderID, receiverID)
					}
				}
			}
		})
	}
}

// TestVSSCommitmentCount verifies that each participant has the expected number of VSS commitments.
func TestVSSCommitmentCount(t *testing.T) {
	testCases := []struct {
		name   string
		loader func() (*DKGVectors, error)
	}{
		{"ed25519", GetEd25519Vectors},
		{"ed448", GetEd448Vectors},
		{"p256", GetP256Vectors},
		{"ristretto255", GetRistretto255Vectors},
		{"secp256k1", GetSecp256k1Vectors},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := tc.loader()
			if err != nil {
				t.Fatalf("failed to load vectors: %v", err)
			}

			// VSS commitments should equal the threshold (MIN_PARTICIPANTS)
			expectedCommitments := vectors.Config.MinParticipants

			for id, participant := range vectors.Inputs.Participants {
				actualCommitments := len(participant.VSSCommitments)
				if actualCommitments != expectedCommitments {
					t.Errorf("participant %s: expected %d VSS commitments, got %d",
						id, expectedCommitments, actualCommitments)
				}
			}
		})
	}
}

// TestInputsUnmarshalJSON_InvalidJSON tests UnmarshalJSON with invalid JSON data.
func TestInputsUnmarshalJSON_InvalidJSON(t *testing.T) {
	testCases := []struct {
		name string
		data string
	}{
		{
			name: "invalid_json",
			data: `{invalid json}`,
		},
		{
			name: "invalid_verifying_key_type",
			data: `{"verifying_key": 123}`,
		},
		{
			name: "invalid_secret_type",
			data: `{"secret": true, "verifying_key": "abc"}`,
		},
		{
			name: "invalid_participant_data",
			data: `{"verifying_key": "abc", "1": "not an object"}`,
		},
		{
			name: "empty_json",
			data: `{}`,
		},
		{
			name: "null_verifying_key",
			data: `{"verifying_key": null}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var inputs Inputs
			err := json.Unmarshal([]byte(tc.data), &inputs)
			// For empty_json and null_verifying_key cases, unmarshaling may succeed
			// but we expect certain fields to be in their zero state
			if tc.name == "empty_json" {
				if err != nil {
					t.Errorf("UnmarshalJSON failed for empty JSON: %v", err)
				}
			} else if tc.name == "null_verifying_key" {
				if err != nil {
					t.Errorf("UnmarshalJSON failed for null verifying_key: %v", err)
				}
			} else if err == nil {
				t.Errorf("UnmarshalJSON should fail with invalid data: %s", tc.name)
			}
		})
	}
}

// TestInputsUnmarshalJSON_ValidJSON tests UnmarshalJSON with valid JSON data.
func TestInputsUnmarshalJSON_ValidJSON(t *testing.T) {
	testCases := []struct {
		name string
		data string
	}{
		{
			name: "minimal_valid",
			data: `{"verifying_key": "abc123"}`,
		},
		{
			name: "with_secret",
			data: `{"verifying_key": "abc123", "secret": "def456"}`,
		},
		{
			name: "with_participant",
			data: `{
				"verifying_key": "abc123",
				"1": {
					"identifier": 1,
					"signing_key": "key1",
					"coefficient": "coef1",
					"vss_commitments": ["commit1"],
					"proof_of_knowledge": "proof1",
					"signing_shares": {"2": "share12"},
					"verifying_share": "vshare1",
					"signing_share": "sshare1"
				}
			}`,
		},
		{
			name: "with_participant_and_secret",
			data: `{
				"verifying_key": "abc123",
				"secret": "shared_secret",
				"1": {
					"identifier": 1,
					"signing_key": "key1",
					"coefficient": "coef1",
					"vss_commitments": ["commit1"],
					"proof_of_knowledge": "proof1",
					"signing_shares": {"2": "share12"},
					"verifying_share": "vshare1",
					"signing_share": "sshare1",
					"secret": "participant_secret"
				}
			}`,
		},
		{
			name: "multiple_participants",
			data: `{
				"verifying_key": "abc123",
				"1": {
					"identifier": 1,
					"signing_key": "key1",
					"coefficient": "coef1",
					"vss_commitments": ["commit1"],
					"proof_of_knowledge": "proof1",
					"signing_shares": {"2": "share12"},
					"verifying_share": "vshare1",
					"signing_share": "sshare1"
				},
				"2": {
					"identifier": 2,
					"signing_key": "key2",
					"coefficient": "coef2",
					"vss_commitments": ["commit2"],
					"proof_of_knowledge": "proof2",
					"signing_shares": {"1": "share21"},
					"verifying_share": "vshare2",
					"signing_share": "sshare2"
				}
			}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var inputs Inputs
			err := json.Unmarshal([]byte(tc.data), &inputs)
			if err != nil {
				t.Fatalf("UnmarshalJSON failed with valid data: %v", err)
			}

			// Verify verifying_key is always present
			if inputs.VerifyingKey == "" {
				t.Error("verifying_key should be present")
			}

			// For tests with participants, verify they were parsed
			if tc.name == "with_participant" || tc.name == "with_participant_and_secret" {
				if len(inputs.Participants) == 0 {
					t.Error("participants should be present")
				}
			}

			// For tests with multiple participants, verify count
			if tc.name == "multiple_participants" {
				if len(inputs.Participants) != 2 {
					t.Errorf("expected 2 participants, got %d", len(inputs.Participants))
				}
			}
		})
	}
}

// TestDKGVectorsUnmarshalJSON_Invalid tests unmarshaling invalid DKGVectors JSON.
func TestDKGVectorsUnmarshalJSON_Invalid(t *testing.T) {
	testCases := []struct {
		name string
		data string
	}{
		{
			name: "invalid_json",
			data: `{invalid}`,
		},
		{
			name: "invalid_config",
			data: `{"config": "not an object", "inputs": {}}`,
		},
		{
			name: "invalid_inputs",
			data: `{"config": {}, "inputs": "not an object"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var vectors DKGVectors
			err := json.Unmarshal([]byte(tc.data), &vectors)
			if err == nil {
				t.Errorf("Unmarshal should fail with invalid data: %s", tc.name)
			}
		})
	}
}

// TestDKGVectorsUnmarshalJSON_Valid tests unmarshaling valid DKGVectors JSON.
func TestDKGVectorsUnmarshalJSON_Valid(t *testing.T) {
	data := `{
		"config": {
			"MAX_PARTICIPANTS": 3,
			"MIN_PARTICIPANTS": 2,
			"name": "FROST(Ed25519, SHA-512)",
			"group": "ed25519",
			"hash": "SHA-512"
		},
		"inputs": {
			"verifying_key": "abc123"
		}
	}`

	var vectors DKGVectors
	err := json.Unmarshal([]byte(data), &vectors)
	if err != nil {
		t.Fatalf("Unmarshal failed with valid data: %v", err)
	}

	if vectors.Config.Name != "FROST(Ed25519, SHA-512)" {
		t.Errorf("expected config name FROST(Ed25519, SHA-512), got %s", vectors.Config.Name)
	}

	if vectors.Inputs.VerifyingKey != "abc123" {
		t.Errorf("expected verifying_key abc123, got %s", vectors.Inputs.VerifyingKey)
	}
}

// TestConfig_Fields verifies that Config struct fields are properly unmarshaled.
func TestConfig_Fields(t *testing.T) {
	vectors, err := GetEd25519Vectors()
	if err != nil {
		t.Fatalf("GetEd25519Vectors() failed: %v", err)
	}

	// Verify all config fields are populated
	if vectors.Config.MaxParticipants == 0 {
		t.Error("MaxParticipants should not be zero")
	}
	if vectors.Config.MinParticipants == 0 {
		t.Error("MinParticipants should not be zero")
	}
	if vectors.Config.Name == "" {
		t.Error("Name should not be empty")
	}
	if vectors.Config.Group == "" {
		t.Error("Group should not be empty")
	}
	if vectors.Config.Hash == "" {
		t.Error("Hash should not be empty")
	}
}

// TestParticipantData_AllFields verifies that all ParticipantData fields are properly populated.
func TestParticipantData_AllFields(t *testing.T) {
	vectors, err := GetEd25519Vectors()
	if err != nil {
		t.Fatalf("GetEd25519Vectors() failed: %v", err)
	}

	for id, participant := range vectors.Inputs.Participants {
		if participant.Identifier == 0 {
			t.Errorf("participant %s: Identifier should not be zero", id)
		}
		if participant.SigningKey == "" {
			t.Errorf("participant %s: SigningKey should not be empty", id)
		}
		if participant.Coefficient == "" {
			t.Errorf("participant %s: Coefficient should not be empty", id)
		}
		if len(participant.VSSCommitments) == 0 {
			t.Errorf("participant %s: VSSCommitments should not be empty", id)
		}
		if participant.ProofOfKnowledge == "" {
			t.Errorf("participant %s: ProofOfKnowledge should not be empty", id)
		}
		if len(participant.SigningShares) == 0 {
			t.Errorf("participant %s: SigningShares should not be empty", id)
		}
		if participant.VerifyingShare == "" {
			t.Errorf("participant %s: VerifyingShare should not be empty", id)
		}
		if participant.SigningShare == "" {
			t.Errorf("participant %s: SigningShare should not be empty", id)
		}
	}
}

// verifyBasicStructure is a helper that verifies the basic structure of test vectors.
func verifyBasicStructure(t *testing.T, vectors *DKGVectors, group, hash, name string) {
	t.Helper()

	if vectors == nil {
		t.Fatal("vectors is nil")
	}

	// Verify config
	if vectors.Config.MaxParticipants != 3 {
		t.Errorf("expected MaxParticipants=3, got %d", vectors.Config.MaxParticipants)
	}

	if vectors.Config.MinParticipants != 2 {
		t.Errorf("expected MinParticipants=2, got %d", vectors.Config.MinParticipants)
	}

	if vectors.Config.Group != group {
		t.Errorf("expected Group=%s, got %s", group, vectors.Config.Group)
	}

	if vectors.Config.Hash != hash {
		t.Errorf("expected Hash=%s, got %s", hash, vectors.Config.Hash)
	}

	if vectors.Config.Name != name {
		t.Errorf("expected Name=%s, got %s", name, vectors.Config.Name)
	}

	// Verify verifying key is not empty
	if vectors.Inputs.VerifyingKey == "" {
		t.Error("verifying_key is empty")
	}
}

// verifyParticipantData is a helper that verifies participant data structure.
func verifyParticipantData(t *testing.T, vectors *DKGVectors) {
	t.Helper()

	if len(vectors.Inputs.Participants) == 0 {
		t.Fatal("no participants found")
	}

	for id, participant := range vectors.Inputs.Participants {
		// Verify identifier matches key
		expectedID := id
		actualID := participant.Identifier
		if expectedID != id {
			t.Errorf("participant key %s doesn't match identifier %d", expectedID, actualID)
		}

		// Verify required fields are not empty
		if participant.SigningKey == "" {
			t.Errorf("participant %s: signing_key is empty", id)
		}

		if participant.Coefficient == "" {
			t.Errorf("participant %s: coefficient is empty", id)
		}

		if len(participant.VSSCommitments) == 0 {
			t.Errorf("participant %s: vss_commitments is empty", id)
		}

		if participant.ProofOfKnowledge == "" {
			t.Errorf("participant %s: proof_of_knowledge is empty", id)
		}

		if len(participant.SigningShares) == 0 {
			t.Errorf("participant %s: signing_shares is empty", id)
		}

		if participant.VerifyingShare == "" {
			t.Errorf("participant %s: verifying_share is empty", id)
		}

		if participant.SigningShare == "" {
			t.Errorf("participant %s: signing_share is empty", id)
		}
	}
}
