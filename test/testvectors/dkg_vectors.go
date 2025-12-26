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

// Package testvectors provides RFC 9591 DKG test vectors for FROST ciphersuites.
//
// This package embeds the official FROST DKG test vectors from the reference
// implementation and provides Go structs and functions to access them for testing
// purposes. The test vectors include configuration, participant data, signing keys,
// VSS commitments, and proofs of knowledge for multiple ciphersuites.
//
// Supported ciphersuites:
//
// - Ed25519 with SHA-512
// - Ed448 with SHAKE256
// - P-256 with SHA-256
// - ristretto255 with SHA-512
// - secp256k1 with SHA-256
package testvectors

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed vectors_ed25519.json
//go:embed vectors_ed448.json
//go:embed vectors_p256.json
//go:embed vectors_ristretto255.json
//go:embed vectors_secp256k1.json
var vectorsFS embed.FS

// Config represents the configuration section of the DKG test vectors.
type Config struct {
	// MaxParticipants is the maximum number of participants in the DKG protocol.
	MaxParticipants int `json:"MAX_PARTICIPANTS"`

	// MinParticipants is the minimum number of participants required for threshold signing.
	MinParticipants int `json:"MIN_PARTICIPANTS"`

	// Name is the human-readable name of the ciphersuite (e.g., "FROST(Ed25519, SHA-512)").
	Name string `json:"name"`

	// Group is the cryptographic group identifier (e.g., "ed25519", "ed25519").
	Group string `json:"group"`

	// Hash is the hash function used (e.g., "SHA-256", "SHA-512", "SHAKE256").
	Hash string `json:"hash"`
}

// ParticipantData contains all test data for a single DKG participant.
type ParticipantData struct {
	// Identifier is the unique participant ID (1-indexed).
	Identifier int `json:"identifier"`

	// SigningKey is the participant's secret signing key (hex-encoded).
	SigningKey string `json:"signing_key"`

	// Coefficient is the secret polynomial coefficient for this participant (hex-encoded).
	Coefficient string `json:"coefficient"`

	// VSSCommitments are the Verifiable Secret Sharing commitment values (hex-encoded).
	VSSCommitments []string `json:"vss_commitments"`

	// ProofOfKnowledge is the Schnorr proof of knowledge for the secret (hex-encoded).
	ProofOfKnowledge string `json:"proof_of_knowledge"`

	// SigningShares maps participant IDs to the shares this participant sends them (hex-encoded).
	SigningShares map[string]string `json:"signing_shares"`

	// VerifyingShare is the public verification share for this participant (hex-encoded).
	VerifyingShare string `json:"verifying_share"`

	// SigningShare is the final signing share this participant receives (hex-encoded).
	SigningShare string `json:"signing_share"`

	// Secret is an optional secret value for certain ciphersuites (hex-encoded).
	Secret string `json:"secret,omitempty"`
}

// Inputs contains all participant data and the group verifying key.
type Inputs struct {
	// VerifyingKey is the group's public verifying key (hex-encoded).
	VerifyingKey string `json:"verifying_key"`

	// Secret is an optional shared secret for certain ciphersuites (hex-encoded).
	Secret string `json:"secret,omitempty"`

	// Participants maps participant IDs (as strings) to their test data.
	// Note: JSON requires string keys, so participant IDs are string representations.
	Participants map[string]ParticipantData `json:"-"`
}

// UnmarshalJSON implements custom unmarshaling to handle the mixed structure
// where participant data and metadata coexist at the same level.
func (i *Inputs) UnmarshalJSON(data []byte) error {
	// First unmarshal into a temporary map to separate participant data from metadata
	var temp map[string]json.RawMessage
	if err := json.Unmarshal(data, &temp); err != nil {
		return fmt.Errorf("failed to unmarshal inputs: %w", err)
	}

	// Extract top-level fields
	if verifyingKeyData, ok := temp["verifying_key"]; ok {
		if err := json.Unmarshal(verifyingKeyData, &i.VerifyingKey); err != nil {
			return fmt.Errorf("failed to unmarshal verifying_key: %w", err)
		}
	}

	if secretData, ok := temp["secret"]; ok {
		if err := json.Unmarshal(secretData, &i.Secret); err != nil {
			return fmt.Errorf("failed to unmarshal secret: %w", err)
		}
	}

	// Extract participant data (any numeric string key)
	i.Participants = make(map[string]ParticipantData)
	for key, rawMsg := range temp {
		// Skip non-participant keys
		if key == "verifying_key" || key == "secret" {
			continue
		}

		var participant ParticipantData
		if err := json.Unmarshal(rawMsg, &participant); err != nil {
			return fmt.Errorf("failed to unmarshal participant %s: %w", key, err)
		}
		i.Participants[key] = participant
	}

	return nil
}

// DKGVectors represents the complete DKG test vector structure.
type DKGVectors struct {
	// Config contains the ciphersuite configuration.
	Config Config `json:"config"`

	// Inputs contains all participant data and the group verifying key.
	Inputs Inputs `json:"inputs"`
}

// GetEd25519Vectors loads and returns the Ed25519 DKG test vectors.
//
// The vectors are for FROST(Ed25519, SHA-512) with 3 max participants
// and a 2-of-3 threshold.
func GetEd25519Vectors() (*DKGVectors, error) {
	return loadVectors("vectors_ed25519.json")
}

// GetEd448Vectors loads and returns the Ed448 DKG test vectors.
//
// The vectors are for FROST(Ed448, SHAKE256) with 3 max participants
// and a 2-of-3 threshold.
func GetEd448Vectors() (*DKGVectors, error) {
	return loadVectors("vectors_ed448.json")
}

// GetP256Vectors loads and returns the P-256 DKG test vectors.
//
// The vectors are for FROST(P-256, SHA-256) with 3 max participants
// and a 2-of-3 threshold.
func GetP256Vectors() (*DKGVectors, error) {
	return loadVectors("vectors_p256.json")
}

// GetRistretto255Vectors loads and returns the ristretto255 DKG test vectors.
//
// The vectors are for FROST(Ed25519, SHA-512) using the ristretto255 group
// with 3 max participants and a 2-of-3 threshold.
func GetRistretto255Vectors() (*DKGVectors, error) {
	return loadVectors("vectors_ristretto255.json")
}

// GetSecp256k1Vectors loads and returns the secp256k1 DKG test vectors.
//
// The vectors are for FROST(secp256k1, SHA-256) with 3 max participants
// and a 2-of-3 threshold.
func GetSecp256k1Vectors() (*DKGVectors, error) {
	return loadVectors("vectors_secp256k1.json")
}

// loadVectors is an internal helper that loads and parses a test vector JSON file.
func loadVectors(filename string) (*DKGVectors, error) {
	data, err := vectorsFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read vector file %s: %w", filename, err)
	}

	var vectors DKGVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vectors from %s: %w", filename, err)
	}

	return &vectors, nil
}
