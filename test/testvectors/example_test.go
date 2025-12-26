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

package testvectors_test

import (
	"encoding/hex"
	"fmt"
	"log"
	"sort"

	"github.com/jeremyhahn/go-frostdkg/test/testvectors"
)

// ExampleGetEd25519Vectors demonstrates how to load and use Ed25519 test vectors.
func ExampleGetEd25519Vectors() {
	// Load the Ed25519 test vectors
	vectors, err := testvectors.GetEd25519Vectors()
	if err != nil {
		log.Fatalf("failed to load vectors: %v", err)
	}

	// Access configuration
	fmt.Printf("Ciphersuite: %s\n", vectors.Config.Name)
	fmt.Printf("Threshold: %d-of-%d\n", vectors.Config.MinParticipants, vectors.Config.MaxParticipants)

	// Access participant data
	participant := vectors.Inputs.Participants["1"]

	// Decode and display hex-encoded values
	signingKey, _ := hex.DecodeString(participant.SigningKey)
	fmt.Printf("Participant 1 signing key length: %d bytes\n", len(signingKey))

	vssCommitment, _ := hex.DecodeString(participant.VSSCommitments[0])
	fmt.Printf("First VSS commitment length: %d bytes\n", len(vssCommitment))

	// Output:
	// Ciphersuite: FROST(Ed25519, SHA-512)
	// Threshold: 2-of-3
	// Participant 1 signing key length: 32 bytes
	// First VSS commitment length: 32 bytes
}

// ExampleGetEd448Vectors demonstrates how to load and use Ed448 test vectors.
func ExampleGetEd448Vectors() {
	// Load the Ed448 test vectors
	vectors, err := testvectors.GetEd448Vectors()
	if err != nil {
		log.Fatalf("failed to load vectors: %v", err)
	}

	// Display ciphersuite information
	fmt.Printf("Group: %s\n", vectors.Config.Group)
	fmt.Printf("Hash: %s\n", vectors.Config.Hash)

	// Count participants
	fmt.Printf("Number of participants: %d\n", len(vectors.Inputs.Participants))

	// Output:
	// Group: ed448
	// Hash: SHAKE256
	// Number of participants: 3
}

// ExampleDKGVectors_iterateParticipants demonstrates how to iterate over all participants.
func ExampleDKGVectors_iterateParticipants() {
	vectors, err := testvectors.GetP256Vectors()
	if err != nil {
		log.Fatalf("failed to load vectors: %v", err)
	}

	// Get sorted list of participant IDs for deterministic output
	participantIDs := make([]string, 0, len(vectors.Inputs.Participants))
	for id := range vectors.Inputs.Participants {
		participantIDs = append(participantIDs, id)
	}
	sort.Strings(participantIDs)

	// Iterate through participants in sorted order
	for _, id := range participantIDs {
		participant := vectors.Inputs.Participants[id]
		fmt.Printf("Participant %s has %d VSS commitments\n", id, len(participant.VSSCommitments))
	}

	// Output:
	// Participant 1 has 2 VSS commitments
	// Participant 2 has 2 VSS commitments
	// Participant 3 has 2 VSS commitments
}
