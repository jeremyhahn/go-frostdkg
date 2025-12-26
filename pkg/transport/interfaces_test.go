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

package transport

import (
	"testing"
)

// TestProtocolConstants verifies that protocol constants are defined correctly.
func TestProtocolConstants(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		expected string
	}{
		{"gRPC", ProtocolGRPC, "grpc"},
		{"HTTP", ProtocolHTTP, "http"},
		{"QUIC", ProtocolQUIC, "quic"},
		{"libp2p", ProtocolLibp2p, "libp2p"},
		{"MCP", ProtocolMCP, "mcp"},
		{"Unix", ProtocolUnix, "unix"},
		{"Memory", ProtocolMemory, "memory"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.protocol) != tt.expected {
				t.Errorf("Protocol constant mismatch: got %s, want %s", tt.protocol, tt.expected)
			}
		})
	}
}

// TestDKGParamsValidation tests basic DKGParams structure validation.
func TestDKGParamsValidation(t *testing.T) {
	validParams := &DKGParams{
		HostSeckey:     make([]byte, SecretKeySize),
		HostPubkeys:    [][]byte{make([]byte, PublicKeySize), make([]byte, PublicKeySize), make([]byte, PublicKeySize)},
		Threshold:      2,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	// Test valid params structure (no validation method yet, just ensure it can be created)
	if validParams.Threshold < 1 || validParams.Threshold > len(validParams.HostPubkeys) {
		t.Error("Valid params should have threshold in valid range")
	}

	if validParams.ParticipantIdx < 0 || validParams.ParticipantIdx >= len(validParams.HostPubkeys) {
		t.Error("Valid params should have participant index in valid range")
	}

	if len(validParams.HostSeckey) != 32 {
		t.Error("Host secret key should be 32 bytes")
	}

	if len(validParams.Random) != 32 {
		t.Error("Random should be 32 bytes")
	}
}

// TestDKGParamsInvalidThreshold tests DKGParams with invalid threshold.
func TestDKGParamsInvalidThreshold(t *testing.T) {
	tests := []struct {
		name       string
		threshold  int
		numKeys    int
		shouldFail bool
	}{
		{"threshold=0", 0, 3, true},
		{"threshold=1", 1, 3, false},
		{"threshold=2", 2, 3, false},
		{"threshold=3", 3, 3, false},
		{"threshold>n", 4, 3, true},
		{"negative threshold", -1, 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := &DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    make([][]byte, tt.numKeys),
				Threshold:      tt.threshold,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			}

			// Initialize host pubkeys
			for i := 0; i < tt.numKeys; i++ {
				params.HostPubkeys[i] = make([]byte, PublicKeySize)
			}

			// Manual validation (since we haven't implemented Validate() yet)
			isValid := params.Threshold >= 1 && params.Threshold <= len(params.HostPubkeys)

			if tt.shouldFail && isValid {
				t.Error("Expected invalid threshold to fail validation")
			}
			if !tt.shouldFail && !isValid {
				t.Error("Expected valid threshold to pass validation")
			}
		})
	}
}

// TestDKGParamsInvalidParticipantIndex tests DKGParams with invalid participant index.
func TestDKGParamsInvalidParticipantIndex(t *testing.T) {
	tests := []struct {
		name       string
		index      int
		numKeys    int
		shouldFail bool
	}{
		{"negative index", -1, 3, true},
		{"index=0", 0, 3, false},
		{"index=1", 1, 3, false},
		{"index=n-1", 2, 3, false},
		{"index=n", 3, 3, true},
		{"index>n", 5, 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := &DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    make([][]byte, tt.numKeys),
				Threshold:      2,
				ParticipantIdx: tt.index,
				Random:         make([]byte, 32),
			}

			// Initialize host pubkeys
			for i := 0; i < tt.numKeys; i++ {
				params.HostPubkeys[i] = make([]byte, PublicKeySize)
			}

			// Manual validation
			isValid := params.ParticipantIdx >= 0 && params.ParticipantIdx < len(params.HostPubkeys)

			if tt.shouldFail && isValid {
				t.Error("Expected invalid participant index to fail validation")
			}
			if !tt.shouldFail && !isValid {
				t.Error("Expected valid participant index to pass validation")
			}
		})
	}
}

// TestDKGParamsInvalidKeyLengths tests DKGParams with invalid key lengths.
func TestDKGParamsInvalidKeyLengths(t *testing.T) {
	tests := []struct {
		name          string
		hostSeckeyLen int
		randomLen     int
		shouldFail    bool
	}{
		{"valid lengths", 32, 32, false},
		{"short host seckey", 16, 32, true},
		{"long host seckey", 64, 32, true},
		{"short random", 32, 16, true},
		{"long random", 32, 64, true},
		{"empty host seckey", 0, 32, true},
		{"empty random", 32, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := &DKGParams{
				HostSeckey:     make([]byte, tt.hostSeckeyLen),
				HostPubkeys:    [][]byte{make([]byte, PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         make([]byte, tt.randomLen),
			}

			// Manual validation
			isValid := len(params.HostSeckey) == 32 && len(params.Random) == 32

			if tt.shouldFail && isValid {
				t.Error("Expected invalid key lengths to fail validation")
			}
			if !tt.shouldFail && !isValid {
				t.Error("Expected valid key lengths to pass validation")
			}
		})
	}
}

// TestDKGResultStructure tests basic DKGResult structure.
func TestDKGResultStructure(t *testing.T) {
	result := &DKGResult{
		SecretShare:     make([]byte, SecretKeySize),
		ThresholdPubkey: make([]byte, PublicKeySize),
		PublicShares:    [][]byte{make([]byte, PublicKeySize), make([]byte, PublicKeySize)},
		SessionID:       "test-session-123",
		RecoveryData:    make([]byte, 100),
	}

	if len(result.SecretShare) != 32 {
		t.Error("Secret share should be 32 bytes")
	}

	if len(result.ThresholdPubkey) != PublicKeySize {
		t.Errorf("Threshold pubkey should be %d bytes (x-only)", PublicKeySize)
	}

	if len(result.PublicShares) != 2 {
		t.Error("Expected 2 public shares")
	}

	if result.SessionID == "" {
		t.Error("Session ID should not be empty")
	}
}

// TestSessionConfigValidation tests basic SessionConfig validation.
func TestSessionConfigValidation(t *testing.T) {
	validConfig := &SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
		Timeout:         DefaultSessionTimeout,
	}

	// Manual validation (since Validate() will be tested in config_test.go)
	if validConfig.Threshold < 1 || validConfig.Threshold > validConfig.NumParticipants {
		t.Error("Valid config should have threshold in valid range")
	}

	if validConfig.NumParticipants < 1 {
		t.Error("Valid config should have at least 1 participant")
	}

	if validConfig.Ciphersuite == "" {
		t.Error("Ciphersuite should not be empty")
	}
}

// TestSessionConfigInvalidThreshold tests SessionConfig with invalid threshold.
func TestSessionConfigInvalidThreshold(t *testing.T) {
	tests := []struct {
		name       string
		threshold  int
		numParts   int
		shouldFail bool
	}{
		{"threshold=0", 0, 3, true},
		{"threshold=1", 1, 3, false},
		{"threshold=n", 3, 3, false},
		{"threshold>n", 4, 3, true},
		{"negative threshold", -1, 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &SessionConfig{
				Threshold:       tt.threshold,
				NumParticipants: tt.numParts,
				Ciphersuite:     "test",
				Timeout:         DefaultSessionTimeout,
			}

			isValid := cfg.Threshold >= 1 && cfg.Threshold <= cfg.NumParticipants

			if tt.shouldFail && isValid {
				t.Error("Expected invalid threshold to fail validation")
			}
			if !tt.shouldFail && !isValid {
				t.Error("Expected valid threshold to pass validation")
			}
		})
	}
}
