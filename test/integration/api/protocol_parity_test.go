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

//go:build integration

package api

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/memory"
)

// TransportFactory creates a coordinator and participants for a specific transport.
type TransportFactory func(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
	cleanup *CleanupManager,
) (transport.Coordinator, []transport.Participant, string, error)

// createMemoryTransport creates memory transport coordinator and participants.
func createMemoryTransport(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
	cleanup *CleanupManager,
) (transport.Coordinator, []transport.Participant, string, error) {
	coord, err := CreateMemoryCoordinator(sessionID, threshold, numParticipants, ciphersuite)
	if err != nil {
		return nil, nil, "", err
	}

	memCoord := coord.(*memory.MemoryCoordinator)
	participants, err := CreateMemoryParticipants(numParticipants, memCoord)
	if err != nil {
		return nil, nil, "", err
	}

	return coord, participants, sessionID, nil
}

// createGRPCTransport creates gRPC transport coordinator and participants.
func createGRPCTransport(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
	cleanup *CleanupManager,
) (transport.Coordinator, []transport.Participant, string, error) {
	certs, err := GenerateTestCertificates()
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate certificates: %w", err)
	}
	cleanup.AddCertificates(certs)

	coord, address, err := CreateGRPCCoordinator(sessionID, threshold, numParticipants, ciphersuite, certs)
	if err != nil {
		return nil, nil, "", err
	}

	participants, err := CreateGRPCParticipants(numParticipants, certs, ciphersuite)
	if err != nil {
		return nil, nil, "", err
	}

	return coord, participants, address, nil
}

// createHTTPTransport creates HTTP transport coordinator and participants.
func createHTTPTransport(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
	cleanup *CleanupManager,
) (transport.Coordinator, []transport.Participant, string, error) {
	certs, err := GenerateTestCertificates()
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate certificates: %w", err)
	}
	cleanup.AddCertificates(certs)

	coord, address, err := CreateHTTPCoordinator(sessionID, threshold, numParticipants, ciphersuite, certs)
	if err != nil {
		return nil, nil, "", err
	}

	participants, err := CreateHTTPParticipants(numParticipants, certs, ciphersuite)
	if err != nil {
		return nil, nil, "", err
	}

	return coord, participants, address, nil
}

// createQUICTransport creates QUIC transport coordinator and participants.
func createQUICTransport(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
	cleanup *CleanupManager,
) (transport.Coordinator, []transport.Participant, string, error) {
	certs, err := GenerateTestCertificates()
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate certificates: %w", err)
	}
	cleanup.AddCertificates(certs)

	coord, address, err := CreateQUICCoordinator(sessionID, threshold, numParticipants, ciphersuite, certs)
	if err != nil {
		return nil, nil, "", err
	}

	participants, err := CreateQUICParticipants(numParticipants, certs, ciphersuite)
	if err != nil {
		return nil, nil, "", err
	}

	return coord, participants, address, nil
}

// createUnixTransport creates Unix socket transport coordinator and participants.
func createUnixTransport(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
	cleanup *CleanupManager,
) (transport.Coordinator, []transport.Participant, string, error) {
	coord, socketPath, err := CreateUnixCoordinator(sessionID, threshold, numParticipants, ciphersuite)
	if err != nil {
		return nil, nil, "", err
	}

	// Add cleanup for socket file
	cleanup.Add(func() error {
		return os.Remove(socketPath)
	})

	participants, err := CreateUnixParticipants(numParticipants, ciphersuite)
	if err != nil {
		return nil, nil, "", err
	}

	return coord, participants, socketPath, nil
}

// TestProtocolParity_2of3_Threshold tests 2-of-3 threshold DKG across all transports.
// This ensures all transport implementations are functionally equivalent.
func TestProtocolParity_2of3_Threshold(t *testing.T) {
	const (
		threshold       = 2
		numParticipants = 3
		ciphersuite     = "FROST-ED25519-SHA512-v1"
	)

	testCases := []struct {
		name    string
		factory TransportFactory
	}{
		{"Memory", createMemoryTransport},
		{"gRPC", createGRPCTransport},
		{"HTTP", createHTTPTransport},
		{"QUIC", createQUICTransport},
		{"Unix", createUnixTransport},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runDKGTest(t, threshold, numParticipants, ciphersuite, tc.factory)
		})
	}
}

// TestProtocolParity_3of5_Threshold tests 3-of-5 threshold DKG across all transports.
func TestProtocolParity_3of5_Threshold(t *testing.T) {
	const (
		threshold       = 3
		numParticipants = 5
		ciphersuite     = "FROST-ED25519-SHA512-v1"
	)

	testCases := []struct {
		name    string
		factory TransportFactory
	}{
		{"Memory", createMemoryTransport},
		{"gRPC", createGRPCTransport},
		{"HTTP", createHTTPTransport},
		{"QUIC", createQUICTransport},
		{"Unix", createUnixTransport},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runDKGTest(t, threshold, numParticipants, ciphersuite, tc.factory)
		})
	}
}

// TestProtocolParity_ErrorCases tests error handling across all transports.
func TestProtocolParity_ErrorCases(t *testing.T) {
	testCases := []struct {
		name    string
		factory TransportFactory
	}{
		{"Memory", createMemoryTransport},
		{"gRPC", createGRPCTransport},
		{"HTTP", createHTTPTransport},
		{"QUIC", createQUICTransport},
		{"Unix", createUnixTransport},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("InvalidThreshold", func(t *testing.T) {
				cleanup := NewCleanupManager()
				defer cleanup.Cleanup()

				sessionID := GenerateSessionID()
				_, _, _, err := tc.factory(sessionID, 0, 3, "FROST-ED25519-SHA512-v1", cleanup)
				if err == nil {
					t.Fatal("Expected error for invalid threshold")
				}
			})

			t.Run("ThresholdTooHigh", func(t *testing.T) {
				cleanup := NewCleanupManager()
				defer cleanup.Cleanup()

				sessionID := GenerateSessionID()
				_, _, _, err := tc.factory(sessionID, 5, 3, "FROST-ED25519-SHA512-v1", cleanup)
				if err == nil {
					t.Fatal("Expected error for threshold > n")
				}
			})

			t.Run("Timeout", func(t *testing.T) {
				ctx := context.Background()
				cleanup := NewCleanupManager()
				defer cleanup.Cleanup()

				sessionID := GenerateSessionID()
				coord, _, _, err := tc.factory(sessionID, 2, 3, "FROST-ED25519-SHA512-v1", cleanup)
				if err != nil {
					t.Fatalf("Failed to create transport: %v", err)
				}
				cleanup.AddCoordinator(coord)

				if err := coord.Start(ctx); err != nil {
					t.Fatalf("Failed to start coordinator: %v", err)
				}

				// Wait with short timeout (should timeout)
				timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()

				err = coord.WaitForParticipants(timeoutCtx, 3)
				if err == nil {
					t.Fatal("Expected timeout error")
				}
			})
		})
	}
}

// runDKGTest is a helper that runs a complete DKG test for any transport.
func runDKGTest(
	t *testing.T,
	threshold int,
	numParticipants int,
	ciphersuite string,
	factory TransportFactory,
) {
	t.Helper()

	ctx := context.Background()
	cleanup := NewCleanupManager()
	defer cleanup.Cleanup()

	// Generate session ID
	sessionID := GenerateSessionID()

	// Generate host keys
	hostSeckeys, hostPubkeys, err := GenerateHostKeys(numParticipants)
	if err != nil {
		t.Fatalf("Failed to generate host keys: %v", err)
	}

	// Create transport-specific coordinator and participants
	coord, participants, address, err := factory(sessionID, threshold, numParticipants, ciphersuite, cleanup)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}

	cleanup.AddCoordinator(coord)
	for _, p := range participants {
		cleanup.AddParticipant(p)
	}

	// Start coordinator
	if err := coord.Start(ctx); err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	// Connect all participants
	for i, p := range participants {
		if err := p.Connect(ctx, address); err != nil {
			t.Fatalf("Participant %d failed to connect: %v", i, err)
		}
	}

	// Note: We don't call WaitForParticipants here because for non-memory transports,
	// participants don't register with the session until they send a join message
	// during RunDKG. The individual transport tests also don't use WaitForParticipants.

	// Create DKG params for each participant
	params := make([]*transport.DKGParams, numParticipants)
	for i := 0; i < numParticipants; i++ {
		params[i], err = GenerateDKGParams(i, threshold, hostSeckeys, hostPubkeys)
		if err != nil {
			t.Fatalf("Failed to generate params for participant %d: %v", i, err)
		}
	}

	// Run DKG for all participants concurrently
	dkgRunner := NewConcurrentDKGRunner(2 * time.Minute)
	results, err := dkgRunner.RunParticipants(ctx, participants, params)
	if err != nil {
		t.Fatalf("DKG execution failed: %v", err)
	}

	// Verify we got results for all participants
	if len(results) != numParticipants {
		t.Fatalf("Expected %d results, got %d", numParticipants, len(results))
	}

	// Verify each result
	for i, result := range results {
		verifyAction := &VerifyResultAction{
			Result:          result,
			ExpectedSession: sessionID,
			NumParticipants: numParticipants,
		}

		if err := verifyAction.Execute(ctx); err != nil {
			t.Fatalf("Result %d verification failed: %v", i, err)
		}
	}

	// Compare results across participants
	compareAction := &CompareResultsAction{
		Results: results,
	}

	if err := compareAction.Execute(ctx); err != nil {
		t.Fatalf("Result comparison failed: %v", err)
	}

	t.Logf("DKG %d-of-%d completed successfully", threshold, numParticipants)
}
