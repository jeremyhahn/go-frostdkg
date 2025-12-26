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

// Package libp2p_test contains integration tests for libp2p transport
package libp2p_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/libp2p"
	"github.com/jeremyhahn/go-frostdkg/test/integration/api"
)

const (
	defaultCiphersuite = "FROST-ED25519-SHA512-v1"
	testTimeout        = 2 * time.Minute
)

// TestLibp2p_2of3_Threshold tests 2-of-3 threshold DKG using libp2p transport.
func TestLibp2p_2of3_Threshold(t *testing.T) {
	const (
		threshold       = 2
		numParticipants = 3
	)

	ctx := context.Background()
	cleanup := api.NewCleanupManager()
	defer cleanup.Cleanup()

	sessionID := api.GenerateSessionID()

	// Generate host keys
	hostSeckeys, hostPubkeys, err := api.GenerateHostKeys(numParticipants)
	if err != nil {
		t.Fatalf("Failed to generate host keys: %v", err)
	}

	// Create coordinator
	coord, address, err := createLibp2pCoordinator(sessionID, threshold, numParticipants, defaultCiphersuite)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}
	cleanup.AddCoordinator(coord)

	// Start coordinator
	if err := coord.Start(ctx); err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	// Create participants
	participants, err := createLibp2pParticipants(numParticipants, defaultCiphersuite)
	if err != nil {
		t.Fatalf("Failed to create participants: %v", err)
	}

	for _, p := range participants {
		cleanup.AddParticipant(p)
	}

	// Connect participants
	for i, p := range participants {
		if err := p.Connect(ctx, address); err != nil {
			t.Fatalf("Participant %d failed to connect: %v", i, err)
		}
	}

	// Generate DKG params
	params := make([]*transport.DKGParams, numParticipants)
	for i := 0; i < numParticipants; i++ {
		params[i], err = api.GenerateDKGParams(i, threshold, hostSeckeys, hostPubkeys)
		if err != nil {
			t.Fatalf("Failed to generate params for participant %d: %v", i, err)
		}
	}

	// Run DKG
	dkgRunner := api.NewConcurrentDKGRunner(testTimeout)
	results, err := dkgRunner.RunParticipants(ctx, participants, params)
	if err != nil {
		t.Fatalf("DKG execution failed: %v", err)
	}

	if len(results) != numParticipants {
		t.Fatalf("Expected %d results, got %d", numParticipants, len(results))
	}

	// Verify each result
	for i, result := range results {
		verifyAction := &api.VerifyResultAction{
			Result:          result,
			ExpectedSession: sessionID,
			NumParticipants: numParticipants,
		}

		if err := verifyAction.Execute(ctx); err != nil {
			t.Fatalf("Result %d verification failed: %v", i, err)
		}
	}

	// Compare results across participants
	compareAction := &api.CompareResultsAction{
		Results: results,
	}

	if err := compareAction.Execute(ctx); err != nil {
		t.Fatalf("Result comparison failed: %v", err)
	}

	t.Logf("libp2p transport 2-of-3 DKG completed successfully")
}

// TestLibp2p_3of5_Threshold tests 3-of-5 threshold DKG using libp2p transport.
func TestLibp2p_3of5_Threshold(t *testing.T) {
	const (
		threshold       = 3
		numParticipants = 5
	)

	ctx := context.Background()
	cleanup := api.NewCleanupManager()
	defer cleanup.Cleanup()

	sessionID := api.GenerateSessionID()

	// Generate host keys
	hostSeckeys, hostPubkeys, err := api.GenerateHostKeys(numParticipants)
	if err != nil {
		t.Fatalf("Failed to generate host keys: %v", err)
	}

	// Create coordinator
	coord, address, err := createLibp2pCoordinator(sessionID, threshold, numParticipants, defaultCiphersuite)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}
	cleanup.AddCoordinator(coord)

	// Start coordinator
	if err := coord.Start(ctx); err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	// Create participants
	participants, err := createLibp2pParticipants(numParticipants, defaultCiphersuite)
	if err != nil {
		t.Fatalf("Failed to create participants: %v", err)
	}

	for _, p := range participants {
		cleanup.AddParticipant(p)
	}

	// Connect participants
	for i, p := range participants {
		if err := p.Connect(ctx, address); err != nil {
			t.Fatalf("Participant %d failed to connect: %v", i, err)
		}
	}

	// Generate DKG params
	params := make([]*transport.DKGParams, numParticipants)
	for i := 0; i < numParticipants; i++ {
		params[i], err = api.GenerateDKGParams(i, threshold, hostSeckeys, hostPubkeys)
		if err != nil {
			t.Fatalf("Failed to generate params for participant %d: %v", i, err)
		}
	}

	// Run DKG
	dkgRunner := api.NewConcurrentDKGRunner(testTimeout)
	results, err := dkgRunner.RunParticipants(ctx, participants, params)
	if err != nil {
		t.Fatalf("DKG execution failed: %v", err)
	}

	if len(results) != numParticipants {
		t.Fatalf("Expected %d results, got %d", numParticipants, len(results))
	}

	// Verify each result
	for i, result := range results {
		verifyAction := &api.VerifyResultAction{
			Result:          result,
			ExpectedSession: sessionID,
			NumParticipants: numParticipants,
		}

		if err := verifyAction.Execute(ctx); err != nil {
			t.Fatalf("Result %d verification failed: %v", i, err)
		}
	}

	// Compare results across participants
	compareAction := &api.CompareResultsAction{
		Results: results,
	}

	if err := compareAction.Execute(ctx); err != nil {
		t.Fatalf("Result comparison failed: %v", err)
	}

	t.Logf("libp2p transport 3-of-5 DKG completed successfully")
}

// TestLibp2p_ErrorCases tests error handling with libp2p transport.
func TestLibp2p_ErrorCases(t *testing.T) {
	ctx := context.Background()

	t.Run("InvalidThreshold", func(t *testing.T) {
		sessionID := api.GenerateSessionID()
		_, _, err := createLibp2pCoordinator(sessionID, 0, 3, defaultCiphersuite)
		if err == nil {
			t.Fatal("Expected error for invalid threshold")
		}
	})

	t.Run("Timeout", func(t *testing.T) {
		cleanup := api.NewCleanupManager()
		defer cleanup.Cleanup()

		sessionID := api.GenerateSessionID()
		coord, _, err := createLibp2pCoordinator(sessionID, 2, 3, defaultCiphersuite)
		if err != nil {
			t.Fatalf("Failed to create coordinator: %v", err)
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
}

// Helper functions

// createLibp2pCoordinator creates a libp2p-based coordinator for testing.
func createLibp2pCoordinator(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
) (transport.Coordinator, string, error) {
	sessionConfig := &transport.SessionConfig{
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     ciphersuite,
		Timeout:         5 * time.Minute,
	}

	coordCfg := libp2p.DefaultHostConfig()
	coordCfg.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}

	coord, err := libp2p.NewP2PCoordinator(sessionID, sessionConfig, coordCfg)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create coordinator: %w", err)
	}

	// Get address (available after coordinator is created)
	address := coord.Address()

	return coord, address, nil
}

// createLibp2pParticipants creates n libp2p-based participants for testing.
func createLibp2pParticipants(n int, ciphersuite string) ([]transport.Participant, error) {
	if n < 1 {
		return nil, fmt.Errorf("n must be >= 1")
	}

	participants := make([]transport.Participant, n)

	for i := 0; i < n; i++ {
		partCfg := libp2p.DefaultHostConfig()
		partCfg.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}

		participant, err := libp2p.NewP2PParticipant(partCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create participant %d: %w", i, err)
		}

		participants[i] = participant
	}

	return participants, nil
}
