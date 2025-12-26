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
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/memory"
)

// TestMemoryTransport_2of3_Threshold tests 2-of-3 threshold DKG using memory transport.
func TestMemoryTransport_2of3_Threshold(t *testing.T) {
	const (
		threshold       = 2
		numParticipants = 3
		ciphersuite     = "FROST-ED25519-SHA512-v1"
	)

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

	// Create coordinator
	coord, err := CreateMemoryCoordinator(sessionID, threshold, numParticipants, ciphersuite)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}
	cleanup.AddCoordinator(coord)

	// Start coordinator
	if err := coord.Start(ctx); err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	// Get memory coordinator for creating participants
	memCoord := coord.(*memory.MemoryCoordinator)

	// Create participants
	participants, err := CreateMemoryParticipants(numParticipants, memCoord)
	if err != nil {
		t.Fatalf("Failed to create participants: %v", err)
	}

	for _, p := range participants {
		cleanup.AddParticipant(p)
	}

	// Create DKG params for each participant
	params := make([]*transport.DKGParams, numParticipants)
	for i := 0; i < numParticipants; i++ {
		params[i], err = GenerateDKGParams(i, threshold, hostSeckeys, hostPubkeys)
		if err != nil {
			t.Fatalf("Failed to generate params for participant %d: %v", i, err)
		}
	}

	// Connect all participants
	for i, p := range participants {
		if err := p.Connect(ctx, sessionID); err != nil {
			t.Fatalf("Participant %d failed to connect: %v", i, err)
		}
	}

	// Wait for all participants to connect
	if err := coord.WaitForParticipants(ctx, numParticipants); err != nil {
		t.Fatalf("Failed to wait for participants: %v", err)
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

	t.Logf("Memory transport 2-of-3 DKG completed successfully")
}

// TestMemoryTransport_3of5_Threshold tests 3-of-5 threshold DKG using memory transport.
func TestMemoryTransport_3of5_Threshold(t *testing.T) {
	const (
		threshold       = 3
		numParticipants = 5
		ciphersuite     = "FROST-ED25519-SHA512-v1"
	)

	ctx := context.Background()
	cleanup := NewCleanupManager()
	defer cleanup.Cleanup()

	sessionID := GenerateSessionID()

	hostSeckeys, hostPubkeys, err := GenerateHostKeys(numParticipants)
	if err != nil {
		t.Fatalf("Failed to generate host keys: %v", err)
	}

	coord, err := CreateMemoryCoordinator(sessionID, threshold, numParticipants, ciphersuite)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}
	cleanup.AddCoordinator(coord)

	if err := coord.Start(ctx); err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	memCoord := coord.(*memory.MemoryCoordinator)

	participants, err := CreateMemoryParticipants(numParticipants, memCoord)
	if err != nil {
		t.Fatalf("Failed to create participants: %v", err)
	}

	for _, p := range participants {
		cleanup.AddParticipant(p)
	}

	params := make([]*transport.DKGParams, numParticipants)
	for i := 0; i < numParticipants; i++ {
		params[i], err = GenerateDKGParams(i, threshold, hostSeckeys, hostPubkeys)
		if err != nil {
			t.Fatalf("Failed to generate params for participant %d: %v", i, err)
		}
	}

	for i, p := range participants {
		if err := p.Connect(ctx, sessionID); err != nil {
			t.Fatalf("Participant %d failed to connect: %v", i, err)
		}
	}

	if err := coord.WaitForParticipants(ctx, numParticipants); err != nil {
		t.Fatalf("Failed to wait for participants: %v", err)
	}

	dkgRunner := NewConcurrentDKGRunner(2 * time.Minute)
	results, err := dkgRunner.RunParticipants(ctx, participants, params)
	if err != nil {
		t.Fatalf("DKG execution failed: %v", err)
	}

	if len(results) != numParticipants {
		t.Fatalf("Expected %d results, got %d", numParticipants, len(results))
	}

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

	compareAction := &CompareResultsAction{
		Results: results,
	}

	if err := compareAction.Execute(ctx); err != nil {
		t.Fatalf("Result comparison failed: %v", err)
	}

	t.Logf("Memory transport 3-of-5 DKG completed successfully")
}

// TestMemoryTransport_ErrorCases tests error handling.
func TestMemoryTransport_ErrorCases(t *testing.T) {
	ctx := context.Background()

	t.Run("InvalidThreshold", func(t *testing.T) {
		sessionID := GenerateSessionID()
		_, err := CreateMemoryCoordinator(sessionID, 0, 3, "FROST-ED25519-SHA512-v1")
		if err == nil {
			t.Fatal("Expected error for invalid threshold")
		}
	})

	t.Run("ThresholdTooHigh", func(t *testing.T) {
		sessionID := GenerateSessionID()
		_, err := CreateMemoryCoordinator(sessionID, 5, 3, "FROST-ED25519-SHA512-v1")
		if err == nil {
			t.Fatal("Expected error for threshold > n")
		}
	})

	t.Run("Timeout", func(t *testing.T) {
		sessionID := GenerateSessionID()
		coord, err := CreateMemoryCoordinator(sessionID, 2, 3, "FROST-ED25519-SHA512-v1")
		if err != nil {
			t.Fatalf("Failed to create coordinator: %v", err)
		}
		defer coord.Stop(ctx)

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

// TestMemoryTransport_UsingTestRunner demonstrates using the TestRunner framework.
func TestMemoryTransport_UsingTestRunner(t *testing.T) {
	const (
		threshold       = 2
		numParticipants = 3
		ciphersuite     = "FROST-ED25519-SHA512-v1"
	)

	ctx := context.Background()
	cleanup := NewCleanupManager()
	defer cleanup.Cleanup()

	sessionID := GenerateSessionID()

	hostSeckeys, hostPubkeys, err := GenerateHostKeys(numParticipants)
	if err != nil {
		t.Fatalf("Failed to generate host keys: %v", err)
	}

	coord, err := CreateMemoryCoordinator(sessionID, threshold, numParticipants, ciphersuite)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}
	cleanup.AddCoordinator(coord)

	memCoord := coord.(*memory.MemoryCoordinator)

	participants, err := CreateMemoryParticipants(numParticipants, memCoord)
	if err != nil {
		t.Fatalf("Failed to create participants: %v", err)
	}

	for _, p := range participants {
		cleanup.AddParticipant(p)
	}

	// Start coordinator BEFORE using the test runner, so it uses the background
	// context which won't be cancelled when the test runner's context expires.
	// This is important because the coordinator's processMessages goroutine
	// needs to keep running after the test runner completes.
	if err := coord.Start(ctx); err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	// Create test runner for connecting participants
	runner := NewTestRunner(2 * time.Minute)

	// Connect all participants
	for _, p := range participants {
		runner.AddAction(&JoinSessionAction{
			Participant: p,
			Address:     sessionID,
		})
	}

	runner.AddAction(&WaitForParticipantsAction{
		Coordinator: coord,
		Count:       numParticipants,
	})

	// Execute the test sequence
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Test runner failed: %v", err)
	}

	// Now run DKG
	params := make([]*transport.DKGParams, numParticipants)
	for i := 0; i < numParticipants; i++ {
		params[i], err = GenerateDKGParams(i, threshold, hostSeckeys, hostPubkeys)
		if err != nil {
			t.Fatalf("Failed to generate params for participant %d: %v", i, err)
		}
	}

	dkgRunner := NewConcurrentDKGRunner(2 * time.Minute)
	results, err := dkgRunner.RunParticipants(ctx, participants, params)
	if err != nil {
		t.Fatalf("DKG execution failed: %v", err)
	}

	// Verify results
	compareAction := &CompareResultsAction{
		Results: results,
	}

	if err := compareAction.Execute(ctx); err != nil {
		t.Fatalf("Result comparison failed: %v", err)
	}

	t.Logf("TestRunner framework test completed successfully")
}
