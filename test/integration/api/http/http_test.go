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

package http_test

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/test/integration/api"
)

// TestHTTP_2of3_Threshold tests 2-of-3 threshold DKG using HTTP transport.
func TestHTTP_2of3_Threshold(t *testing.T) {
	const (
		threshold       = 2
		numParticipants = 3
		ciphersuite     = "FROST-ED25519-SHA512-v1"
	)

	ctx := context.Background()
	cleanup := api.NewCleanupManager()
	defer cleanup.Cleanup()

	sessionID := api.GenerateSessionID()

	hostSeckeys, hostPubkeys, err := api.GenerateHostKeys(numParticipants)
	if err != nil {
		t.Fatalf("Failed to generate host keys: %v", err)
	}

	certs, err := api.GenerateTestCertificates()
	if err != nil {
		t.Fatalf("Failed to generate certificates: %v", err)
	}
	cleanup.AddCertificates(certs)

	coord, address, err := api.CreateHTTPCoordinator(sessionID, threshold, numParticipants, ciphersuite, certs)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}
	cleanup.AddCoordinator(coord)

	participants, err := api.CreateHTTPParticipants(numParticipants, certs, ciphersuite)
	if err != nil {
		t.Fatalf("Failed to create participants: %v", err)
	}

	for _, p := range participants {
		cleanup.AddParticipant(p)
	}

	if err := coord.Start(ctx); err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	for i, p := range participants {
		if err := p.Connect(ctx, address); err != nil {
			t.Fatalf("Participant %d failed to connect: %v", i, err)
		}
	}

	params := make([]*transport.DKGParams, numParticipants)
	for i := 0; i < numParticipants; i++ {
		params[i], err = api.GenerateDKGParams(i, threshold, hostSeckeys, hostPubkeys)
		if err != nil {
			t.Fatalf("Failed to generate params for participant %d: %v", i, err)
		}
	}

	dkgRunner := api.NewConcurrentDKGRunner(2 * time.Minute)
	results, err := dkgRunner.RunParticipants(ctx, participants, params)
	if err != nil {
		t.Fatalf("DKG execution failed: %v", err)
	}

	if len(results) != numParticipants {
		t.Fatalf("Expected %d results, got %d", numParticipants, len(results))
	}

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

	compareAction := &api.CompareResultsAction{
		Results: results,
	}

	if err := compareAction.Execute(ctx); err != nil {
		t.Fatalf("Result comparison failed: %v", err)
	}

	t.Logf("HTTP transport 2-of-3 DKG completed successfully")
}

// TestHTTP_3of5_Threshold tests 3-of-5 threshold DKG using HTTP transport.
func TestHTTP_3of5_Threshold(t *testing.T) {
	const (
		threshold       = 3
		numParticipants = 5
		ciphersuite     = "FROST-ED25519-SHA512-v1"
	)

	ctx := context.Background()
	cleanup := api.NewCleanupManager()
	defer cleanup.Cleanup()

	sessionID := api.GenerateSessionID()

	hostSeckeys, hostPubkeys, err := api.GenerateHostKeys(numParticipants)
	if err != nil {
		t.Fatalf("Failed to generate host keys: %v", err)
	}

	certs, err := api.GenerateTestCertificates()
	if err != nil {
		t.Fatalf("Failed to generate certificates: %v", err)
	}
	cleanup.AddCertificates(certs)

	coord, address, err := api.CreateHTTPCoordinator(sessionID, threshold, numParticipants, ciphersuite, certs)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}
	cleanup.AddCoordinator(coord)

	participants, err := api.CreateHTTPParticipants(numParticipants, certs, ciphersuite)
	if err != nil {
		t.Fatalf("Failed to create participants: %v", err)
	}

	for _, p := range participants {
		cleanup.AddParticipant(p)
	}

	if err := coord.Start(ctx); err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	for i, p := range participants {
		if err := p.Connect(ctx, address); err != nil {
			t.Fatalf("Participant %d failed to connect: %v", i, err)
		}
	}

	params := make([]*transport.DKGParams, numParticipants)
	for i := 0; i < numParticipants; i++ {
		params[i], err = api.GenerateDKGParams(i, threshold, hostSeckeys, hostPubkeys)
		if err != nil {
			t.Fatalf("Failed to generate params for participant %d: %v", i, err)
		}
	}

	dkgRunner := api.NewConcurrentDKGRunner(2 * time.Minute)
	results, err := dkgRunner.RunParticipants(ctx, participants, params)
	if err != nil {
		t.Fatalf("DKG execution failed: %v", err)
	}

	if len(results) != numParticipants {
		t.Fatalf("Expected %d results, got %d", numParticipants, len(results))
	}

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

	compareAction := &api.CompareResultsAction{
		Results: results,
	}

	if err := compareAction.Execute(ctx); err != nil {
		t.Fatalf("Result comparison failed: %v", err)
	}

	t.Logf("HTTP transport 3-of-5 DKG completed successfully")
}

// TestHTTP_ErrorCases tests error handling with HTTP transport.
func TestHTTP_ErrorCases(t *testing.T) {
	ctx := context.Background()

	t.Run("InvalidThreshold", func(t *testing.T) {
		cleanup := api.NewCleanupManager()
		defer cleanup.Cleanup()

		certs, err := api.GenerateTestCertificates()
		if err != nil {
			t.Fatalf("Failed to generate certificates: %v", err)
		}
		cleanup.AddCertificates(certs)

		sessionID := api.GenerateSessionID()
		_, _, err = api.CreateHTTPCoordinator(sessionID, 0, 3, "FROST-ED25519-SHA512-v1", certs)
		if err == nil {
			t.Fatal("Expected error for invalid threshold")
		}
	})

	t.Run("Timeout", func(t *testing.T) {
		cleanup := api.NewCleanupManager()
		defer cleanup.Cleanup()

		certs, err := api.GenerateTestCertificates()
		if err != nil {
			t.Fatalf("Failed to generate certificates: %v", err)
		}
		cleanup.AddCertificates(certs)

		sessionID := api.GenerateSessionID()
		coord, _, err := api.CreateHTTPCoordinator(sessionID, 2, 3, "FROST-ED25519-SHA512-v1", certs)
		if err != nil {
			t.Fatalf("Failed to create coordinator: %v", err)
		}
		cleanup.AddCoordinator(coord)

		if err := coord.Start(ctx); err != nil {
			t.Fatalf("Failed to start coordinator: %v", err)
		}

		timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		err = coord.WaitForParticipants(timeoutCtx, 3)
		if err == nil {
			t.Fatal("Expected timeout error")
		}
	})
}
