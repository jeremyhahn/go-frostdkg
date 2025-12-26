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

// Package api provides protocol-agnostic integration test framework for FROST DKG.
//
// This package defines centralized test actions and utilities that work across
// all transport implementations (gRPC, HTTP, QUIC, Unix sockets, memory).
//
// The TestAction interface enables composable test scenarios that verify
// protocol parity across all transports.
package api

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TestAction represents a single test action in a DKG protocol sequence.
// Actions are protocol-agnostic and can be executed against any transport.
type TestAction interface {
	// Execute performs the action and returns an error if it fails.
	Execute(ctx context.Context) error

	// Name returns a human-readable name for this action.
	Name() string
}

// CreateSessionAction creates a new DKG session on the coordinator.
type CreateSessionAction struct {
	Coordinator     transport.Coordinator
	SessionID       string
	Threshold       int
	NumParticipants int
	Ciphersuite     string
}

// Execute creates the session.
func (a *CreateSessionAction) Execute(ctx context.Context) error {
	if a.Coordinator == nil {
		return fmt.Errorf("coordinator is nil")
	}

	// Start the coordinator
	if err := a.Coordinator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start coordinator: %w", err)
	}

	return nil
}

// Name returns the action name.
func (a *CreateSessionAction) Name() string {
	return fmt.Sprintf("CreateSession(%s)", a.SessionID)
}

// JoinSessionAction joins a participant to the session.
type JoinSessionAction struct {
	Participant transport.Participant
	Address     string
}

// Execute joins the session.
func (a *JoinSessionAction) Execute(ctx context.Context) error {
	if a.Participant == nil {
		return fmt.Errorf("participant is nil")
	}

	if err := a.Participant.Connect(ctx, a.Address); err != nil {
		return fmt.Errorf("failed to connect to session: %w", err)
	}

	return nil
}

// Name returns the action name.
func (a *JoinSessionAction) Name() string {
	return fmt.Sprintf("JoinSession(%s)", a.Address)
}

// RunDKGAction executes the DKG protocol for a participant.
type RunDKGAction struct {
	Participant transport.Participant
	Params      *transport.DKGParams
	ResultChan  chan *transport.DKGResult
	ErrorChan   chan error
}

// Execute runs the DKG protocol.
func (a *RunDKGAction) Execute(ctx context.Context) error {
	if a.Participant == nil {
		return fmt.Errorf("participant is nil")
	}

	if a.Params == nil {
		return fmt.Errorf("DKG params are nil")
	}

	// Run DKG in a goroutine so we don't block
	go func() {
		result, err := a.Participant.RunDKG(ctx, a.Params)
		if err != nil {
			if a.ErrorChan != nil {
				select {
				case a.ErrorChan <- err:
				case <-ctx.Done():
				}
			}
			return
		}

		if a.ResultChan != nil {
			select {
			case a.ResultChan <- result:
			case <-ctx.Done():
			}
		}
	}()

	return nil
}

// Name returns the action name.
func (a *RunDKGAction) Name() string {
	return fmt.Sprintf("RunDKG(participant=%d)", a.Params.ParticipantIdx)
}

// WaitForParticipantsAction waits for participants to connect.
type WaitForParticipantsAction struct {
	Coordinator transport.Coordinator
	Count       int
}

// Execute waits for the specified number of participants.
func (a *WaitForParticipantsAction) Execute(ctx context.Context) error {
	if a.Coordinator == nil {
		return fmt.Errorf("coordinator is nil")
	}

	if err := a.Coordinator.WaitForParticipants(ctx, a.Count); err != nil {
		return fmt.Errorf("failed to wait for %d participants: %w", a.Count, err)
	}

	return nil
}

// Name returns the action name.
func (a *WaitForParticipantsAction) Name() string {
	return fmt.Sprintf("WaitForParticipants(count=%d)", a.Count)
}

// StopCoordinatorAction stops the coordinator.
type StopCoordinatorAction struct {
	Coordinator transport.Coordinator
}

// Execute stops the coordinator.
func (a *StopCoordinatorAction) Execute(ctx context.Context) error {
	if a.Coordinator == nil {
		return fmt.Errorf("coordinator is nil")
	}

	if err := a.Coordinator.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop coordinator: %w", err)
	}

	return nil
}

// Name returns the action name.
func (a *StopCoordinatorAction) Name() string {
	return "StopCoordinator"
}

// DisconnectParticipantAction disconnects a participant.
type DisconnectParticipantAction struct {
	Participant transport.Participant
}

// Execute disconnects the participant.
func (a *DisconnectParticipantAction) Execute(ctx context.Context) error {
	if a.Participant == nil {
		return fmt.Errorf("participant is nil")
	}

	if err := a.Participant.Disconnect(); err != nil {
		return fmt.Errorf("failed to disconnect participant: %w", err)
	}

	return nil
}

// Name returns the action name.
func (a *DisconnectParticipantAction) Name() string {
	return "DisconnectParticipant"
}

// VerifyResultAction verifies the DKG result.
type VerifyResultAction struct {
	Result          *transport.DKGResult
	ExpectedSession string
	NumParticipants int
}

// Execute verifies the result.
func (a *VerifyResultAction) Execute(ctx context.Context) error {
	if a.Result == nil {
		return fmt.Errorf("result is nil")
	}

	if a.Result.SessionID != a.ExpectedSession {
		return fmt.Errorf("session ID mismatch: got %s, want %s", a.Result.SessionID, a.ExpectedSession)
	}

	if len(a.Result.SecretShare) != transport.SecretKeySize {
		return fmt.Errorf("invalid secret share length: got %d, want %d", len(a.Result.SecretShare), transport.SecretKeySize)
	}

	if len(a.Result.ThresholdPubkey) != transport.PublicKeySize {
		return fmt.Errorf("invalid threshold pubkey length: got %d, want %d", len(a.Result.ThresholdPubkey), transport.PublicKeySize)
	}

	if len(a.Result.PublicShares) != a.NumParticipants {
		return fmt.Errorf("invalid public shares count: got %d, want %d", len(a.Result.PublicShares), a.NumParticipants)
	}

	for i, share := range a.Result.PublicShares {
		if len(share) != transport.PublicKeySize {
			return fmt.Errorf("public share %d has invalid length: got %d, want %d", i, len(share), transport.PublicKeySize)
		}
	}

	if len(a.Result.RecoveryData) == 0 {
		return fmt.Errorf("recovery data is empty")
	}

	return nil
}

// Name returns the action name.
func (a *VerifyResultAction) Name() string {
	return "VerifyResult"
}

// CompareResultsAction compares DKG results from multiple participants.
type CompareResultsAction struct {
	Results []*transport.DKGResult
}

// Execute compares the results.
func (a *CompareResultsAction) Execute(ctx context.Context) error {
	if len(a.Results) < 2 {
		return fmt.Errorf("need at least 2 results to compare")
	}

	first := a.Results[0]

	for i, result := range a.Results[1:] {
		// Session ID should match
		if result.SessionID != first.SessionID {
			return fmt.Errorf("result %d: session ID mismatch: got %s, want %s", i+1, result.SessionID, first.SessionID)
		}

		// Threshold pubkey should match
		if len(result.ThresholdPubkey) != len(first.ThresholdPubkey) {
			return fmt.Errorf("result %d: threshold pubkey length mismatch", i+1)
		}

		for j := range result.ThresholdPubkey {
			if result.ThresholdPubkey[j] != first.ThresholdPubkey[j] {
				return fmt.Errorf("result %d: threshold pubkey mismatch at byte %d", i+1, j)
			}
		}

		// Public shares should match
		if len(result.PublicShares) != len(first.PublicShares) {
			return fmt.Errorf("result %d: public shares count mismatch", i+1)
		}

		for j := range result.PublicShares {
			if len(result.PublicShares[j]) != len(first.PublicShares[j]) {
				return fmt.Errorf("result %d: public share %d length mismatch", i+1, j)
			}

			for k := range result.PublicShares[j] {
				if result.PublicShares[j][k] != first.PublicShares[j][k] {
					return fmt.Errorf("result %d: public share %d mismatch at byte %d", i+1, j, k)
				}
			}
		}

		// Recovery data should match
		if len(result.RecoveryData) != len(first.RecoveryData) {
			return fmt.Errorf("result %d: recovery data length mismatch", i+1)
		}

		for j := range result.RecoveryData {
			if result.RecoveryData[j] != first.RecoveryData[j] {
				return fmt.Errorf("result %d: recovery data mismatch at byte %d", i+1, j)
			}
		}

		// Secret shares should be DIFFERENT (each participant has their own)
		if len(result.SecretShare) == len(first.SecretShare) {
			allMatch := true
			for j := range result.SecretShare {
				if result.SecretShare[j] != first.SecretShare[j] {
					allMatch = false
					break
				}
			}
			if allMatch && i > 0 {
				return fmt.Errorf("result %d: secret shares should differ between participants", i+1)
			}
		}
	}

	return nil
}

// Name returns the action name.
func (a *CompareResultsAction) Name() string {
	return fmt.Sprintf("CompareResults(count=%d)", len(a.Results))
}
