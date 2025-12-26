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

package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// MemoryParticipant implements the Participant interface for in-memory testing.
type MemoryParticipant struct {
	participantID  string
	coordinator    *MemoryCoordinator
	sessionID      string
	participantIdx int
	connected      bool
	connectedMu    sync.RWMutex
	receiveChan    chan *transport.Envelope
	sessionInfo    *transport.SessionInfoMessage
}

// NewMemoryParticipant creates a new in-memory participant.
func NewMemoryParticipant(participantID string) (*MemoryParticipant, error) {
	if participantID == "" {
		return nil, transport.ErrInvalidConfig
	}

	return &MemoryParticipant{
		participantID: participantID,
		receiveChan:   make(chan *transport.Envelope, 100),
	}, nil
}

// Connect establishes a connection to the coordinator.
func (mp *MemoryParticipant) Connect(ctx context.Context, addr string) error {
	mp.connectedMu.Lock()
	defer mp.connectedMu.Unlock()

	if mp.connected {
		return transport.ErrAlreadyConnected
	}

	if mp.coordinator == nil {
		return transport.NewConnectionError(addr, fmt.Errorf("no coordinator set"))
	}

	// In memory transport, addr is the session ID
	mp.sessionID = addr

	// Register with the coordinator's transport
	// Use empty pubkey for now - real pubkey is set during joinSession
	conn, err := mp.coordinator.GetTransport().AddParticipant(mp.sessionID, mp.participantID, make([]byte, transport.PublicKeySize))
	if err != nil {
		return transport.NewConnectionError(addr, err)
	}

	// Store our assigned index
	mp.participantIdx = conn.Index
	mp.connected = true

	return nil
}

// Disconnect closes the connection to the coordinator.
func (mp *MemoryParticipant) Disconnect() error {
	mp.connectedMu.Lock()
	defer mp.connectedMu.Unlock()

	if !mp.connected {
		return transport.ErrNotConnected
	}

	if mp.coordinator != nil {
		// Remove from session - ignore error if already removed
		_ = mp.coordinator.GetTransport().RemoveParticipant(mp.sessionID, mp.participantID)
	}

	mp.connected = false
	close(mp.receiveChan)
	mp.receiveChan = make(chan *transport.Envelope, 100)

	return nil
}

// RunDKG executes the FROST DKG protocol using the provided parameters.
func (mp *MemoryParticipant) RunDKG(ctx context.Context, params *transport.DKGParams) (*transport.DKGResult, error) {
	mp.connectedMu.RLock()
	if !mp.connected {
		mp.connectedMu.RUnlock()
		return nil, transport.ErrNotConnected
	}
	mp.connectedMu.RUnlock()

	// Validate parameters
	if err := mp.validateDKGParams(params); err != nil {
		return nil, err
	}

	// Join session
	if err := mp.joinSession(ctx, params); err != nil {
		return nil, fmt.Errorf("failed to join session: %w", err)
	}

	// Execute DKG rounds
	result, err := mp.executeDKG(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("DKG execution failed: %w", err)
	}

	return result, nil
}

// validateDKGParams validates the DKG parameters.
func (mp *MemoryParticipant) validateDKGParams(params *transport.DKGParams) error {
	if params == nil {
		return transport.ErrInvalidDKGParams
	}

	if len(params.HostSeckey) != 32 {
		return transport.ErrInvalidHostKey
	}

	if len(params.Random) != 32 {
		return transport.ErrInvalidRandomness
	}

	if len(params.HostPubkeys) == 0 {
		return transport.ErrInvalidDKGParams
	}

	if params.ParticipantIdx < 0 || params.ParticipantIdx >= len(params.HostPubkeys) {
		return transport.ErrInvalidParticipantIndex
	}

	if params.Threshold < 1 || params.Threshold > len(params.HostPubkeys) {
		return transport.ErrInvalidThreshold
	}

	for i, pubkey := range params.HostPubkeys {
		if len(pubkey) != transport.PublicKeySize {
			return transport.NewParticipantError("", i, transport.ErrInvalidHostKey)
		}
	}

	return nil
}

// joinSession sends a join request and waits for session info.
func (mp *MemoryParticipant) joinSession(ctx context.Context, params *transport.DKGParams) error {
	if mp.coordinator == nil {
		return fmt.Errorf("no coordinator set")
	}

	// Get my host public key
	myPubkey := params.HostPubkeys[params.ParticipantIdx]

	// Create join message
	joinMsg := &transport.JoinMessage{
		HostPubkey: myPubkey,
	}

	payload, err := mp.coordinator.GetTransport().Serializer().Marshal(joinMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal join message: %w", err)
	}

	envelope := &transport.Envelope{
		SessionID: mp.sessionID,
		Type:      transport.MsgTypeJoin,
		SenderIdx: params.ParticipantIdx,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	// Send join request
	responseChan := make(chan *transport.Envelope, 1)
	errorChan := make(chan error, 1)

	msg := &Message{
		Envelope:      envelope,
		ResponseChan:  responseChan,
		ErrorChan:     errorChan,
		ParticipantID: mp.participantID,
	}

	// Check if session is closed before sending
	session := mp.coordinator.GetSession()
	session.CloseMu.RLock()
	if session.Closed {
		session.CloseMu.RUnlock()
		return transport.ErrSessionClosed
	}
	// Send while holding read lock to prevent race with CloseSession
	select {
	case session.MessageChan <- msg:
		session.CloseMu.RUnlock()
	case <-ctx.Done():
		session.CloseMu.RUnlock()
		return transport.ErrConnectionTimeout
	}

	// Wait for session info response
	select {
	case response := <-responseChan:
		if response.Type != transport.MsgTypeSessionInfo {
			return transport.ErrUnexpectedMessage
		}

		var sessionInfo transport.SessionInfoMessage
		if err := mp.coordinator.GetTransport().Serializer().UnmarshalPayload(response, &sessionInfo); err != nil {
			return fmt.Errorf("failed to unmarshal session info: %w", err)
		}

		mp.sessionInfo = &sessionInfo
		mp.participantIdx = sessionInfo.ParticipantIdx

		return nil

	case err := <-errorChan:
		return err

	case <-ctx.Done():
		return transport.ErrConnectionTimeout
	}
}

// executeDKG runs the DKG protocol rounds.
func (mp *MemoryParticipant) executeDKG(ctx context.Context, params *transport.DKGParams) (*transport.DKGResult, error) {
	// This is a simplified stub implementation for testing the transport layer.
	// In a real implementation, this would execute the full FROST DKG protocol.
	//
	// The actual DKG rounds would be:
	// 1. Round 1: Generate and broadcast VSS commitments and PoP
	// 2. Wait for aggregated Round 1 from coordinator
	// 3. Round 2: Generate and send encrypted shares
	// 4. Wait for aggregated Round 2 from coordinator
	// 5. Generate CertEq signature
	// 6. Wait for final certificate
	// 7. Return DKG result

	// For testing purposes, we'll create a mock result
	// Real implementation would integrate with the FROST library

	result := &transport.DKGResult{
		SecretShare:     make([]byte, transport.SecretKeySize),
		ThresholdPubkey: make([]byte, transport.PublicKeySize),
		PublicShares:    make([][]byte, len(params.HostPubkeys)),
		SessionID:       mp.sessionID,
		RecoveryData:    make([]byte, 64),
	}

	// Fill with unique test data per participant
	// Secret share is unique per participant (participant index in first byte)
	result.SecretShare[0] = byte(params.ParticipantIdx + 1)
	for i := 1; i < transport.SecretKeySize; i++ {
		result.SecretShare[i] = byte(0x42 + params.ParticipantIdx)
	}

	// Threshold pubkey is the same for all participants
	for i := range result.ThresholdPubkey {
		result.ThresholdPubkey[i] = byte(0xAB)
	}

	// Public shares differ by participant index
	for i := range result.PublicShares {
		result.PublicShares[i] = make([]byte, transport.PublicKeySize)
		result.PublicShares[i][0] = byte(i + 1)
		for j := 1; j < transport.PublicKeySize; j++ {
			result.PublicShares[i][j] = byte(0xCD)
		}
	}

	// Recovery data is the same for all participants in real DKG
	// Use a deterministic value based on session
	for i := range result.RecoveryData {
		result.RecoveryData[i] = byte(0xEE)
	}

	return result, nil
}

// SendToCoordinator sends a message to the coordinator.
func (mp *MemoryParticipant) SendToCoordinator(ctx context.Context, envelope *transport.Envelope) error {
	mp.connectedMu.RLock()
	if !mp.connected {
		mp.connectedMu.RUnlock()
		return transport.ErrNotConnected
	}
	mp.connectedMu.RUnlock()

	if mp.coordinator == nil {
		return fmt.Errorf("no coordinator set")
	}

	msg := &Message{
		Envelope:      envelope,
		ParticipantID: mp.participantID,
	}

	// Check if session is closed before sending
	session := mp.coordinator.GetSession()
	session.CloseMu.RLock()
	if session.Closed {
		session.CloseMu.RUnlock()
		return transport.ErrSessionClosed
	}
	// Send while holding read lock to prevent race with CloseSession
	select {
	case session.MessageChan <- msg:
		session.CloseMu.RUnlock()
		return nil
	case <-ctx.Done():
		session.CloseMu.RUnlock()
		return transport.ErrMessageTimeout
	}
}

// ReceiveFromCoordinator receives a message from the coordinator.
func (mp *MemoryParticipant) ReceiveFromCoordinator(ctx context.Context) (*transport.Envelope, error) {
	mp.connectedMu.RLock()
	if !mp.connected {
		mp.connectedMu.RUnlock()
		return nil, transport.ErrNotConnected
	}
	mp.connectedMu.RUnlock()

	select {
	case envelope, ok := <-mp.receiveChan:
		if !ok {
			return nil, transport.ErrConnectionClosed
		}
		return envelope, nil
	case <-ctx.Done():
		return nil, transport.ErrMessageTimeout
	}
}

// SetCoordinator sets the coordinator for this participant (testing only).
func (mp *MemoryParticipant) SetCoordinator(coordinator *MemoryCoordinator) {
	mp.coordinator = coordinator
}

// GetParticipantID returns the participant's ID.
func (mp *MemoryParticipant) GetParticipantID() string {
	return mp.participantID
}

// GetParticipantIndex returns the participant's index in the session.
func (mp *MemoryParticipant) GetParticipantIndex() int {
	return mp.participantIdx
}

// GetSessionInfo returns the session information.
func (mp *MemoryParticipant) GetSessionInfo() *transport.SessionInfoMessage {
	return mp.sessionInfo
}
