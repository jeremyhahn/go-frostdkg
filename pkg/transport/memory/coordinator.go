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

// MemoryCoordinator implements the Coordinator interface for in-memory testing.
type MemoryCoordinator struct {
	transport *MemoryTransport
	sessionID string
	config    *transport.SessionConfig
	session   *Session
	started   bool
	startedMu sync.RWMutex
	stopChan  chan struct{}
	stopOnce  sync.Once
}

// NewMemoryCoordinator creates a new in-memory coordinator.
func NewMemoryCoordinator(sessionID string, config *transport.SessionConfig) (*MemoryCoordinator, error) {
	if sessionID == "" {
		return nil, transport.ErrInvalidConfig
	}

	if config == nil {
		return nil, transport.ErrInvalidConfig
	}

	// Check participant count first
	if config.NumParticipants < 1 {
		return nil, transport.ErrInvalidParticipantCount
	}

	// Then check threshold
	if config.Threshold < 1 || config.Threshold > config.NumParticipants {
		return nil, transport.ErrInvalidThreshold
	}

	// Create transport
	codecType := "json"
	mt, err := NewMemoryTransport(codecType)
	if err != nil {
		return nil, fmt.Errorf("failed to create memory transport: %w", err)
	}

	return &MemoryCoordinator{
		transport: mt,
		sessionID: sessionID,
		config:    config,
		stopChan:  make(chan struct{}),
	}, nil
}

// Start begins accepting participant connections.
func (mc *MemoryCoordinator) Start(ctx context.Context) error {
	mc.startedMu.Lock()
	defer mc.startedMu.Unlock()

	if mc.started {
		return fmt.Errorf("coordinator already started")
	}

	// Create session
	session, err := mc.transport.CreateSession(mc.sessionID, mc.config)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	mc.session = session
	mc.started = true

	// Start message processing goroutine
	go mc.processMessages(ctx)

	return nil
}

// Stop gracefully shuts down the coordinator.
func (mc *MemoryCoordinator) Stop(ctx context.Context) error {
	var stopErr error

	mc.stopOnce.Do(func() {
		mc.startedMu.Lock()
		if !mc.started {
			mc.startedMu.Unlock()
			stopErr = fmt.Errorf("coordinator not started")
			return
		}
		mc.startedMu.Unlock()

		// Signal shutdown
		close(mc.stopChan)

		// Close session
		if err := mc.transport.CloseSession(mc.sessionID); err != nil {
			stopErr = fmt.Errorf("failed to close session: %w", err)
			return
		}

		mc.startedMu.Lock()
		mc.started = false
		mc.startedMu.Unlock()
	})

	return stopErr
}

// Address returns the session identifier (used as address for memory transport).
func (mc *MemoryCoordinator) Address() string {
	return mc.sessionID
}

// SessionID returns the unique identifier for this DKG session.
func (mc *MemoryCoordinator) SessionID() string {
	return mc.sessionID
}

// WaitForParticipants blocks until n participants have connected.
func (mc *MemoryCoordinator) WaitForParticipants(ctx context.Context, n int) error {
	if n < 1 {
		return transport.ErrInvalidParticipantCount
	}

	if n > mc.config.NumParticipants {
		return transport.ErrInvalidParticipantCount
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return transport.ErrConnectionTimeout
		case <-mc.stopChan:
			return transport.ErrSessionClosed
		case <-ticker.C:
			mc.session.ParticipantsMu.RLock()
			count := len(mc.session.Participants)
			mc.session.ParticipantsMu.RUnlock()

			if count >= n {
				return nil
			}
		}
	}
}

// processMessages handles message routing between participants.
func (mc *MemoryCoordinator) processMessages(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-mc.stopChan:
			return
		case msg, ok := <-mc.session.MessageChan:
			if !ok {
				return
			}
			mc.handleMessage(ctx, msg)
		}
	}
}

// handleMessage processes a single message from a participant.
func (mc *MemoryCoordinator) handleMessage(ctx context.Context, msg *Message) {
	// Message handling depends on the message type
	// For now, this is a simple relay - the actual DKG protocol logic
	// would be implemented by the participants themselves
	envelope := msg.Envelope

	switch envelope.Type {
	case transport.MsgTypeJoin:
		// Handle join request
		mc.handleJoinMessage(ctx, msg)

	case transport.MsgTypeRound1:
		// Collect round 1 messages and broadcast aggregated result
		mc.handleRound1Message(ctx, msg)

	case transport.MsgTypeRound2:
		// Route round 2 messages to specific participants
		mc.handleRound2Message(ctx, msg)

	case transport.MsgTypeCertEqSign:
		// Collect CertEq signatures
		mc.handleCertEqSignMessage(ctx, msg)

	default:
		// Unknown message type
		if msg.ErrorChan != nil {
			select {
			case msg.ErrorChan <- transport.ErrUnexpectedMessage:
			default:
			}
		}
	}
}

// handleJoinMessage processes a participant join request.
func (mc *MemoryCoordinator) handleJoinMessage(ctx context.Context, msg *Message) {
	var joinMsg transport.JoinMessage
	if err := mc.transport.Serializer().UnmarshalPayload(msg.Envelope, &joinMsg); err != nil {
		if msg.ErrorChan != nil {
			select {
			case msg.ErrorChan <- err:
			default:
			}
		}
		return
	}

	// Get or add participant
	conn, err := mc.transport.GetParticipant(mc.sessionID, msg.ParticipantID)
	if err != nil {
		// Participant not registered yet, add them
		conn, err = mc.transport.AddParticipant(mc.sessionID, msg.ParticipantID, joinMsg.HostPubkey)
		if err != nil {
			if msg.ErrorChan != nil {
				select {
				case msg.ErrorChan <- err:
				default:
				}
			}
			return
		}
	} else {
		// Participant already registered (from Connect), update their pubkey
		conn.HostPubkey = joinMsg.HostPubkey
	}

	// Build session info response
	mc.session.ParticipantsMu.RLock()
	hostPubkeys := make([][]byte, len(mc.session.Participants))
	for _, p := range mc.session.Participants {
		hostPubkeys[p.Index] = p.HostPubkey
	}
	mc.session.ParticipantsMu.RUnlock()

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       mc.sessionID,
		Threshold:       mc.config.Threshold,
		NumParticipants: mc.config.NumParticipants,
		ParticipantIdx:  conn.Index,
		HostPubkeys:     hostPubkeys,
		Ciphersuite:     mc.config.Ciphersuite,
	}

	payload, err := mc.transport.Serializer().Marshal(sessionInfo)
	if err != nil {
		if msg.ErrorChan != nil {
			select {
			case msg.ErrorChan <- err:
			default:
			}
		}
		return
	}

	response := &transport.Envelope{
		SessionID: mc.sessionID,
		Type:      transport.MsgTypeSessionInfo,
		SenderIdx: -1, // From coordinator
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	if msg.ResponseChan != nil {
		select {
		case msg.ResponseChan <- response:
		case <-ctx.Done():
		}
	}
}

// handleRound1Message collects round 1 messages and broadcasts aggregated result.
func (mc *MemoryCoordinator) handleRound1Message(ctx context.Context, msg *Message) {
	// In a real implementation, this would collect messages from all participants
	// and broadcast the aggregated result. For testing, we can implement a simpler version.
	// This is a stub - actual aggregation logic would be implemented based on FROST DKG protocol.

	if msg.ResponseChan != nil {
		// Acknowledge receipt
		ack := &transport.Envelope{
			SessionID: mc.sessionID,
			Type:      transport.MsgTypeRound1Agg,
			SenderIdx: -1,
			Timestamp: time.Now().Unix(),
		}
		select {
		case msg.ResponseChan <- ack:
		case <-ctx.Done():
		}
	}
}

// handleRound2Message routes round 2 messages to specific participants.
func (mc *MemoryCoordinator) handleRound2Message(ctx context.Context, msg *Message) {
	// Route to specific participant based on message content
	// This is a stub - actual routing logic would be implemented based on FROST DKG protocol.

	if msg.ResponseChan != nil {
		ack := &transport.Envelope{
			SessionID: mc.sessionID,
			Type:      transport.MsgTypeRound2Agg,
			SenderIdx: -1,
			Timestamp: time.Now().Unix(),
		}
		select {
		case msg.ResponseChan <- ack:
		case <-ctx.Done():
		}
	}
}

// handleCertEqSignMessage collects CertEq signatures.
func (mc *MemoryCoordinator) handleCertEqSignMessage(ctx context.Context, msg *Message) {
	// Collect signatures and create final certificate
	// This is a stub - actual certificate generation would be implemented based on FROST DKG protocol.

	if msg.ResponseChan != nil {
		ack := &transport.Envelope{
			SessionID: mc.sessionID,
			Type:      transport.MsgTypeCertificate,
			SenderIdx: -1,
			Timestamp: time.Now().Unix(),
		}
		select {
		case msg.ResponseChan <- ack:
		case <-ctx.Done():
		}
	}
}

// GetTransport returns the underlying memory transport (for testing).
func (mc *MemoryCoordinator) GetTransport() *MemoryTransport {
	return mc.transport
}

// GetSession returns the current session (for testing).
func (mc *MemoryCoordinator) GetSession() *Session {
	return mc.session
}
