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

// Package memory provides an in-memory transport implementation for testing FROST DKG protocol.
//
// The memory transport enables testing without network I/O by using channels for message
// passing between coordinator and participants within the same process.
//
// Key features:
//   - Channel-based message routing
//   - Thread-safe operations
//   - Support for multiple concurrent DKG sessions
//   - No TLS (in-memory only)
//   - Zero network overhead
package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// Message represents an internal message in the memory transport.
type Message struct {
	Envelope      *transport.Envelope
	ResponseChan  chan *transport.Envelope
	ErrorChan     chan error
	ParticipantID string
}

// Session represents an active DKG session in memory.
type Session struct {
	ID             string
	Config         *transport.SessionConfig
	Participants   map[string]*ParticipantConnection
	ParticipantsMu sync.RWMutex
	MessageChan    chan *Message
	Started        time.Time
	Closed         bool
	CloseMu        sync.RWMutex
}

// ParticipantConnection represents a participant's connection to the coordinator.
type ParticipantConnection struct {
	ID          string
	Index       int
	HostPubkey  []byte
	MessageChan chan *transport.Envelope
	SessionID   string
	Connected   bool
	ConnectedMu sync.RWMutex
}

// MemoryTransport manages in-memory message passing for testing.
type MemoryTransport struct {
	sessions   map[string]*Session
	sessionsMu sync.RWMutex
	serializer *transport.Serializer
}

// NewMemoryTransport creates a new in-memory transport for testing.
func NewMemoryTransport(codecType string) (*MemoryTransport, error) {
	if codecType == "" {
		codecType = "json"
	}

	serializer, err := transport.NewSerializer(codecType)
	if err != nil {
		return nil, fmt.Errorf("failed to create serializer: %w", err)
	}

	return &MemoryTransport{
		sessions:   make(map[string]*Session),
		serializer: serializer,
	}, nil
}

// CreateSession creates a new DKG session.
func (mt *MemoryTransport) CreateSession(sessionID string, config *transport.SessionConfig) (*Session, error) {
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

	mt.sessionsMu.Lock()
	defer mt.sessionsMu.Unlock()

	if _, exists := mt.sessions[sessionID]; exists {
		return nil, transport.ErrSessionExists
	}

	session := &Session{
		ID:           sessionID,
		Config:       config,
		Participants: make(map[string]*ParticipantConnection),
		MessageChan:  make(chan *Message, 100),
		Started:      time.Now(),
		Closed:       false,
	}

	mt.sessions[sessionID] = session
	return session, nil
}

// GetSession retrieves a session by ID.
func (mt *MemoryTransport) GetSession(sessionID string) (*Session, error) {
	mt.sessionsMu.RLock()
	defer mt.sessionsMu.RUnlock()

	session, exists := mt.sessions[sessionID]
	if !exists {
		return nil, transport.ErrSessionNotFound
	}

	return session, nil
}

// CloseSession closes and removes a session.
func (mt *MemoryTransport) CloseSession(sessionID string) error {
	mt.sessionsMu.Lock()
	defer mt.sessionsMu.Unlock()

	session, exists := mt.sessions[sessionID]
	if !exists {
		return transport.ErrSessionNotFound
	}

	session.CloseMu.Lock()
	if !session.Closed {
		session.Closed = true
		close(session.MessageChan)
	}
	session.CloseMu.Unlock()

	delete(mt.sessions, sessionID)
	return nil
}

// AddParticipant adds a participant to a session.
func (mt *MemoryTransport) AddParticipant(sessionID, participantID string, hostPubkey []byte) (*ParticipantConnection, error) {
	session, err := mt.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	session.ParticipantsMu.Lock()
	defer session.ParticipantsMu.Unlock()

	// Check if session is full
	if len(session.Participants) >= session.Config.NumParticipants {
		return nil, transport.ErrSessionFull
	}

	// Check for duplicate
	if _, exists := session.Participants[participantID]; exists {
		return nil, transport.ErrDuplicateParticipant
	}

	// Create participant connection with buffered channel
	conn := &ParticipantConnection{
		ID:          participantID,
		Index:       len(session.Participants),
		HostPubkey:  hostPubkey,
		MessageChan: make(chan *transport.Envelope, 100),
		SessionID:   sessionID,
		Connected:   true,
	}

	session.Participants[participantID] = conn
	return conn, nil
}

// GetParticipant retrieves a participant from a session.
func (mt *MemoryTransport) GetParticipant(sessionID, participantID string) (*ParticipantConnection, error) {
	session, err := mt.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	session.ParticipantsMu.RLock()
	defer session.ParticipantsMu.RUnlock()

	conn, exists := session.Participants[participantID]
	if !exists {
		return nil, transport.NewParticipantError(participantID, -1, transport.ErrNotConnected)
	}

	return conn, nil
}

// RemoveParticipant removes a participant from a session.
func (mt *MemoryTransport) RemoveParticipant(sessionID, participantID string) error {
	session, err := mt.GetSession(sessionID)
	if err != nil {
		return err
	}

	session.ParticipantsMu.Lock()
	defer session.ParticipantsMu.Unlock()

	conn, exists := session.Participants[participantID]
	if !exists {
		return transport.NewParticipantError(participantID, -1, transport.ErrNotConnected)
	}

	conn.ConnectedMu.Lock()
	if conn.Connected {
		conn.Connected = false
		close(conn.MessageChan)
	}
	conn.ConnectedMu.Unlock()

	delete(session.Participants, participantID)
	return nil
}

// SendToParticipant sends a message to a specific participant.
func (mt *MemoryTransport) SendToParticipant(ctx context.Context, sessionID, participantID string, envelope *transport.Envelope) error {
	conn, err := mt.GetParticipant(sessionID, participantID)
	if err != nil {
		return err
	}

	conn.ConnectedMu.RLock()
	defer conn.ConnectedMu.RUnlock()

	if !conn.Connected {
		return transport.NewParticipantError(participantID, conn.Index, transport.ErrConnectionClosed)
	}

	select {
	case conn.MessageChan <- envelope:
		return nil
	case <-ctx.Done():
		return transport.ErrMessageTimeout
	}
}

// BroadcastToParticipants sends a message to all participants in a session.
func (mt *MemoryTransport) BroadcastToParticipants(ctx context.Context, sessionID string, envelope *transport.Envelope) error {
	session, err := mt.GetSession(sessionID)
	if err != nil {
		return err
	}

	session.ParticipantsMu.RLock()
	participants := make([]*ParticipantConnection, 0, len(session.Participants))
	for _, conn := range session.Participants {
		participants = append(participants, conn)
	}
	session.ParticipantsMu.RUnlock()

	// Send to all participants
	for _, conn := range participants {
		if err := mt.SendToParticipant(ctx, sessionID, conn.ID, envelope); err != nil {
			return err
		}
	}

	return nil
}

// Serializer returns the transport's serializer.
func (mt *MemoryTransport) Serializer() *transport.Serializer {
	return mt.serializer
}
