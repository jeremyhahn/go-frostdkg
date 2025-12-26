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
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TestNewMemoryTransport tests creating a new memory transport.
func TestNewMemoryTransport(t *testing.T) {
	tests := []struct {
		name      string
		codecType string
		wantErr   bool
	}{
		{
			name:      "json codec",
			codecType: "json",
			wantErr:   false,
		},
		{
			name:      "msgpack codec",
			codecType: "msgpack",
			wantErr:   false,
		},
		{
			name:      "cbor codec",
			codecType: "cbor",
			wantErr:   false,
		},
		{
			name:      "default codec",
			codecType: "",
			wantErr:   false,
		},
		{
			name:      "invalid codec",
			codecType: "invalid",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mt, err := NewMemoryTransport(tt.codecType)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMemoryTransport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && mt == nil {
				t.Error("NewMemoryTransport() returned nil transport")
			}
		})
	}
}

// TestMemoryTransportCreateSession tests session creation.
func TestMemoryTransportCreateSession(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	tests := []struct {
		name      string
		sessionID string
		config    *transport.SessionConfig
		wantErr   error
	}{
		{
			name:      "valid session",
			sessionID: "session-1",
			config: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			},
			wantErr: nil,
		},
		{
			name:      "empty session ID",
			sessionID: "",
			config: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
			},
			wantErr: transport.ErrInvalidConfig,
		},
		{
			name:      "nil config",
			sessionID: "session-2",
			config:    nil,
			wantErr:   transport.ErrInvalidConfig,
		},
		{
			name:      "invalid threshold too low",
			sessionID: "session-3",
			config: &transport.SessionConfig{
				Threshold:       0,
				NumParticipants: 3,
			},
			wantErr: transport.ErrInvalidThreshold,
		},
		{
			name:      "invalid threshold too high",
			sessionID: "session-4",
			config: &transport.SessionConfig{
				Threshold:       4,
				NumParticipants: 3,
			},
			wantErr: transport.ErrInvalidThreshold,
		},
		{
			name:      "invalid participant count",
			sessionID: "session-5",
			config: &transport.SessionConfig{
				Threshold:       1,
				NumParticipants: 0,
			},
			wantErr: transport.ErrInvalidParticipantCount,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := mt.CreateSession(tt.sessionID, tt.config)
			if err != tt.wantErr {
				t.Errorf("CreateSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil && session == nil {
				t.Error("CreateSession() returned nil session")
			}
		})
	}
}

// TestMemoryTransportDuplicateSession tests creating duplicate sessions.
func TestMemoryTransportDuplicateSession(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	// Create first session
	_, err = mt.CreateSession("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create first session: %v", err)
	}

	// Try to create duplicate
	_, err = mt.CreateSession("session-1", config)
	if err != transport.ErrSessionExists {
		t.Errorf("CreateSession() duplicate error = %v, want %v", err, transport.ErrSessionExists)
	}
}

// TestMemoryTransportGetSession tests retrieving sessions.
func TestMemoryTransportGetSession(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	// Create session
	created, err := mt.CreateSession("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Get existing session
	retrieved, err := mt.GetSession("session-1")
	if err != nil {
		t.Errorf("GetSession() error = %v, want nil", err)
	}
	if retrieved != created {
		t.Error("GetSession() returned different session instance")
	}

	// Get non-existent session
	_, err = mt.GetSession("non-existent")
	if err != transport.ErrSessionNotFound {
		t.Errorf("GetSession() error = %v, want %v", err, transport.ErrSessionNotFound)
	}
}

// TestMemoryTransportCloseSession tests closing sessions.
func TestMemoryTransportCloseSession(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	// Create and close session
	_, err = mt.CreateSession("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = mt.CloseSession("session-1")
	if err != nil {
		t.Errorf("CloseSession() error = %v, want nil", err)
	}

	// Verify session is gone
	_, err = mt.GetSession("session-1")
	if err != transport.ErrSessionNotFound {
		t.Errorf("GetSession() after close error = %v, want %v", err, transport.ErrSessionNotFound)
	}

	// Close non-existent session
	err = mt.CloseSession("non-existent")
	if err != transport.ErrSessionNotFound {
		t.Errorf("CloseSession() error = %v, want %v", err, transport.ErrSessionNotFound)
	}
}

// TestMemoryTransportAddParticipant tests adding participants to a session.
func TestMemoryTransportAddParticipant(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	_, err = mt.CreateSession("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Add first participant
	pubkey1 := make([]byte, 33)
	conn1, err := mt.AddParticipant("session-1", "participant-1", pubkey1)
	if err != nil {
		t.Errorf("AddParticipant() error = %v, want nil", err)
	}
	if conn1 == nil {
		t.Fatal("AddParticipant() returned nil connection")
	}
	if conn1.Index != 0 {
		t.Errorf("AddParticipant() index = %d, want 0", conn1.Index)
	}

	// Add second participant
	pubkey2 := make([]byte, 33)
	conn2, err := mt.AddParticipant("session-1", "participant-2", pubkey2)
	if err != nil {
		t.Errorf("AddParticipant() error = %v, want nil", err)
	}
	if conn2.Index != 1 {
		t.Errorf("AddParticipant() index = %d, want 1", conn2.Index)
	}

	// Add duplicate participant
	_, err = mt.AddParticipant("session-1", "participant-1", pubkey1)
	if err != transport.ErrDuplicateParticipant {
		t.Errorf("AddParticipant() duplicate error = %v, want %v", err, transport.ErrDuplicateParticipant)
	}

	// Add to non-existent session
	_, err = mt.AddParticipant("non-existent", "participant-3", pubkey1)
	if err != transport.ErrSessionNotFound {
		t.Errorf("AddParticipant() error = %v, want %v", err, transport.ErrSessionNotFound)
	}
}

// TestMemoryTransportSessionFull tests session capacity limits.
func TestMemoryTransportSessionFull(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	_, err = mt.CreateSession("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Add participants up to limit
	for i := 0; i < 2; i++ {
		pubkey := make([]byte, 33)
		_, err = mt.AddParticipant("session-1", string(rune('A'+i)), pubkey)
		if err != nil {
			t.Errorf("AddParticipant(%d) error = %v, want nil", i, err)
		}
	}

	// Try to add one more
	pubkey := make([]byte, 33)
	_, err = mt.AddParticipant("session-1", "overflow", pubkey)
	if err != transport.ErrSessionFull {
		t.Errorf("AddParticipant() overflow error = %v, want %v", err, transport.ErrSessionFull)
	}
}

// TestMemoryTransportRemoveParticipant tests removing participants.
func TestMemoryTransportRemoveParticipant(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	_, err = mt.CreateSession("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	pubkey := make([]byte, 33)
	_, err = mt.AddParticipant("session-1", "participant-1", pubkey)
	if err != nil {
		t.Fatalf("Failed to add participant: %v", err)
	}

	// Remove participant
	err = mt.RemoveParticipant("session-1", "participant-1")
	if err != nil {
		t.Errorf("RemoveParticipant() error = %v, want nil", err)
	}

	// Remove non-existent participant
	err = mt.RemoveParticipant("session-1", "non-existent")
	if err == nil {
		t.Error("RemoveParticipant() non-existent should return error")
	}
}

// TestMemoryTransportSendToParticipant tests sending messages to participants.
func TestMemoryTransportSendToParticipant(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	_, err = mt.CreateSession("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	pubkey := make([]byte, 33)
	conn, err := mt.AddParticipant("session-1", "participant-1", pubkey)
	if err != nil {
		t.Fatalf("Failed to add participant: %v", err)
	}

	ctx := context.Background()
	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeRound1,
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().Unix(),
	}

	// Send message
	err = mt.SendToParticipant(ctx, "session-1", "participant-1", envelope)
	if err != nil {
		t.Errorf("SendToParticipant() error = %v, want nil", err)
	}

	// Receive message
	select {
	case received := <-conn.MessageChan:
		if received != envelope {
			t.Error("Received different envelope than sent")
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for message")
	}

	// Send to non-existent participant
	err = mt.SendToParticipant(ctx, "session-1", "non-existent", envelope)
	if err == nil {
		t.Error("SendToParticipant() to non-existent should return error")
	}
}

// TestMemoryTransportBroadcast tests broadcasting to all participants.
func TestMemoryTransportBroadcast(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	_, err = mt.CreateSession("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Add three participants
	var conns []*ParticipantConnection
	for i := 0; i < 3; i++ {
		pubkey := make([]byte, 33)
		conn, err := mt.AddParticipant("session-1", string(rune('A'+i)), pubkey)
		if err != nil {
			t.Fatalf("Failed to add participant %d: %v", i, err)
		}
		conns = append(conns, conn)
	}

	ctx := context.Background()
	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeRound1Agg,
		SenderIdx: -1,
		Payload:   []byte("broadcast"),
		Timestamp: time.Now().Unix(),
	}

	// Broadcast
	err = mt.BroadcastToParticipants(ctx, "session-1", envelope)
	if err != nil {
		t.Errorf("BroadcastToParticipants() error = %v, want nil", err)
	}

	// Verify all participants received
	for i, conn := range conns {
		select {
		case received := <-conn.MessageChan:
			if received != envelope {
				t.Errorf("Participant %d received different envelope", i)
			}
		case <-time.After(1 * time.Second):
			t.Errorf("Participant %d timeout waiting for broadcast", i)
		}
	}
}

// TestNewMemoryCoordinator tests creating a coordinator.
func TestNewMemoryCoordinator(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		config    *transport.SessionConfig
		wantErr   bool
	}{
		{
			name:      "valid coordinator",
			sessionID: "session-1",
			config: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			},
			wantErr: false,
		},
		{
			name:      "empty session ID",
			sessionID: "",
			config: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
			},
			wantErr: true,
		},
		{
			name:      "nil config",
			sessionID: "session-2",
			config:    nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc, err := NewMemoryCoordinator(tt.sessionID, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMemoryCoordinator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && mc == nil {
				t.Error("NewMemoryCoordinator() returned nil")
			}
		})
	}
}

// TestMemoryCoordinatorStartStop tests coordinator lifecycle.
func TestMemoryCoordinatorStartStop(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()

	// Start coordinator
	err = mc.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v, want nil", err)
	}

	// Verify coordinator is started
	if mc.SessionID() != "session-1" {
		t.Errorf("SessionID() = %s, want session-1", mc.SessionID())
	}

	// Stop coordinator
	err = mc.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() error = %v, want nil", err)
	}

	// Stop again should not error (sync.Once prevents double execution)
	err = mc.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() called twice error = %v, want nil (sync.Once)", err)
	}
}

// TestMemoryCoordinatorWaitForParticipants tests waiting for participants.
func TestMemoryCoordinatorWaitForParticipants(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	// Add participants in background
	go func() {
		time.Sleep(200 * time.Millisecond)
		for i := 0; i < 3; i++ {
			pubkey := make([]byte, 33)
			_, _ = mc.GetTransport().AddParticipant("session-1", string(rune('A'+i)), pubkey)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Wait for 3 participants
	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	err = mc.WaitForParticipants(waitCtx, 3)
	if err != nil {
		t.Errorf("WaitForParticipants() error = %v, want nil", err)
	}
}

// TestMemoryCoordinatorWaitTimeout tests wait timeout.
func TestMemoryCoordinatorWaitTimeout(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	// Wait with short timeout (no participants added)
	waitCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()

	err = mc.WaitForParticipants(waitCtx, 3)
	if err != transport.ErrConnectionTimeout {
		t.Errorf("WaitForParticipants() error = %v, want %v", err, transport.ErrConnectionTimeout)
	}
}

// TestNewMemoryParticipant tests creating a participant.
func TestNewMemoryParticipant(t *testing.T) {
	tests := []struct {
		name          string
		participantID string
		wantErr       bool
	}{
		{
			name:          "valid participant",
			participantID: "participant-1",
			wantErr:       false,
		},
		{
			name:          "empty ID",
			participantID: "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp, err := NewMemoryParticipant(tt.participantID)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMemoryParticipant() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && mp == nil {
				t.Error("NewMemoryParticipant() returned nil")
			}
		})
	}
}

// TestMemoryParticipantConnectDisconnect tests participant connection lifecycle.
func TestMemoryParticipantConnectDisconnect(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	if err := mc.Start(ctx); err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(ctx) }()

	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}
	mp.SetCoordinator(mc)

	// Connect
	err = mp.Connect(ctx, "session-1")
	if err != nil {
		t.Errorf("Connect() error = %v, want nil", err)
	}

	// Connect again should error
	err = mp.Connect(ctx, "session-1")
	if err != transport.ErrAlreadyConnected {
		t.Errorf("Connect() twice error = %v, want %v", err, transport.ErrAlreadyConnected)
	}

	// Disconnect
	err = mp.Disconnect()
	if err != nil {
		t.Errorf("Disconnect() error = %v, want nil", err)
	}

	// Disconnect again should error
	err = mp.Disconnect()
	if err != transport.ErrNotConnected {
		t.Errorf("Disconnect() twice error = %v, want %v", err, transport.ErrNotConnected)
	}
}

// TestMemoryParticipantValidateDKGParams tests DKG parameter validation.
func TestMemoryParticipantValidateDKGParams(t *testing.T) {
	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	validParams := &transport.DKGParams{
		HostSeckey: make([]byte, transport.SecretKeySize),
		HostPubkeys: [][]byte{
			make([]byte, transport.PublicKeySize),
			make([]byte, transport.PublicKeySize),
			make([]byte, transport.PublicKeySize),
		},
		Threshold:      2,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	tests := []struct {
		name    string
		params  *transport.DKGParams
		wantErr error
	}{
		{
			name:    "valid params",
			params:  validParams,
			wantErr: nil,
		},
		{
			name:    "nil params",
			params:  nil,
			wantErr: transport.ErrInvalidDKGParams,
		},
		{
			name: "invalid seckey length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 16),
				HostPubkeys:    validParams.HostPubkeys,
				Threshold:      2,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			wantErr: transport.ErrInvalidHostKey,
		},
		{
			name: "invalid random length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    validParams.HostPubkeys,
				Threshold:      2,
				ParticipantIdx: 0,
				Random:         make([]byte, 16),
			},
			wantErr: transport.ErrInvalidRandomness,
		},
		{
			name: "invalid participant index",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    validParams.HostPubkeys,
				Threshold:      2,
				ParticipantIdx: 10,
				Random:         make([]byte, 32),
			},
			wantErr: transport.ErrInvalidParticipantIndex,
		},
		{
			name: "invalid threshold",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    validParams.HostPubkeys,
				Threshold:      0,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			wantErr: transport.ErrInvalidThreshold,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mp.validateDKGParams(tt.params)
			if err != tt.wantErr {
				t.Errorf("validateDKGParams() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestMemoryParticipantJoinSession tests joining a session.
func TestMemoryParticipantJoinSession(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	mp.SetCoordinator(mc)

	err = mp.Connect(ctx, "session-1")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	params := &transport.DKGParams{
		HostSeckey: make([]byte, transport.SecretKeySize),
		HostPubkeys: [][]byte{
			make([]byte, transport.PublicKeySize),
			make([]byte, transport.PublicKeySize),
			make([]byte, transport.PublicKeySize),
		},
		Threshold:      2,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	joinCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	err = mp.joinSession(joinCtx, params)
	if err != nil {
		t.Errorf("joinSession() error = %v, want nil", err)
	}

	if mp.GetSessionInfo() == nil {
		t.Error("joinSession() did not set session info")
	}
}

// TestMemoryParticipantRunDKG tests running a full DKG session.
func TestMemoryParticipantRunDKG(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	mp.SetCoordinator(mc)

	err = mp.Connect(ctx, "session-1")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = mp.Disconnect() }()

	params := &transport.DKGParams{
		HostSeckey: make([]byte, transport.SecretKeySize),
		HostPubkeys: [][]byte{
			make([]byte, transport.PublicKeySize),
			make([]byte, transport.PublicKeySize),
			make([]byte, transport.PublicKeySize),
		},
		Threshold:      2,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	dkgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result, err := mp.RunDKG(dkgCtx, params)
	if err != nil {
		t.Errorf("RunDKG() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("RunDKG() returned nil result")
	}

	if len(result.SecretShare) != 32 {
		t.Errorf("SecretShare length = %d, want 32", len(result.SecretShare))
	}

	if len(result.ThresholdPubkey) != transport.PublicKeySize {
		t.Errorf("ThresholdPubkey length = %d, want %d", len(result.ThresholdPubkey), transport.PublicKeySize)
	}

	if len(result.PublicShares) != 3 {
		t.Errorf("PublicShares length = %d, want 3", len(result.PublicShares))
	}
}

// TestConcurrentSessions tests multiple concurrent DKG sessions.
func TestConcurrentSessions(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	// Create multiple sessions concurrently
	numSessions := 5
	sessions := make([]*Session, numSessions)

	for i := 0; i < numSessions; i++ {
		sessionID := string(rune('A' + i))
		session, err := mt.CreateSession(sessionID, config)
		if err != nil {
			t.Errorf("CreateSession(%s) error = %v", sessionID, err)
		}
		sessions[i] = session
	}

	// Verify all sessions exist
	for i := 0; i < numSessions; i++ {
		sessionID := string(rune('A' + i))
		session, err := mt.GetSession(sessionID)
		if err != nil {
			t.Errorf("GetSession(%s) error = %v", sessionID, err)
		}
		if session != sessions[i] {
			t.Errorf("GetSession(%s) returned different session", sessionID)
		}
	}
}

// TestMessageTimeout tests message send timeout.
func TestMessageTimeout(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	_, err = mt.CreateSession("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	pubkey := make([]byte, 33)
	conn, err := mt.AddParticipant("session-1", "participant-1", pubkey)
	if err != nil {
		t.Fatalf("Failed to add participant: %v", err)
	}

	// Fill the channel buffer
	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeRound1,
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().Unix(),
	}

	for i := 0; i < 100; i++ {
		conn.MessageChan <- envelope
	}

	// Try to send with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = mt.SendToParticipant(ctx, "session-1", "participant-1", envelope)
	if err != transport.ErrMessageTimeout {
		t.Errorf("SendToParticipant() timeout error = %v, want %v", err, transport.ErrMessageTimeout)
	}
}

// TestCoordinatorAddress tests getting the coordinator address.
func TestCoordinatorAddress(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("test-session", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	addr := mc.Address()
	if addr != "test-session" {
		t.Errorf("Address() = %s, want test-session", addr)
	}
}

// TestParticipantGetters tests participant getter methods.
func TestParticipantGetters(t *testing.T) {
	mp, err := NewMemoryParticipant("test-participant")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	if mp.GetParticipantID() != "test-participant" {
		t.Errorf("GetParticipantID() = %s, want test-participant", mp.GetParticipantID())
	}

	// Index should be 0 initially
	if mp.GetParticipantIndex() != 0 {
		t.Errorf("GetParticipantIndex() = %d, want 0", mp.GetParticipantIndex())
	}
}

// TestParticipantSendReceive tests sending and receiving messages.
func TestParticipantSendReceive(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	mp.SetCoordinator(mc)

	err = mp.Connect(ctx, "session-1")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = mp.Disconnect() }()

	// Test SendToCoordinator
	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeRound1,
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().Unix(),
	}

	err = mp.SendToCoordinator(ctx, envelope)
	if err != nil {
		t.Errorf("SendToCoordinator() error = %v, want nil", err)
	}

	// Test ReceiveFromCoordinator with timeout
	recvCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	_, err = mp.ReceiveFromCoordinator(recvCtx)
	if err != transport.ErrMessageTimeout {
		t.Errorf("ReceiveFromCoordinator() timeout error = %v, want %v", err, transport.ErrMessageTimeout)
	}
}

// TestParticipantSendNotConnected tests sending when not connected.
func TestParticipantSendNotConnected(t *testing.T) {
	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	ctx := context.Background()
	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeRound1,
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().Unix(),
	}

	err = mp.SendToCoordinator(ctx, envelope)
	if err != transport.ErrNotConnected {
		t.Errorf("SendToCoordinator() not connected error = %v, want %v", err, transport.ErrNotConnected)
	}

	_, err = mp.ReceiveFromCoordinator(ctx)
	if err != transport.ErrNotConnected {
		t.Errorf("ReceiveFromCoordinator() not connected error = %v, want %v", err, transport.ErrNotConnected)
	}
}

// TestValidateDKGParamsEmptyPubkeys tests validation with empty host pubkeys.
func TestValidateDKGParamsEmptyPubkeys(t *testing.T) {
	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	params := &transport.DKGParams{
		HostSeckey:     make([]byte, 32),
		HostPubkeys:    [][]byte{},
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	err = mp.validateDKGParams(params)
	if err != transport.ErrInvalidDKGParams {
		t.Errorf("validateDKGParams() empty pubkeys error = %v, want %v", err, transport.ErrInvalidDKGParams)
	}
}

// TestCoordinatorStartAlreadyStarted tests starting an already started coordinator.
func TestCoordinatorStartAlreadyStarted(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()

	// Start coordinator
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	// Try to start again
	err = mc.Start(ctx)
	if err == nil {
		t.Error("Start() called twice should return error")
	}
}

// TestRunDKGNotConnected tests RunDKG when not connected.
func TestRunDKGNotConnected(t *testing.T) {
	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	ctx := context.Background()
	params := &transport.DKGParams{
		HostSeckey: make([]byte, 32),
		HostPubkeys: [][]byte{
			make([]byte, 33),
			make([]byte, 33),
			make([]byte, 33),
		},
		Threshold:      2,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	_, err = mp.RunDKG(ctx, params)
	if err != transport.ErrNotConnected {
		t.Errorf("RunDKG() not connected error = %v, want %v", err, transport.ErrNotConnected)
	}
}

// TestRunDKGInvalidParams tests RunDKG with invalid parameters.
func TestRunDKGInvalidParams(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	mp.SetCoordinator(mc)

	err = mp.Connect(ctx, "session-1")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = mp.Disconnect() }()

	// Invalid params - nil
	_, err = mp.RunDKG(ctx, nil)
	if err == nil {
		t.Error("RunDKG() with nil params should return error")
	}

	// Invalid params - wrong seckey length
	params := &transport.DKGParams{
		HostSeckey: make([]byte, 16),
		HostPubkeys: [][]byte{
			make([]byte, 33),
		},
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	_, err = mp.RunDKG(ctx, params)
	if err != transport.ErrInvalidHostKey {
		t.Errorf("RunDKG() invalid params error = %v, want %v", err, transport.ErrInvalidHostKey)
	}
}

// TestBroadcastError tests broadcast when participant send fails.
func TestBroadcastError(t *testing.T) {
	mt, err := NewMemoryTransport("json")
	if err != nil {
		t.Fatalf("Failed to create memory transport: %v", err)
	}

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	_, err = mt.CreateSession("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Add one participant
	pubkey := make([]byte, 33)
	_, err = mt.AddParticipant("session-1", "participant-1", pubkey)
	if err != nil {
		t.Fatalf("Failed to add participant: %v", err)
	}

	// Disconnect the participant by removing it
	err = mt.RemoveParticipant("session-1", "participant-1")
	if err != nil {
		t.Fatalf("Failed to remove participant: %v", err)
	}

	// Re-add but mark as disconnected
	conn, err := mt.AddParticipant("session-1", "participant-1", pubkey)
	if err != nil {
		t.Fatalf("Failed to re-add participant: %v", err)
	}

	// Close the connection
	conn.ConnectedMu.Lock()
	conn.Connected = false
	close(conn.MessageChan)
	conn.ConnectedMu.Unlock()

	ctx := context.Background()
	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeRound1Agg,
		SenderIdx: -1,
		Payload:   []byte("broadcast"),
		Timestamp: time.Now().Unix(),
	}

	// Broadcast should fail
	err = mt.BroadcastToParticipants(ctx, "session-1", envelope)
	if err == nil {
		t.Error("BroadcastToParticipants() to disconnected participant should return error")
	}
}

// TestJoinSessionNoCoordinator tests joining when coordinator is not set.
func TestJoinSessionNoCoordinator(t *testing.T) {
	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	ctx := context.Background()
	// Connect should fail without coordinator
	err = mp.Connect(ctx, "session-1")
	if err == nil {
		t.Error("Connect() without coordinator should return error")
	}
}

// TestHandleRound1Message tests the Round1 message handler.
func TestHandleRound1Message(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	// Create a Round1 message
	round1Msg := &transport.Round1Message{
		Commitment: [][]byte{make([]byte, 33)},
		POP:        make([]byte, 64),
		Pubnonce:   make([]byte, 33),
	}

	payload, err := mc.GetTransport().Serializer().Marshal(round1Msg)
	if err != nil {
		t.Fatalf("Failed to marshal Round1 message: %v", err)
	}

	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeRound1,
		SenderIdx: 0,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	responseChan := make(chan *transport.Envelope, 1)
	msg := &Message{
		Envelope:      envelope,
		ResponseChan:  responseChan,
		ParticipantID: "participant-1",
	}

	mc.handleRound1Message(ctx, msg)

	// Check that we received an acknowledgment
	select {
	case response := <-responseChan:
		if response.Type != transport.MsgTypeRound1Agg {
			t.Errorf("Response type = %v, want %v", response.Type, transport.MsgTypeRound1Agg)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for Round1 response")
	}
}

// TestHandleRound2Message tests the Round2 message handler.
func TestHandleRound2Message(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	// Create a Round2 message
	round2Msg := &transport.Round2Message{
		EncryptedShares: make([]byte, 128),
	}

	payload, err := mc.GetTransport().Serializer().Marshal(round2Msg)
	if err != nil {
		t.Fatalf("Failed to marshal Round2 message: %v", err)
	}

	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeRound2,
		SenderIdx: 0,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	responseChan := make(chan *transport.Envelope, 1)
	msg := &Message{
		Envelope:      envelope,
		ResponseChan:  responseChan,
		ParticipantID: "participant-1",
	}

	mc.handleRound2Message(ctx, msg)

	// Check that we received an acknowledgment
	select {
	case response := <-responseChan:
		if response.Type != transport.MsgTypeRound2Agg {
			t.Errorf("Response type = %v, want %v", response.Type, transport.MsgTypeRound2Agg)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for Round2 response")
	}
}

// TestHandleCertEqSignMessage tests the CertEqSign message handler.
func TestHandleCertEqSignMessage(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	// Create a CertEqSign message
	certEqSignMsg := &transport.CertEqSignMessage{
		Signature: make([]byte, 64),
	}

	payload, err := mc.GetTransport().Serializer().Marshal(certEqSignMsg)
	if err != nil {
		t.Fatalf("Failed to marshal CertEqSign message: %v", err)
	}

	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeCertEqSign,
		SenderIdx: 0,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	responseChan := make(chan *transport.Envelope, 1)
	msg := &Message{
		Envelope:      envelope,
		ResponseChan:  responseChan,
		ParticipantID: "participant-1",
	}

	mc.handleCertEqSignMessage(ctx, msg)

	// Check that we received a certificate
	select {
	case response := <-responseChan:
		if response.Type != transport.MsgTypeCertificate {
			t.Errorf("Response type = %v, want %v", response.Type, transport.MsgTypeCertificate)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for Certificate response")
	}
}

// TestHandleUnknownMessage tests handling an unknown message type.
func TestHandleUnknownMessage(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	// Create a message with unknown type
	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MessageType(99), // Unknown type
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().Unix(),
	}

	errorChan := make(chan error, 1)
	msg := &Message{
		Envelope:      envelope,
		ErrorChan:     errorChan,
		ParticipantID: "participant-1",
	}

	mc.handleMessage(ctx, msg)

	// Check that we received an error
	select {
	case err := <-errorChan:
		if err != transport.ErrUnexpectedMessage {
			t.Errorf("Error = %v, want %v", err, transport.ErrUnexpectedMessage)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for error response")
	}
}

// TestReceiveFromCoordinatorConnectionClosed tests receiving when connection is closed.
func TestReceiveFromCoordinatorConnectionClosed(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	if err := mc.Start(ctx); err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(ctx) }()

	mp, err := NewMemoryParticipant("participant-1")
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}
	mp.SetCoordinator(mc)

	err = mp.Connect(ctx, "session-1")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Close the receive channel
	close(mp.receiveChan)

	_, err = mp.ReceiveFromCoordinator(ctx)
	if err != transport.ErrConnectionClosed {
		t.Errorf("ReceiveFromCoordinator() closed error = %v, want %v", err, transport.ErrConnectionClosed)
	}
}

// TestStopNotStarted tests stopping a coordinator that was never started.
func TestStopNotStarted(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()

	// Try to stop without starting
	err = mc.Stop(ctx)
	if err == nil {
		t.Error("Stop() on never-started coordinator should return error")
	}
}

// TestWaitForParticipantsSessionClosed tests waiting when session gets closed.
func TestWaitForParticipantsSessionClosed(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	// Stop coordinator in background after a short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = mc.Stop(context.Background())
	}()

	// Wait for participants (should return session closed error)
	err = mc.WaitForParticipants(ctx, 3)
	if err != transport.ErrSessionClosed {
		t.Errorf("WaitForParticipants() error = %v, want %v", err, transport.ErrSessionClosed)
	}
}

// TestHandleJoinMessageErrors tests join message handler error paths.
func TestHandleJoinMessageErrors(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	// Test with invalid payload
	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeJoin,
		SenderIdx: 0,
		Payload:   []byte("invalid json"),
		Timestamp: time.Now().Unix(),
	}

	errorChan := make(chan error, 1)
	msg := &Message{
		Envelope:      envelope,
		ErrorChan:     errorChan,
		ParticipantID: "participant-1",
	}

	mc.handleJoinMessage(ctx, msg)

	// Check that we received an error
	select {
	case err := <-errorChan:
		if err == nil {
			t.Error("Expected error for invalid join message payload")
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for error response")
	}
}

// TestProcessMessagesContextCanceled tests message processing when context is canceled.
func TestProcessMessagesContextCanceled(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	// Cancel context immediately
	cancel()

	// Give it time to process
	time.Sleep(100 * time.Millisecond)

	// Stop should work even after context cancellation
	err = mc.Stop(context.Background())
	if err != nil {
		t.Errorf("Stop() error = %v, want nil", err)
	}
}

// TestWaitForParticipantsInvalidCount tests invalid participant counts.
func TestWaitForParticipantsInvalidCount(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	// Test with count < 1
	err = mc.WaitForParticipants(ctx, 0)
	if err != transport.ErrInvalidParticipantCount {
		t.Errorf("WaitForParticipants(0) error = %v, want %v", err, transport.ErrInvalidParticipantCount)
	}

	// Test with count > NumParticipants
	err = mc.WaitForParticipants(ctx, 10)
	if err != transport.ErrInvalidParticipantCount {
		t.Errorf("WaitForParticipants(10) error = %v, want %v", err, transport.ErrInvalidParticipantCount)
	}
}

// TestHandleJoinMessageSessionFull tests join when session is full.
func TestHandleJoinMessageSessionFull(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	mc, err := NewMemoryCoordinator("session-1", config)
	if err != nil {
		t.Fatalf("Failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = mc.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}
	defer func() { _ = mc.Stop(context.Background()) }()

	// Fill the session
	pubkey := make([]byte, 33)
	for i := 0; i < 2; i++ {
		_, err = mc.GetTransport().AddParticipant("session-1", string(rune('A'+i)), pubkey)
		if err != nil {
			t.Fatalf("Failed to add participant %d: %v", i, err)
		}
	}

	// Try to join a full session
	joinMsg := &transport.JoinMessage{
		HostPubkey: pubkey,
	}

	payload, err := mc.GetTransport().Serializer().Marshal(joinMsg)
	if err != nil {
		t.Fatalf("Failed to marshal join message: %v", err)
	}

	envelope := &transport.Envelope{
		SessionID: "session-1",
		Type:      transport.MsgTypeJoin,
		SenderIdx: 2,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	errorChan := make(chan error, 1)
	msg := &Message{
		Envelope:      envelope,
		ErrorChan:     errorChan,
		ParticipantID: "participant-overflow",
	}

	mc.handleJoinMessage(ctx, msg)

	// Check that we received a session full error
	select {
	case err := <-errorChan:
		if err != transport.ErrSessionFull {
			t.Errorf("Error = %v, want %v", err, transport.ErrSessionFull)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for error response")
	}
}
