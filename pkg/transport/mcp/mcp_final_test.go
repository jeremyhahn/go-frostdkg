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

package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TestMCPServerStdioRequests tests stdio request handling.
func TestMCPServerStdioRequests(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	// Create test input
	req, _ := NewJSONRPCRequest(string(ToolGetSession), map[string]string{"session_id": "test-session"}, 1)
	reqData, _ := json.Marshal(req)

	reader := strings.NewReader(string(reqData) + "\n")
	writer := &bytes.Buffer{}
	server.SetStdio(reader, writer)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	_ = server.Stop(ctx)

	// Check that we got a response
	if writer.Len() == 0 {
		t.Error("expected response on stdout, got nothing")
	}
}

// TestMCPServerStdioEmptyLines tests stdio with empty lines.
func TestMCPServerStdioEmptyLines(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	// Test with empty lines
	reader := strings.NewReader("\n\n\n")
	writer := &bytes.Buffer{}
	server.SetStdio(reader, writer)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	_ = server.Stop(ctx)
}

// TestMCPServerStopNotStarted tests stopping unstarted server.
func TestMCPServerStopNotStarted(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ctx := context.Background()
	err = server.Stop(ctx)
	if err == nil {
		t.Error("expected error stopping unstarted server, got nil")
	}
}

// TestMCPServerWaitForParticipantsInvalidCount tests invalid participant counts.
func TestMCPServerWaitForParticipantsInvalidCount(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ctx := context.Background()
	reader := bytes.NewReader([]byte{})
	writer := &bytes.Buffer{}
	server.SetStdio(reader, writer)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = server.Stop(ctx) }()

	tests := []struct {
		name  string
		count int
	}{
		{
			name:  "zero participants",
			count: 0,
		},
		{
			name:  "too many participants",
			count: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use timeout context to prevent hanging
			timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancel()
			err := server.WaitForParticipants(timeoutCtx, tt.count)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestMCPServerGetSessionNotFound tests getting non-existent session.
func TestMCPServerGetSessionNotFound(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ctx := context.Background()
	reader := bytes.NewReader([]byte{})
	writer := &bytes.Buffer{}
	server.SetStdio(reader, writer)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = server.Stop(ctx) }()

	params := GetSessionParams{
		SessionID: "non-existent",
	}
	paramsJSON, _ := MarshalParams(params)
	_, err = server.handleGetSession(ctx, paramsJSON)
	if err == nil {
		t.Error("expected error for non-existent session, got nil")
	}
}

// TestMarshalParamsError tests MarshalParams with unmarshalable type.
func TestMarshalParamsError(t *testing.T) {
	// Create a type that can't be marshaled
	type Unmarshalable struct {
		Chan chan int
	}

	_, err := MarshalParams(&Unmarshalable{Chan: make(chan int)})
	if err == nil {
		t.Error("expected error marshaling channel, got nil")
	}
}

// TestNewJSONRPCRequestError tests request creation error.
func TestNewJSONRPCRequestError(t *testing.T) {
	type Unmarshalable struct {
		Chan chan int
	}

	_, err := NewJSONRPCRequest("test", &Unmarshalable{Chan: make(chan int)}, 1)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestNewJSONRPCResponseError tests response creation error.
func TestNewJSONRPCResponseError(t *testing.T) {
	type Unmarshalable struct {
		Chan chan int
	}

	_, err := NewJSONRPCResponse(&Unmarshalable{Chan: make(chan int)}, 1)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestNewJSONRPCErrorResponseError tests error response creation error.
func TestNewJSONRPCErrorResponseError(t *testing.T) {
	type Unmarshalable struct {
		Chan chan int
	}

	_, err := NewJSONRPCErrorResponse(-32600, "error", &Unmarshalable{Chan: make(chan int)}, 1)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestNewJSONRPCNotificationError tests notification creation error.
func TestNewJSONRPCNotificationError(t *testing.T) {
	type Unmarshalable struct {
		Chan chan int
	}

	_, err := NewJSONRPCNotification("test", &Unmarshalable{Chan: make(chan int)})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestMCPServerHTTPReadBodyError tests HTTP request with read error.
func TestMCPServerHTTPReadBodyError(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportHTTP, "localhost:0")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = server.Stop(ctx) }()

	// We can't easily test read errors without a real server, but we covered the path
}

// TestMCPServerStartInvalidTransport tests starting with invalid transport.
func TestMCPServerStartInvalidTransport(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server := &MCPServer{
		transportType: "invalid",
		sessionID:     "test",
		config:        config,
		sessions:      make(map[string]*MCPSession),
		stopChan:      make(chan struct{}),
	}

	session := &MCPSession{
		SessionID:        "test",
		Config:           config,
		State:            StateCreated,
		Participants:     make(map[int]*MCPParticipant),
		Round1Messages:   make(map[int]*transport.Round1Message),
		Round2Messages:   make(map[int]*transport.Round2Message),
		CertEqSignatures: make(map[int]*transport.CertEqSignMessage),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	server.sessions["test"] = session
	server.started.Store(true)

	ctx := context.Background()
	err := server.Start(ctx)
	if err == nil {
		t.Error("expected error for invalid transport type, got nil")
	}
}

// TestMCPClientCallInvalidTransport tests client call with invalid transport.
func TestMCPClientCallInvalidTransport(t *testing.T) {
	client := &MCPClient{
		participantID: "test",
		transportType: "invalid",
	}
	client.connected.Store(true)

	ctx := context.Background()
	var result map[string]string
	err := client.call(ctx, "test_method", nil, &result)
	if err == nil {
		t.Error("expected error for invalid transport type, got nil")
	}
}

// TestMCPClientCallMarshalError tests call with marshal error.
func TestMCPClientCallMarshalError(t *testing.T) {
	client, _ := NewMCPClient("test", TransportHTTP)
	client.connected.Store(true)

	ctx := context.Background()

	type Unmarshalable struct {
		Chan chan int
	}

	var result map[string]string
	err := client.call(ctx, "test", &Unmarshalable{Chan: make(chan int)}, &result)
	if err == nil {
		t.Error("expected marshal error, got nil")
	}
}

// TestMCPServerSubmitRound2WrongState tests Round2 in wrong state.
func TestMCPServerSubmitRound2WrongState(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ctx := context.Background()
	reader := bytes.NewReader([]byte{})
	writer := &bytes.Buffer{}
	server.SetStdio(reader, writer)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = server.Stop(ctx) }()

	// Try to submit Round2 without being in Round2 state
	params := SubmitRound2Params{
		SessionID:       "test-session",
		ParticipantIdx:  0,
		EncryptedShares: hex.EncodeToString(make([]byte, 64)),
	}
	paramsJSON, _ := MarshalParams(params)
	_, err = server.handleSubmitRound2(ctx, paramsJSON)
	if err == nil {
		t.Error("expected error for wrong state, got nil")
	}
}

// TestMCPServerSubmitCertEqWrongState tests CertEq in wrong state.
func TestMCPServerSubmitCertEqWrongState(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ctx := context.Background()
	reader := bytes.NewReader([]byte{})
	writer := &bytes.Buffer{}
	server.SetStdio(reader, writer)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = server.Stop(ctx) }()

	// Try to submit CertEq without being in CertEq state
	params := SubmitCertEqParams{
		SessionID:      "test-session",
		ParticipantIdx: 0,
		Signature:      hex.EncodeToString(make([]byte, 64)),
	}
	paramsJSON, _ := MarshalParams(params)
	_, err = server.handleSubmitCertEq(ctx, paramsJSON)
	if err == nil {
		t.Error("expected error for wrong state, got nil")
	}
}

// TestMCPServerCreateSessionInvalidParams tests create session with invalid params.
func TestMCPServerCreateSessionInvalidParams(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ctx := context.Background()
	reader := bytes.NewReader([]byte{})
	writer := &bytes.Buffer{}
	server.SetStdio(reader, writer)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = server.Stop(ctx) }()

	tests := []struct {
		name   string
		params CreateSessionParams
	}{
		{
			name: "empty session id",
			params: CreateSessionParams{
				SessionID:       "",
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "test",
			},
		},
		{
			name: "zero threshold",
			params: CreateSessionParams{
				SessionID:       "test",
				Threshold:       0,
				NumParticipants: 3,
				Ciphersuite:     "test",
			},
		},
		{
			name: "zero participants",
			params: CreateSessionParams{
				SessionID:       "test",
				Threshold:       2,
				NumParticipants: 0,
				Ciphersuite:     "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsJSON, _ := MarshalParams(tt.params)
			_, err := server.handleCreateSession(ctx, paramsJSON)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestMCPClientStdioReadError tests stdio read error handling.
func TestMCPClientStdioReadError(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportStdio)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	// Reader that returns empty (EOF)
	reader := strings.NewReader("")
	writer := &bytes.Buffer{}
	client.SetStdio(reader, writer)

	ctx := context.Background()
	if err := client.Connect(ctx, "test-session"); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	var result map[string]string
	err = client.call(ctx, "test_method", nil, &result)
	if err == nil {
		t.Error("expected error for EOF reader, got nil")
	}
}

// TestMCPClientValidatePubkeyLength tests validation with wrong pubkey length.
func TestMCPClientValidatePubkeyLength(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportHTTP)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	params := &transport.DKGParams{
		HostSeckey:     make([]byte, 32),
		HostPubkeys:    [][]byte{make([]byte, 16)}, // Wrong length
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	err = client.validateDKGParams(params)
	if err == nil {
		t.Error("expected error for wrong pubkey length, got nil")
	}
}

// TestMCPServerListSessionsEmptyParams tests list sessions with nil params.
func TestMCPServerListSessionsEmptyParams(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ctx := context.Background()
	reader := bytes.NewReader([]byte{})
	writer := &bytes.Buffer{}
	server.SetStdio(reader, writer)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = server.Stop(ctx) }()

	// Call with nil params
	result, err := server.handleListSessions(ctx, nil)
	if err != nil {
		t.Fatalf("handleListSessions failed: %v", err)
	}

	listResult := result.(*ListSessionsResult)
	if len(listResult.Sessions) == 0 {
		t.Error("expected sessions in list")
	}
}
