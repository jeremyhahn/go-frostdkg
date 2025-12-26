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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TestJSONRPCRequestMarshaling tests JSON marshaling/unmarshaling.
func TestJSONRPCRequestMarshaling(t *testing.T) {
	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "test_method",
		Params:  json.RawMessage(`{"key": "value"}`),
		ID:      1,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var unmarshaled JSONRPCRequest
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if unmarshaled.Method != req.Method {
		t.Errorf("Method mismatch: expected %s, got %s", req.Method, unmarshaled.Method)
	}
}

// TestJSONRPCResponseMarshaling tests response marshaling/unmarshaling.
func TestJSONRPCResponseMarshaling(t *testing.T) {
	resp := &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		Result:  json.RawMessage(`{"status": "ok"}`),
		ID:      1,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var unmarshaled JSONRPCResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	var result map[string]string
	if err := unmarshaled.GetResult(&result); err != nil {
		t.Fatalf("GetResult failed: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("Result mismatch: expected ok, got %s", result["status"])
	}
}

// TestJSONRPCResponseGetError tests error retrieval.
func TestJSONRPCResponseGetError(t *testing.T) {
	tests := []struct {
		name      string
		response  *JSONRPCResponse
		wantError bool
	}{
		{
			name: "response with error",
			response: &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				Error: &JSONRPCError{
					Code:    -32600,
					Message: "Invalid request",
				},
				ID: 1,
			},
			wantError: true,
		},
		{
			name: "response without error",
			response: &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				Result:  json.RawMessage(`{"status": "ok"}`),
				ID:      1,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.response.GetError()
			if (err != nil) != tt.wantError {
				t.Errorf("GetError() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestJSONRPCResponseGetResultErrors tests error cases for GetResult.
func TestJSONRPCResponseGetResultErrors(t *testing.T) {
	tests := []struct {
		name     string
		response *JSONRPCResponse
	}{
		{
			name: "response with error",
			response: &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				Error: &JSONRPCError{
					Code:    -32600,
					Message: "Invalid request",
				},
				ID: 1,
			},
		},
		{
			name: "response without result",
			response: &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				ID:      1,
				Result:  nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]string
			err := tt.response.GetResult(&result)
			if err == nil {
				t.Error("GetResult should fail")
			}
		})
	}
}

// TestMCPServerHTTPStartStop tests HTTP server lifecycle.
func TestMCPServerHTTPStartStop(t *testing.T) {
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

	// Start server
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Stop server
	if err := server.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

// TestMCPServerHTTPJSONRPCRequest tests HTTP JSON-RPC request handling.
func TestMCPServerHTTPJSONRPCRequest(t *testing.T) {
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

	// Create test server
	ts := httptest.NewServer(http.HandlerFunc(server.handleHTTPRequest))
	defer ts.Close()

	tests := []struct {
		name       string
		request    *JSONRPCRequest
		wantStatus int
	}{
		{
			name: "valid get session",
			request: &JSONRPCRequest{
				JSONRPC: JSONRPCVersion,
				Method:  string(ToolGetSession),
				Params:  json.RawMessage(`{"session_id": "test-session"}`),
				ID:      1,
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "invalid method",
			request: &JSONRPCRequest{
				JSONRPC: JSONRPCVersion,
				Method:  "invalid_method",
				Params:  json.RawMessage(`{}`),
				ID:      2,
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqData, _ := json.Marshal(tt.request)
			resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(reqData))
			if err != nil {
				t.Fatalf("POST failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

// TestMCPServerHTTPInvalidMethod tests HTTP method validation.
func TestMCPServerHTTPInvalidMethod(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportHTTP, "localhost:0")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleHTTPRequest))
	defer ts.Close()

	// Test GET request (should fail)
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, resp.StatusCode)
	}
}

// TestMCPServerHTTPToolsInvalidMethod tests tools endpoint with invalid method.
func TestMCPServerHTTPToolsInvalidMethod(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportHTTP, "localhost:0")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleToolsRequest))
	defer ts.Close()

	// Test POST request (should fail)
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, resp.StatusCode)
	}
}

// TestMCPServerJoinSessionErrors tests error cases for joining sessions.
func TestMCPServerJoinSessionErrors(t *testing.T) {
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

	tests := []struct {
		name   string
		params JoinSessionParams
	}{
		{
			name: "invalid pubkey hex",
			params: JoinSessionParams{
				SessionID:  "test-session",
				HostPubkey: "invalid-hex",
			},
		},
		{
			name: "wrong pubkey length",
			params: JoinSessionParams{
				SessionID:  "test-session",
				HostPubkey: hex.EncodeToString(make([]byte, 16)),
			},
		},
		{
			name: "session not found",
			params: JoinSessionParams{
				SessionID:  "non-existent",
				HostPubkey: hex.EncodeToString(make([]byte, transport.PublicKeySize)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsJSON, _ := MarshalParams(tt.params)
			_, err := server.handleJoinSession(ctx, paramsJSON)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestMCPServerJoinSessionFull tests session full error.
func TestMCPServerJoinSessionFull(t *testing.T) {
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

	pubkey := make([]byte, transport.PublicKeySize)
	pubkey[0] = 0x02

	// Join 2 participants
	for i := 0; i < 2; i++ {
		params := JoinSessionParams{
			SessionID:  "test-session",
			HostPubkey: hex.EncodeToString(pubkey),
		}
		paramsJSON, _ := MarshalParams(params)
		_, err := server.handleJoinSession(ctx, paramsJSON)
		if err != nil {
			t.Fatalf("Join %d failed: %v", i, err)
		}
	}

	// Try to join third participant (should fail)
	params := JoinSessionParams{
		SessionID:  "test-session",
		HostPubkey: hex.EncodeToString(pubkey),
	}
	paramsJSON, _ := MarshalParams(params)
	_, err = server.handleJoinSession(ctx, paramsJSON)
	if err == nil {
		t.Error("expected error for full session, got nil")
	}
}

// TestMCPServerSubmitRound1Errors tests Round1 submission errors.
func TestMCPServerSubmitRound1Errors(t *testing.T) {
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

	tests := []struct {
		name   string
		params SubmitRound1Params
	}{
		{
			name: "session not found",
			params: SubmitRound1Params{
				SessionID:      "non-existent",
				ParticipantIdx: 0,
				Commitment:     []string{hex.EncodeToString(make([]byte, 33))},
				POP:            hex.EncodeToString(make([]byte, 64)),
				Pubnonce:       hex.EncodeToString(make([]byte, 66)),
			},
		},
		{
			name: "invalid commitment hex",
			params: SubmitRound1Params{
				SessionID:      "test-session",
				ParticipantIdx: 0,
				Commitment:     []string{"invalid-hex"},
				POP:            hex.EncodeToString(make([]byte, 64)),
				Pubnonce:       hex.EncodeToString(make([]byte, 66)),
			},
		},
		{
			name: "invalid pop hex",
			params: SubmitRound1Params{
				SessionID:      "test-session",
				ParticipantIdx: 0,
				Commitment:     []string{hex.EncodeToString(make([]byte, 33))},
				POP:            "invalid-hex",
				Pubnonce:       hex.EncodeToString(make([]byte, 66)),
			},
		},
		{
			name: "invalid pubnonce hex",
			params: SubmitRound1Params{
				SessionID:      "test-session",
				ParticipantIdx: 0,
				Commitment:     []string{hex.EncodeToString(make([]byte, 33))},
				POP:            hex.EncodeToString(make([]byte, 64)),
				Pubnonce:       "invalid-hex",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsJSON, _ := MarshalParams(tt.params)
			_, err := server.handleSubmitRound1(ctx, paramsJSON)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestMCPServerSubmitRound1WrongState tests Round1 in wrong state.
func TestMCPServerSubmitRound1WrongState(t *testing.T) {
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

	// Submit Round1 before joining participants (should fail - wrong state)
	params := SubmitRound1Params{
		SessionID:      "test-session",
		ParticipantIdx: 0,
		Commitment:     []string{hex.EncodeToString(make([]byte, 33))},
		POP:            hex.EncodeToString(make([]byte, 64)),
		Pubnonce:       hex.EncodeToString(make([]byte, 66)),
	}
	paramsJSON, _ := MarshalParams(params)
	_, err = server.handleSubmitRound1(ctx, paramsJSON)
	if err == nil {
		t.Error("expected error for wrong state, got nil")
	}
}

// TestMCPServerSubmitRound2Errors tests Round2 submission errors.
func TestMCPServerSubmitRound2Errors(t *testing.T) {
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

	tests := []struct {
		name   string
		params SubmitRound2Params
	}{
		{
			name: "session not found",
			params: SubmitRound2Params{
				SessionID:       "non-existent",
				ParticipantIdx:  0,
				EncryptedShares: hex.EncodeToString(make([]byte, 64)),
			},
		},
		{
			name: "invalid encrypted shares hex",
			params: SubmitRound2Params{
				SessionID:       "test-session",
				ParticipantIdx:  0,
				EncryptedShares: "invalid-hex",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsJSON, _ := MarshalParams(tt.params)
			_, err := server.handleSubmitRound2(ctx, paramsJSON)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestMCPServerSubmitCertEqErrors tests CertEq submission errors.
func TestMCPServerSubmitCertEqErrors(t *testing.T) {
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

	tests := []struct {
		name   string
		params SubmitCertEqParams
	}{
		{
			name: "session not found",
			params: SubmitCertEqParams{
				SessionID:      "non-existent",
				ParticipantIdx: 0,
				Signature:      hex.EncodeToString(make([]byte, 64)),
			},
		},
		{
			name: "invalid signature hex",
			params: SubmitCertEqParams{
				SessionID:      "test-session",
				ParticipantIdx: 0,
				Signature:      "invalid-hex",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsJSON, _ := MarshalParams(tt.params)
			_, err := server.handleSubmitCertEq(ctx, paramsJSON)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestMCPServerGetResultErrors tests get result errors.
func TestMCPServerGetResultErrors(t *testing.T) {
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

	tests := []struct {
		name   string
		params GetResultParams
	}{
		{
			name: "session not found",
			params: GetResultParams{
				SessionID: "non-existent",
			},
		},
		{
			name: "session not completed",
			params: GetResultParams{
				SessionID: "test-session",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsJSON, _ := MarshalParams(tt.params)
			_, err := server.handleGetResult(ctx, paramsJSON)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestMCPServerCreateSessionDuplicate tests creating duplicate session.
func TestMCPServerCreateSessionDuplicate(t *testing.T) {
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

	// Try to create session with same ID as initial session
	params := CreateSessionParams{
		SessionID:       "test-session",
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}
	paramsJSON, _ := MarshalParams(params)
	_, err = server.handleCreateSession(ctx, paramsJSON)
	if err == nil {
		t.Error("expected error for duplicate session, got nil")
	}
}

// TestMCPClientCallNotConnected tests calling when not connected.
func TestMCPClientCallNotConnected(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportHTTP)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	ctx := context.Background()
	var result map[string]string
	err = client.call(ctx, "test_method", nil, &result)
	if err != transport.ErrNotConnected {
		t.Errorf("expected ErrNotConnected, got %v", err)
	}
}

// TestMCPClientRunDKGNotConnected tests RunDKG when not connected.
func TestMCPClientRunDKGNotConnected(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportHTTP)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	ctx := context.Background()
	params := &transport.DKGParams{
		HostSeckey:     make([]byte, 32),
		HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	_, err = client.RunDKG(ctx, params)
	if err != transport.ErrNotConnected {
		t.Errorf("expected ErrNotConnected, got %v", err)
	}
}

// TestMCPClientStdioNotConfigured tests stdio call without configuration.
func TestMCPClientStdioNotConfigured(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportStdio)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx, "test-session"); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	var result map[string]string
	err = client.call(ctx, "test_method", nil, &result)
	if err == nil {
		t.Error("expected error for unconfigured stdio, got nil")
	}
}

// TestMCPServerInvalidJSONRPCRequest tests handling of invalid JSON-RPC requests.
func TestMCPServerInvalidJSONRPCRequest(t *testing.T) {
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

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "invalid json",
			data: []byte("not json"),
		},
		{
			name: "invalid request structure",
			data: []byte(`{"invalid": "request"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := server.handleJSONRPCRequest(ctx, tt.data)
			if resp == nil {
				t.Error("expected error response, got nil")
			}
			if resp != nil && resp.Error == nil {
				t.Error("expected error in response")
			}
		})
	}
}

// TestMCPServerNotification tests handling of notifications (no response).
func TestMCPServerNotification(t *testing.T) {
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

	// Create notification (no ID)
	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  string(ToolGetSession),
		Params:  json.RawMessage(`{"session_id": "test-session"}`),
		ID:      nil,
	}

	reqData, _ := json.Marshal(req)
	resp := server.handleJSONRPCRequest(ctx, reqData)
	if resp != nil {
		t.Error("expected nil response for notification, got response")
	}
}

// TestMCPClientHTTPError tests HTTP client error handling.
func TestMCPClientHTTPError(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportHTTP)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	ctx := context.Background()
	// Connect to invalid address
	if err := client.Connect(ctx, "http://invalid.invalid:99999"); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	var result map[string]string
	err = client.call(ctx, "test_method", nil, &result)
	if err == nil {
		t.Error("expected error for invalid server, got nil")
	}
}

// TestNewJSONRPCNotification tests notification creation.
func TestNewJSONRPCNotification(t *testing.T) {
	notif, err := NewJSONRPCNotification("test_method", map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("NewJSONRPCNotification failed: %v", err)
	}

	if notif.JSONRPC != JSONRPCVersion {
		t.Errorf("expected JSONRPC version %s, got %s", JSONRPCVersion, notif.JSONRPC)
	}
	if notif.Method != "test_method" {
		t.Errorf("expected method test_method, got %s", notif.Method)
	}
}
