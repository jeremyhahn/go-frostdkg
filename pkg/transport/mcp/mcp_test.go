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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TestToolDefinitions tests that all required tools are defined.
func TestToolDefinitions(t *testing.T) {
	tools := GetToolDefinitions()

	expectedTools := map[ToolName]bool{
		ToolCreateSession: false,
		ToolJoinSession:   false,
		ToolGetSession:    false,
		ToolSubmitRound1:  false,
		ToolSubmitRound2:  false,
		ToolSubmitCertEq:  false,
		ToolGetResult:     false,
		ToolListSessions:  false,
	}

	for _, tool := range tools {
		if _, exists := expectedTools[tool.Name]; exists {
			expectedTools[tool.Name] = true
		}
	}

	for toolName, found := range expectedTools {
		if !found {
			t.Errorf("Tool %s not defined", toolName)
		}
	}

	// Verify each tool has required fields
	for _, tool := range tools {
		if tool.Name == "" {
			t.Error("Tool has empty name")
		}
		if tool.Description == "" {
			t.Errorf("Tool %s has empty description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("Tool %s has nil InputSchema", tool.Name)
		}
	}
}

// TestToolError tests ToolError implementation.
func TestToolError(t *testing.T) {
	tests := []struct {
		name        string
		code        int
		message     string
		expectError string
	}{
		{
			name:        "simple error",
			code:        1000,
			message:     "test error",
			expectError: "test error",
		},
		{
			name:        "empty message",
			code:        1001,
			message:     "",
			expectError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewToolError(tt.code, tt.message)
			if err.Code != tt.code {
				t.Errorf("expected code %d, got %d", tt.code, err.Code)
			}
			if err.Error() != tt.expectError {
				t.Errorf("expected error %q, got %q", tt.expectError, err.Error())
			}
		})
	}
}

// TestMarshalUnmarshalParams tests parameter marshaling.
func TestMarshalUnmarshalParams(t *testing.T) {
	original := &CreateSessionParams{
		SessionID:       "test-session",
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
		TimeoutSeconds:  300,
	}

	data, err := MarshalParams(original)
	if err != nil {
		t.Fatalf("MarshalParams failed: %v", err)
	}

	var unmarshaled CreateSessionParams
	if err := UnmarshalParams(data, &unmarshaled); err != nil {
		t.Fatalf("UnmarshalParams failed: %v", err)
	}

	if unmarshaled.SessionID != original.SessionID {
		t.Errorf("SessionID mismatch: expected %s, got %s", original.SessionID, unmarshaled.SessionID)
	}
	if unmarshaled.Threshold != original.Threshold {
		t.Errorf("Threshold mismatch: expected %d, got %d", original.Threshold, unmarshaled.Threshold)
	}
	if unmarshaled.NumParticipants != original.NumParticipants {
		t.Errorf("NumParticipants mismatch: expected %d, got %d", original.NumParticipants, unmarshaled.NumParticipants)
	}
}

// TestJSONRPCRequest tests JSON-RPC request creation and validation.
func TestJSONRPCRequest(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		params    interface{}
		id        interface{}
		wantError bool
	}{
		{
			name:      "valid request",
			method:    "test_method",
			params:    map[string]string{"key": "value"},
			id:        1,
			wantError: false,
		},
		{
			name:      "notification (no id)",
			method:    "test_method",
			params:    nil,
			id:        nil,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := NewJSONRPCRequest(tt.method, tt.params, tt.id)
			if err != nil {
				t.Fatalf("NewJSONRPCRequest failed: %v", err)
			}

			if req.JSONRPC != JSONRPCVersion {
				t.Errorf("expected JSONRPC version %s, got %s", JSONRPCVersion, req.JSONRPC)
			}
			if req.Method != tt.method {
				t.Errorf("expected method %s, got %s", tt.method, req.Method)
			}
			if req.ID != tt.id {
				t.Errorf("expected id %v, got %v", tt.id, req.ID)
			}

			if err := req.Validate(); err != nil {
				t.Errorf("Validate failed: %v", err)
			}

			// Test IsNotification
			isNotification := req.IsNotification()
			expectedNotification := tt.id == nil
			if isNotification != expectedNotification {
				t.Errorf("IsNotification: expected %v, got %v", expectedNotification, isNotification)
			}
		})
	}
}

// TestJSONRPCRequestValidation tests request validation.
func TestJSONRPCRequestValidation(t *testing.T) {
	tests := []struct {
		name      string
		request   *JSONRPCRequest
		wantError bool
	}{
		{
			name: "valid request",
			request: &JSONRPCRequest{
				JSONRPC: JSONRPCVersion,
				Method:  "test_method",
				ID:      1,
			},
			wantError: false,
		},
		{
			name: "invalid version",
			request: &JSONRPCRequest{
				JSONRPC: "1.0",
				Method:  "test_method",
				ID:      1,
			},
			wantError: true,
		},
		{
			name: "empty method",
			request: &JSONRPCRequest{
				JSONRPC: JSONRPCVersion,
				Method:  "",
				ID:      1,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestJSONRPCResponse tests JSON-RPC response creation.
func TestJSONRPCResponse(t *testing.T) {
	tests := []struct {
		name      string
		result    interface{}
		error     *JSONRPCError
		id        interface{}
		wantError bool
	}{
		{
			name:      "success response",
			result:    map[string]string{"status": "ok"},
			error:     nil,
			id:        1,
			wantError: false,
		},
		{
			name:   "error response",
			result: nil,
			error: &JSONRPCError{
				Code:    -32600,
				Message: "Invalid request",
			},
			id:        1,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *JSONRPCResponse
			var err error

			if tt.error != nil {
				resp, err = NewJSONRPCErrorResponse(tt.error.Code, tt.error.Message, nil, tt.id)
			} else {
				resp, err = NewJSONRPCResponse(tt.result, tt.id)
			}

			if err != nil {
				t.Fatalf("Failed to create response: %v", err)
			}

			if resp.JSONRPC != JSONRPCVersion {
				t.Errorf("expected JSONRPC version %s, got %s", JSONRPCVersion, resp.JSONRPC)
			}

			if err := resp.Validate(); err != nil {
				t.Errorf("Validate failed: %v", err)
			}
		})
	}
}

// TestJSONRPCResponseValidation tests response validation.
func TestJSONRPCResponseValidation(t *testing.T) {
	tests := []struct {
		name      string
		response  *JSONRPCResponse
		wantError bool
	}{
		{
			name: "valid success response",
			response: &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				Result:  json.RawMessage(`{"status": "ok"}`),
				ID:      1,
			},
			wantError: false,
		},
		{
			name: "valid error response",
			response: &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				Error: &JSONRPCError{
					Code:    -32600,
					Message: "Invalid request",
				},
				ID: 1,
			},
			wantError: false,
		},
		{
			name: "invalid version",
			response: &JSONRPCResponse{
				JSONRPC: "1.0",
				Result:  json.RawMessage(`{"status": "ok"}`),
				ID:      1,
			},
			wantError: true,
		},
		{
			name: "both result and error",
			response: &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				Result:  json.RawMessage(`{"status": "ok"}`),
				Error: &JSONRPCError{
					Code:    -32600,
					Message: "Invalid request",
				},
				ID: 1,
			},
			wantError: true,
		},
		{
			name: "neither result nor error",
			response: &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				ID:      1,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.response.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestMCPServerCreation tests MCP server creation.
func TestMCPServerCreation(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     string
		config        *transport.SessionConfig
		transportType TransportType
		address       string
		wantError     bool
	}{
		{
			name:      "valid stdio server",
			sessionID: "test-session",
			config: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			},
			transportType: TransportStdio,
			address:       "",
			wantError:     false,
		},
		{
			name:      "valid http server",
			sessionID: "test-session",
			config: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			},
			transportType: TransportHTTP,
			address:       "localhost:8080",
			wantError:     false,
		},
		{
			name:      "empty session id",
			sessionID: "",
			config: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
			},
			transportType: TransportStdio,
			address:       "",
			wantError:     true,
		},
		{
			name:          "nil config",
			sessionID:     "test-session",
			config:        nil,
			transportType: TransportStdio,
			address:       "",
			wantError:     true,
		},
		{
			name:      "invalid threshold",
			sessionID: "test-session",
			config: &transport.SessionConfig{
				Threshold:       5,
				NumParticipants: 3,
			},
			transportType: TransportStdio,
			address:       "",
			wantError:     true,
		},
		{
			name:      "http without address",
			sessionID: "test-session",
			config: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
			},
			transportType: TransportHTTP,
			address:       "",
			wantError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewMCPServer(tt.sessionID, tt.config, tt.transportType, tt.address)
			if (err != nil) != tt.wantError {
				t.Errorf("NewMCPServer() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				if server.SessionID() != tt.sessionID {
					t.Errorf("SessionID() = %s, want %s", server.SessionID(), tt.sessionID)
				}
			}
		})
	}
}

// TestMCPServerLifecycle tests server start/stop.
func TestMCPServerLifecycle(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	// Set stdio for testing
	reader := bytes.NewReader([]byte{})
	writer := &bytes.Buffer{}
	server.SetStdio(reader, writer)

	ctx := context.Background()

	// Start server
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Starting again should fail
	if err := server.Start(ctx); err == nil {
		t.Error("Starting already started server should fail")
	}

	// Stop server
	if err := server.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

// TestMCPServerHTTPTools tests the HTTP tools endpoint.
func TestMCPServerHTTPTools(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportHTTP, "localhost:0")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	// Create test server
	ts := httptest.NewServer(http.HandlerFunc(server.handleToolsRequest))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET /tools failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatal("response does not contain tools array")
	}

	if len(tools) == 0 {
		t.Error("tools array is empty")
	}
}

// TestMCPServerCreateSession tests session creation.
func TestMCPServerCreateSession(t *testing.T) {
	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("initial-session", config, TransportStdio, "")
	if err != nil {
		t.Fatalf("NewMCPServer failed: %v", err)
	}

	ctx := context.Background()

	// Start server
	reader := bytes.NewReader([]byte{})
	writer := &bytes.Buffer{}
	server.SetStdio(reader, writer)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = server.Stop(ctx) }()

	tests := []struct {
		name      string
		params    CreateSessionParams
		wantError bool
	}{
		{
			name: "valid session",
			params: CreateSessionParams{
				SessionID:       "new-session",
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			},
			wantError: false,
		},
		{
			name: "invalid threshold",
			params: CreateSessionParams{
				SessionID:       "bad-session",
				Threshold:       5,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, _ := MarshalParams(tt.params)
			result, err := server.handleCreateSession(ctx, params)

			if (err != nil) != tt.wantError {
				t.Errorf("handleCreateSession() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				createResult, ok := result.(*CreateSessionResult)
				if !ok {
					t.Fatal("result is not CreateSessionResult")
				}
				if createResult.SessionID != tt.params.SessionID {
					t.Errorf("SessionID = %s, want %s", createResult.SessionID, tt.params.SessionID)
				}
			}
		})
	}
}

// TestMCPServerJoinSession tests joining a session.
func TestMCPServerJoinSession(t *testing.T) {
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

	// Create a valid 33-byte pubkey
	pubkey := make([]byte, transport.PublicKeySize)
	pubkey[0] = 0x02 // compressed pubkey prefix

	params := JoinSessionParams{
		SessionID:  "test-session",
		HostPubkey: hex.EncodeToString(pubkey),
	}

	paramsJSON, _ := MarshalParams(params)
	result, err := server.handleJoinSession(ctx, paramsJSON)
	if err != nil {
		t.Fatalf("handleJoinSession failed: %v", err)
	}

	joinResult, ok := result.(*JoinSessionResult)
	if !ok {
		t.Fatal("result is not JoinSessionResult")
	}

	if joinResult.SessionID != "test-session" {
		t.Errorf("SessionID = %s, want test-session", joinResult.SessionID)
	}
	if joinResult.ParticipantIdx != 0 {
		t.Errorf("ParticipantIdx = %d, want 0", joinResult.ParticipantIdx)
	}
}

// TestMCPServerGetSession tests retrieving session info.
func TestMCPServerGetSession(t *testing.T) {
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
		SessionID: "test-session",
	}

	paramsJSON, _ := MarshalParams(params)
	result, err := server.handleGetSession(ctx, paramsJSON)
	if err != nil {
		t.Fatalf("handleGetSession failed: %v", err)
	}

	getResult, ok := result.(*GetSessionResult)
	if !ok {
		t.Fatal("result is not GetSessionResult")
	}

	if getResult.SessionID != "test-session" {
		t.Errorf("SessionID = %s, want test-session", getResult.SessionID)
	}
	if getResult.Threshold != 2 {
		t.Errorf("Threshold = %d, want 2", getResult.Threshold)
	}
}

// TestMCPServerSubmitRound1 tests Round1 submission.
func TestMCPServerSubmitRound1(t *testing.T) {
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

	// Join two participants first
	pubkey := make([]byte, transport.PublicKeySize)
	pubkey[0] = 0x02

	for i := 0; i < 2; i++ {
		joinParams := JoinSessionParams{
			SessionID:  "test-session",
			HostPubkey: hex.EncodeToString(pubkey),
		}
		paramsJSON, _ := MarshalParams(joinParams)
		_, err := server.handleJoinSession(ctx, paramsJSON)
		if err != nil {
			t.Fatalf("handleJoinSession failed: %v", err)
		}
	}

	// Submit Round1 from first participant
	params := SubmitRound1Params{
		SessionID:      "test-session",
		ParticipantIdx: 0,
		Commitment:     []string{hex.EncodeToString(make([]byte, 33))},
		POP:            hex.EncodeToString(make([]byte, 64)),
		Pubnonce:       hex.EncodeToString(make([]byte, 66)),
	}

	paramsJSON, _ := MarshalParams(params)
	result, err := server.handleSubmitRound1(ctx, paramsJSON)
	if err != nil {
		t.Fatalf("handleSubmitRound1 failed: %v", err)
	}

	submitResult, ok := result.(*SubmitRound1Result)
	if !ok {
		t.Fatal("result is not SubmitRound1Result")
	}

	if submitResult.Status != "received" {
		t.Errorf("Status = %s, want received", submitResult.Status)
	}
	if submitResult.WaitingFor != 1 {
		t.Errorf("WaitingFor = %d, want 1", submitResult.WaitingFor)
	}
}

// TestMCPServerListSessions tests listing sessions.
func TestMCPServerListSessions(t *testing.T) {
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

	params := ListSessionsParams{
		IncludeCompleted: false,
	}

	paramsJSON, _ := MarshalParams(params)
	result, err := server.handleListSessions(ctx, paramsJSON)
	if err != nil {
		t.Fatalf("handleListSessions failed: %v", err)
	}

	listResult, ok := result.(*ListSessionsResult)
	if !ok {
		t.Fatal("result is not ListSessionsResult")
	}

	if len(listResult.Sessions) == 0 {
		t.Error("Sessions list is empty")
	}

	found := false
	for _, session := range listResult.Sessions {
		if session.SessionID == "test-session" {
			found = true
			break
		}
	}
	if !found {
		t.Error("test-session not found in sessions list")
	}
}

// TestMCPClientCreation tests MCP client creation.
func TestMCPClientCreation(t *testing.T) {
	tests := []struct {
		name          string
		participantID string
		transportType TransportType
		wantError     bool
	}{
		{
			name:          "valid stdio client",
			participantID: "participant-1",
			transportType: TransportStdio,
			wantError:     false,
		},
		{
			name:          "valid http client",
			participantID: "participant-1",
			transportType: TransportHTTP,
			wantError:     false,
		},
		{
			name:          "empty participant id",
			participantID: "",
			transportType: TransportStdio,
			wantError:     true,
		},
		{
			name:          "invalid transport type",
			participantID: "participant-1",
			transportType: "invalid",
			wantError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewMCPClient(tt.participantID, tt.transportType)
			if (err != nil) != tt.wantError {
				t.Errorf("NewMCPClient() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				if client.GetParticipantID() != tt.participantID {
					t.Errorf("GetParticipantID() = %s, want %s", client.GetParticipantID(), tt.participantID)
				}
			}
		})
	}
}

// TestMCPClientConnect tests client connection.
func TestMCPClientConnect(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportHTTP)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	ctx := context.Background()

	// Connect
	if err := client.Connect(ctx, "http://localhost:8080"); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Connecting again should fail
	if err := client.Connect(ctx, "http://localhost:8080"); err == nil {
		t.Error("Connecting already connected client should fail")
	}

	// Disconnect
	if err := client.Disconnect(); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}

	// Disconnecting again should fail
	if err := client.Disconnect(); err == nil {
		t.Error("Disconnecting already disconnected client should fail")
	}
}

// TestMCPClientHTTPCall tests HTTP JSON-RPC calls.
func TestMCPClientHTTPCall(t *testing.T) {
	// Create test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req JSONRPCRequest
		_ = json.Unmarshal(body, &req)

		resp, _ := NewJSONRPCResponse(map[string]string{"status": "ok"}, req.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client, err := NewMCPClient("participant-1", TransportHTTP)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx, ts.URL); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	var result map[string]string
	if err := client.call(ctx, "test_method", nil, &result); err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %s", result["status"])
	}
}

// TestMCPClientStdioCall tests stdio JSON-RPC calls.
func TestMCPClientStdioCall(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportStdio)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	// Prepare stdio
	resp, _ := NewJSONRPCResponse(map[string]string{"status": "ok"}, 1)
	respData, _ := json.Marshal(resp)
	reader := strings.NewReader(string(respData) + "\n")
	writer := &bytes.Buffer{}

	client.SetStdio(reader, writer)

	ctx := context.Background()
	if err := client.Connect(ctx, "test-session"); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	var result map[string]string
	if err := client.call(ctx, "test_method", nil, &result); err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %s", result["status"])
	}
}

// TestMCPClientValidateDKGParams tests DKG parameter validation.
func TestMCPClientValidateDKGParams(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportHTTP)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	tests := []struct {
		name      string
		params    *transport.DKGParams
		wantError bool
	}{
		{
			name: "valid params",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize), make([]byte, transport.PublicKeySize)},
				Threshold:      2,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			wantError: false,
		},
		{
			name:      "nil params",
			params:    nil,
			wantError: true,
		},
		{
			name: "invalid seckey",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 16),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			wantError: true,
		},
		{
			name: "invalid random",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         make([]byte, 16),
			},
			wantError: true,
		},
		{
			name: "invalid threshold",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      5,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			wantError: true,
		},
		{
			name: "invalid participant index",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: 5,
				Random:         make([]byte, 32),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateDKGParams(tt.params)
			if (err != nil) != tt.wantError {
				t.Errorf("validateDKGParams() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestMCPServerWaitForParticipants tests waiting for participants.
func TestMCPServerWaitForParticipants(t *testing.T) {
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

	// Start goroutine to join participants
	go func() {
		time.Sleep(100 * time.Millisecond)
		pubkey := make([]byte, transport.PublicKeySize)
		pubkey[0] = 0x02

		for i := 0; i < 2; i++ {
			joinParams := JoinSessionParams{
				SessionID:  "test-session",
				HostPubkey: hex.EncodeToString(pubkey),
			}
			paramsJSON, _ := MarshalParams(joinParams)
			_, _ = server.handleJoinSession(ctx, paramsJSON)
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// Wait for participants
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := server.WaitForParticipants(waitCtx, 2); err != nil {
		t.Fatalf("WaitForParticipants failed: %v", err)
	}
}

// TestMCPServerWaitForParticipantsTimeout tests timeout waiting for participants.
func TestMCPServerWaitForParticipantsTimeout(t *testing.T) {
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

	// Wait with timeout (should timeout)
	waitCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()

	err = server.WaitForParticipants(waitCtx, 3)
	if err != transport.ErrConnectionTimeout {
		t.Errorf("expected ErrConnectionTimeout, got %v", err)
	}
}
