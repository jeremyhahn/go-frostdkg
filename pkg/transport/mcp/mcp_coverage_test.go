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

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TestMCPClientSubmitRound1 tests Round1 submission from client.
func TestMCPClientSubmitRound1(t *testing.T) {
	// Create test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
			return
		}

		result := &SubmitRound1Result{
			Status:     "received",
			WaitingFor: 1,
		}
		resp, _ := NewJSONRPCResponse(result, req.ID)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
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

	// Set session info
	client.sessionID = "test-session"
	client.participantIdx = 0

	msg := &transport.Round1Message{
		Commitment: [][]byte{make([]byte, 33)},
		POP:        make([]byte, 64),
		Pubnonce:   make([]byte, 66),
	}

	result, err := client.SubmitRound1(ctx, msg)
	if err != nil {
		t.Fatalf("SubmitRound1 failed: %v", err)
	}

	if result.Status != "received" {
		t.Errorf("expected status received, got %s", result.Status)
	}
}

// TestMCPClientSubmitRound2 tests Round2 submission from client.
func TestMCPClientSubmitRound2(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
			return
		}

		result := &SubmitRound2Result{
			Status:     "received",
			WaitingFor: 1,
		}
		resp, _ := NewJSONRPCResponse(result, req.ID)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
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

	client.sessionID = "test-session"
	client.participantIdx = 0

	msg := &transport.Round2Message{
		EncryptedShares: make([]byte, 64),
	}

	result, err := client.SubmitRound2(ctx, msg)
	if err != nil {
		t.Fatalf("SubmitRound2 failed: %v", err)
	}

	if result.Status != "received" {
		t.Errorf("expected status received, got %s", result.Status)
	}
}

// TestMCPClientSubmitCertEq tests CertEq submission from client.
func TestMCPClientSubmitCertEq(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
			return
		}

		result := &SubmitCertEqResult{
			Status:     "received",
			WaitingFor: 1,
		}
		resp, _ := NewJSONRPCResponse(result, req.ID)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
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

	client.sessionID = "test-session"
	client.participantIdx = 0

	msg := &transport.CertEqSignMessage{
		Signature: make([]byte, 64),
	}

	result, err := client.SubmitCertEq(ctx, msg)
	if err != nil {
		t.Fatalf("SubmitCertEq failed: %v", err)
	}

	if result.Status != "received" {
		t.Errorf("expected status received, got %s", result.Status)
	}
}

// TestMCPClientGetSession tests getting session info from client.
func TestMCPClientGetSession(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
			return
		}

		result := &GetSessionResult{
			SessionID:           "test-session",
			Threshold:           2,
			NumParticipants:     3,
			CurrentParticipants: 2,
			Ciphersuite:         "FROST-ED25519-SHA512-v1",
			Status:              "round1",
		}
		resp, _ := NewJSONRPCResponse(result, req.ID)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
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

	client.sessionID = "test-session"

	result, err := client.GetSession(ctx)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if result.SessionID != "test-session" {
		t.Errorf("expected session_id test-session, got %s", result.SessionID)
	}
}

// TestMCPClientGetResult tests getting DKG result from client.
func TestMCPClientGetResult(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
			return
		}

		result := &GetResultResult{
			SessionID:       "test-session",
			ThresholdPubkey: hex.EncodeToString(make([]byte, transport.PublicKeySize)),
			PublicShares:    []string{},
			RecoveryData:    hex.EncodeToString(make([]byte, 64)),
			Status:          "completed",
		}
		resp, _ := NewJSONRPCResponse(result, req.ID)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
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

	client.sessionID = "test-session"

	result, err := client.GetResult(ctx)
	if err != nil {
		t.Fatalf("GetResult failed: %v", err)
	}

	if result.SessionID != "test-session" {
		t.Errorf("expected session_id test-session, got %s", result.SessionID)
	}
	if result.Status != "completed" {
		t.Errorf("expected status completed, got %s", result.Status)
	}
}

// TestMCPClientGetParticipantIndex tests getting participant index.
func TestMCPClientGetParticipantIndex(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportHTTP)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	client.participantIdx = 5

	if client.GetParticipantIndex() != 5 {
		t.Errorf("expected index 5, got %d", client.GetParticipantIndex())
	}
}

// TestMCPClientGetSessionInfo tests getting session info.
func TestMCPClientGetSessionInfo(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportHTTP)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	sessionInfo := &JoinSessionResult{
		SessionID:       "test-session",
		ParticipantIdx:  0,
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	client.sessionInfo = sessionInfo

	info := client.GetSessionInfo()
	if info == nil {
		t.Fatal("GetSessionInfo returned nil")
	}
	if info.SessionID != "test-session" {
		t.Errorf("expected session_id test-session, got %s", info.SessionID)
	}
}

// TestMCPClientSetHTTPClient tests setting custom HTTP client.
func TestMCPClientSetHTTPClient(t *testing.T) {
	client, err := NewMCPClient("participant-1", TransportHTTP)
	if err != nil {
		t.Fatalf("NewMCPClient failed: %v", err)
	}

	customClient := &http.Client{}
	client.SetHTTPClient(customClient)

	// Verify it was set (we can't directly compare, but we can check it doesn't crash)
	if client.httpClient == nil {
		t.Error("httpClient should not be nil after SetHTTPClient")
	}
}

// TestMCPServerAddress tests server address methods.
func TestMCPServerAddress(t *testing.T) {
	tests := []struct {
		name          string
		transportType TransportType
		address       string
		expectAddr    string
	}{
		{
			name:          "stdio address",
			transportType: TransportStdio,
			address:       "",
			expectAddr:    "test-session",
		},
		{
			name:          "http address",
			transportType: TransportHTTP,
			address:       "localhost:8080",
			expectAddr:    "localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			}

			server, err := NewMCPServer("test-session", config, tt.transportType, tt.address)
			if err != nil {
				t.Fatalf("NewMCPServer failed: %v", err)
			}

			if server.Address() != tt.expectAddr {
				t.Errorf("expected address %s, got %s", tt.expectAddr, server.Address())
			}
		})
	}
}

// TestMCPServerSubmitRound2Complete tests completing Round2.
func TestMCPServerSubmitRound2Complete(t *testing.T) {
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

	// Join participants
	pubkey := make([]byte, transport.PublicKeySize)
	pubkey[0] = 0x02
	for i := 0; i < 2; i++ {
		joinParams := JoinSessionParams{
			SessionID:  "test-session",
			HostPubkey: hex.EncodeToString(pubkey),
		}
		paramsJSON, _ := MarshalParams(joinParams)
		_, _ = server.handleJoinSession(ctx, paramsJSON)
	}

	// Submit all Round1 messages
	for i := 0; i < 2; i++ {
		params := SubmitRound1Params{
			SessionID:      "test-session",
			ParticipantIdx: i,
			Commitment:     []string{hex.EncodeToString(make([]byte, 33))},
			POP:            hex.EncodeToString(make([]byte, 64)),
			Pubnonce:       hex.EncodeToString(make([]byte, 66)),
		}
		paramsJSON, _ := MarshalParams(params)
		_, _ = server.handleSubmitRound1(ctx, paramsJSON)
	}

	// Submit Round2 messages
	for i := 0; i < 2; i++ {
		params := SubmitRound2Params{
			SessionID:       "test-session",
			ParticipantIdx:  i,
			EncryptedShares: hex.EncodeToString(make([]byte, 64)),
		}
		paramsJSON, _ := MarshalParams(params)
		result, err := server.handleSubmitRound2(ctx, paramsJSON)
		if err != nil {
			t.Fatalf("handleSubmitRound2 failed: %v", err)
		}

		if i == 1 {
			// Last message should complete Round2
			submitResult := result.(*SubmitRound2Result)
			if submitResult.Status != "complete" {
				t.Errorf("expected status complete, got %s", submitResult.Status)
			}
		}
	}
}

// TestMCPServerSubmitCertEqComplete tests completing CertEq.
func TestMCPServerSubmitCertEqComplete(t *testing.T) {
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

	// Setup session through all rounds
	pubkey := make([]byte, transport.PublicKeySize)
	pubkey[0] = 0x02
	for i := 0; i < 2; i++ {
		joinParams := JoinSessionParams{
			SessionID:  "test-session",
			HostPubkey: hex.EncodeToString(pubkey),
		}
		paramsJSON, _ := MarshalParams(joinParams)
		_, _ = server.handleJoinSession(ctx, paramsJSON)
	}

	// Round1
	for i := 0; i < 2; i++ {
		params := SubmitRound1Params{
			SessionID:      "test-session",
			ParticipantIdx: i,
			Commitment:     []string{hex.EncodeToString(make([]byte, 33))},
			POP:            hex.EncodeToString(make([]byte, 64)),
			Pubnonce:       hex.EncodeToString(make([]byte, 66)),
		}
		paramsJSON, _ := MarshalParams(params)
		_, _ = server.handleSubmitRound1(ctx, paramsJSON)
	}

	// Round2
	for i := 0; i < 2; i++ {
		params := SubmitRound2Params{
			SessionID:       "test-session",
			ParticipantIdx:  i,
			EncryptedShares: hex.EncodeToString(make([]byte, 64)),
		}
		paramsJSON, _ := MarshalParams(params)
		_, _ = server.handleSubmitRound2(ctx, paramsJSON)
	}

	// CertEq
	for i := 0; i < 2; i++ {
		params := SubmitCertEqParams{
			SessionID:      "test-session",
			ParticipantIdx: i,
			Signature:      hex.EncodeToString(make([]byte, 64)),
		}
		paramsJSON, _ := MarshalParams(params)
		result, err := server.handleSubmitCertEq(ctx, paramsJSON)
		if err != nil {
			t.Fatalf("handleSubmitCertEq failed: %v", err)
		}

		if i == 1 {
			// Last message should complete CertEq
			submitResult := result.(*SubmitCertEqResult)
			if submitResult.Status != "complete" {
				t.Errorf("expected status complete, got %s", submitResult.Status)
			}
			if submitResult.Certificate == "" {
				t.Error("expected certificate, got empty string")
			}
		}
	}
}

// TestMCPServerListSessionsWithCompleted tests listing with completed sessions.
func TestMCPServerListSessionsWithCompleted(t *testing.T) {
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

	// Mark session as completed
	server.sessions["test-session"].State = StateCompleted

	params := ListSessionsParams{
		IncludeCompleted: true,
	}
	paramsJSON, _ := MarshalParams(params)
	result, err := server.handleListSessions(ctx, paramsJSON)
	if err != nil {
		t.Fatalf("handleListSessions failed: %v", err)
	}

	listResult := result.(*ListSessionsResult)
	if len(listResult.Sessions) == 0 {
		t.Error("expected completed session in list")
	}
}

// TestNewJSONRPCErrorResponseWithData tests error response with data.
func TestNewJSONRPCErrorResponseWithData(t *testing.T) {
	data := map[string]string{"detail": "extra info"}
	resp, err := NewJSONRPCErrorResponse(-32600, "Invalid request", data, 1)
	if err != nil {
		t.Fatalf("NewJSONRPCErrorResponse failed: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error in response")
	}
	if resp.Error.Data == nil {
		t.Error("expected error data")
	}
}

// TestMCPClientRunDKGFlow tests full RunDKG flow.
func TestMCPClientRunDKGFlow(t *testing.T) {
	// Create mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
			return
		}

		var result interface{}
		if req.Method == string(ToolJoinSession) {
			result = &JoinSessionResult{
				SessionID:       "test-session",
				ParticipantIdx:  0,
				Threshold:       2,
				NumParticipants: 2,
				HostPubkeys:     []string{hex.EncodeToString(make([]byte, transport.PublicKeySize))},
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			}
		}

		resp, _ := NewJSONRPCResponse(result, req.ID)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
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

	params := &transport.DKGParams{
		HostSeckey:     make([]byte, 32),
		HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize), make([]byte, transport.PublicKeySize)},
		Threshold:      2,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	result, err := client.RunDKG(ctx, params)
	if err != nil {
		t.Fatalf("RunDKG failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if len(result.SecretShare) != 32 {
		t.Errorf("expected SecretShare length 32, got %d", len(result.SecretShare))
	}
}

// TestMCPServerInvalidParamsUnmarshal tests handling of unmarshal errors.
func TestMCPServerInvalidParamsUnmarshal(t *testing.T) {
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
		name   string
		method string
		params json.RawMessage
	}{
		{
			name:   "invalid create session params",
			method: string(ToolCreateSession),
			params: json.RawMessage(`invalid json`),
		},
		{
			name:   "invalid join session params",
			method: string(ToolJoinSession),
			params: json.RawMessage(`invalid json`),
		},
		{
			name:   "invalid get session params",
			method: string(ToolGetSession),
			params: json.RawMessage(`invalid json`),
		},
		{
			name:   "invalid submit round1 params",
			method: string(ToolSubmitRound1),
			params: json.RawMessage(`invalid json`),
		},
		{
			name:   "invalid submit round2 params",
			method: string(ToolSubmitRound2),
			params: json.RawMessage(`invalid json`),
		},
		{
			name:   "invalid submit certeq params",
			method: string(ToolSubmitCertEq),
			params: json.RawMessage(`invalid json`),
		},
		{
			name:   "invalid get result params",
			method: string(ToolGetResult),
			params: json.RawMessage(`invalid json`),
		},
		{
			name:   "invalid list sessions params",
			method: string(ToolListSessions),
			params: json.RawMessage(`invalid json`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := server.handleToolCall(ctx, tt.method, tt.params)
			if err == nil {
				t.Error("expected error for invalid params, got nil")
			}
		})
	}
}

// TestMCPClientCallInvalidResponse tests handling invalid responses.
func TestMCPClientCallInvalidResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return invalid JSON
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
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
	err = client.call(ctx, "test_method", nil, &result)
	if err == nil {
		t.Error("expected error for invalid response, got nil")
	}
}

// TestMCPClientCallBadHTTPStatus tests handling bad HTTP status.
func TestMCPClientCallBadHTTPStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
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
	err = client.call(ctx, "test_method", nil, &result)
	if err == nil {
		t.Error("expected error for bad HTTP status, got nil")
	}
}
