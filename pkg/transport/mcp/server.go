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
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TransportType specifies the MCP transport mechanism.
type TransportType string

const (
	// TransportStdio uses stdin/stdout for JSON-RPC communication.
	TransportStdio TransportType = "stdio"

	// TransportHTTP uses HTTP/SSE for JSON-RPC communication.
	TransportHTTP TransportType = "http"
)

// SessionState represents the state of a DKG session.
type SessionState string

const (
	// StateCreated indicates session is created but no participants joined.
	StateCreated SessionState = "created"

	// StateWaitingParticipants indicates waiting for participants to join.
	StateWaitingParticipants SessionState = "waiting_participants"

	// StateRound1 indicates Round1 in progress.
	StateRound1 SessionState = "round1"

	// StateRound2 indicates Round2 in progress.
	StateRound2 SessionState = "round2"

	// StateCertEq indicates CertEq signature collection in progress.
	StateCertEq SessionState = "certeq"

	// StateCompleted indicates DKG completed successfully.
	StateCompleted SessionState = "completed"

	// StateFailed indicates DKG failed.
	StateFailed SessionState = "failed"
)

// MCPSession represents an active DKG session on the MCP server.
type MCPSession struct {
	SessionID        string
	Config           *transport.SessionConfig
	State            SessionState
	Participants     map[int]*MCPParticipant
	Round1Messages   map[int]*transport.Round1Message
	Round2Messages   map[int]*transport.Round2Message
	CertEqSignatures map[int]*transport.CertEqSignMessage
	Result           *GetResultResult
	CreatedAt        time.Time
	UpdatedAt        time.Time
	mu               sync.RWMutex
}

// MCPParticipant represents a participant in an MCP session.
type MCPParticipant struct {
	Index      int
	HostPubkey []byte
	JoinedAt   time.Time
}

// MCPServer implements the Coordinator interface using MCP (Model Context Protocol).
type MCPServer struct {
	transportType TransportType
	address       string
	sessionID     string
	config        *transport.SessionConfig
	sessions      map[string]*MCPSession
	sessionsMu    sync.RWMutex
	started       atomic.Bool
	httpServer    *http.Server
	stopChan      chan struct{}
	reader        io.Reader
	writer        io.Writer
	wg            sync.WaitGroup
}

// NewMCPServer creates a new MCP server coordinator.
func NewMCPServer(sessionID string, config *transport.SessionConfig, transportType TransportType, address string) (*MCPServer, error) {
	if sessionID == "" {
		return nil, transport.ErrInvalidConfig
	}

	if config == nil {
		return nil, transport.ErrInvalidConfig
	}

	if config.NumParticipants < 1 {
		return nil, transport.ErrInvalidParticipantCount
	}

	if config.Threshold < 1 || config.Threshold > config.NumParticipants {
		return nil, transport.ErrInvalidThreshold
	}

	if transportType != TransportStdio && transportType != TransportHTTP {
		return nil, transport.NewProtocolError(transport.ProtocolMCP,
			fmt.Errorf("invalid transport type: %s", transportType))
	}

	if transportType == TransportHTTP && address == "" {
		return nil, transport.ErrInvalidAddress
	}

	return &MCPServer{
		transportType: transportType,
		address:       address,
		sessionID:     sessionID,
		config:        config,
		sessions:      make(map[string]*MCPSession),
		stopChan:      make(chan struct{}),
	}, nil
}

// Start begins listening for JSON-RPC requests.
func (s *MCPServer) Start(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return fmt.Errorf("server already started")
	}

	// Create initial session
	session := &MCPSession{
		SessionID:        s.sessionID,
		Config:           s.config,
		State:            StateCreated,
		Participants:     make(map[int]*MCPParticipant),
		Round1Messages:   make(map[int]*transport.Round1Message),
		Round2Messages:   make(map[int]*transport.Round2Message),
		CertEqSignatures: make(map[int]*transport.CertEqSignMessage),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	s.sessionsMu.Lock()
	s.sessions[s.sessionID] = session
	s.sessionsMu.Unlock()

	switch s.transportType {
	case TransportStdio:
		return s.startStdio(ctx)
	case TransportHTTP:
		return s.startHTTP(ctx)
	default:
		return transport.NewProtocolError(transport.ProtocolMCP,
			fmt.Errorf("unsupported transport type: %s", s.transportType))
	}
}

// Stop gracefully shuts down the server.
func (s *MCPServer) Stop(ctx context.Context) error {
	if !s.started.Load() {
		return fmt.Errorf("server not started")
	}

	close(s.stopChan)

	if s.transportType == TransportHTTP && s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			return err
		}
	}

	// Wait for goroutines to finish
	s.wg.Wait()

	s.started.Store(false)
	return nil
}

// Address returns the network address.
func (s *MCPServer) Address() string {
	if s.transportType == TransportStdio {
		return s.sessionID
	}
	return s.address
}

// SessionID returns the unique identifier for this DKG session.
func (s *MCPServer) SessionID() string {
	return s.sessionID
}

// WaitForParticipants blocks until n participants have connected.
func (s *MCPServer) WaitForParticipants(ctx context.Context, n int) error {
	if n < 1 {
		return transport.ErrInvalidParticipantCount
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[s.sessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return transport.ErrSessionNotFound
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return transport.ErrConnectionTimeout
		case <-s.stopChan:
			return transport.ErrSessionClosed
		case <-ticker.C:
			session.mu.RLock()
			count := len(session.Participants)
			session.mu.RUnlock()

			if count >= n {
				return nil
			}
		}
	}
}

// startStdio starts the stdio JSON-RPC handler.
func (s *MCPServer) startStdio(ctx context.Context) error {
	// Default to stdin/stdout if not set
	if s.reader == nil {
		s.reader = bufio.NewReader(io.Reader(nil))
	}
	if s.writer == nil {
		s.writer = io.Writer(nil)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleStdioRequests(ctx)
	}()
	return nil
}

// startHTTP starts the HTTP JSON-RPC handler.
func (s *MCPServer) startHTTP(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/jsonrpc", s.handleHTTPRequest)
	mux.HandleFunc("/tools", s.handleToolsRequest)

	s.httpServer = &http.Server{
		Addr:    s.address,
		Handler: mux,
	}

	go func() {
		_ = s.httpServer.ListenAndServe()
	}()

	return nil
}

// handleStdioRequests processes JSON-RPC requests from stdio.
func (s *MCPServer) handleStdioRequests(ctx context.Context) {
	scanner := bufio.NewScanner(s.reader)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		response := s.handleJSONRPCRequest(ctx, line)
		if response != nil {
			data, err := json.Marshal(response)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintln(s.writer, string(data))
		}
	}
}

// handleHTTPRequest processes JSON-RPC requests over HTTP.
func (s *MCPServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	response := s.handleJSONRPCRequest(r.Context(), body)
	if response == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// handleToolsRequest returns the list of available tools.
func (s *MCPServer) handleToolsRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tools := GetToolDefinitions()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"tools": tools,
	})
}

// handleJSONRPCRequest processes a JSON-RPC request and returns a response.
func (s *MCPServer) handleJSONRPCRequest(ctx context.Context, data []byte) *JSONRPCResponse {
	var req JSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		resp, _ := NewJSONRPCErrorResponse(JSONRPCParseError, "Parse error", nil, nil)
		return resp
	}

	if err := req.Validate(); err != nil {
		resp, _ := NewJSONRPCErrorResponse(JSONRPCInvalidRequest, "Invalid request", nil, req.ID)
		return resp
	}

	// If it's a notification, don't return a response
	if req.IsNotification() {
		_, _ = s.handleToolCall(ctx, req.Method, req.Params)
		return nil
	}

	result, err := s.handleToolCall(ctx, req.Method, req.Params)
	if err != nil {
		var toolErr *ToolError
		code := JSONRPCInternalError
		message := err.Error()

		if e, ok := err.(*ToolError); ok {
			toolErr = e
			code = toolErr.Code
			message = toolErr.Message
		}

		resp, _ := NewJSONRPCErrorResponse(code, message, nil, req.ID)
		return resp
	}

	resp, _ := NewJSONRPCResponse(result, req.ID)
	return resp
}

// handleToolCall dispatches tool calls to appropriate handlers.
func (s *MCPServer) handleToolCall(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	switch ToolName(method) {
	case ToolCreateSession:
		return s.handleCreateSession(ctx, params)
	case ToolJoinSession:
		return s.handleJoinSession(ctx, params)
	case ToolGetSession:
		return s.handleGetSession(ctx, params)
	case ToolSubmitRound1:
		return s.handleSubmitRound1(ctx, params)
	case ToolSubmitRound2:
		return s.handleSubmitRound2(ctx, params)
	case ToolSubmitCertEq:
		return s.handleSubmitCertEq(ctx, params)
	case ToolGetResult:
		return s.handleGetResult(ctx, params)
	case ToolListSessions:
		return s.handleListSessions(ctx, params)
	default:
		return nil, NewToolError(JSONRPCMethodNotFound, fmt.Sprintf("method not found: %s", method))
	}
}

// Tool handler implementations

func (s *MCPServer) handleCreateSession(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p CreateSessionParams
	if err := UnmarshalParams(params, &p); err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid parameters")
	}

	if p.SessionID == "" || p.Threshold < 1 || p.NumParticipants < 1 {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "missing required parameters")
	}

	if p.Threshold > p.NumParticipants {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "threshold must be <= num_participants")
	}

	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	if _, exists := s.sessions[p.SessionID]; exists {
		return nil, NewToolError(int(ErrorCodeSessionExists), "session already exists")
	}

	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	config := &transport.SessionConfig{
		Threshold:       p.Threshold,
		NumParticipants: p.NumParticipants,
		Ciphersuite:     p.Ciphersuite,
		Timeout:         timeout,
	}

	session := &MCPSession{
		SessionID:        p.SessionID,
		Config:           config,
		State:            StateCreated,
		Participants:     make(map[int]*MCPParticipant),
		Round1Messages:   make(map[int]*transport.Round1Message),
		Round2Messages:   make(map[int]*transport.Round2Message),
		CertEqSignatures: make(map[int]*transport.CertEqSignMessage),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	s.sessions[p.SessionID] = session

	return &CreateSessionResult{
		SessionID:       p.SessionID,
		Threshold:       p.Threshold,
		NumParticipants: p.NumParticipants,
		Ciphersuite:     p.Ciphersuite,
		Status:          string(StateCreated),
	}, nil
}

func (s *MCPServer) handleJoinSession(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p JoinSessionParams
	if err := UnmarshalParams(params, &p); err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid parameters")
	}

	hostPubkey, err := hex.DecodeString(p.HostPubkey)
	if err != nil || len(hostPubkey) != transport.PublicKeySize {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid host_pubkey: must be 32 bytes hex encoded")
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[p.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return nil, NewToolError(int(ErrorCodeSessionNotFound), "session not found")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if len(session.Participants) >= session.Config.NumParticipants {
		return nil, NewToolError(int(ErrorCodeSessionFull), "session is full")
	}

	// Assign next available index
	participantIdx := len(session.Participants)

	participant := &MCPParticipant{
		Index:      participantIdx,
		HostPubkey: hostPubkey,
		JoinedAt:   time.Now(),
	}

	session.Participants[participantIdx] = participant
	session.UpdatedAt = time.Now()

	if len(session.Participants) == session.Config.NumParticipants {
		session.State = StateRound1
	} else {
		session.State = StateWaitingParticipants
	}

	// Build host pubkeys array
	hostPubkeys := make([]string, len(session.Participants))
	for idx, p := range session.Participants {
		hostPubkeys[idx] = hex.EncodeToString(p.HostPubkey)
	}

	return &JoinSessionResult{
		SessionID:       p.SessionID,
		ParticipantIdx:  participantIdx,
		Threshold:       session.Config.Threshold,
		NumParticipants: session.Config.NumParticipants,
		HostPubkeys:     hostPubkeys,
		Ciphersuite:     session.Config.Ciphersuite,
	}, nil
}

func (s *MCPServer) handleGetSession(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p GetSessionParams
	if err := UnmarshalParams(params, &p); err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid parameters")
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[p.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return nil, NewToolError(int(ErrorCodeSessionNotFound), "session not found")
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	hostPubkeys := make([]string, len(session.Participants))
	for idx, p := range session.Participants {
		hostPubkeys[idx] = hex.EncodeToString(p.HostPubkey)
	}

	return &GetSessionResult{
		SessionID:           p.SessionID,
		Threshold:           session.Config.Threshold,
		NumParticipants:     session.Config.NumParticipants,
		CurrentParticipants: len(session.Participants),
		Ciphersuite:         session.Config.Ciphersuite,
		Status:              string(session.State),
		HostPubkeys:         hostPubkeys,
	}, nil
}

func (s *MCPServer) handleSubmitRound1(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p SubmitRound1Params
	if err := UnmarshalParams(params, &p); err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid parameters")
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[p.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return nil, NewToolError(int(ErrorCodeSessionNotFound), "session not found")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.State != StateRound1 {
		return nil, NewToolError(int(ErrorCodeInvalidState),
			fmt.Sprintf("invalid state for round1: %s", session.State))
	}

	// Decode commitment
	commitment := make([][]byte, len(p.Commitment))
	for i, c := range p.Commitment {
		data, err := hex.DecodeString(c)
		if err != nil {
			return nil, NewToolError(int(ErrorCodeInvalidParams),
				fmt.Sprintf("invalid commitment[%d]: %v", i, err))
		}
		commitment[i] = data
	}

	pop, err := hex.DecodeString(p.POP)
	if err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid pop")
	}

	pubnonce, err := hex.DecodeString(p.Pubnonce)
	if err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid pubnonce")
	}

	msg := &transport.Round1Message{
		Commitment: commitment,
		POP:        pop,
		Pubnonce:   pubnonce,
	}

	session.Round1Messages[p.ParticipantIdx] = msg
	session.UpdatedAt = time.Now()

	result := &SubmitRound1Result{
		Status:     "received",
		WaitingFor: session.Config.NumParticipants - len(session.Round1Messages),
	}

	// If all Round1 messages received, transition to Round2
	if len(session.Round1Messages) == session.Config.NumParticipants {
		session.State = StateRound2
		result.Status = "complete"
		result.WaitingFor = 0

		// Build aggregated data
		allCommitments := make([][]string, session.Config.NumParticipants)
		allPOPs := make([]string, session.Config.NumParticipants)
		allPubnonces := make([]string, session.Config.NumParticipants)

		for idx, msg := range session.Round1Messages {
			commitmentStrs := make([]string, len(msg.Commitment))
			for i, c := range msg.Commitment {
				commitmentStrs[i] = hex.EncodeToString(c)
			}
			allCommitments[idx] = commitmentStrs
			allPOPs[idx] = hex.EncodeToString(msg.POP)
			allPubnonces[idx] = hex.EncodeToString(msg.Pubnonce)
		}

		result.AllCommitments = allCommitments
		result.AllPOPs = allPOPs
		result.AllPubnonces = allPubnonces
	}

	return result, nil
}

func (s *MCPServer) handleSubmitRound2(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p SubmitRound2Params
	if err := UnmarshalParams(params, &p); err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid parameters")
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[p.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return nil, NewToolError(int(ErrorCodeSessionNotFound), "session not found")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.State != StateRound2 {
		return nil, NewToolError(int(ErrorCodeInvalidState),
			fmt.Sprintf("invalid state for round2: %s", session.State))
	}

	encryptedShares, err := hex.DecodeString(p.EncryptedShares)
	if err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid encrypted_shares")
	}

	msg := &transport.Round2Message{
		EncryptedShares: encryptedShares,
	}

	session.Round2Messages[p.ParticipantIdx] = msg
	session.UpdatedAt = time.Now()

	result := &SubmitRound2Result{
		Status:     "received",
		WaitingFor: session.Config.NumParticipants - len(session.Round2Messages),
	}

	// If all Round2 messages received, transition to CertEq
	if len(session.Round2Messages) == session.Config.NumParticipants {
		session.State = StateCertEq
		result.Status = "complete"
		result.WaitingFor = 0
	}

	return result, nil
}

func (s *MCPServer) handleSubmitCertEq(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p SubmitCertEqParams
	if err := UnmarshalParams(params, &p); err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid parameters")
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[p.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return nil, NewToolError(int(ErrorCodeSessionNotFound), "session not found")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.State != StateCertEq {
		return nil, NewToolError(int(ErrorCodeInvalidState),
			fmt.Sprintf("invalid state for certeq: %s", session.State))
	}

	signature, err := hex.DecodeString(p.Signature)
	if err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid signature")
	}

	msg := &transport.CertEqSignMessage{
		Signature: signature,
	}

	session.CertEqSignatures[p.ParticipantIdx] = msg
	session.UpdatedAt = time.Now()

	result := &SubmitCertEqResult{
		Status:     "received",
		WaitingFor: session.Config.NumParticipants - len(session.CertEqSignatures),
	}

	// If all CertEq signatures received, session is complete
	if len(session.CertEqSignatures) == session.Config.NumParticipants {
		session.State = StateCompleted
		result.Status = "complete"
		result.WaitingFor = 0
		// In a real implementation, we would aggregate signatures into a certificate
		result.Certificate = hex.EncodeToString([]byte("mock_certificate"))
	}

	return result, nil
}

func (s *MCPServer) handleGetResult(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p GetResultParams
	if err := UnmarshalParams(params, &p); err != nil {
		return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid parameters")
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[p.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return nil, NewToolError(int(ErrorCodeSessionNotFound), "session not found")
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.State != StateCompleted {
		return nil, NewToolError(int(ErrorCodeInvalidState),
			fmt.Sprintf("session not completed: %s", session.State))
	}

	// In a real implementation, this would return the actual DKG result
	// For now, return mock data
	return &GetResultResult{
		SessionID:       p.SessionID,
		ThresholdPubkey: hex.EncodeToString(make([]byte, 33)),
		PublicShares:    []string{},
		RecoveryData:    hex.EncodeToString(make([]byte, 64)),
		Status:          string(session.State),
	}, nil
}

func (s *MCPServer) handleListSessions(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p ListSessionsParams
	if len(params) > 0 {
		if err := UnmarshalParams(params, &p); err != nil {
			return nil, NewToolError(int(ErrorCodeInvalidParams), "invalid parameters")
		}
	}

	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	sessions := make([]SessionSummary, 0, len(s.sessions))
	for _, session := range s.sessions {
		session.mu.RLock()
		if !p.IncludeCompleted && (session.State == StateCompleted || session.State == StateFailed) {
			session.mu.RUnlock()
			continue
		}

		summary := SessionSummary{
			SessionID:           session.SessionID,
			Threshold:           session.Config.Threshold,
			NumParticipants:     session.Config.NumParticipants,
			CurrentParticipants: len(session.Participants),
			Status:              string(session.State),
			Ciphersuite:         session.Config.Ciphersuite,
		}
		sessions = append(sessions, summary)
		session.mu.RUnlock()
	}

	return &ListSessionsResult{
		Sessions: sessions,
	}, nil
}

// SetStdio sets custom stdio readers/writers (for testing).
func (s *MCPServer) SetStdio(reader io.Reader, writer io.Writer) {
	s.reader = reader
	s.writer = writer
}
