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

package http

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// HTTPServer implements transport.Coordinator using HTTP/REST
type HTTPServer struct {
	config        *transport.Config
	sessionConfig *transport.SessionConfig
	sessionID     string
	server        *http.Server
	listener      net.Listener
	serializer    *transport.Serializer

	mu           sync.RWMutex
	participants map[int]*participantInfo // index -> info
	round1Data   map[int]*transport.Round1Message
	round2Data   map[int]*transport.Round2Message
	certEqSigs   map[int][]byte
	certificate  []byte
	started      bool
	stopped      bool
	waitChan     chan struct{}
}

// participantInfo stores information about a connected participant
type participantInfo struct {
	index      int
	hostPubkey []byte
	joined     time.Time
}

// NewHTTPServer creates a new HTTP server coordinator
func NewHTTPServer(config *transport.Config, sessionConfig *transport.SessionConfig, sessionID string) (*HTTPServer, error) {
	if config == nil {
		return nil, transport.ErrInvalidConfig
	}
	if sessionConfig == nil {
		return nil, transport.ErrInvalidConfig
	}
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	// Validate session config
	if sessionConfig.Threshold < 1 || sessionConfig.Threshold > sessionConfig.NumParticipants {
		return nil, transport.ErrInvalidThreshold
	}
	if sessionConfig.NumParticipants < 1 {
		return nil, transport.ErrInvalidParticipantCount
	}

	// Set defaults
	if config.CodecType == "" {
		config.CodecType = "json"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	// Create serializer
	serializer, err := transport.NewSerializer(config.CodecType)
	if err != nil {
		return nil, err
	}

	s := &HTTPServer{
		config:        config,
		sessionConfig: sessionConfig,
		sessionID:     sessionID,
		serializer:    serializer,
		participants:  make(map[int]*participantInfo),
		round1Data:    make(map[int]*transport.Round1Message),
		round2Data:    make(map[int]*transport.Round2Message),
		certEqSigs:    make(map[int][]byte),
		waitChan:      make(chan struct{}),
	}

	return s, nil
}

// Start begins listening for participant connections
func (s *HTTPServer) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	s.started = true
	s.mu.Unlock()

	// Create TCP listener
	listener, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		return transport.NewConnectionError(s.config.Address, err)
	}
	s.listener = listener

	// Create HTTP server
	mux := http.NewServeMux()
	s.registerHandlers(mux)

	s.server = &http.Server{
		Handler:           mux,
		ReadTimeout:       s.config.Timeout,
		WriteTimeout:      s.config.Timeout,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// Configure TLS if certificates are provided
	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		tlsCfg, err := tlsconfig.ServerConfig(s.config.TLSCertFile, s.config.TLSKeyFile, s.config.TLSCAFile)
		if err != nil {
			_ = s.listener.Close()
			return transport.NewTLSError("failed to configure TLS", err)
		}
		s.server.TLSConfig = tlsCfg
		s.listener = tls.NewListener(s.listener, tlsCfg)
	}

	// Start serving
	go func() {
		if err := s.server.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Log error but don't crash - server is shutting down
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the coordinator
func (s *HTTPServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	s.mu.Unlock()

	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// Address returns the network address the coordinator is listening on
func (s *HTTPServer) Address() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.config.Address
}

// SessionID returns the unique identifier for this DKG session
func (s *HTTPServer) SessionID() string {
	return s.sessionID
}

// WaitForParticipants blocks until n participants have connected
func (s *HTTPServer) WaitForParticipants(ctx context.Context, n int) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.mu.RLock()
			count := len(s.participants)
			s.mu.RUnlock()

			if count >= n {
				return nil
			}
		}
	}
}

// registerHandlers sets up HTTP routes
func (s *HTTPServer) registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc(PathHealth, s.handleHealth)
	mux.HandleFunc(PathSessions, s.handleCreateSession)
	mux.HandleFunc("/"+apiVersion+"/sessions/", s.handleSessionRoutes)
}

// handleSessionRoutes routes session-specific requests
func (s *HTTPServer) handleSessionRoutes(w http.ResponseWriter, r *http.Request) {
	// Extract session ID from path
	path := strings.TrimPrefix(r.URL.Path, "/"+apiVersion+"/sessions/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		s.writeError(w, r, http.StatusBadRequest, "session ID required")
		return
	}

	sessionID := parts[0]
	if sessionID != s.sessionID {
		s.writeError(w, r, http.StatusNotFound, "session not found")
		return
	}

	// Route based on remaining path
	if len(parts) == 1 {
		// /sessions/{id}
		s.handleGetSession(w, r, sessionID)
		return
	}

	action := parts[1]
	switch action {
	case "join":
		s.handleJoinSession(w, r, sessionID)
	case "round1":
		s.handleRound1(w, r, sessionID)
	case "round2":
		s.handleRound2(w, r, sessionID)
	case "certeq":
		s.handleCertEq(w, r, sessionID)
	case "certificate":
		s.handleGetCertificate(w, r, sessionID)
	default:
		s.writeError(w, r, http.StatusNotFound, "unknown endpoint")
	}
}

// handleHealth handles health check requests
func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, r, http.StatusMethodNotAllowed, "only GET allowed")
		return
	}

	w.Header().Set(HeaderContentType, ContentTypeText)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// handleCreateSession handles session creation (not used in our coordinator pattern)
func (s *HTTPServer) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, r, http.StatusMethodNotAllowed, "only POST allowed")
		return
	}

	// Return existing session info
	s.mu.RLock()
	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       s.sessionID,
		Threshold:       s.sessionConfig.Threshold,
		NumParticipants: s.sessionConfig.NumParticipants,
		Ciphersuite:     s.sessionConfig.Ciphersuite,
	}
	s.mu.RUnlock()

	s.writeResponse(w, r, http.StatusOK, sessionInfo)
}

// handleGetSession returns session information
func (s *HTTPServer) handleGetSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodGet {
		s.writeError(w, r, http.StatusMethodNotAllowed, "only GET allowed")
		return
	}

	s.mu.RLock()
	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       s.sessionID,
		Threshold:       s.sessionConfig.Threshold,
		NumParticipants: s.sessionConfig.NumParticipants,
		Ciphersuite:     s.sessionConfig.Ciphersuite,
	}
	s.mu.RUnlock()

	s.writeResponse(w, r, http.StatusOK, sessionInfo)
}

// handleJoinSession handles participant join requests
func (s *HTTPServer) handleJoinSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		s.writeError(w, r, http.StatusMethodNotAllowed, "only POST allowed")
		return
	}

	// Read and deserialize join message
	joinMsg := &transport.JoinMessage{}
	if err := s.readRequest(r, joinMsg); err != nil {
		s.writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if session is full
	if len(s.participants) >= s.sessionConfig.NumParticipants {
		s.mu.Unlock()
		s.writeError(w, r, http.StatusConflict, "session full")
		s.mu.Lock()
		return
	}

	// Check for duplicate participant
	for _, p := range s.participants {
		if hex.EncodeToString(p.hostPubkey) == hex.EncodeToString(joinMsg.HostPubkey) {
			s.mu.Unlock()
			s.writeError(w, r, http.StatusConflict, "participant already joined")
			s.mu.Lock()
			return
		}
	}

	// Assign participant index
	participantIdx := len(s.participants)

	// Store participant info
	s.participants[participantIdx] = &participantInfo{
		index:      participantIdx,
		hostPubkey: joinMsg.HostPubkey,
		joined:     time.Now(),
	}

	// Build host pubkeys list
	hostPubkeys := make([][]byte, s.sessionConfig.NumParticipants)
	for idx, p := range s.participants {
		hostPubkeys[idx] = p.hostPubkey
	}

	// Return session info with participant index
	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       s.sessionID,
		Threshold:       s.sessionConfig.Threshold,
		NumParticipants: s.sessionConfig.NumParticipants,
		ParticipantIdx:  participantIdx,
		HostPubkeys:     hostPubkeys,
		Ciphersuite:     s.sessionConfig.Ciphersuite,
	}

	s.mu.Unlock()
	s.writeResponse(w, r, http.StatusCreated, sessionInfo)
	s.mu.Lock()
}

// handleRound1 handles Round1 message submission and retrieval
func (s *HTTPServer) handleRound1(w http.ResponseWriter, r *http.Request, sessionID string) {
	switch r.Method {
	case http.MethodPost:
		s.handleRound1Post(w, r, sessionID)
	case http.MethodGet:
		s.handleRound1Get(w, r, sessionID)
	default:
		s.writeError(w, r, http.StatusMethodNotAllowed, "only GET and POST allowed")
	}
}

// handleRound1Post handles Round1 message submission
func (s *HTTPServer) handleRound1Post(w http.ResponseWriter, r *http.Request, sessionID string) {
	// Parse participant index from query params
	participantIdx := s.getParticipantIndex(r)
	if participantIdx < 0 {
		s.writeError(w, r, http.StatusBadRequest, "participant_idx query parameter required")
		return
	}

	// Read and deserialize Round1 message
	round1Msg := &transport.Round1Message{}
	if err := s.readRequest(r, round1Msg); err != nil {
		s.writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify participant exists
	if _, exists := s.participants[participantIdx]; !exists {
		s.mu.Unlock()
		s.writeError(w, r, http.StatusNotFound, "participant not found")
		s.mu.Lock()
		return
	}

	// Store Round1 data
	s.round1Data[participantIdx] = round1Msg

	s.mu.Unlock()
	s.writeResponse(w, r, http.StatusCreated, map[string]string{"status": "accepted"})
	s.mu.Lock()
}

// handleRound1Get returns aggregated Round1 data
func (s *HTTPServer) handleRound1Get(w http.ResponseWriter, r *http.Request, sessionID string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Wait for all participants to submit Round1
	if len(s.round1Data) < s.sessionConfig.NumParticipants {
		s.mu.RUnlock()
		s.writeError(w, r, http.StatusAccepted, "waiting for all participants")
		s.mu.RLock()
		return
	}

	// Build aggregated Round1 message
	allCommitments := make([][][]byte, s.sessionConfig.NumParticipants)
	allPOPs := make([][]byte, s.sessionConfig.NumParticipants)
	allPubnonces := make([][]byte, s.sessionConfig.NumParticipants)

	for idx := 0; idx < s.sessionConfig.NumParticipants; idx++ {
		if r1, exists := s.round1Data[idx]; exists {
			allCommitments[idx] = r1.Commitment
			allPOPs[idx] = r1.POP
			allPubnonces[idx] = r1.Pubnonce
		}
	}

	round1Agg := &transport.Round1AggMessage{
		AllCommitments: allCommitments,
		AllPOPs:        allPOPs,
		AllPubnonces:   allPubnonces,
	}

	s.mu.RUnlock()
	s.writeResponse(w, r, http.StatusOK, round1Agg)
	s.mu.RLock()
}

// handleRound2 handles Round2 message submission and retrieval
func (s *HTTPServer) handleRound2(w http.ResponseWriter, r *http.Request, sessionID string) {
	switch r.Method {
	case http.MethodPost:
		s.handleRound2Post(w, r, sessionID)
	case http.MethodGet:
		s.handleRound2Get(w, r, sessionID)
	default:
		s.writeError(w, r, http.StatusMethodNotAllowed, "only GET and POST allowed")
	}
}

// handleRound2Post handles Round2 message submission
func (s *HTTPServer) handleRound2Post(w http.ResponseWriter, r *http.Request, sessionID string) {
	participantIdx := s.getParticipantIndex(r)
	if participantIdx < 0 {
		s.writeError(w, r, http.StatusBadRequest, "participant_idx query parameter required")
		return
	}

	round2Msg := &transport.Round2Message{}
	if err := s.readRequest(r, round2Msg); err != nil {
		s.writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.participants[participantIdx]; !exists {
		s.mu.Unlock()
		s.writeError(w, r, http.StatusNotFound, "participant not found")
		s.mu.Lock()
		return
	}

	s.round2Data[participantIdx] = round2Msg

	s.mu.Unlock()
	s.writeResponse(w, r, http.StatusCreated, map[string]string{"status": "accepted"})
	s.mu.Lock()
}

// handleRound2Get returns Round2 data for the requesting participant
func (s *HTTPServer) handleRound2Get(w http.ResponseWriter, r *http.Request, sessionID string) {
	participantIdx := s.getParticipantIndex(r)
	if participantIdx < 0 {
		s.writeError(w, r, http.StatusBadRequest, "participant_idx query parameter required")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if all Round2 data is available
	if len(s.round2Data) < s.sessionConfig.NumParticipants {
		s.mu.RUnlock()
		s.writeError(w, r, http.StatusAccepted, "waiting for all participants")
		s.mu.RLock()
		return
	}

	// In a real implementation, each participant would receive different encrypted shares
	// For now, return all Round2 messages
	messages := make([]*transport.Round2Message, s.sessionConfig.NumParticipants)
	for idx := 0; idx < s.sessionConfig.NumParticipants; idx++ {
		if r2, exists := s.round2Data[idx]; exists {
			messages[idx] = r2
		}
	}

	s.mu.RUnlock()
	s.writeResponse(w, r, http.StatusOK, messages)
	s.mu.RLock()
}

// handleCertEq handles CertEq signature submission
func (s *HTTPServer) handleCertEq(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		s.writeError(w, r, http.StatusMethodNotAllowed, "only POST allowed")
		return
	}

	participantIdx := s.getParticipantIndex(r)
	if participantIdx < 0 {
		s.writeError(w, r, http.StatusBadRequest, "participant_idx query parameter required")
		return
	}

	certEqMsg := &transport.CertEqSignMessage{}
	if err := s.readRequest(r, certEqMsg); err != nil {
		s.writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.participants[participantIdx]; !exists {
		s.mu.Unlock()
		s.writeError(w, r, http.StatusNotFound, "participant not found")
		s.mu.Lock()
		return
	}

	s.certEqSigs[participantIdx] = certEqMsg.Signature

	s.mu.Unlock()
	s.writeResponse(w, r, http.StatusCreated, map[string]string{"status": "accepted"})
	s.mu.Lock()
}

// handleGetCertificate returns the final certificate
func (s *HTTPServer) handleGetCertificate(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodGet {
		s.writeError(w, r, http.StatusMethodNotAllowed, "only GET allowed")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.certificate == nil {
		s.mu.RUnlock()
		s.writeError(w, r, http.StatusAccepted, "certificate not ready")
		s.mu.RLock()
		return
	}

	certMsg := &transport.CertificateMessage{
		Certificate: s.certificate,
	}

	s.mu.RUnlock()
	s.writeResponse(w, r, http.StatusOK, certMsg)
	s.mu.RLock()
}

// getParticipantIndex extracts participant index from query parameters
func (s *HTTPServer) getParticipantIndex(r *http.Request) int {
	idxStr := r.URL.Query().Get("participant_idx")
	if idxStr == "" {
		return -1
	}

	var idx int
	if _, err := fmt.Sscanf(idxStr, "%d", &idx); err != nil {
		return -1
	}

	return idx
}

// readRequest reads and deserializes a request body
func (s *HTTPServer) readRequest(r *http.Request, v interface{}) error {
	// Limit request body size
	maxSize := int64(1 << 20) // 1MB default
	if s.config.MaxMessageSize > 0 {
		maxSize = int64(s.config.MaxMessageSize)
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxSize)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Determine serializer based on Content-Type
	contentType := r.Header.Get(HeaderContentType)
	codecType := ParseContentType(contentType)
	if codecType == "" {
		codecType = s.config.CodecType // fallback to default
	}

	serializer, err := transport.NewSerializer(codecType)
	if err != nil {
		return err
	}

	return serializer.Unmarshal(body, v)
}

// writeResponse serializes and writes a response
func (s *HTTPServer) writeResponse(w http.ResponseWriter, r *http.Request, status int, v interface{}) {
	// Determine serializer based on Accept header
	accept := r.Header.Get(HeaderAccept)
	codecType := ParseContentType(accept)
	if codecType == "" {
		codecType = s.config.CodecType // fallback to default
	}

	serializer, err := transport.NewSerializer(codecType)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("serialization error: %v", err))
		return
	}

	data, err := serializer.Marshal(v)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("failed to serialize response: %v", err))
		return
	}

	w.Header().Set(HeaderContentType, CodecToContentType(codecType))
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// writeError writes an error response
func (s *HTTPServer) writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	errorMsg := &transport.ErrorMessage{
		Code:    status,
		Message: message,
	}

	// Always use JSON for errors
	data, err := json.Marshal(errorMsg)
	if err != nil {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":500,"message":"internal server error"}`))
		return
	}

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
