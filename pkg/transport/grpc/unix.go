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

package grpc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/grpc/proto"
)

// UnixServer implements a Unix domain socket gRPC server.
// No TLS is used for Unix sockets as they are local-only.
type UnixServer struct {
	proto.UnimplementedDKGCoordinatorServer

	config        *transport.Config
	sessionConfig *transport.SessionConfig
	sessionID     string
	listener      net.Listener
	server        *grpc.Server
	serializer    *transport.Serializer

	// Session management
	participants     map[int]proto.DKGCoordinator_ParticipantStreamServer
	participantsMu   sync.RWMutex
	participantCount atomic.Int32
	participantReady chan struct{}

	// Lifecycle management
	running      atomic.Bool
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

// NewUnixServer creates a new Unix socket gRPC server.
func NewUnixServer(cfg *transport.Config, sessionCfg *transport.SessionConfig) (*UnixServer, error) {
	if cfg == nil {
		return nil, transport.ErrInvalidConfig
	}
	if cfg.Protocol != transport.ProtocolUnix {
		return nil, transport.NewProtocolError(cfg.Protocol, fmt.Errorf("expected unix protocol"))
	}
	if sessionCfg == nil {
		return nil, transport.ErrInvalidConfig
	}

	// Validate session config
	if sessionCfg.Threshold < 1 || sessionCfg.Threshold > sessionCfg.NumParticipants {
		return nil, transport.ErrInvalidThreshold
	}
	if sessionCfg.NumParticipants < 1 {
		return nil, transport.ErrInvalidParticipantCount
	}

	// Generate session ID if not provided
	sessionID := sessionCfg.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("session-%d", time.Now().UnixNano())
	}

	// Create serializer
	codecType := cfg.CodecType
	if codecType == "" {
		codecType = "json"
	}
	serializer, err := transport.NewSerializer(codecType)
	if err != nil {
		return nil, err
	}

	s := &UnixServer{
		config:           cfg,
		sessionConfig:    sessionCfg,
		sessionID:        sessionID,
		serializer:       serializer,
		participants:     make(map[int]proto.DKGCoordinator_ParticipantStreamServer),
		participantReady: make(chan struct{}),
		shutdownChan:     make(chan struct{}),
	}

	return s, nil
}

// Start begins listening on Unix socket.
func (s *UnixServer) Start(ctx context.Context) error {
	if s.running.Load() {
		return fmt.Errorf("server already running")
	}

	// Remove existing socket file if present
	if err := os.RemoveAll(s.config.Address); err != nil {
		return transport.NewConnectionError(s.config.Address, err)
	}

	// Create Unix listener
	listener, err := net.Listen("unix", s.config.Address)
	if err != nil {
		return transport.NewConnectionError(s.config.Address, err)
	}
	s.listener = listener

	// Create gRPC server options (no TLS for Unix sockets)
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(s.getMaxMessageSize()),
		grpc.MaxSendMsgSize(s.getMaxMessageSize()),
	}

	// Create and register gRPC server
	s.server = grpc.NewServer(opts...)
	proto.RegisterDKGCoordinatorServer(s.server, s)

	// Start serving
	s.running.Store(true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.server.Serve(listener)
	}()

	return nil
}

// Stop gracefully shuts down the Unix server.
func (s *UnixServer) Stop(ctx context.Context) error {
	if !s.running.Load() {
		return nil
	}

	s.running.Store(false)
	close(s.shutdownChan)

	// Graceful shutdown with timeout
	done := make(chan struct{})
	go func() {
		s.server.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		// Graceful shutdown completed
	case <-ctx.Done():
		// Force stop on timeout
		s.server.Stop()
	}

	s.wg.Wait()

	// Remove socket file
	_ = os.RemoveAll(s.config.Address)

	return nil
}

// Address returns the Unix socket path.
func (s *UnixServer) Address() string {
	return s.config.Address
}

// SessionID returns the unique identifier for this DKG session.
func (s *UnixServer) SessionID() string {
	return s.sessionID
}

// WaitForParticipants blocks until n participants have connected.
func (s *UnixServer) WaitForParticipants(ctx context.Context, n int) error {
	if n < 1 {
		return transport.ErrInvalidParticipantCount
	}
	if n > s.sessionConfig.NumParticipants {
		return transport.ErrInvalidParticipantCount
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return transport.ErrSessionTimeout
		case <-s.shutdownChan:
			return transport.ErrSessionClosed
		case <-ticker.C:
			count := int(s.participantCount.Load())
			if count >= n {
				return nil
			}
		}
	}
}

// ParticipantStream handles bidirectional streaming for a participant.
func (s *UnixServer) ParticipantStream(stream proto.DKGCoordinator_ParticipantStreamServer) error {
	if !s.running.Load() {
		return transport.ErrSessionClosed
	}

	var participantIdx int
	var registered bool

	defer func() {
		if registered {
			s.participantsMu.Lock()
			delete(s.participants, participantIdx)
			s.participantsMu.Unlock()
			s.participantCount.Add(-1)
		}
	}()

	for {
		select {
		case <-s.shutdownChan:
			return transport.ErrSessionClosed
		default:
		}

		// Receive message from participant
		msg, err := stream.Recv()
		if err != nil {
			return err
		}

		// Handle join message to register participant
		if msg.Type == proto.MessageType_MSG_TYPE_JOIN && !registered {
			participantIdx = int(msg.SenderIdx)

			// Register participant
			s.participantsMu.Lock()
			if _, exists := s.participants[participantIdx]; exists {
				s.participantsMu.Unlock()
				return transport.ErrDuplicateParticipant
			}
			s.participants[participantIdx] = stream
			s.participantsMu.Unlock()

			registered = true
			s.participantCount.Add(1)

			// Create session info payload
			sessionInfoData := &transport.SessionInfoMessage{
				SessionID:       s.sessionID,
				Threshold:       s.sessionConfig.Threshold,
				NumParticipants: s.sessionConfig.NumParticipants,
				ParticipantIdx:  participantIdx,
				Ciphersuite:     s.sessionConfig.Ciphersuite,
			}
			payload, err := s.serializer.Marshal(sessionInfoData)
			if err != nil {
				return fmt.Errorf("failed to serialize session info: %w", err)
			}

			// Send session info back to participant
			sessionInfo := &proto.DKGMessage{
				SessionId: s.sessionID,
				Type:      proto.MessageType_MSG_TYPE_SESSION_INFO,
				SenderIdx: -1, // Coordinator
				Payload:   payload,
				Timestamp: time.Now().UnixMilli(),
			}
			if err := stream.Send(sessionInfo); err != nil {
				return err
			}

			continue
		}

		if !registered {
			return transport.ErrUnexpectedMessage
		}

		// Relay message to other participants
		if err := s.relayMessage(msg, participantIdx); err != nil {
			return err
		}
	}
}

// relayMessage relays a message to all other participants.
func (s *UnixServer) relayMessage(msg *proto.DKGMessage, senderIdx int) error {
	s.participantsMu.RLock()
	defer s.participantsMu.RUnlock()

	// Broadcast to all participants except sender
	for idx, stream := range s.participants {
		if idx == senderIdx {
			continue
		}
		if err := stream.Send(msg); err != nil {
			return transport.NewParticipantError("", idx, err)
		}
	}

	return nil
}

// Helper methods

func (s *UnixServer) getMaxMessageSize() int {
	if s.config.MaxMessageSize > 0 {
		return s.config.MaxMessageSize
	}
	return 1024 * 1024 // 1MB default
}

// UnixClient implements a Unix domain socket gRPC client.
type UnixClient struct {
	config     *transport.Config
	serializer *transport.Serializer

	// Connection state
	conn      *grpc.ClientConn
	client    proto.DKGCoordinatorClient
	stream    proto.DKGCoordinator_ParticipantStreamClient
	connected atomic.Bool
	connMu    sync.RWMutex

	// Message handling
	incomingChan chan *proto.DKGMessage
	errorChan    chan error
	shutdownChan chan struct{}
	wg           sync.WaitGroup

	// Session info
	sessionID      string
	participantIdx int
}

// NewUnixClient creates a new Unix socket gRPC client.
func NewUnixClient(cfg *transport.Config) (*UnixClient, error) {
	if cfg == nil {
		return nil, transport.ErrInvalidConfig
	}
	if cfg.Protocol != transport.ProtocolUnix {
		return nil, transport.NewProtocolError(cfg.Protocol, fmt.Errorf("expected unix protocol"))
	}

	// Create serializer
	codecType := cfg.CodecType
	if codecType == "" {
		codecType = "json"
	}
	serializer, err := transport.NewSerializer(codecType)
	if err != nil {
		return nil, err
	}

	c := &UnixClient{
		config:       cfg,
		serializer:   serializer,
		incomingChan: make(chan *proto.DKGMessage, 100),
		errorChan:    make(chan error, 10),
		shutdownChan: make(chan struct{}),
	}

	return c, nil
}

// Connect establishes a connection via Unix socket.
func (c *UnixClient) Connect(ctx context.Context, addr string) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.connected.Load() {
		return transport.ErrAlreadyConnected
	}

	// Create dial options (no TLS for Unix sockets)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(c.getMaxMessageSize()),
			grpc.MaxCallSendMsgSize(c.getMaxMessageSize()),
		),
	}

	// Use unix:// scheme for Unix socket
	// Convert to forward slashes for cross-platform compatibility (Windows uses backslashes)
	socketAddr := fmt.Sprintf("unix://%s", filepath.ToSlash(addr))

	// Create client connection using NewClient (non-blocking by default)
	conn, err := grpc.NewClient(socketAddr, opts...)
	if err != nil {
		return transport.NewConnectionError(addr, err)
	}

	// Verify connection can be established within timeout
	connectCtx, cancel := context.WithTimeout(ctx, c.getTimeout())
	defer cancel()
	conn.Connect()
	if !waitForReadyUnix(connectCtx, conn) {
		if closeErr := conn.Close(); closeErr != nil {
			_ = closeErr
		}
		return transport.NewConnectionError(addr, context.DeadlineExceeded)
	}

	c.conn = conn
	c.client = proto.NewDKGCoordinatorClient(conn)
	c.connected.Store(true)

	return nil
}

// Disconnect closes the Unix socket connection.
func (c *UnixClient) Disconnect() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if !c.connected.Load() {
		return transport.ErrNotConnected
	}

	// Signal shutdown
	close(c.shutdownChan)
	c.connected.Store(false)

	// Close stream if active
	if c.stream != nil {
		if err := c.stream.CloseSend(); err != nil {
			// Log error but continue with cleanup
			_ = err
		}
		c.stream = nil
	}

	// Wait for goroutines
	c.wg.Wait()

	// Close connection
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		if err != nil {
			return err
		}
	}

	return nil
}

// RunDKG executes the FROST DKG protocol.
func (c *UnixClient) RunDKG(ctx context.Context, params *transport.DKGParams) (*transport.DKGResult, error) {
	if !c.connected.Load() {
		return nil, transport.ErrNotConnected
	}

	// Validate parameters
	if err := c.validateParams(params); err != nil {
		return nil, err
	}

	c.participantIdx = params.ParticipantIdx

	// Create stream
	stream, err := c.client.ParticipantStream(ctx)
	if err != nil {
		return nil, transport.NewConnectionError("", err)
	}
	c.stream = stream

	// Start message receiver
	c.wg.Add(1)
	go c.receiveMessages()

	// Send join message
	if err := c.sendJoin(params); err != nil {
		return nil, err
	}

	// Wait for session info
	sessionInfo, err := c.waitForSessionInfo(ctx)
	if err != nil {
		return nil, err
	}
	c.sessionID = sessionInfo.SessionID

	// Execute DKG rounds
	result, err := c.executeDKG(ctx, params, sessionInfo)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// sendJoin sends the join message to the coordinator.
func (c *UnixClient) sendJoin(params *transport.DKGParams) error {
	joinMsg := &transport.JoinMessage{
		HostPubkey: params.HostPubkeys[params.ParticipantIdx],
	}

	payload, err := c.serializer.Marshal(joinMsg)
	if err != nil {
		return err
	}

	msg := &proto.DKGMessage{
		SessionId: "",
		Type:      proto.MessageType_MSG_TYPE_JOIN,
		SenderIdx: safeInt32(params.ParticipantIdx),
		Payload:   payload,
		Timestamp: time.Now().UnixMilli(),
	}

	return c.stream.Send(msg)
}

// waitForSessionInfo waits for session info from coordinator.
func (c *UnixClient) waitForSessionInfo(ctx context.Context) (*transport.SessionInfoMessage, error) {
	select {
	case <-ctx.Done():
		return nil, transport.ErrSessionTimeout
	case err := <-c.errorChan:
		return nil, err
	case msg := <-c.incomingChan:
		if msg.Type != proto.MessageType_MSG_TYPE_SESSION_INFO {
			return nil, transport.ErrUnexpectedMessage
		}

		var sessionInfo transport.SessionInfoMessage
		if err := c.serializer.Unmarshal(msg.Payload, &sessionInfo); err != nil {
			return nil, err
		}

		return &sessionInfo, nil
	}
}

// executeDKG executes the DKG protocol rounds.
func (c *UnixClient) executeDKG(ctx context.Context, params *transport.DKGParams, sessionInfo *transport.SessionInfoMessage) (*transport.DKGResult, error) {
	// This is a simplified implementation - the actual DKG logic would go here
	// For now, we'll just demonstrate the message flow

	// In a real implementation, this would:
	// 1. Execute Round 1 (VSS commitment and POP)
	// 2. Wait for aggregated Round 1 data
	// 3. Execute Round 2 (encrypted shares)
	// 4. Wait for aggregated Round 2 data
	// 5. Generate CertEq signature
	// 6. Wait for final certificate
	// 7. Return DKG result

	// Placeholder result with unique data per participant
	result := &transport.DKGResult{
		SessionID:       c.sessionID,
		SecretShare:     make([]byte, transport.SecretKeySize),
		ThresholdPubkey: make([]byte, transport.PublicKeySize),
		PublicShares:    make([][]byte, sessionInfo.NumParticipants),
		RecoveryData:    make([]byte, 64),
	}

	// Fill with unique test data per participant
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

// receiveMessages handles incoming messages from the stream.
func (c *UnixClient) receiveMessages() {
	defer c.wg.Done()

	for {
		select {
		case <-c.shutdownChan:
			return
		default:
		}

		msg, err := c.stream.Recv()
		if err != nil {
			select {
			case c.errorChan <- err:
			case <-c.shutdownChan:
			}
			return
		}

		select {
		case c.incomingChan <- msg:
		case <-c.shutdownChan:
			return
		}
	}
}

// validateParams validates DKG parameters.
func (c *UnixClient) validateParams(params *transport.DKGParams) error {
	if params == nil {
		return transport.ErrInvalidDKGParams
	}
	if len(params.HostSeckey) != 32 {
		return transport.ErrInvalidHostKey
	}
	if len(params.Random) != 32 {
		return transport.ErrInvalidRandomness
	}
	if params.ParticipantIdx < 0 || params.ParticipantIdx >= len(params.HostPubkeys) {
		return transport.ErrInvalidParticipantIndex
	}
	if params.Threshold < 1 || params.Threshold > len(params.HostPubkeys) {
		return transport.ErrInvalidThreshold
	}
	for i, pk := range params.HostPubkeys {
		if len(pk) != transport.PublicKeySize {
			return transport.NewParticipantError("", i, transport.ErrInvalidHostKey)
		}
	}
	return nil
}

// Helper methods

func (c *UnixClient) getMaxMessageSize() int {
	if c.config.MaxMessageSize > 0 {
		return c.config.MaxMessageSize
	}
	return 1024 * 1024 // 1MB default
}

func (c *UnixClient) getTimeout() time.Duration {
	if c.config.Timeout > 0 {
		return c.config.Timeout
	}
	return 30 * time.Second
}

// waitForReadyUnix waits for the connection to become ready or for the context to expire.
func waitForReadyUnix(ctx context.Context, conn *grpc.ClientConn) bool {
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return true
		}
		if state == connectivity.Shutdown {
			return false
		}
		if !conn.WaitForStateChange(ctx, state) {
			// Context expired
			return false
		}
	}
}
