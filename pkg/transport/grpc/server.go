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
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/grpc/proto"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// GRPCServer implements the transport.Coordinator interface using gRPC.
type GRPCServer struct {
	proto.UnimplementedDKGCoordinatorServer

	config        *transport.Config
	sessionConfig *transport.SessionConfig
	sessionID     string
	listener      net.Listener
	server        *grpc.Server
	serializer    *transport.Serializer
	logger        transport.Logger

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

// NewGRPCServer creates a new gRPC-based coordinator server.
func NewGRPCServer(cfg *transport.Config, sessionCfg *transport.SessionConfig) (*GRPCServer, error) {
	if cfg == nil {
		return nil, transport.ErrInvalidConfig
	}
	if cfg.Protocol != transport.ProtocolGRPC && cfg.Protocol != transport.ProtocolUnix {
		return nil, transport.NewProtocolError(cfg.Protocol, fmt.Errorf("expected grpc or unix protocol"))
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

	// Set up logger
	logger := cfg.Logger
	if logger == nil {
		logger = transport.NopLogger{}
	}

	s := &GRPCServer{
		config:           cfg,
		sessionConfig:    sessionCfg,
		sessionID:        sessionID,
		serializer:       serializer,
		logger:           logger,
		participants:     make(map[int]proto.DKGCoordinator_ParticipantStreamServer),
		participantReady: make(chan struct{}),
		shutdownChan:     make(chan struct{}),
	}

	return s, nil
}

// Start begins listening for participant connections.
func (s *GRPCServer) Start(ctx context.Context) error {
	if s.running.Load() {
		return fmt.Errorf("server already running")
	}

	// Create listener - use unix socket for ProtocolUnix, tcp otherwise
	network := "tcp"
	if s.config.Protocol == transport.ProtocolUnix {
		network = "unix"
	}
	listener, err := net.Listen(network, s.config.Address)
	if err != nil {
		return transport.NewConnectionError(s.config.Address, err)
	}
	s.listener = listener

	// Create gRPC server options
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(s.getMaxMessageSize()),
		grpc.MaxSendMsgSize(s.getMaxMessageSize()),
	}

	// Add keepalive parameters
	if s.config.KeepAlive {
		opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    s.getKeepAliveInterval(),
			Timeout: 20 * time.Second,
		}))
		opts = append(opts, grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}))
	}

	// Configure TLS 1.3 for TCP connections
	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		tlsConfig, err := tlsconfig.ServerConfig(
			s.config.TLSCertFile,
			s.config.TLSKeyFile,
			s.config.TLSCAFile,
		)
		if err != nil {
			if closeErr := listener.Close(); closeErr != nil {
				// Log close error but return the original TLS error
				_ = closeErr
			}
			return transport.NewTLSError("failed to create TLS config", err)
		}
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.Creds(creds))
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

// Stop gracefully shuts down the coordinator.
func (s *GRPCServer) Stop(ctx context.Context) error {
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
	return nil
}

// Address returns the network address the coordinator is listening on.
func (s *GRPCServer) Address() string {
	if s.listener == nil {
		return s.config.Address
	}
	return s.listener.Addr().String()
}

// SessionID returns the unique identifier for this DKG session.
func (s *GRPCServer) SessionID() string {
	return s.sessionID
}

// WaitForParticipants blocks until n participants have connected.
func (s *GRPCServer) WaitForParticipants(ctx context.Context, n int) error {
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
func (s *GRPCServer) ParticipantStream(stream proto.DKGCoordinator_ParticipantStreamServer) error {
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
			newCount := s.participantCount.Add(-1)
			s.logger.Info("Participant %d disconnected (active: %d/%d)", participantIdx, newCount, s.sessionConfig.NumParticipants)
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
			newCount := s.participantCount.Add(1)
			s.logger.Info("Participant %d joined (active: %d/%d)", participantIdx, newCount, s.sessionConfig.NumParticipants)

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
		s.logger.Debug("Relaying %s from participant %d", msg.Type.String(), participantIdx)
		if err := s.relayMessage(msg, participantIdx); err != nil {
			s.logger.Error("Failed to relay message from participant %d: %v", participantIdx, err)
			return err
		}
	}
}

// relayMessage relays a message to all other participants.
func (s *GRPCServer) relayMessage(msg *proto.DKGMessage, senderIdx int) error {
	s.participantsMu.RLock()
	defer s.participantsMu.RUnlock()

	// Determine target participants based on message type
	switch msg.Type {
	case proto.MessageType_MSG_TYPE_ROUND1,
		proto.MessageType_MSG_TYPE_ROUND1_AGG,
		proto.MessageType_MSG_TYPE_ROUND2_AGG,
		proto.MessageType_MSG_TYPE_CERTIFICATE,
		proto.MessageType_MSG_TYPE_COMPLETE:
		// Broadcast to all participants
		for idx, stream := range s.participants {
			if idx == senderIdx {
				continue // Don't send back to sender
			}
			if err := stream.Send(msg); err != nil {
				return transport.NewParticipantError("", idx, err)
			}
		}

	case proto.MessageType_MSG_TYPE_ROUND2:
		// Point-to-point messages - relay to all (encrypted for specific recipient)
		for idx, stream := range s.participants {
			if idx == senderIdx {
				continue
			}
			if err := stream.Send(msg); err != nil {
				return transport.NewParticipantError("", idx, err)
			}
		}

	default:
		// Other messages, relay to all
		for idx, stream := range s.participants {
			if idx == senderIdx {
				continue
			}
			if err := stream.Send(msg); err != nil {
				return transport.NewParticipantError("", idx, err)
			}
		}
	}

	return nil
}

// Helper methods

func (s *GRPCServer) getMaxMessageSize() int {
	if s.config.MaxMessageSize > 0 {
		return s.config.MaxMessageSize
	}
	return 1024 * 1024 // 1MB default
}

func (s *GRPCServer) getKeepAliveInterval() time.Duration {
	if s.config.KeepAliveInterval > 0 {
		return s.config.KeepAliveInterval
	}
	return 30 * time.Second
}
