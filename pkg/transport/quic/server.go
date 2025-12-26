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

package quic

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// QUICServer implements the transport.Coordinator interface using QUIC.
//
// QUIC provides:
//   - UDP-based transport with built-in TLS 1.3
//   - Multiplexed streams over a single connection
//   - 0-RTT connection establishment (after initial handshake)
//   - Improved congestion control and loss recovery
//   - Connection migration support
//
// The server accepts multiple QUIC connections from participants and relays
// DKG protocol messages using bidirectional streams.
type QUICServer struct {
	config        *transport.Config
	sessionConfig *transport.SessionConfig
	sessionID     string
	listener      *quic.Listener
	serializer    *transport.Serializer

	// Session management
	participants     map[int]*participantConn
	participantsMu   sync.RWMutex
	participantCount atomic.Int32

	// Lifecycle management
	running      atomic.Bool
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

// participantConn represents a connection to a participant.
type participantConn struct {
	conn       *quic.Conn
	stream     *quic.Stream
	idx        int
	mu         sync.Mutex
	registered bool
}

// NewQUICServer creates a new QUIC-based coordinator server.
func NewQUICServer(cfg *transport.Config, sessionCfg *transport.SessionConfig) (*QUICServer, error) {
	if cfg == nil {
		return nil, transport.ErrInvalidConfig
	}
	if cfg.Protocol != transport.ProtocolQUIC {
		return nil, transport.NewProtocolError(cfg.Protocol, fmt.Errorf("expected quic protocol"))
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

	// QUIC requires TLS 1.3
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, transport.NewTLSError("QUIC requires TLS certificate and key", transport.ErrTLSRequired)
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

	// Generate session ID if not provided
	sessionID := sessionCfg.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("session-%d", time.Now().UnixNano())
	}

	s := &QUICServer{
		config:        cfg,
		sessionConfig: sessionCfg,
		sessionID:     sessionID,
		serializer:    serializer,
		participants:  make(map[int]*participantConn),
		shutdownChan:  make(chan struct{}),
	}

	return s, nil
}

// Start begins listening for participant connections.
func (s *QUICServer) Start(ctx context.Context) error {
	if s.running.Load() {
		return fmt.Errorf("server already running")
	}

	// Load TLS configuration (QUIC requires TLS 1.3)
	tlsConfig, err := tlsconfig.ServerConfig(
		s.config.TLSCertFile,
		s.config.TLSKeyFile,
		s.config.TLSCAFile,
	)
	if err != nil {
		return transport.NewTLSError("failed to create TLS config", err)
	}

	// Configure QUIC-specific TLS settings
	tlsConfig.NextProtos = []string{"frostdkg-quic"}

	// Create QUIC configuration
	maxMsgSize := s.getMaxMessageSize()
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 time.Duration(s.getTimeout()),
		MaxIncomingStreams:             1000,
		MaxIncomingUniStreams:          -1, // Disable unidirectional streams
		KeepAlivePeriod:                s.getKeepAliveInterval(),
		EnableDatagrams:                false,
		Allow0RTT:                      true, // Enable 0-RTT for faster reconnections
		MaxStreamReceiveWindow:         safeUint64(maxMsgSize),
		MaxConnectionReceiveWindow:     safeUint64(maxMsgSize * 10),
		DisablePathMTUDiscovery:        false,
		InitialStreamReceiveWindow:     safeUint64(maxMsgSize),
		InitialConnectionReceiveWindow: safeUint64(maxMsgSize * 10),
	}

	// Create UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", s.config.Address)
	if err != nil {
		return transport.NewConnectionError(s.config.Address, err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return transport.NewConnectionError(s.config.Address, err)
	}

	// Create QUIC listener
	listener, err := quic.Listen(udpConn, tlsConfig, quicConfig)
	if err != nil {
		_ = udpConn.Close()
		return transport.NewConnectionError(s.config.Address, err)
	}
	s.listener = listener

	// Start accepting connections
	s.running.Store(true)
	s.wg.Add(1)
	go s.acceptConnections()

	return nil
}

// Stop gracefully shuts down the coordinator.
func (s *QUICServer) Stop(ctx context.Context) error {
	if !s.running.Load() {
		return nil
	}

	s.running.Store(false)
	close(s.shutdownChan)

	// Close all participant connections
	s.participantsMu.Lock()
	for _, p := range s.participants {
		if p.stream != nil {
			_ = p.stream.Close()
		}
		if p.conn != nil {
			_ = p.conn.CloseWithError(0, "server shutdown")
		}
	}
	s.participantsMu.Unlock()

	// Close listener
	if s.listener != nil {
		_ = s.listener.Close()
	}

	// Wait for goroutines with context timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return transport.ErrSessionTimeout
	}
}

// Address returns the network address the coordinator is listening on.
func (s *QUICServer) Address() string {
	if s.listener == nil {
		return s.config.Address
	}
	return s.listener.Addr().String()
}

// SessionID returns the unique identifier for this DKG session.
func (s *QUICServer) SessionID() string {
	return s.sessionID
}

// WaitForParticipants blocks until n participants have connected.
func (s *QUICServer) WaitForParticipants(ctx context.Context, n int) error {
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

// acceptConnections accepts incoming QUIC connections.
func (s *QUICServer) acceptConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.shutdownChan:
			return
		default:
		}

		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			if s.running.Load() {
				// Only log if not shutting down
				continue
			}
			return
		}

		// Handle connection in separate goroutine
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single participant connection.
func (s *QUICServer) handleConnection(conn *quic.Conn) {
	defer s.wg.Done()

	// Accept the first bidirectional stream
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(1, "failed to accept stream")
		return
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
		_ = stream.Close()
		_ = conn.CloseWithError(0, "session complete")
	}()

	// Message handling loop
	for {
		select {
		case <-s.shutdownChan:
			return
		default:
		}

		// Read message from stream
		envelope, err := s.readMessage(stream)
		if err != nil {
			if err == io.EOF {
				return
			}
			// Send error and continue
			_ = s.sendError(stream, transport.ErrInvalidMessage)
			continue
		}

		// Handle join message to register participant
		if envelope.Type == transport.MsgTypeJoin && !registered {
			var joinMsg transport.JoinMessage
			if err := s.serializer.UnmarshalPayload(envelope, &joinMsg); err != nil {
				_ = s.sendError(stream, err)
				continue
			}

			participantIdx = envelope.SenderIdx

			// Register participant
			s.participantsMu.Lock()
			if _, exists := s.participants[participantIdx]; exists {
				s.participantsMu.Unlock()
				_ = s.sendError(stream, transport.ErrDuplicateParticipant)
				return
			}

			pConn := &participantConn{
				conn:       conn,
				stream:     stream,
				idx:        participantIdx,
				registered: true,
			}
			s.participants[participantIdx] = pConn
			s.participantsMu.Unlock()

			registered = true
			s.participantCount.Add(1)

			// Send session info back to participant
			if err := s.sendSessionInfo(stream); err != nil {
				return
			}

			continue
		}

		if !registered {
			_ = s.sendError(stream, transport.ErrUnexpectedMessage)
			return
		}

		// Relay message to other participants
		if err := s.relayMessage(envelope, participantIdx); err != nil {
			_ = s.sendError(stream, err)
			continue
		}
	}
}

// readMessage reads a message from the stream.
// Message format: [4 bytes length][message data]
func (s *QUICServer) readMessage(stream *quic.Stream) (*transport.Envelope, error) {
	// Read message length (4 bytes, big-endian)
	var lengthBuf [4]byte
	if _, err := io.ReadFull(stream, lengthBuf[:]); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lengthBuf[:])
	if length > safeUint32(s.getMaxMessageSize()) {
		return nil, transport.ErrMessageTooLarge
	}

	// Read message data
	data := make([]byte, length)
	if _, err := io.ReadFull(stream, data); err != nil {
		return nil, err
	}

	// Unmarshal envelope
	var envelope transport.Envelope
	if err := s.serializer.UnmarshalEnvelope(data, &envelope); err != nil {
		return nil, err
	}

	return &envelope, nil
}

// writeMessage writes a message to the stream.
func (s *QUICServer) writeMessage(stream *quic.Stream, envelope *transport.Envelope) error {
	// Marshal envelope
	data, err := s.serializer.Marshal(envelope)
	if err != nil {
		return err
	}

	if len(data) > s.getMaxMessageSize() {
		return transport.ErrMessageTooLarge
	}

	// Write message length (4 bytes, big-endian)
	// Length is bounded by MaxMessageSize check above, safe for uint32
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], safeUint32(len(data)))
	if _, err := stream.Write(lengthBuf[:]); err != nil {
		return err
	}

	// Write message data
	if _, err := stream.Write(data); err != nil {
		return err
	}

	return nil
}

// sendSessionInfo sends session information to a participant.
func (s *QUICServer) sendSessionInfo(stream *quic.Stream) error {
	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       s.sessionID,
		Threshold:       s.sessionConfig.Threshold,
		NumParticipants: s.sessionConfig.NumParticipants,
		Ciphersuite:     s.sessionConfig.Ciphersuite,
	}

	payload, err := s.serializer.Marshal(sessionInfo)
	if err != nil {
		return err
	}

	envelope := &transport.Envelope{
		SessionID: s.sessionID,
		Type:      transport.MsgTypeSessionInfo,
		SenderIdx: -1, // Coordinator
		Payload:   payload,
		Timestamp: time.Now().UnixMilli(),
	}

	return s.writeMessage(stream, envelope)
}

// sendError sends an error message to a participant.
func (s *QUICServer) sendError(stream *quic.Stream, err error) error {
	errorMsg := &transport.ErrorMessage{
		Code:    1,
		Message: err.Error(),
	}

	payload, marshalErr := s.serializer.Marshal(errorMsg)
	if marshalErr != nil {
		return marshalErr
	}

	envelope := &transport.Envelope{
		SessionID: s.sessionID,
		Type:      transport.MsgTypeError,
		SenderIdx: -1,
		Payload:   payload,
		Timestamp: time.Now().UnixMilli(),
	}

	return s.writeMessage(stream, envelope)
}

// relayMessage relays a message to all other participants.
func (s *QUICServer) relayMessage(envelope *transport.Envelope, senderIdx int) error {
	s.participantsMu.RLock()
	defer s.participantsMu.RUnlock()

	// Determine target participants based on message type
	var errs []error

	switch envelope.Type {
	case transport.MsgTypeRound1,
		transport.MsgTypeRound1Agg,
		transport.MsgTypeRound2Agg,
		transport.MsgTypeCertificate,
		transport.MsgTypeComplete:
		// Broadcast to all participants except sender
		for idx, p := range s.participants {
			if idx == senderIdx {
				continue
			}
			p.mu.Lock()
			err := s.writeMessage(p.stream, envelope)
			p.mu.Unlock()
			if err != nil {
				errs = append(errs, transport.NewParticipantError("", idx, err))
			}
		}

	case transport.MsgTypeRound2:
		// Point-to-point messages - relay to all (encrypted for specific recipient)
		for idx, p := range s.participants {
			if idx == senderIdx {
				continue
			}
			p.mu.Lock()
			err := s.writeMessage(p.stream, envelope)
			p.mu.Unlock()
			if err != nil {
				errs = append(errs, transport.NewParticipantError("", idx, err))
			}
		}

	default:
		// Other messages, relay to all
		for idx, p := range s.participants {
			if idx == senderIdx {
				continue
			}
			p.mu.Lock()
			err := s.writeMessage(p.stream, envelope)
			p.mu.Unlock()
			if err != nil {
				errs = append(errs, transport.NewParticipantError("", idx, err))
			}
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Helper methods

func (s *QUICServer) getMaxMessageSize() int {
	if s.config.MaxMessageSize > 0 {
		return s.config.MaxMessageSize
	}
	return 1024 * 1024 // 1MB default
}

func (s *QUICServer) getTimeout() int64 {
	if s.config.Timeout > 0 {
		return int64(s.config.Timeout)
	}
	return int64(30 * time.Second)
}

func (s *QUICServer) getKeepAliveInterval() time.Duration {
	if s.config.KeepAliveInterval > 0 {
		return s.config.KeepAliveInterval
	}
	return 30 * time.Second
}
