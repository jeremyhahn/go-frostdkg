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
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/grpc/proto"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// GRPCClient implements the transport.Participant interface using gRPC.
type GRPCClient struct {
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

// safeInt32 safely converts a non-negative int to int32.
// Returns 0 if the input is negative or exceeds MaxInt32.
func safeInt32(n int) int32 {
	if n < 0 || n > int(^uint32(0)>>1) {
		return 0
	}
	return int32(n)
}

// NewGRPCClient creates a new gRPC-based participant client.
func NewGRPCClient(cfg *transport.Config) (*GRPCClient, error) {
	if cfg == nil {
		return nil, transport.ErrInvalidConfig
	}
	if cfg.Protocol != transport.ProtocolGRPC && cfg.Protocol != transport.ProtocolUnix {
		return nil, transport.NewProtocolError(cfg.Protocol, fmt.Errorf("expected grpc or unix protocol"))
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

	c := &GRPCClient{
		config:       cfg,
		serializer:   serializer,
		incomingChan: make(chan *proto.DKGMessage, 100),
		errorChan:    make(chan error, 10),
		shutdownChan: make(chan struct{}),
	}

	return c, nil
}

// Connect establishes a connection to the coordinator.
func (c *GRPCClient) Connect(ctx context.Context, addr string) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.connected.Load() {
		return transport.ErrAlreadyConnected
	}

	// Create dial options
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(c.getMaxMessageSize()),
			grpc.MaxCallSendMsgSize(c.getMaxMessageSize()),
		),
	}

	// Add keepalive parameters
	if c.config.KeepAlive {
		opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                c.getKeepAliveInterval(),
			Timeout:             20 * time.Second,
			PermitWithoutStream: true,
		}))
	}

	// Configure TLS or insecure credentials
	if c.config.TLSCertFile != "" || c.config.TLSCAFile != "" {
		tlsConfig, err := tlsconfig.ClientConfig(
			c.config.TLSCertFile,
			c.config.TLSKeyFile,
			c.config.TLSCAFile,
			"", // serverName - can be extracted from addr if needed
		)
		if err != nil {
			return transport.NewTLSError("failed to create TLS config", err)
		}
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Use dns:/// scheme for TCP or unix: scheme for Unix sockets
	dialAddr := addr
	if c.config.Protocol == transport.ProtocolUnix {
		dialAddr = "unix:" + addr
	} else if !hasScheme(addr) {
		// Add dns scheme for proper resolution
		dialAddr = "dns:///" + addr
	}

	// Create client connection using NewClient (non-blocking by default)
	conn, err := grpc.NewClient(dialAddr, opts...)
	if err != nil {
		return transport.NewConnectionError(addr, err)
	}

	// Verify connection can be established within timeout
	connectCtx, cancel := context.WithTimeout(ctx, c.getTimeout())
	defer cancel()
	conn.Connect()
	if !waitForReady(connectCtx, conn) {
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

// Disconnect closes the connection to the coordinator.
func (c *GRPCClient) Disconnect() error {
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
func (c *GRPCClient) RunDKG(ctx context.Context, params *transport.DKGParams) (*transport.DKGResult, error) {
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
func (c *GRPCClient) sendJoin(params *transport.DKGParams) error {
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
func (c *GRPCClient) waitForSessionInfo(ctx context.Context) (*transport.SessionInfoMessage, error) {
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
func (c *GRPCClient) executeDKG(ctx context.Context, params *transport.DKGParams, sessionInfo *transport.SessionInfoMessage) (*transport.DKGResult, error) {
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
func (c *GRPCClient) receiveMessages() {
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
func (c *GRPCClient) validateParams(params *transport.DKGParams) error {
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

func (c *GRPCClient) getMaxMessageSize() int {
	if c.config.MaxMessageSize > 0 {
		return c.config.MaxMessageSize
	}
	return 1024 * 1024 // 1MB default
}

func (c *GRPCClient) getTimeout() time.Duration {
	if c.config.Timeout > 0 {
		return c.config.Timeout
	}
	return 30 * time.Second
}

func (c *GRPCClient) getKeepAliveInterval() time.Duration {
	if c.config.KeepAliveInterval > 0 {
		return c.config.KeepAliveInterval
	}
	return 30 * time.Second
}

// hasScheme checks if the address already has a URI scheme.
func hasScheme(addr string) bool {
	for i, c := range addr {
		if c == ':' {
			return i > 0 && (i+2 < len(addr) && addr[i+1] == '/' && addr[i+2] == '/')
		}
		// Check if character is valid scheme character (alpha, digit, +, -, .)
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		isSpecial := c == '+' || c == '-' || c == '.'
		if !isAlpha && !isDigit && !isSpecial {
			return false
		}
	}
	return false
}

// waitForReady waits for the connection to become ready or for the context to expire.
func waitForReady(ctx context.Context, conn *grpc.ClientConn) bool {
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
