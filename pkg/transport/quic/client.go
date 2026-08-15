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
	"crypto/tls"
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

// QUICClient implements the transport.Participant interface using QUIC.
//
// The client establishes a QUIC connection to the coordinator and uses
// a bidirectional stream for sending and receiving DKG protocol messages.
//
// Features:
//   - 0-RTT connection establishment (after initial handshake)
//   - Automatic connection migration on network changes
//   - Built-in congestion control
//   - Stream multiplexing (future: multiple concurrent DKG sessions)
type QUICClient struct {
	config     *transport.Config
	serializer *transport.Serializer

	// Connection state
	conn      *quic.Conn
	stream    *quic.Stream
	connected atomic.Bool
	connMu    sync.RWMutex

	// Message handling
	incomingChan chan *transport.Envelope
	errorChan    chan error
	shutdownChan chan struct{}
	wg           sync.WaitGroup

	// Session info
	sessionID      string
	participantIdx int
}

// NewQUICClient creates a new QUIC-based participant client.
func NewQUICClient(cfg *transport.Config) (*QUICClient, error) {
	if cfg == nil {
		return nil, transport.ErrInvalidConfig
	}
	if cfg.Protocol != transport.ProtocolQUIC {
		return nil, transport.NewProtocolError(cfg.Protocol, fmt.Errorf("expected quic protocol"))
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

	c := &QUICClient{
		config:       cfg,
		serializer:   serializer,
		incomingChan: make(chan *transport.Envelope, 100),
		errorChan:    make(chan error, 10),
		shutdownChan: make(chan struct{}),
	}

	return c, nil
}

// Connect establishes a QUIC connection to the coordinator.
func (c *QUICClient) Connect(ctx context.Context, addr string) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.connected.Load() {
		return transport.ErrAlreadyConnected
	}

	// Create TLS configuration
	var tlsConfig *tls.Config
	var err error

	if c.config.TLSCertFile != "" || c.config.TLSCAFile != "" {
		// Extract server name from address
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		tlsConfig, err = tlsconfig.ClientConfig(
			c.config.TLSCertFile,
			c.config.TLSKeyFile,
			c.config.TLSCAFile,
			host,
		)
		if err != nil {
			return transport.NewTLSError("failed to create TLS config", err)
		}
	} else {
		return transport.NewTLSError("QUIC requires TLS configuration - set TLSCertFile or TLSCAFile (use InsecureClientConfig explicitly for testing)", transport.ErrTLSRequired)
	}

	// Configure QUIC-specific TLS settings
	tlsConfig.NextProtos = []string{"frostdkg-quic"}

	// Create QUIC configuration
	maxMsgSize := c.getMaxMessageSize()
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 c.getTimeout(),
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          -1, // Disable unidirectional streams
		KeepAlivePeriod:                c.getKeepAliveInterval(),
		EnableDatagrams:                false,
		Allow0RTT:                      false, // Disabled: 0-RTT is vulnerable to replay attacks
		MaxStreamReceiveWindow:         safeUint64(maxMsgSize),
		MaxConnectionReceiveWindow:     safeUint64(maxMsgSize * 10),
		DisablePathMTUDiscovery:        false,
		InitialStreamReceiveWindow:     safeUint64(maxMsgSize),
		InitialConnectionReceiveWindow: safeUint64(maxMsgSize * 10),
	}

	// Establish QUIC connection
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return transport.NewConnectionError(addr, err)
	}

	// Open bidirectional stream for DKG messages
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "failed to open stream")
		return transport.NewConnectionError(addr, err)
	}

	c.conn = conn
	c.stream = stream
	c.connected.Store(true)

	// Start message receiver
	c.wg.Add(1)
	go c.receiveMessages()

	return nil
}

// Disconnect closes the connection to the coordinator.
func (c *QUICClient) Disconnect() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if !c.connected.Load() {
		return transport.ErrNotConnected
	}

	// Signal shutdown
	close(c.shutdownChan)
	c.connected.Store(false)

	// Close stream
	if c.stream != nil {
		_ = c.stream.Close()
		c.stream = nil
	}

	// Wait for goroutines
	c.wg.Wait()

	// Close connection
	if c.conn != nil {
		err := c.conn.CloseWithError(0, "client disconnect")
		c.conn = nil
		if err != nil {
			return err
		}
	}

	return nil
}

// RunDKG executes the FROST DKG protocol.
//
// EXPERIMENTAL: this transport does not run the DKG ceremony. The connection,
// join and session-info exchange happen as written, then this returns
// transport.ErrDKGNotImplemented rather than key material. See package
// transport and software task #61.
func (c *QUICClient) RunDKG(ctx context.Context, params *transport.DKGParams) (*transport.DKGResult, error) {
	if !c.connected.Load() {
		return nil, transport.ErrNotConnected
	}

	// Validate parameters
	if err := c.validateParams(params); err != nil {
		return nil, err
	}

	c.participantIdx = params.ParticipantIdx

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
func (c *QUICClient) sendJoin(params *transport.DKGParams) error {
	joinMsg := &transport.JoinMessage{
		HostPubkey: params.HostPubkeys[params.ParticipantIdx],
	}

	payload, err := c.serializer.Marshal(joinMsg)
	if err != nil {
		return err
	}

	envelope := &transport.Envelope{
		SessionID: "",
		Type:      transport.MsgTypeJoin,
		SenderIdx: params.ParticipantIdx,
		Payload:   payload,
		Timestamp: time.Now().UnixMilli(),
	}

	return c.writeMessage(envelope)
}

// waitForSessionInfo waits for session info from coordinator.
func (c *QUICClient) waitForSessionInfo(ctx context.Context) (*transport.SessionInfoMessage, error) {
	timeout := time.NewTimer(c.getTimeout())
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return nil, transport.ErrSessionTimeout
	case <-timeout.C:
		return nil, transport.ErrSessionTimeout
	case err := <-c.errorChan:
		return nil, err
	case envelope := <-c.incomingChan:
		if envelope.Type != transport.MsgTypeSessionInfo {
			return nil, transport.ErrUnexpectedMessage
		}

		var sessionInfo transport.SessionInfoMessage
		if err := c.serializer.UnmarshalPayload(envelope, &sessionInfo); err != nil {
			return nil, err
		}

		return &sessionInfo, nil
	}
}

// executeDKG would run the DKG protocol rounds. It does not: this transport
// carries the protocol messages but never drives the ceremony, so it has no
// key material to return.
//
// It previously built a DKGResult from a fixed pattern derived from the
// participant index and returned it with a nil error, which no caller could
// tell apart from a real ceremony. Failing closed is the only safe behaviour
// until the transport is wired to the real pkg/dkg driver (tracked as
// software task #61).
func (c *QUICClient) executeDKG(ctx context.Context, params *transport.DKGParams, sessionInfo *transport.SessionInfoMessage) (*transport.DKGResult, error) {
	return nil, transport.ErrDKGNotImplemented
}

// receiveMessages handles incoming messages from the stream.
func (c *QUICClient) receiveMessages() {
	defer c.wg.Done()

	for {
		select {
		case <-c.shutdownChan:
			return
		default:
		}

		envelope, err := c.readMessage()
		if err != nil {
			if err == io.EOF {
				return
			}
			select {
			case c.errorChan <- err:
			case <-c.shutdownChan:
			}
			return
		}

		select {
		case c.incomingChan <- envelope:
		case <-c.shutdownChan:
			return
		}
	}
}

// readMessage reads a message from the stream.
// Message format: [4 bytes length][message data]
func (c *QUICClient) readMessage() (*transport.Envelope, error) {
	// Get stream reference under read lock
	c.connMu.RLock()
	stream := c.stream
	c.connMu.RUnlock()

	if stream == nil {
		return nil, io.EOF
	}

	// Read message length (4 bytes, big-endian)
	var lengthBuf [4]byte
	if _, err := io.ReadFull(stream, lengthBuf[:]); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lengthBuf[:])
	if length > safeUint32(c.getMaxMessageSize()) {
		return nil, transport.ErrMessageTooLarge
	}

	// Read message data
	data := make([]byte, length)
	if _, err := io.ReadFull(stream, data); err != nil {
		return nil, err
	}

	// Unmarshal envelope
	var envelope transport.Envelope
	if err := c.serializer.UnmarshalEnvelope(data, &envelope); err != nil {
		return nil, err
	}

	return &envelope, nil
}

// writeMessage writes a message to the stream.
func (c *QUICClient) writeMessage(envelope *transport.Envelope) error {
	// Marshal envelope
	data, err := c.serializer.Marshal(envelope)
	if err != nil {
		return err
	}

	if len(data) > c.getMaxMessageSize() {
		return transport.ErrMessageTooLarge
	}

	// Get stream reference under read lock
	c.connMu.RLock()
	stream := c.stream
	c.connMu.RUnlock()

	if stream == nil {
		return transport.ErrNotConnected
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

// validateParams validates DKG parameters.
func (c *QUICClient) validateParams(params *transport.DKGParams) error {
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

func (c *QUICClient) getMaxMessageSize() int {
	if c.config.MaxMessageSize > 0 {
		return c.config.MaxMessageSize
	}
	return 1024 * 1024 // 1MB default
}

// safeUint64 safely converts a non-negative int to uint64.
// Returns 0 if the input is negative (should not happen with validated config).
func safeUint64(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// safeUint32 safely converts a non-negative int to uint32.
// Returns 0 if the input is negative or exceeds MaxUint32.
func safeUint32(n int) uint32 {
	if n < 0 || n > int(^uint32(0)) {
		return 0
	}
	return uint32(n)
}

func (c *QUICClient) getTimeout() time.Duration {
	if c.config.Timeout > 0 {
		return c.config.Timeout
	}
	return 30 * time.Second
}

func (c *QUICClient) getKeepAliveInterval() time.Duration {
	if c.config.KeepAliveInterval > 0 {
		return c.config.KeepAliveInterval
	}
	return 30 * time.Second
}
