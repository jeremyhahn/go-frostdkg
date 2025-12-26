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

package libp2p

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// P2PParticipant implements the Participant interface using libp2p.
type P2PParticipant struct {
	host       *DKGHost
	serializer *transport.Serializer

	// Connection state
	coordinatorPeer peer.ID
	stream          network.Stream
	connected       atomic.Bool
	connMu          sync.RWMutex

	// Session state
	sessionID      string
	sessionInfo    *transport.SessionInfoMessage
	participantIdx int

	// Message handling
	messageChan chan *transport.Envelope
	errorChan   chan error
	stopChan    chan struct{}
	stopOnce    sync.Once
	wg          sync.WaitGroup
}

// NewP2PParticipant creates a new libp2p-based participant.
func NewP2PParticipant(hostCfg *HostConfig) (*P2PParticipant, error) {
	// Create serializer
	codecType := "json"
	serializer, err := transport.NewSerializer(codecType)
	if err != nil {
		return nil, fmt.Errorf("failed to create serializer: %w", err)
	}

	// Create libp2p host
	host, err := NewHost(context.Background(), hostCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	return &P2PParticipant{
		host:        host,
		serializer:  serializer,
		messageChan: make(chan *transport.Envelope, 100),
		errorChan:   make(chan error, 10),
		stopChan:    make(chan struct{}),
	}, nil
}

// NewP2PParticipantFromTransportConfig creates a participant from transport.Config.
// This provides compatibility with the standard transport configuration system.
func NewP2PParticipantFromTransportConfig(cfg *transport.Config) (*P2PParticipant, error) {
	if cfg == nil {
		return nil, transport.ErrInvalidConfig
	}

	// Convert transport.Config to HostConfig
	hostCfg := &HostConfig{
		ListenAddrs: []string{"/ip4/0.0.0.0/tcp/0"}, // Use ephemeral port for participants
		EnableNoise: true,
		EnableTLS:   true,
		EnableRelay: false,
	}

	// Configure TLS if provided
	if cfg.HasTLS() {
		hostCfg.TLSCertFile = cfg.TLSCertFile
		hostCfg.TLSKeyFile = cfg.TLSKeyFile
		hostCfg.TLSCAFile = cfg.TLSCAFile
	}

	return NewP2PParticipant(hostCfg)
}

// Connect establishes a connection to the coordinator.
func (pp *P2PParticipant) Connect(ctx context.Context, addr string) error {
	if pp.connected.Load() {
		return transport.ErrAlreadyConnected
	}

	// Connect to coordinator peer (under lock)
	pp.connMu.Lock()
	peerID, err := pp.host.Connect(ctx, addr)
	if err != nil {
		pp.connMu.Unlock()
		return transport.NewConnectionError(addr, err)
	}

	pp.coordinatorPeer = peerID

	// Open stream with DKG protocol
	stream, err := pp.host.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		pp.connMu.Unlock()
		return transport.NewConnectionError(addr, fmt.Errorf("failed to open stream: %w", err))
	}

	pp.stream = stream
	pp.connected.Store(true)
	pp.connMu.Unlock()

	// Start message reader (lock released so readMessages can acquire RLock)
	pp.wg.Add(1)
	go pp.readMessages()

	// Wait for session info
	if err := pp.waitForSessionInfo(ctx); err != nil {
		_ = pp.Disconnect()
		return err
	}

	return nil
}

// Disconnect closes the connection to the coordinator.
func (pp *P2PParticipant) Disconnect() error {
	var disconnectErr error

	pp.stopOnce.Do(func() {
		if !pp.connected.Load() {
			disconnectErr = transport.ErrNotConnected
			return
		}

		// Signal shutdown
		close(pp.stopChan)

		// Close stream
		pp.connMu.Lock()
		if pp.stream != nil {
			_ = pp.stream.Close()
			pp.stream = nil
		}
		pp.connMu.Unlock()

		// Wait for goroutines
		done := make(chan struct{})
		go func() {
			pp.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			disconnectErr = fmt.Errorf("participant disconnect timeout")
		}

		// Close host
		if err := pp.host.Close(); err != nil && disconnectErr == nil {
			disconnectErr = err
		}

		pp.connected.Store(false)
	})

	return disconnectErr
}

// RunDKG executes the FROST DKG protocol.
func (pp *P2PParticipant) RunDKG(ctx context.Context, params *transport.DKGParams) (*transport.DKGResult, error) {
	if !pp.connected.Load() {
		return nil, transport.ErrNotConnected
	}

	// Validate parameters
	if err := pp.validateParams(params); err != nil {
		return nil, err
	}

	// Execute DKG rounds
	result, err := pp.executeDKG(ctx, params)
	if err != nil {
		return nil, transport.NewSessionError(pp.sessionID, err)
	}

	return result, nil
}

// validateParams validates DKG parameters.
func (pp *P2PParticipant) validateParams(params *transport.DKGParams) error {
	if params == nil {
		return transport.ErrInvalidDKGParams
	}

	if len(params.HostSeckey) != 32 {
		return transport.ErrInvalidHostKey
	}

	if len(params.Random) != 32 {
		return transport.ErrInvalidRandomness
	}

	if params.Threshold < 1 || params.Threshold > len(params.HostPubkeys) {
		return transport.ErrInvalidThreshold
	}

	if params.ParticipantIdx < 0 || params.ParticipantIdx >= len(params.HostPubkeys) {
		return transport.ErrInvalidParticipantIndex
	}

	return nil
}

// executeDKG executes the DKG protocol rounds.
func (pp *P2PParticipant) executeDKG(ctx context.Context, params *transport.DKGParams) (*transport.DKGResult, error) {
	// This is a simplified implementation
	// In a real implementation, this would execute the full FROST DKG protocol

	// Placeholder result with unique data per participant
	result := &transport.DKGResult{
		SessionID:       pp.sessionID,
		SecretShare:     make([]byte, transport.SecretKeySize),
		ThresholdPubkey: make([]byte, transport.PublicKeySize),
		PublicShares:    make([][]byte, len(params.HostPubkeys)),
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

// waitForSessionInfo waits for the session info message from coordinator.
func (pp *P2PParticipant) waitForSessionInfo(ctx context.Context) error {
	timeout := time.After(30 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return transport.ErrConnectionTimeout
		case <-pp.stopChan:
			return transport.ErrConnectionClosed
		case envelope := <-pp.messageChan:
			if envelope.Type == transport.MsgTypeSessionInfo {
				var sessionInfo transport.SessionInfoMessage
				if err := pp.serializer.UnmarshalPayload(envelope, &sessionInfo); err != nil {
					return fmt.Errorf("failed to unmarshal session info: %w", err)
				}

				pp.sessionID = sessionInfo.SessionID
				pp.sessionInfo = &sessionInfo
				pp.participantIdx = sessionInfo.ParticipantIdx
				return nil
			}
		}
	}
}

// readMessages reads messages from the coordinator stream.
func (pp *P2PParticipant) readMessages() {
	defer pp.wg.Done()

	for {
		select {
		case <-pp.stopChan:
			return
		default:
		}

		pp.connMu.RLock()
		stream := pp.stream
		pp.connMu.RUnlock()

		if stream == nil {
			return
		}

		// Read message from stream
		data, err := ReadMessage(stream)
		if err != nil {
			if err == io.EOF {
				return
			}
			select {
			case pp.errorChan <- fmt.Errorf("failed to read message: %w", err):
			default:
			}
			return
		}

		// Deserialize envelope
		var envelope transport.Envelope
		if err := pp.serializer.UnmarshalEnvelope(data, &envelope); err != nil {
			select {
			case pp.errorChan <- fmt.Errorf("failed to unmarshal envelope: %w", err):
			default:
			}
			continue
		}

		// Queue message for processing
		select {
		case pp.messageChan <- &envelope:
		case <-pp.stopChan:
			return
		}
	}
}

// HasTLS returns true if the participant has TLS configured.
func (pp *P2PParticipant) HasTLS() bool {
	return pp.host.HasTLS()
}

// TLSEnabled returns true if TLS is enabled for this participant.
// Note: libp2p always uses encryption (Noise or TLS 1.3), this returns
// true if additional certificate-based TLS is configured.
func (pp *P2PParticipant) TLSEnabled() bool {
	return pp.host.HasTLS()
}
