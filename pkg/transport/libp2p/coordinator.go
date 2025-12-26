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

// P2PCoordinator implements the Coordinator interface using libp2p.
type P2PCoordinator struct {
	host       *DKGHost
	sessionID  string
	config     *transport.SessionConfig
	serializer *transport.Serializer

	// Participant management
	participants     map[peer.ID]*participantConn
	participantsList []peer.ID
	participantsMu   sync.RWMutex

	// Message routing
	messageChan chan *incomingMessage
	errorChan   chan error

	// Lifecycle
	started  atomic.Bool
	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// Session state
	readyChan chan struct{}
	readyOnce sync.Once
}

type participantConn struct {
	peerID peer.ID
	stream network.Stream
	index  int
}

type incomingMessage struct {
	from     peer.ID
	envelope *transport.Envelope
}

// NewP2PCoordinator creates a new libp2p-based coordinator.
func NewP2PCoordinator(sessionID string, config *transport.SessionConfig, hostCfg *HostConfig) (*P2PCoordinator, error) {
	if sessionID == "" {
		return nil, transport.ErrInvalidConfig
	}

	if config == nil {
		return nil, transport.ErrInvalidConfig
	}

	// Validate session config
	if config.NumParticipants < 1 {
		return nil, transport.ErrInvalidParticipantCount
	}

	if config.Threshold < 1 || config.Threshold > config.NumParticipants {
		return nil, transport.ErrInvalidThreshold
	}

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

	return &P2PCoordinator{
		host:         host,
		sessionID:    sessionID,
		config:       config,
		serializer:   serializer,
		participants: make(map[peer.ID]*participantConn),
		messageChan:  make(chan *incomingMessage, 100),
		errorChan:    make(chan error, 10),
		stopChan:     make(chan struct{}),
		readyChan:    make(chan struct{}),
	}, nil
}

// NewP2PCoordinatorFromTransportConfig creates a coordinator from transport.Config.
// This provides compatibility with the standard transport configuration system.
func NewP2PCoordinatorFromTransportConfig(sessionID string, transportCfg *transport.Config, sessionCfg *transport.SessionConfig) (*P2PCoordinator, error) {
	if transportCfg == nil {
		return nil, transport.ErrInvalidConfig
	}

	// Convert transport.Config to HostConfig
	hostCfg := &HostConfig{
		ListenAddrs: []string{transportCfg.Address},
		EnableNoise: true,
		EnableTLS:   true,
		EnableRelay: false,
	}

	// Configure TLS if provided
	if transportCfg.HasTLS() {
		hostCfg.TLSCertFile = transportCfg.TLSCertFile
		hostCfg.TLSKeyFile = transportCfg.TLSKeyFile
		hostCfg.TLSCAFile = transportCfg.TLSCAFile
	}

	return NewP2PCoordinator(sessionID, sessionCfg, hostCfg)
}

// Start begins accepting participant connections.
func (pc *P2PCoordinator) Start(ctx context.Context) error {
	if pc.started.Swap(true) {
		return fmt.Errorf("coordinator already started")
	}

	// Set stream handler
	pc.host.host.SetStreamHandler(ProtocolID, pc.handleStream)

	// Start message processor
	pc.wg.Add(1)
	go pc.processMessages(ctx)

	return nil
}

// Stop gracefully shuts down the coordinator.
func (pc *P2PCoordinator) Stop(ctx context.Context) error {
	var stopErr error

	pc.stopOnce.Do(func() {
		if !pc.started.Load() {
			stopErr = fmt.Errorf("coordinator not started")
			return
		}

		// Signal shutdown
		close(pc.stopChan)

		// Close all participant streams
		pc.participantsMu.Lock()
		for _, conn := range pc.participants {
			if conn.stream != nil {
				_ = conn.stream.Close()
			}
		}
		pc.participantsMu.Unlock()

		// Wait for goroutines with timeout
		done := make(chan struct{})
		go func() {
			pc.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-ctx.Done():
			stopErr = ctx.Err()
		case <-time.After(5 * time.Second):
			stopErr = fmt.Errorf("coordinator shutdown timeout")
		}

		// Close host
		if err := pc.host.Close(); err != nil && stopErr == nil {
			stopErr = err
		}
	})

	return stopErr
}

// Address returns the network address the coordinator is listening on.
func (pc *P2PCoordinator) Address() string {
	addrs := pc.host.AddrStrings()
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

// SessionID returns the unique identifier for this DKG session.
func (pc *P2PCoordinator) SessionID() string {
	return pc.sessionID
}

// WaitForParticipants blocks until n participants have connected.
func (pc *P2PCoordinator) WaitForParticipants(ctx context.Context, n int) error {
	if n != pc.config.NumParticipants {
		return fmt.Errorf("expected %d participants, got %d", pc.config.NumParticipants, n)
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return transport.NewSessionError(pc.sessionID, ctx.Err())
		case <-pc.stopChan:
			return transport.ErrSessionClosed
		case <-ticker.C:
			pc.participantsMu.RLock()
			count := len(pc.participants)
			pc.participantsMu.RUnlock()

			if count >= n {
				// Signal ready
				pc.readyOnce.Do(func() {
					close(pc.readyChan)
				})
				return nil
			}
		}
	}
}

// handleStream handles incoming streams from participants.
func (pc *P2PCoordinator) handleStream(stream network.Stream) {
	peerID := stream.Conn().RemotePeer()

	// Check if we're still accepting participants
	pc.participantsMu.Lock()
	if len(pc.participants) >= pc.config.NumParticipants {
		pc.participantsMu.Unlock()
		_ = stream.Reset()
		return
	}

	// Check for duplicate participant
	if _, exists := pc.participants[peerID]; exists {
		pc.participantsMu.Unlock()
		_ = stream.Reset()
		return
	}

	// Add participant
	index := len(pc.participants)
	conn := &participantConn{
		peerID: peerID,
		stream: stream,
		index:  index,
	}
	pc.participants[peerID] = conn
	pc.participantsList = append(pc.participantsList, peerID)
	pc.participantsMu.Unlock()

	// Send session info
	if err := pc.sendSessionInfo(conn); err != nil {
		select {
		case pc.errorChan <- fmt.Errorf("failed to send session info to %s: %w", peerID, err):
		default:
		}
		return
	}

	// Start reading messages from this participant
	pc.wg.Add(1)
	go pc.readParticipantMessages(conn)
}

// sendSessionInfo sends session information to a participant.
func (pc *P2PCoordinator) sendSessionInfo(conn *participantConn) error {
	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       pc.sessionID,
		Threshold:       pc.config.Threshold,
		NumParticipants: pc.config.NumParticipants,
		ParticipantIdx:  conn.index,
		HostPubkeys:     [][]byte{}, // Will be populated with actual host keys
		Ciphersuite:     pc.config.Ciphersuite,
	}

	data, err := pc.serializer.MarshalEnvelope(pc.sessionID, transport.MsgTypeSessionInfo, -1, sessionInfo, time.Now().Unix())
	if err != nil {
		return err
	}

	return WriteMessage(conn.stream, data)
}

// readParticipantMessages reads messages from a participant stream.
func (pc *P2PCoordinator) readParticipantMessages(conn *participantConn) {
	defer pc.wg.Done()
	defer func() {
		// Remove participant on disconnect
		pc.participantsMu.Lock()
		delete(pc.participants, conn.peerID)
		pc.participantsMu.Unlock()
	}()

	for {
		select {
		case <-pc.stopChan:
			return
		default:
		}

		// Read message from stream
		data, err := ReadMessage(conn.stream)
		if err != nil {
			if err == io.EOF {
				return
			}
			select {
			case pc.errorChan <- fmt.Errorf("failed to read from %s: %w", conn.peerID, err):
			default:
			}
			return
		}

		// Deserialize envelope
		var envelope transport.Envelope
		if err := pc.serializer.UnmarshalEnvelope(data, &envelope); err != nil {
			select {
			case pc.errorChan <- fmt.Errorf("failed to unmarshal envelope from %s: %w", conn.peerID, err):
			default:
			}
			continue
		}

		// Queue message for processing
		select {
		case pc.messageChan <- &incomingMessage{from: conn.peerID, envelope: &envelope}:
		case <-pc.stopChan:
			return
		}
	}
}

// processMessages processes incoming messages and routes them.
func (pc *P2PCoordinator) processMessages(ctx context.Context) {
	defer pc.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pc.stopChan:
			return
		case msg := <-pc.messageChan:
			// Process and broadcast message
			if err := pc.broadcastMessage(msg.envelope); err != nil {
				select {
				case pc.errorChan <- err:
				default:
				}
			}
		case err := <-pc.errorChan:
			// Log error (in production, use proper logging)
			_ = err
		}
	}
}

// broadcastMessage broadcasts a message to all participants except the sender.
func (pc *P2PCoordinator) broadcastMessage(envelope *transport.Envelope) error {
	data, err := pc.serializer.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	pc.participantsMu.RLock()
	defer pc.participantsMu.RUnlock()

	for _, conn := range pc.participants {
		// Skip sender based on index
		if conn.index == envelope.SenderIdx {
			continue
		}

		if err := WriteMessage(conn.stream, data); err != nil {
			// Log error but continue with other participants
			select {
			case pc.errorChan <- fmt.Errorf("failed to send to %s: %w", conn.peerID, err):
			default:
			}
		}
	}

	return nil
}

// HasTLS returns true if the coordinator has TLS configured.
func (pc *P2PCoordinator) HasTLS() bool {
	return pc.host.HasTLS()
}

// TLSEnabled returns true if TLS is enabled for this coordinator.
// Note: libp2p always uses encryption (Noise or TLS 1.3), this returns
// true if additional certificate-based TLS is configured.
func (pc *P2PCoordinator) TLSEnabled() bool {
	return pc.host.HasTLS()
}
