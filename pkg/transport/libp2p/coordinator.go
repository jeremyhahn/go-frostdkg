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

	// Participant management. participants holds the LIVE connections and
	// shrinks on disconnect; assignedIndexes is the session-long binding of a
	// peer identity to its participant index and never does.
	participants     map[peer.ID]*participantConn
	assignedIndexes  map[peer.ID]int
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

// incomingMessage carries a message together with the connection it was
// authenticated on. The binding travels WITH the message rather than being
// looked up again at fan-out time: the reader goroutine removes its
// participant from the live map as soon as the stream ends, so a sender that
// disconnects right after its last message — or simply loses its connection —
// would otherwise have that already-authenticated message dropped.
type incomingMessage struct {
	conn     *participantConn
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
		host:            host,
		sessionID:       sessionID,
		config:          config,
		serializer:      serializer,
		participants:    make(map[peer.ID]*participantConn),
		assignedIndexes: make(map[peer.ID]int),

		messageChan: make(chan *incomingMessage, 100),
		errorChan:   make(chan error, 10),
		stopChan:    make(chan struct{}),
		readyChan:   make(chan struct{}),
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
		// NewP2PCoordinator binds the listen address, so a coordinator that
		// was constructed but never started still holds the socket. Release
		// it here rather than leaking it for the lifetime of the process; the
		// not-started error is still reported to the caller.
		if !pc.started.Load() {
			stopErr = fmt.Errorf("coordinator not started")
			if err := pc.host.Close(); err != nil {
				stopErr = fmt.Errorf("coordinator not started (host close: %w)", err)
			}
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

	pc.participantsMu.Lock()

	// Reject a second live connection from a peer that already has one.
	if _, exists := pc.participants[peerID]; exists {
		pc.participantsMu.Unlock()
		_ = stream.Reset()
		return
	}

	index, err := pc.assignIndexLocked(peerID)
	if err != nil {
		pc.participantsMu.Unlock()
		_ = stream.Reset()
		return
	}

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

// assignIndexLocked returns the participant index bound to a peer identity for
// the whole session, assigning a fresh one the first time that identity is
// seen. Callers hold participantsMu.
//
// The index MUST NOT be derived from how many peers happen to be connected. It
// used to be len(pc.participants), and disconnects punch holes in that count:
// with 0, 1 and 2 joined, participant 1 leaving and a new peer arriving hands
// the newcomer index 2 while the original participant 2 still holds it. Both
// then pass authorizeSender for index 2, which is the impersonation the
// binding exists to prevent, and the fan-out skips both of them.
//
// So the binding is permanent for the session: a peer that reconnects gets its
// own index back, an index a peer has left is never handed to another, and a
// peer arriving after all NumParticipants indices are spoken for is refused
// rather than seated on top of someone.
func (pc *P2PCoordinator) assignIndexLocked(peerID peer.ID) (int, error) {
	if index, ok := pc.assignedIndexes[peerID]; ok {
		return index, nil
	}
	if len(pc.assignedIndexes) >= pc.config.NumParticipants {
		return 0, transport.ErrSessionFull
	}
	index := len(pc.assignedIndexes)
	pc.assignedIndexes[peerID] = index
	return index, nil
}

// authorizeSender binds a message's declared sender index to the authenticated
// peer it arrived from.
//
// libp2p authenticates every connection: conn.peerID is the remote peer's
// cryptographic identity, and handleStream assigns conn.index to that identity
// when it joins. Nothing else establishes who sent a message. A coordinator
// that relays envelope.SenderIdx unchecked therefore lets participant 2 send
// a Round 1 commitment, a Round 2 share, or a CertEq signature that every
// other participant attributes to participant 0 — and, because the
// skip-the-sender branch also keys off the claimed index, delivers the forgery
// to the participant being impersonated while sparing the forger.
func authorizeSender(conn *participantConn, envelope *transport.Envelope) error {
	if envelope.SenderIdx != conn.index {
		return transport.NewSenderIdentityError(conn.peerID.String(), conn.index, envelope.SenderIdx)
	}
	return nil
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

		// The sender index is attacker-controlled until it is checked against
		// the peer that sent it. Drop the message here, before it can be
		// queued or relayed.
		if err := authorizeSender(conn, &envelope); err != nil {
			select {
			case pc.errorChan <- err:
			default:
			}
			continue
		}

		// Queue message for processing
		select {
		case pc.messageChan <- &incomingMessage{conn: conn, envelope: &envelope}:
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
			if err := pc.broadcastMessage(msg); err != nil {
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
//
// The relay is where a forged sender index would do its damage, so the binding
// is enforced here as well as at ingress. It is checked against the connection
// the message was authenticated on, which the message carries, rather than
// against a fresh lookup in the live participant map: the map is the right
// answer for "who should receive this" and the wrong one for "who sent this",
// because a sender may already have disconnected by the time its last message
// is fanned out.
func (pc *P2PCoordinator) broadcastMessage(msg *incomingMessage) error {
	if msg == nil || msg.conn == nil {
		return transport.NewSenderIdentityError("", -1, -1)
	}
	if err := authorizeSender(msg.conn, msg.envelope); err != nil {
		return err
	}

	data, err := pc.serializer.Marshal(msg.envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	pc.participantsMu.RLock()
	defer pc.participantsMu.RUnlock()

	for _, conn := range pc.participants {
		// Skip the sender, identified by the index bound to its authenticated
		// peer rather than the one the message declares.
		if conn.index == msg.conn.index {
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
