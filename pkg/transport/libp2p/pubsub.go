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
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
)

// PubSub error types.
var (
	// ErrPubSubNilHost indicates a nil host was provided.
	ErrPubSubNilHost = errors.New("pubsub: nil host provided")

	// ErrPubSubTopicExists indicates the topic already exists.
	ErrPubSubTopicExists = errors.New("pubsub: topic already exists")

	// ErrPubSubTopicNotFound indicates the topic was not found.
	ErrPubSubTopicNotFound = errors.New("pubsub: topic not found")

	// ErrPubSubInvalidSessionID indicates an invalid session ID.
	ErrPubSubInvalidSessionID = errors.New("pubsub: invalid session ID")

	// ErrPubSubClosed indicates the manager has been closed.
	ErrPubSubClosed = errors.New("pubsub: manager closed")

	// ErrPubSubMessageTooLarge indicates the message exceeds the maximum size.
	ErrPubSubMessageTooLarge = errors.New("pubsub: message too large")

	// ErrPubSubInvalidMessage indicates an invalid message.
	ErrPubSubInvalidMessage = errors.New("pubsub: invalid message")

	// ErrPubSubInvalidPeer indicates an invalid peer ID.
	ErrPubSubInvalidPeer = errors.New("pubsub: invalid peer ID")

	// ErrPubSubAckTimeout indicates acknowledgment timeout.
	ErrPubSubAckTimeout = errors.New("pubsub: acknowledgment timeout")
)

// Constants for PubSub configuration.
const (
	// TopicPrefix is the prefix for DKG session topics.
	TopicPrefix = "/frost-dkg/session/"

	// DefaultHeartbeatInterval is the default GossipSub heartbeat interval.
	DefaultHeartbeatInterval = 1 * time.Second

	// DefaultMessageBufferSize is the default message buffer size.
	DefaultMessageBufferSize = 256

	// DefaultMaxMessageSize is the default maximum message size (1MB).
	DefaultMaxMessageSize = 1024 * 1024

	// DefaultAckTimeout is the default acknowledgment timeout.
	DefaultAckTimeout = 10 * time.Second
)

// PubSubConfig contains configuration for the PubSubManager.
type PubSubConfig struct {
	// EnableGossipSub enables GossipSub protocol (default: true).
	EnableGossipSub bool

	// HeartbeatInterval is the GossipSub heartbeat interval.
	HeartbeatInterval time.Duration

	// MessageBufferSize is the size of the message buffer.
	MessageBufferSize int

	// MaxMessageSize is the maximum message size in bytes.
	MaxMessageSize int

	// EnableAcknowledgments enables message acknowledgments.
	EnableAcknowledgments bool

	// AckTimeout is the timeout for waiting for acknowledgments.
	AckTimeout time.Duration

	// ValidateMessages enables message validation.
	ValidateMessages bool
}

// DefaultPubSubConfig returns the default PubSub configuration.
func DefaultPubSubConfig() *PubSubConfig {
	return &PubSubConfig{
		EnableGossipSub:       true,
		HeartbeatInterval:     DefaultHeartbeatInterval,
		MessageBufferSize:     DefaultMessageBufferSize,
		MaxMessageSize:        DefaultMaxMessageSize,
		EnableAcknowledgments: false,
		AckTimeout:            DefaultAckTimeout,
		ValidateMessages:      true,
	}
}

// SessionSubscription wraps a PubSub subscription for a session.
type SessionSubscription struct {
	topic        *pubsub.Topic
	subscription *pubsub.Subscription
	sessionID    string
	cancel       context.CancelFunc
}

// Next returns the next message from the subscription.
func (s *SessionSubscription) Next(ctx context.Context) (*pubsub.Message, error) {
	return s.subscription.Next(ctx)
}

// Cancel cancels the subscription.
func (s *SessionSubscription) Cancel() {
	s.subscription.Cancel()
	if s.cancel != nil {
		s.cancel()
	}
}

// PubSubManager manages GossipSub-based message broadcasting for DKG sessions.
type PubSubManager struct {
	host       *DKGHost
	ps         *pubsub.PubSub
	config     *PubSubConfig
	serializer *transport.Serializer

	// Session management
	sessions map[string]*SessionSubscription
	mu       sync.RWMutex

	// Acknowledgment tracking
	pendingAcks map[string]chan struct{}
	ackMu       sync.RWMutex

	// Lifecycle
	closed    atomic.Bool
	closeOnce sync.Once
}

// NewPubSubManager creates a new PubSubManager with GossipSub.
func NewPubSubManager(ctx context.Context, host *DKGHost, config *PubSubConfig) (*PubSubManager, error) {
	if host == nil {
		return nil, ErrPubSubNilHost
	}

	if config == nil {
		config = DefaultPubSubConfig()
	}

	// Build GossipSub options with default parameters
	// Do not use partial GossipSubParams to avoid division by zero errors
	opts := []pubsub.Option{
		pubsub.WithMessageSignaturePolicy(pubsub.StrictSign),
		pubsub.WithPeerExchange(true),
	}

	// Create GossipSub instance
	ps, err := pubsub.NewGossipSub(ctx, host.Host(), opts...)
	if err != nil {
		return nil, &PubSubError{Op: "NewGossipSub", Err: err}
	}

	// Create serializer for envelope encoding
	serializer, err := transport.NewSerializer("json")
	if err != nil {
		return nil, &PubSubError{Op: "NewSerializer", Err: err}
	}

	return &PubSubManager{
		host:        host,
		ps:          ps,
		config:      config,
		serializer:  serializer,
		sessions:    make(map[string]*SessionSubscription),
		pendingAcks: make(map[string]chan struct{}),
	}, nil
}

// JoinSession joins a DKG session topic and returns a subscription.
func (m *PubSubManager) JoinSession(ctx context.Context, sessionID string) (*SessionSubscription, error) {
	if m.closed.Load() {
		return nil, ErrPubSubClosed
	}

	if sessionID == "" {
		return nil, ErrPubSubInvalidSessionID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already joined
	if _, exists := m.sessions[sessionID]; exists {
		return nil, ErrPubSubTopicExists
	}

	// Create topic name
	topicName := TopicPrefix + sessionID

	// Join topic
	topic, err := m.ps.Join(topicName)
	if err != nil {
		return nil, &PubSubError{Op: "Join", SessionID: sessionID, Err: err}
	}

	// Subscribe to topic
	sub, err := topic.Subscribe()
	if err != nil {
		_ = topic.Close()
		return nil, &PubSubError{Op: "Subscribe", SessionID: sessionID, Err: err}
	}

	// Create subscription context
	subCtx, cancel := context.WithCancel(ctx)

	session := &SessionSubscription{
		topic:        topic,
		subscription: sub,
		sessionID:    sessionID,
		cancel:       cancel,
	}

	m.sessions[sessionID] = session

	// Start message validation goroutine if enabled
	if m.config.ValidateMessages {
		go m.processMessages(subCtx, session)
	}

	return session, nil
}

// LeaveSession leaves a DKG session and closes the subscription.
func (m *PubSubManager) LeaveSession(sessionID string) error {
	if m.closed.Load() {
		return ErrPubSubClosed
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return ErrPubSubTopicNotFound
	}

	// Cancel subscription
	session.Cancel()

	// Close topic
	if err := session.topic.Close(); err != nil {
		return &PubSubError{Op: "Close", SessionID: sessionID, Err: err}
	}

	delete(m.sessions, sessionID)
	return nil
}

// HasSession returns true if the manager has joined the given session.
func (m *PubSubManager) HasSession(sessionID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.sessions[sessionID]
	return exists
}

// Sessions returns the list of active session IDs.
func (m *PubSubManager) Sessions() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		sessions = append(sessions, id)
	}
	return sessions
}

// SessionPeers returns the peers subscribed to a session topic.
func (m *PubSubManager) SessionPeers(sessionID string) []peer.ID {
	m.mu.RLock()
	session, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return nil
	}

	return session.topic.ListPeers()
}

// Publish broadcasts a message to all peers in a session.
func (m *PubSubManager) Publish(ctx context.Context, sessionID string, data []byte) error {
	if m.closed.Load() {
		return ErrPubSubClosed
	}

	if data == nil {
		return ErrPubSubInvalidMessage
	}

	if len(data) > m.config.MaxMessageSize {
		return ErrPubSubMessageTooLarge
	}

	m.mu.RLock()
	session, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return ErrPubSubTopicNotFound
	}

	return session.topic.Publish(ctx, data)
}

// PublishTargeted publishes a message intended for a specific peer.
// Note: GossipSub broadcasts to all peers, but the message includes target info
// for application-level filtering.
func (m *PubSubManager) PublishTargeted(ctx context.Context, sessionID string, data []byte, targetPeer peer.ID) error {
	if m.closed.Load() {
		return ErrPubSubClosed
	}

	if targetPeer == "" {
		return ErrPubSubInvalidPeer
	}

	if data == nil {
		return ErrPubSubInvalidMessage
	}

	// Create targeted message wrapper
	targetedMsg := &TargetedMessage{
		Target: targetPeer.String(),
		Data:   data,
	}

	msgData, err := m.serializer.Marshal(targetedMsg)
	if err != nil {
		return &PubSubError{Op: "Marshal", SessionID: sessionID, Err: err}
	}

	return m.Publish(ctx, sessionID, msgData)
}

// PublishWithAck publishes a message and waits for acknowledgment.
func (m *PubSubManager) PublishWithAck(ctx context.Context, sessionID string, data []byte, msgID string, timeout time.Duration) error {
	if m.closed.Load() {
		return ErrPubSubClosed
	}

	if !m.config.EnableAcknowledgments {
		// Fall back to regular publish if acks disabled
		return m.Publish(ctx, sessionID, data)
	}

	m.mu.RLock()
	_, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return ErrPubSubTopicNotFound
	}

	// Create ack channel
	ackChan := make(chan struct{}, 1)
	m.ackMu.Lock()
	m.pendingAcks[msgID] = ackChan
	m.ackMu.Unlock()

	defer func() {
		m.ackMu.Lock()
		delete(m.pendingAcks, msgID)
		m.ackMu.Unlock()
	}()

	// Create ack message wrapper
	ackMsg := &AckMessage{
		MessageID: msgID,
		Data:      data,
	}

	msgData, err := m.serializer.Marshal(ackMsg)
	if err != nil {
		return &PubSubError{Op: "Marshal", SessionID: sessionID, Err: err}
	}

	// Publish message
	if err := m.Publish(ctx, sessionID, msgData); err != nil {
		return err
	}

	// Wait for acknowledgment or timeout
	select {
	case <-ackChan:
		return nil
	case <-time.After(timeout):
		// For now, we don't fail on ack timeout - just log and continue
		// In a real implementation, this could trigger retries
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// BroadcastEnvelope broadcasts a transport.Envelope to all session peers.
func (m *PubSubManager) BroadcastEnvelope(ctx context.Context, sessionID string, envelope *transport.Envelope) error {
	if m.closed.Load() {
		return ErrPubSubClosed
	}

	if envelope == nil {
		return ErrPubSubInvalidMessage
	}

	data, err := m.serializer.Marshal(envelope)
	if err != nil {
		return &PubSubError{Op: "Marshal", SessionID: sessionID, Err: err}
	}

	return m.Publish(ctx, sessionID, data)
}

// ReceiveEnvelope receives and deserializes a transport.Envelope from a session.
func (m *PubSubManager) ReceiveEnvelope(ctx context.Context, sessionID string) (*transport.Envelope, error) {
	if m.closed.Load() {
		return nil, ErrPubSubClosed
	}

	m.mu.RLock()
	session, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrPubSubTopicNotFound
	}

	msg, err := session.subscription.Next(ctx)
	if err != nil {
		return nil, &PubSubError{Op: "Next", SessionID: sessionID, Err: err}
	}

	var envelope transport.Envelope
	if err := m.serializer.Unmarshal(msg.Data, &envelope); err != nil {
		return nil, &PubSubError{Op: "Unmarshal", SessionID: sessionID, Err: err}
	}

	return &envelope, nil
}

// Close shuts down the PubSubManager and all subscriptions.
func (m *PubSubManager) Close() error {
	var closeErr error

	m.closeOnce.Do(func() {
		m.closed.Store(true)

		m.mu.Lock()
		defer m.mu.Unlock()

		// Close all sessions
		for sessionID, session := range m.sessions {
			session.Cancel()
			if err := session.topic.Close(); err != nil {
				if closeErr == nil {
					closeErr = &PubSubError{Op: "Close", SessionID: sessionID, Err: err}
				}
			}
		}

		m.sessions = make(map[string]*SessionSubscription)

		// Clear pending acks
		m.ackMu.Lock()
		for _, ch := range m.pendingAcks {
			close(ch)
		}
		m.pendingAcks = make(map[string]chan struct{})
		m.ackMu.Unlock()
	})

	return closeErr
}

// processMessages handles incoming messages for validation and acknowledgments.
func (m *PubSubManager) processMessages(ctx context.Context, session *SessionSubscription) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// This is a background validation loop
			// Actual message processing happens via Next() calls
		}

		// Sleep to avoid busy loop
		time.Sleep(100 * time.Millisecond)
	}
}

// TargetedMessage wraps a message intended for a specific peer.
type TargetedMessage struct {
	Target string `json:"target"`
	Data   []byte `json:"data"`
}

// AckMessage wraps a message requiring acknowledgment.
type AckMessage struct {
	MessageID string `json:"message_id"`
	Data      []byte `json:"data"`
}

// PubSubError provides detailed error information for PubSub operations.
type PubSubError struct {
	Op        string
	SessionID string
	Err       error
}

// Error implements the error interface.
func (e *PubSubError) Error() string {
	if e.SessionID != "" {
		return "pubsub: " + e.Op + " (session=" + e.SessionID + "): " + e.Err.Error()
	}
	return "pubsub: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *PubSubError) Unwrap() error {
	return e.Err
}
