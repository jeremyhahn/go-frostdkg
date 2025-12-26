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
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	connmanager "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	ma "github.com/multiformats/go-multiaddr"
)

// Connection pool errors.
var (
	// ErrPoolClosed indicates the connection pool has been closed.
	ErrPoolClosed = errors.New("libp2p: connection pool closed")

	// ErrConnectionLimitReached indicates maximum connections have been reached.
	ErrConnectionLimitReached = errors.New("libp2p: connection limit reached")

	// ErrPeerConnectionLimitReached indicates maximum connections to a peer have been reached.
	ErrPeerConnectionLimitReached = errors.New("libp2p: peer connection limit reached")

	// ErrStreamLimitReached indicates maximum streams have been reached.
	ErrStreamLimitReached = errors.New("libp2p: stream limit reached")

	// ErrHealthCheckFailed indicates a connection health check failed.
	ErrHealthCheckFailed = errors.New("libp2p: health check failed")

	// ErrInvalidPoolConfig indicates invalid connection pool configuration.
	ErrInvalidPoolConfig = errors.New("libp2p: invalid pool configuration")

	// ErrPeerNotTracked indicates the peer was not found in the connection pool.
	ErrPeerNotTracked = errors.New("libp2p: peer not tracked in pool")
)

// SessionPriority represents the priority level for a DKG session.
// This maps to MessagePriority for connection tagging purposes.
type SessionPriority int

const (
	// SessionPriorityLow indicates a low-priority session.
	SessionPriorityLow SessionPriority = iota
	// SessionPriorityNormal indicates a normal-priority session.
	SessionPriorityNormal
	// SessionPriorityHigh indicates a high-priority session.
	SessionPriorityHigh
	// SessionPriorityCritical indicates a critical-priority session that should never be trimmed.
	SessionPriorityCritical
)

// String returns a string representation of the priority.
func (p SessionPriority) String() string {
	switch p {
	case SessionPriorityLow:
		return "low"
	case SessionPriorityNormal:
		return "normal"
	case SessionPriorityHigh:
		return "high"
	case SessionPriorityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// PoolConfig contains configuration for the connection pool.
type PoolConfig struct {
	// LowWatermark is the minimum number of connections to maintain.
	// Connections below this count will not be trimmed.
	LowWatermark int

	// HighWatermark is the maximum number of connections before trimming starts.
	// When reached, connections are trimmed down to LowWatermark.
	HighWatermark int

	// MaxConnectionsPerPeer limits connections to a single peer.
	MaxConnectionsPerPeer int

	// MaxStreamsPerConnection limits streams multiplexed on a single connection.
	MaxStreamsPerConnection int

	// GracePeriod is the minimum duration a connection must be open before
	// it can be trimmed.
	GracePeriod time.Duration

	// IdleTimeout is the duration after which idle connections are closed.
	IdleTimeout time.Duration

	// HealthCheckInterval is how often to check connection health.
	HealthCheckInterval time.Duration

	// EnablePriorityTagging enables session priority tagging for connections.
	EnablePriorityTagging bool

	// CleanupInterval is how often the cleanup goroutine runs.
	CleanupInterval time.Duration
}

// DefaultPoolConfig returns a default connection pool configuration.
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		LowWatermark:            64,
		HighWatermark:           128,
		MaxConnectionsPerPeer:   4,
		MaxStreamsPerConnection: 256,
		GracePeriod:             30 * time.Second,
		IdleTimeout:             5 * time.Minute,
		HealthCheckInterval:     30 * time.Second,
		EnablePriorityTagging:   true,
		CleanupInterval:         time.Minute,
	}
}

// Validate validates the pool configuration.
func (c *PoolConfig) Validate() error {
	if c.LowWatermark < 1 {
		return ErrInvalidPoolConfig
	}
	if c.HighWatermark < c.LowWatermark {
		return ErrInvalidPoolConfig
	}
	if c.MaxConnectionsPerPeer < 1 {
		return ErrInvalidPoolConfig
	}
	if c.MaxStreamsPerConnection < 1 {
		return ErrInvalidPoolConfig
	}
	if c.GracePeriod < 0 {
		return ErrInvalidPoolConfig
	}
	if c.IdleTimeout < 0 {
		return ErrInvalidPoolConfig
	}
	if c.HealthCheckInterval < 0 {
		return ErrInvalidPoolConfig
	}
	return nil
}

// peerConnState tracks connection state for a peer.
type peerConnState struct {
	peerID       peer.ID
	lastActivity atomic.Int64
	streamCount  atomic.Int32
	priority     atomic.Int32
	sessionTags  sync.Map // map[string]SessionPriority
}

// ConnectionPool manages peer connections with optimized reuse and multiplexing.
type ConnectionPool struct {
	config   *PoolConfig
	connMgr  connmgr.ConnManager
	limiter  network.ResourceManager
	notifiee *poolNotifiee

	// Peer connection tracking
	peers     sync.Map // map[peer.ID]*peerConnState
	peerCount atomic.Int32

	// Statistics
	totalConnections    atomic.Int64
	reuseCount          atomic.Int64
	trimmedConnections  atomic.Int64
	healthCheckFailures atomic.Int64

	// Lifecycle
	closed   atomic.Bool
	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// poolNotifiee receives notifications about connection events.
type poolNotifiee struct {
	pool *ConnectionPool
}

// NewConnectionPool creates a new connection pool with the given configuration.
func NewConnectionPool(config *PoolConfig) (*ConnectionPool, error) {
	if config == nil {
		config = DefaultPoolConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create the basic connection manager
	cm, err := connmanager.NewConnManager(
		config.LowWatermark,
		config.HighWatermark,
		connmanager.WithGracePeriod(config.GracePeriod),
	)
	if err != nil {
		return nil, &PoolError{Op: "create", Err: err}
	}

	// Create resource limits for stream management
	limiter, err := createResourceManager(config)
	if err != nil {
		return nil, &PoolError{Op: "create_limiter", Err: err}
	}

	pool := &ConnectionPool{
		config:   config,
		connMgr:  cm,
		limiter:  limiter,
		stopChan: make(chan struct{}),
	}

	pool.notifiee = &poolNotifiee{pool: pool}

	// Start cleanup goroutine
	pool.wg.Add(1)
	go pool.cleanupLoop()

	// Start health check goroutine if enabled
	if config.HealthCheckInterval > 0 {
		pool.wg.Add(1)
		go pool.healthCheckLoop()
	}

	return pool, nil
}

// createResourceManager creates a resource manager for stream limiting.
func createResourceManager(config *PoolConfig) (network.ResourceManager, error) {
	limits := rcmgr.DefaultLimits

	// Configure connection limits
	limits.SystemBaseLimit.Conns = config.HighWatermark * 2
	limits.SystemBaseLimit.ConnsInbound = config.HighWatermark
	limits.SystemBaseLimit.ConnsOutbound = config.HighWatermark
	limits.SystemBaseLimit.Streams = config.HighWatermark * config.MaxStreamsPerConnection
	limits.SystemBaseLimit.StreamsInbound = config.HighWatermark * config.MaxStreamsPerConnection / 2
	limits.SystemBaseLimit.StreamsOutbound = config.HighWatermark * config.MaxStreamsPerConnection / 2

	// Configure per-peer limits
	limits.ServicePeerBaseLimit.Streams = config.MaxStreamsPerConnection
	limits.ServicePeerBaseLimit.StreamsInbound = config.MaxStreamsPerConnection / 2
	limits.ServicePeerBaseLimit.StreamsOutbound = config.MaxStreamsPerConnection / 2

	scaledLimits := limits.AutoScale()

	rm, err := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(scaledLimits))
	if err != nil {
		return nil, err
	}

	return rm, nil
}

// ConnManager returns the underlying connection manager for use with libp2p.
func (p *ConnectionPool) ConnManager() connmgr.ConnManager {
	return p.connMgr
}

// ResourceManager returns the resource manager for use with libp2p.
func (p *ConnectionPool) ResourceManager() network.ResourceManager {
	return p.limiter
}

// LibP2POptions returns libp2p options for configuring a host with this pool.
func (p *ConnectionPool) LibP2POptions() []libp2p.Option {
	return []libp2p.Option{
		libp2p.ConnectionManager(p.connMgr),
		libp2p.ResourceManager(p.limiter),
	}
}

// Notifiee returns a network notifiee for tracking connection events.
func (p *ConnectionPool) Notifiee() network.Notifiee {
	return p.notifiee
}

// TrackConnection adds a peer connection to the pool for tracking.
func (p *ConnectionPool) TrackConnection(peerID peer.ID) error {
	if p.closed.Load() {
		return ErrPoolClosed
	}

	// Check total connection limit
	if p.peerCount.Load() >= safeInt32(p.config.HighWatermark) {
		return ErrConnectionLimitReached
	}

	// Get or create peer state
	state := p.getOrCreatePeerState(peerID)

	// Update activity timestamp
	state.lastActivity.Store(time.Now().UnixNano())

	p.totalConnections.Add(1)

	return nil
}

// UntrackConnection removes a peer connection from tracking.
func (p *ConnectionPool) UntrackConnection(peerID peer.ID) {
	if _, loaded := p.peers.LoadAndDelete(peerID); loaded {
		p.peerCount.Add(-1)
	}
}

// TagSession tags a connection with a session and priority for connection management.
func (p *ConnectionPool) TagSession(peerID peer.ID, sessionID string, priority SessionPriority) error {
	if p.closed.Load() {
		return ErrPoolClosed
	}

	if !p.config.EnablePriorityTagging {
		return nil
	}

	state, ok := p.peers.Load(peerID)
	if !ok {
		return ErrPeerNotTracked
	}

	peerState := state.(*peerConnState)

	// Store session tag
	peerState.sessionTags.Store(sessionID, priority)

	// Update overall priority (use highest)
	currentPriority := SessionPriority(peerState.priority.Load())
	if priority > currentPriority {
		peerState.priority.Store(safeInt32(int(priority)))
	}

	// Tag in connection manager with appropriate weight
	weight := p.priorityToWeight(priority)
	p.connMgr.TagPeer(peerID, sessionID, weight)

	// Protect critical connections
	if priority == SessionPriorityCritical {
		p.connMgr.Protect(peerID, sessionID)
	}

	return nil
}

// UntagSession removes a session tag from a connection.
func (p *ConnectionPool) UntagSession(peerID peer.ID, sessionID string) {
	if !p.config.EnablePriorityTagging {
		return
	}

	state, ok := p.peers.Load(peerID)
	if !ok {
		return
	}

	peerState := state.(*peerConnState)

	// Remove session tag
	peerState.sessionTags.Delete(sessionID)

	// Untag in connection manager
	p.connMgr.UntagPeer(peerID, sessionID)

	// Unprotect if was critical
	p.connMgr.Unprotect(peerID, sessionID)

	// Recalculate highest priority
	p.recalculatePriority(peerState)
}

// RecordActivity records activity on a peer connection.
func (p *ConnectionPool) RecordActivity(peerID peer.ID) {
	if state, ok := p.peers.Load(peerID); ok {
		peerState := state.(*peerConnState)
		peerState.lastActivity.Store(time.Now().UnixNano())
	}
}

// RecordStreamOpen records that a stream was opened on a connection.
func (p *ConnectionPool) RecordStreamOpen(peerID peer.ID) error {
	if p.closed.Load() {
		return ErrPoolClosed
	}

	state, ok := p.peers.Load(peerID)
	if !ok {
		return ErrPeerNotTracked
	}

	peerState := state.(*peerConnState)

	// Check stream limit
	if peerState.streamCount.Load() >= safeInt32(p.config.MaxStreamsPerConnection) {
		return ErrStreamLimitReached
	}

	peerState.streamCount.Add(1)
	peerState.lastActivity.Store(time.Now().UnixNano())

	return nil
}

// RecordStreamClose records that a stream was closed on a connection.
func (p *ConnectionPool) RecordStreamClose(peerID peer.ID) {
	if state, ok := p.peers.Load(peerID); ok {
		peerState := state.(*peerConnState)
		peerState.streamCount.Add(-1)
	}
}

// ShouldReuseConnection checks if a connection to a peer can be reused.
func (p *ConnectionPool) ShouldReuseConnection(peerID peer.ID) bool {
	if p.closed.Load() {
		return false
	}

	state, ok := p.peers.Load(peerID)
	if !ok {
		return false
	}

	peerState := state.(*peerConnState)

	// Check if stream limit allows reuse
	if peerState.streamCount.Load() >= safeInt32(p.config.MaxStreamsPerConnection) {
		return false
	}

	// Check if connection is still within idle timeout
	lastActivity := time.Unix(0, peerState.lastActivity.Load())
	if time.Since(lastActivity) > p.config.IdleTimeout {
		return false
	}

	p.reuseCount.Add(1)
	return true
}

// GetPeerPriority returns the priority of a peer connection.
func (p *ConnectionPool) GetPeerPriority(peerID peer.ID) SessionPriority {
	state, ok := p.peers.Load(peerID)
	if !ok {
		return SessionPriorityNormal
	}

	peerState := state.(*peerConnState)
	return SessionPriority(peerState.priority.Load())
}

// GetPeerStreamCount returns the number of active streams on a peer connection.
func (p *ConnectionPool) GetPeerStreamCount(peerID peer.ID) int {
	state, ok := p.peers.Load(peerID)
	if !ok {
		return 0
	}

	peerState := state.(*peerConnState)
	return int(peerState.streamCount.Load())
}

// Stats returns connection pool statistics.
func (p *ConnectionPool) Stats() PoolStats {
	return PoolStats{
		ActivePeers:         int(p.peerCount.Load()),
		TotalConnections:    p.totalConnections.Load(),
		ReuseCount:          p.reuseCount.Load(),
		TrimmedConnections:  p.trimmedConnections.Load(),
		HealthCheckFailures: p.healthCheckFailures.Load(),
	}
}

// PoolStats contains connection pool statistics.
type PoolStats struct {
	ActivePeers         int
	TotalConnections    int64
	ReuseCount          int64
	TrimmedConnections  int64
	HealthCheckFailures int64
}

// Close shuts down the connection pool.
func (p *ConnectionPool) Close() error {
	var closeErr error

	p.stopOnce.Do(func() {
		p.closed.Store(true)
		close(p.stopChan)

		// Wait for goroutines
		done := make(chan struct{})
		go func() {
			p.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			closeErr = &PoolError{Op: "close", Err: errors.New("shutdown timeout")}
		}

		// Close connection manager
		if closer, ok := p.connMgr.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil && closeErr == nil {
				closeErr = &PoolError{Op: "close_connmgr", Err: err}
			}
		}

		// Close resource manager
		if err := p.limiter.Close(); err != nil && closeErr == nil {
			closeErr = &PoolError{Op: "close_limiter", Err: err}
		}
	})

	return closeErr
}

// cleanupLoop periodically cleans up idle connections.
func (p *ConnectionPool) cleanupLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.cleanupIdleConnections()
		}
	}
}

// cleanupIdleConnections removes connections that have been idle too long.
func (p *ConnectionPool) cleanupIdleConnections() {
	now := time.Now()
	var toRemove []peer.ID

	p.peers.Range(func(key, value any) bool {
		peerID := key.(peer.ID)
		state := value.(*peerConnState)

		// Skip critical priority connections
		if SessionPriority(state.priority.Load()) == SessionPriorityCritical {
			return true
		}

		// Check if idle too long
		lastActivity := time.Unix(0, state.lastActivity.Load())
		if now.Sub(lastActivity) > p.config.IdleTimeout {
			// Only remove if no active streams
			if state.streamCount.Load() == 0 {
				toRemove = append(toRemove, peerID)
			}
		}

		return true
	})

	// Remove idle connections
	for _, peerID := range toRemove {
		p.UntrackConnection(peerID)
		p.trimmedConnections.Add(1)
	}
}

// healthCheckLoop periodically checks connection health.
func (p *ConnectionPool) healthCheckLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.runHealthChecks()
		}
	}
}

// runHealthChecks checks the health of all tracked connections.
func (p *ConnectionPool) runHealthChecks() {
	now := time.Now()
	graceThreshold := now.Add(-p.config.GracePeriod)

	p.peers.Range(func(key, value any) bool {
		state := value.(*peerConnState)

		// Skip connections still in grace period
		lastActivity := time.Unix(0, state.lastActivity.Load())
		if lastActivity.After(graceThreshold) {
			return true
		}

		// For connections past grace period with no activity, increment failure count
		if state.streamCount.Load() == 0 && time.Since(lastActivity) > p.config.IdleTimeout {
			p.healthCheckFailures.Add(1)
		}

		return true
	})
}

// getOrCreatePeerState gets or creates state for a peer.
func (p *ConnectionPool) getOrCreatePeerState(peerID peer.ID) *peerConnState {
	state, loaded := p.peers.LoadOrStore(peerID, &peerConnState{
		peerID: peerID,
	})

	if !loaded {
		p.peerCount.Add(1)
		state.(*peerConnState).lastActivity.Store(time.Now().UnixNano())
		state.(*peerConnState).priority.Store(int32(SessionPriorityNormal))
	}

	return state.(*peerConnState)
}

// priorityToWeight converts session priority to connection manager weight.
func (p *ConnectionPool) priorityToWeight(priority SessionPriority) int {
	switch priority {
	case SessionPriorityLow:
		return 10
	case SessionPriorityNormal:
		return 50
	case SessionPriorityHigh:
		return 100
	case SessionPriorityCritical:
		return 1000
	default:
		return 50
	}
}

// recalculatePriority recalculates the overall priority for a peer.
func (p *ConnectionPool) recalculatePriority(state *peerConnState) {
	var maxPriority SessionPriority

	state.sessionTags.Range(func(key, value any) bool {
		priority := value.(SessionPriority)
		if priority > maxPriority {
			maxPriority = priority
		}
		return true
	})

	state.priority.Store(safeInt32(int(maxPriority)))
}

// Network notifiee implementation

func (n *poolNotifiee) Listen(network.Network, ma.Multiaddr)      {}
func (n *poolNotifiee) ListenClose(network.Network, ma.Multiaddr) {}

func (n *poolNotifiee) Connected(_ network.Network, conn network.Conn) {
	_ = n.pool.TrackConnection(conn.RemotePeer())
}

func (n *poolNotifiee) Disconnected(_ network.Network, conn network.Conn) {
	n.pool.UntrackConnection(conn.RemotePeer())
}

// PoolError wraps connection pool operation errors.
type PoolError struct {
	Op   string
	Peer peer.ID
	Err  error
}

func (e *PoolError) Error() string {
	if e.Peer != "" {
		return "libp2p pool " + e.Op + " (peer=" + e.Peer.String() + "): " + e.Err.Error()
	}
	return "libp2p pool " + e.Op + ": " + e.Err.Error()
}

func (e *PoolError) Unwrap() error {
	return e.Err
}

// PoolConfigOption is a functional option for configuring the connection pool.
type PoolConfigOption func(*PoolConfig)

// WithLowWatermark sets the low watermark for connections.
func WithLowWatermark(n int) PoolConfigOption {
	return func(c *PoolConfig) {
		c.LowWatermark = n
	}
}

// WithHighWatermark sets the high watermark for connections.
func WithHighWatermark(n int) PoolConfigOption {
	return func(c *PoolConfig) {
		c.HighWatermark = n
	}
}

// WithMaxConnectionsPerPeer sets the maximum connections per peer.
func WithMaxConnectionsPerPeer(n int) PoolConfigOption {
	return func(c *PoolConfig) {
		c.MaxConnectionsPerPeer = n
	}
}

// WithMaxStreamsPerConnection sets the maximum streams per connection.
func WithMaxStreamsPerConnection(n int) PoolConfigOption {
	return func(c *PoolConfig) {
		c.MaxStreamsPerConnection = n
	}
}

// WithGracePeriod sets the grace period for new connections.
func WithGracePeriod(d time.Duration) PoolConfigOption {
	return func(c *PoolConfig) {
		c.GracePeriod = d
	}
}

// WithIdleTimeout sets the idle timeout for connections.
func WithIdleTimeout(d time.Duration) PoolConfigOption {
	return func(c *PoolConfig) {
		c.IdleTimeout = d
	}
}

// WithHealthCheckInterval sets the health check interval.
func WithHealthCheckInterval(d time.Duration) PoolConfigOption {
	return func(c *PoolConfig) {
		c.HealthCheckInterval = d
	}
}

// WithPriorityTagging enables or disables priority tagging.
func WithPriorityTagging(enabled bool) PoolConfigOption {
	return func(c *PoolConfig) {
		c.EnablePriorityTagging = enabled
	}
}

// WithCleanupInterval sets the cleanup interval.
func WithCleanupInterval(d time.Duration) PoolConfigOption {
	return func(c *PoolConfig) {
		c.CleanupInterval = d
	}
}

// NewConnectionPoolWithOptions creates a new connection pool with functional options.
func NewConnectionPoolWithOptions(opts ...PoolConfigOption) (*ConnectionPool, error) {
	config := DefaultPoolConfig()
	for _, opt := range opts {
		opt(config)
	}
	return NewConnectionPool(config)
}
