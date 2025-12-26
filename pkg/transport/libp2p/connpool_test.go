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
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper to generate test peer IDs
func generateTestPeerID(t *testing.T, seed int) peer.ID {
	t.Helper()
	// Generate a valid peer ID from a random key
	// Use seed to make deterministic by using it as first byte
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to generate peer ID: %v", err)
	}
	return id
}

// createPoolTestHost creates a libp2p host for testing with the given pool.
func createPoolTestHost(t *testing.T, pool *ConnectionPool) host.Host {
	t.Helper()

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	opts := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	}

	if pool != nil {
		opts = append(opts, pool.LibP2POptions()...)
	}

	h, err := libp2p.New(opts...)
	require.NoError(t, err)

	if pool != nil {
		h.Network().Notify(pool.Notifiee())
	}

	return h
}

func TestDefaultPoolConfig(t *testing.T) {
	config := DefaultPoolConfig()

	assert.Equal(t, 64, config.LowWatermark)
	assert.Equal(t, 128, config.HighWatermark)
	assert.Equal(t, 4, config.MaxConnectionsPerPeer)
	assert.Equal(t, 256, config.MaxStreamsPerConnection)
	assert.Equal(t, 30*time.Second, config.GracePeriod)
	assert.Equal(t, 5*time.Minute, config.IdleTimeout)
	assert.Equal(t, 30*time.Second, config.HealthCheckInterval)
	assert.True(t, config.EnablePriorityTagging)
	assert.Equal(t, time.Minute, config.CleanupInterval)
}

func TestPoolConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *PoolConfig
		expectErr bool
	}{
		{
			name:      "valid default config",
			config:    DefaultPoolConfig(),
			expectErr: false,
		},
		{
			name: "valid custom config",
			config: &PoolConfig{
				LowWatermark:            10,
				HighWatermark:           20,
				MaxConnectionsPerPeer:   2,
				MaxStreamsPerConnection: 100,
				GracePeriod:             time.Second,
				IdleTimeout:             time.Minute,
				HealthCheckInterval:     10 * time.Second,
				CleanupInterval:         30 * time.Second,
			},
			expectErr: false,
		},
		{
			name: "invalid low watermark zero",
			config: &PoolConfig{
				LowWatermark:            0,
				HighWatermark:           10,
				MaxConnectionsPerPeer:   1,
				MaxStreamsPerConnection: 1,
			},
			expectErr: true,
		},
		{
			name: "invalid high watermark less than low",
			config: &PoolConfig{
				LowWatermark:            20,
				HighWatermark:           10,
				MaxConnectionsPerPeer:   1,
				MaxStreamsPerConnection: 1,
			},
			expectErr: true,
		},
		{
			name: "invalid max connections per peer zero",
			config: &PoolConfig{
				LowWatermark:            10,
				HighWatermark:           20,
				MaxConnectionsPerPeer:   0,
				MaxStreamsPerConnection: 1,
			},
			expectErr: true,
		},
		{
			name: "invalid max streams per connection zero",
			config: &PoolConfig{
				LowWatermark:            10,
				HighWatermark:           20,
				MaxConnectionsPerPeer:   1,
				MaxStreamsPerConnection: 0,
			},
			expectErr: true,
		},
		{
			name: "invalid negative grace period",
			config: &PoolConfig{
				LowWatermark:            10,
				HighWatermark:           20,
				MaxConnectionsPerPeer:   1,
				MaxStreamsPerConnection: 1,
				GracePeriod:             -1,
			},
			expectErr: true,
		},
		{
			name: "invalid negative idle timeout",
			config: &PoolConfig{
				LowWatermark:            10,
				HighWatermark:           20,
				MaxConnectionsPerPeer:   1,
				MaxStreamsPerConnection: 1,
				GracePeriod:             0,
				IdleTimeout:             -1,
			},
			expectErr: true,
		},
		{
			name: "invalid negative health check interval",
			config: &PoolConfig{
				LowWatermark:            10,
				HighWatermark:           20,
				MaxConnectionsPerPeer:   1,
				MaxStreamsPerConnection: 1,
				GracePeriod:             0,
				IdleTimeout:             0,
				HealthCheckInterval:     -1,
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectErr {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, ErrInvalidPoolConfig))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewConnectionPool(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		pool, err := NewConnectionPool(nil)
		require.NoError(t, err)
		require.NotNil(t, pool)
		defer func() { _ = pool.Close() }()

		assert.NotNil(t, pool.ConnManager())
		assert.NotNil(t, pool.ResourceManager())
		assert.False(t, pool.closed.Load())
	})

	t.Run("with valid config", func(t *testing.T) {
		config := &PoolConfig{
			LowWatermark:            8,
			HighWatermark:           16,
			MaxConnectionsPerPeer:   2,
			MaxStreamsPerConnection: 32,
			GracePeriod:             time.Second,
			IdleTimeout:             time.Minute,
			HealthCheckInterval:     10 * time.Second,
			CleanupInterval:         30 * time.Second,
			EnablePriorityTagging:   true,
		}

		pool, err := NewConnectionPool(config)
		require.NoError(t, err)
		require.NotNil(t, pool)
		defer func() { _ = pool.Close() }()

		assert.Equal(t, config, pool.config)
	})

	t.Run("with invalid config returns error", func(t *testing.T) {
		config := &PoolConfig{
			LowWatermark:  0, // Invalid
			HighWatermark: 10,
		}

		pool, err := NewConnectionPool(config)
		assert.Error(t, err)
		assert.Nil(t, pool)
	})
}

func TestNewConnectionPoolWithOptions(t *testing.T) {
	pool, err := NewConnectionPoolWithOptions(
		WithLowWatermark(16),
		WithHighWatermark(32),
		WithMaxConnectionsPerPeer(4),
		WithMaxStreamsPerConnection(128),
		WithGracePeriod(5*time.Second),
		WithIdleTimeout(2*time.Minute),
		WithHealthCheckInterval(15*time.Second),
		WithPriorityTagging(false),
		WithCleanupInterval(45*time.Second),
	)
	require.NoError(t, err)
	require.NotNil(t, pool)
	defer func() { _ = pool.Close() }()

	assert.Equal(t, 16, pool.config.LowWatermark)
	assert.Equal(t, 32, pool.config.HighWatermark)
	assert.Equal(t, 4, pool.config.MaxConnectionsPerPeer)
	assert.Equal(t, 128, pool.config.MaxStreamsPerConnection)
	assert.Equal(t, 5*time.Second, pool.config.GracePeriod)
	assert.Equal(t, 2*time.Minute, pool.config.IdleTimeout)
	assert.Equal(t, 15*time.Second, pool.config.HealthCheckInterval)
	assert.False(t, pool.config.EnablePriorityTagging)
	assert.Equal(t, 45*time.Second, pool.config.CleanupInterval)
}

func TestConnectionPoolTrackConnection(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	t.Run("track new connection", func(t *testing.T) {
		peerID := generateTestPeerID(t, 1)

		err := pool.TrackConnection(peerID)
		require.NoError(t, err)

		stats := pool.Stats()
		assert.Equal(t, 1, stats.ActivePeers)
		assert.Equal(t, int64(1), stats.TotalConnections)
	})

	t.Run("track duplicate connection updates count", func(t *testing.T) {
		peerID := generateTestPeerID(t, 2)

		err := pool.TrackConnection(peerID)
		require.NoError(t, err)

		err = pool.TrackConnection(peerID)
		require.NoError(t, err)

		// Should still be 2 peers (from previous test + this one)
		stats := pool.Stats()
		assert.Equal(t, 2, stats.ActivePeers)
		assert.Equal(t, int64(3), stats.TotalConnections)
	})

	t.Run("track connection on closed pool", func(t *testing.T) {
		closedPool, err := NewConnectionPool(&PoolConfig{
			LowWatermark:            1,
			HighWatermark:           2,
			MaxConnectionsPerPeer:   1,
			MaxStreamsPerConnection: 1,
			GracePeriod:             0,
			IdleTimeout:             time.Hour,
			HealthCheckInterval:     0,
			CleanupInterval:         time.Hour,
		})
		require.NoError(t, err)
		require.NoError(t, closedPool.Close())

		peerID := generateTestPeerID(t, 3)
		err = closedPool.TrackConnection(peerID)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPoolClosed))
	})
}

func TestConnectionPoolConnectionLimitEnforcement(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            2,
		HighWatermark:           4,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Track connections up to high watermark
	for i := 0; i < 4; i++ {
		peerID := generateTestPeerID(t, i)
		err := pool.TrackConnection(peerID)
		require.NoError(t, err, "should allow connection %d", i)
	}

	stats := pool.Stats()
	assert.Equal(t, 4, stats.ActivePeers)

	// Next connection should fail
	extraPeer := generateTestPeerID(t, 100)
	err = pool.TrackConnection(extraPeer)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrConnectionLimitReached))

	// Stats should still show 4
	stats = pool.Stats()
	assert.Equal(t, 4, stats.ActivePeers)
}

func TestConnectionPoolUntrackConnection(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 1)

	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	stats := pool.Stats()
	assert.Equal(t, 1, stats.ActivePeers)

	pool.UntrackConnection(peerID)

	stats = pool.Stats()
	assert.Equal(t, 0, stats.ActivePeers)

	// Untracking non-existent peer should be safe
	pool.UntrackConnection(generateTestPeerID(t, 999))
}

func TestConnectionPoolConnectionReuse(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 1)

	// Track connection
	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// Should allow reuse
	assert.True(t, pool.ShouldReuseConnection(peerID))

	// Record some streams but stay under limit
	for i := 0; i < 5; i++ {
		err := pool.RecordStreamOpen(peerID)
		require.NoError(t, err)
	}

	// Should still allow reuse
	assert.True(t, pool.ShouldReuseConnection(peerID))
	assert.Equal(t, 5, pool.GetPeerStreamCount(peerID))

	stats := pool.Stats()
	assert.Equal(t, int64(2), stats.ReuseCount)
}

func TestConnectionPoolStreamLimitEnforcement(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 5, // Low limit for testing
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 1)

	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// Open streams up to limit
	for i := 0; i < 5; i++ {
		err := pool.RecordStreamOpen(peerID)
		require.NoError(t, err, "should allow stream %d", i)
	}

	// Next stream should fail
	err = pool.RecordStreamOpen(peerID)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStreamLimitReached))

	// Should not allow reuse when at stream limit
	assert.False(t, pool.ShouldReuseConnection(peerID))

	// Close a stream
	pool.RecordStreamClose(peerID)
	assert.Equal(t, 4, pool.GetPeerStreamCount(peerID))

	// Now should allow opening another
	err = pool.RecordStreamOpen(peerID)
	assert.NoError(t, err)
}

func TestConnectionPoolIdleConnectionCleanup(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             50 * time.Millisecond, // Very short for testing
		HealthCheckInterval:     0,
		CleanupInterval:         25 * time.Millisecond, // Very short for testing
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 1)

	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	stats := pool.Stats()
	assert.Equal(t, 1, stats.ActivePeers)

	// Wait for idle timeout and cleanup
	time.Sleep(100 * time.Millisecond)

	// Connection should have been cleaned up
	stats = pool.Stats()
	assert.Equal(t, 0, stats.ActivePeers)
	assert.GreaterOrEqual(t, stats.TrimmedConnections, int64(1))
}

func TestConnectionPoolIdleConnectionWithActiveStreamsNotCleaned(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             50 * time.Millisecond,
		HealthCheckInterval:     0,
		CleanupInterval:         25 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 1)

	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// Open a stream to keep connection active
	err = pool.RecordStreamOpen(peerID)
	require.NoError(t, err)

	// Wait for idle timeout
	time.Sleep(100 * time.Millisecond)

	// Connection should NOT be cleaned up because it has active streams
	stats := pool.Stats()
	assert.Equal(t, 1, stats.ActivePeers)
}

func TestConnectionPoolPriorityTagging(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
		EnablePriorityTagging:   true,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 1)

	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// Default priority should be normal
	assert.Equal(t, SessionPriorityNormal, pool.GetPeerPriority(peerID))

	// Tag with low priority session
	err = pool.TagSession(peerID, "session-low", SessionPriorityLow)
	require.NoError(t, err)
	assert.Equal(t, SessionPriorityNormal, pool.GetPeerPriority(peerID)) // Still normal (higher)

	// Tag with high priority session
	err = pool.TagSession(peerID, "session-high", SessionPriorityHigh)
	require.NoError(t, err)
	assert.Equal(t, SessionPriorityHigh, pool.GetPeerPriority(peerID))

	// Tag with critical priority session
	err = pool.TagSession(peerID, "session-critical", SessionPriorityCritical)
	require.NoError(t, err)
	assert.Equal(t, SessionPriorityCritical, pool.GetPeerPriority(peerID))

	// Untag critical session
	pool.UntagSession(peerID, "session-critical")
	assert.Equal(t, SessionPriorityHigh, pool.GetPeerPriority(peerID))

	// Untag high priority session
	pool.UntagSession(peerID, "session-high")
	assert.Equal(t, SessionPriorityLow, pool.GetPeerPriority(peerID))
}

func TestConnectionPoolCriticalPriorityNotCleaned(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             50 * time.Millisecond,
		HealthCheckInterval:     0,
		CleanupInterval:         25 * time.Millisecond,
		EnablePriorityTagging:   true,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 1)

	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// Tag with critical priority
	err = pool.TagSession(peerID, "critical-session", SessionPriorityCritical)
	require.NoError(t, err)

	// Wait for idle timeout
	time.Sleep(100 * time.Millisecond)

	// Critical connection should NOT be cleaned up
	stats := pool.Stats()
	assert.Equal(t, 1, stats.ActivePeers)
}

func TestConnectionPoolTagSessionErrors(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
		EnablePriorityTagging:   true,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	t.Run("tag non-existent peer", func(t *testing.T) {
		peerID := generateTestPeerID(t, 999)
		err := pool.TagSession(peerID, "session", SessionPriorityHigh)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPeerNotTracked))
	})

	t.Run("tag on closed pool", func(t *testing.T) {
		closedPool, err := NewConnectionPool(&PoolConfig{
			LowWatermark:            1,
			HighWatermark:           2,
			MaxConnectionsPerPeer:   1,
			MaxStreamsPerConnection: 1,
			GracePeriod:             0,
			IdleTimeout:             time.Hour,
			HealthCheckInterval:     0,
			CleanupInterval:         time.Hour,
		})
		require.NoError(t, err)

		peerID := generateTestPeerID(t, 1)
		err = closedPool.TrackConnection(peerID)
		require.NoError(t, err)

		require.NoError(t, closedPool.Close())

		err = closedPool.TagSession(peerID, "session", SessionPriorityHigh)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPoolClosed))
	})

	t.Run("tag with priority tagging disabled", func(t *testing.T) {
		disabledPool, err := NewConnectionPool(&PoolConfig{
			LowWatermark:            4,
			HighWatermark:           8,
			MaxConnectionsPerPeer:   2,
			MaxStreamsPerConnection: 10,
			GracePeriod:             0,
			IdleTimeout:             time.Hour,
			HealthCheckInterval:     0,
			CleanupInterval:         time.Hour,
			EnablePriorityTagging:   false,
		})
		require.NoError(t, err)
		defer func() { _ = disabledPool.Close() }()

		peerID := generateTestPeerID(t, 1)
		err = disabledPool.TrackConnection(peerID)
		require.NoError(t, err)

		// Should return nil when tagging is disabled
		err = disabledPool.TagSession(peerID, "session", SessionPriorityHigh)
		assert.NoError(t, err)
	})
}

func TestConnectionPoolRecordActivity(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             100 * time.Millisecond,
		HealthCheckInterval:     0,
		CleanupInterval:         50 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 1)

	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// Keep recording activity to prevent cleanup
	for i := 0; i < 5; i++ {
		time.Sleep(30 * time.Millisecond)
		pool.RecordActivity(peerID)
	}

	// Connection should still be active
	stats := pool.Stats()
	assert.Equal(t, 1, stats.ActivePeers)
	assert.True(t, pool.ShouldReuseConnection(peerID))
}

func TestConnectionPoolLibP2POptions(t *testing.T) {
	pool, err := NewConnectionPool(nil)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	opts := pool.LibP2POptions()
	assert.Len(t, opts, 2)
}

func TestConnectionPoolNotifiee(t *testing.T) {
	pool, err := NewConnectionPool(nil)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	notifiee := pool.Notifiee()
	require.NotNil(t, notifiee)

	// The notifiee methods are interface implementations
	// that would be called by libp2p network events
	// We can verify they don't panic
	notifiee.Listen(nil, nil)
	notifiee.ListenClose(nil, nil)
}

func TestConnectionPoolStats(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Initial stats
	stats := pool.Stats()
	assert.Equal(t, 0, stats.ActivePeers)
	assert.Equal(t, int64(0), stats.TotalConnections)
	assert.Equal(t, int64(0), stats.ReuseCount)
	assert.Equal(t, int64(0), stats.TrimmedConnections)
	assert.Equal(t, int64(0), stats.HealthCheckFailures)

	// Add some connections
	peerIDs := make([]peer.ID, 3)
	for i := 0; i < 3; i++ {
		peerIDs[i] = generateTestPeerID(t, i)
		err := pool.TrackConnection(peerIDs[i])
		require.NoError(t, err)
	}

	stats = pool.Stats()
	assert.Equal(t, 3, stats.ActivePeers)
	assert.Equal(t, int64(3), stats.TotalConnections)

	// Check reuse
	pool.ShouldReuseConnection(peerIDs[0])
	pool.ShouldReuseConnection(peerIDs[0])

	stats = pool.Stats()
	assert.Equal(t, int64(2), stats.ReuseCount)
}

func TestConnectionPoolClose(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     time.Second,
		CleanupInterval:         time.Second,
	})
	require.NoError(t, err)

	// Add some connections
	for i := 0; i < 3; i++ {
		peerID := generateTestPeerID(t, i)
		err := pool.TrackConnection(peerID)
		require.NoError(t, err)
	}

	// Close should not error
	err = pool.Close()
	assert.NoError(t, err)

	// Pool should be marked closed
	assert.True(t, pool.closed.Load())

	// Operations on closed pool should fail
	peerID := generateTestPeerID(t, 100)
	err = pool.TrackConnection(peerID)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPoolClosed))

	// Double close should be safe
	err = pool.Close()
	assert.NoError(t, err)
}

func TestConnectionPoolRecordStreamErrors(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	t.Run("record stream open on non-existent peer", func(t *testing.T) {
		peerID := generateTestPeerID(t, 999)
		err := pool.RecordStreamOpen(peerID)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPeerNotTracked))
	})

	t.Run("record stream open on closed pool", func(t *testing.T) {
		closedPool, err := NewConnectionPool(&PoolConfig{
			LowWatermark:            1,
			HighWatermark:           2,
			MaxConnectionsPerPeer:   1,
			MaxStreamsPerConnection: 1,
			GracePeriod:             0,
			IdleTimeout:             time.Hour,
			HealthCheckInterval:     0,
			CleanupInterval:         time.Hour,
		})
		require.NoError(t, err)
		require.NoError(t, closedPool.Close())

		peerID := generateTestPeerID(t, 1)
		err = closedPool.RecordStreamOpen(peerID)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPoolClosed))
	})

	t.Run("record stream close on non-existent peer is safe", func(t *testing.T) {
		peerID := generateTestPeerID(t, 999)
		// Should not panic
		pool.RecordStreamClose(peerID)
	})
}

func TestSessionPriorityString(t *testing.T) {
	tests := []struct {
		priority SessionPriority
		expected string
	}{
		{SessionPriorityLow, "low"},
		{SessionPriorityNormal, "normal"},
		{SessionPriorityHigh, "high"},
		{SessionPriorityCritical, "critical"},
		{SessionPriority(100), "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.priority.String())
		})
	}
}

func TestPoolError(t *testing.T) {
	t.Run("error with peer", func(t *testing.T) {
		peerID := generateTestPeerID(t, 1)
		err := &PoolError{
			Op:   "test",
			Peer: peerID,
			Err:  errors.New("underlying error"),
		}

		assert.Contains(t, err.Error(), "libp2p pool test")
		assert.Contains(t, err.Error(), "underlying error")
		assert.Equal(t, errors.New("underlying error"), err.Unwrap())
	})

	t.Run("error without peer", func(t *testing.T) {
		err := &PoolError{
			Op:  "test",
			Err: errors.New("underlying error"),
		}

		assert.Contains(t, err.Error(), "libp2p pool test")
		assert.Contains(t, err.Error(), "underlying error")
		assert.NotContains(t, err.Error(), "peer=")
	})
}

func TestConnectionPoolShouldReuseConnectionEdgeCases(t *testing.T) {
	t.Run("non-existent peer returns false", func(t *testing.T) {
		pool, err := NewConnectionPool(nil)
		require.NoError(t, err)
		defer func() { _ = pool.Close() }()

		peerID := generateTestPeerID(t, 1)
		assert.False(t, pool.ShouldReuseConnection(peerID))
	})

	t.Run("closed pool returns false", func(t *testing.T) {
		pool, err := NewConnectionPool(nil)
		require.NoError(t, err)

		peerID := generateTestPeerID(t, 1)
		err = pool.TrackConnection(peerID)
		require.NoError(t, err)

		require.NoError(t, pool.Close())
		assert.False(t, pool.ShouldReuseConnection(peerID))
	})

	t.Run("expired idle connection returns false", func(t *testing.T) {
		pool, err := NewConnectionPool(&PoolConfig{
			LowWatermark:            4,
			HighWatermark:           8,
			MaxConnectionsPerPeer:   2,
			MaxStreamsPerConnection: 10,
			GracePeriod:             0,
			IdleTimeout:             10 * time.Millisecond,
			HealthCheckInterval:     0,
			CleanupInterval:         time.Hour, // Don't cleanup automatically
		})
		require.NoError(t, err)
		defer func() { _ = pool.Close() }()

		peerID := generateTestPeerID(t, 1)
		err = pool.TrackConnection(peerID)
		require.NoError(t, err)

		// Wait for idle timeout
		time.Sleep(20 * time.Millisecond)

		// Should not reuse idle connection
		assert.False(t, pool.ShouldReuseConnection(peerID))
	})
}

func TestConnectionPoolGetPeerStreamCountNonExistent(t *testing.T) {
	pool, err := NewConnectionPool(nil)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 999)
	count := pool.GetPeerStreamCount(peerID)
	assert.Equal(t, 0, count)
}

func TestConnectionPoolGetPeerPriorityNonExistent(t *testing.T) {
	pool, err := NewConnectionPool(nil)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 999)
	priority := pool.GetPeerPriority(peerID)
	assert.Equal(t, SessionPriorityNormal, priority) // Default priority
}

func TestConnectionPoolUntagSessionNonExistent(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
		EnablePriorityTagging:   true,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Should not panic on non-existent peer
	peerID := generateTestPeerID(t, 999)
	pool.UntagSession(peerID, "session")
}

func TestConnectionPoolRecordActivityNonExistent(t *testing.T) {
	pool, err := NewConnectionPool(nil)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Should not panic on non-existent peer
	peerID := generateTestPeerID(t, 999)
	pool.RecordActivity(peerID)
}

// TestConnectionPoolNotifieeWithRealHosts tests the notifiee callbacks with real libp2p hosts.
func TestConnectionPoolNotifieeWithRealHosts(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           16,
		MaxConnectionsPerPeer:   4,
		MaxStreamsPerConnection: 256,
		GracePeriod:             0,
		IdleTimeout:             time.Minute,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Minute,
		EnablePriorityTagging:   true,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Create two hosts
	host1 := createPoolTestHost(t, pool)
	defer func() { _ = host1.Close() }()

	host2 := createPoolTestHost(t, nil)
	defer func() { _ = host2.Close() }()

	// Get host2's address info
	host2AddrInfo := peer.AddrInfo{
		ID:    host2.ID(),
		Addrs: host2.Addrs(),
	}

	// Initial state - no connections
	stats := pool.Stats()
	assert.Equal(t, 0, stats.ActivePeers)

	// Connect host1 to host2 - this should trigger Connected callback
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = host1.Connect(ctx, host2AddrInfo)
	require.NoError(t, err)

	// Wait briefly for connection to be established and notifiee to be called
	time.Sleep(100 * time.Millisecond)

	// Connected callback should have tracked the connection
	stats = pool.Stats()
	assert.GreaterOrEqual(t, stats.ActivePeers, 1, "Connection should be tracked after connect")
	assert.GreaterOrEqual(t, stats.TotalConnections, int64(1))

	// Verify we can find the peer
	assert.True(t, pool.ShouldReuseConnection(host2.ID()), "Should be able to reuse connection to host2")

	// Close the connection - this should trigger Disconnected callback
	err = host1.Network().ClosePeer(host2.ID())
	require.NoError(t, err)

	// Wait for disconnection to be processed
	time.Sleep(100 * time.Millisecond)

	// Disconnected callback should have untracked the connection
	stats = pool.Stats()
	assert.Equal(t, 0, stats.ActivePeers, "Connection should be untracked after disconnect")

	// Should no longer be able to reuse the connection
	assert.False(t, pool.ShouldReuseConnection(host2.ID()))
}

// TestConnectionPoolConnectedDisconnectedCallbacks tests Connected and Disconnected callbacks directly.
func TestConnectionPoolConnectedDisconnectedCallbacks(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           16,
		MaxConnectionsPerPeer:   4,
		MaxStreamsPerConnection: 256,
		GracePeriod:             0,
		IdleTimeout:             time.Minute,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Minute,
		EnablePriorityTagging:   true,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Create two hosts with pool notification on host1
	host1 := createPoolTestHost(t, pool)
	defer func() { _ = host1.Close() }()

	host2 := createPoolTestHost(t, nil)
	defer func() { _ = host2.Close() }()

	// Connect and verify tracking
	ctx := context.Background()
	host2Info := peer.AddrInfo{ID: host2.ID(), Addrs: host2.Addrs()}

	err = host1.Connect(ctx, host2Info)
	require.NoError(t, err)

	// Give time for connection events
	time.Sleep(50 * time.Millisecond)

	// Verify connection is tracked
	priority := pool.GetPeerPriority(host2.ID())
	assert.Equal(t, SessionPriorityNormal, priority)

	// Tag with session
	err = pool.TagSession(host2.ID(), "test-session", SessionPriorityHigh)
	require.NoError(t, err)
	assert.Equal(t, SessionPriorityHigh, pool.GetPeerPriority(host2.ID()))

	// Disconnect
	err = host1.Network().ClosePeer(host2.ID())
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// Peer should be untracked
	assert.Equal(t, 0, pool.Stats().ActivePeers)
}

// TestConnectionPoolListenListenCloseCallbacks tests the Listen and ListenClose callbacks.
func TestConnectionPoolListenListenCloseCallbacks(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           16,
		MaxConnectionsPerPeer:   4,
		MaxStreamsPerConnection: 256,
		GracePeriod:             0,
		IdleTimeout:             time.Minute,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Minute,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	notifiee := pool.Notifiee()
	require.NotNil(t, notifiee)

	// These are no-op implementations, but we verify they don't panic
	// and are properly called during host lifecycle
	h := createPoolTestHost(t, pool)

	// Closing host should trigger ListenClose for all addresses
	err = h.Close()
	require.NoError(t, err)

	// Verify pool is still functional after host close
	assert.False(t, pool.closed.Load())
}

// TestConnectionPoolRunHealthChecks tests the runHealthChecks function.
func TestConnectionPoolRunHealthChecks(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           16,
		MaxConnectionsPerPeer:   4,
		MaxStreamsPerConnection: 256,
		GracePeriod:             10 * time.Millisecond, // Short grace period
		IdleTimeout:             20 * time.Millisecond, // Short idle timeout
		HealthCheckInterval:     0,                     // Disable automatic health checks
		CleanupInterval:         time.Hour,             // Disable automatic cleanup
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Track a peer
	peerID := generateTestPeerID(t, 1)
	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// Initial health check failures should be 0
	stats := pool.Stats()
	assert.Equal(t, int64(0), stats.HealthCheckFailures)

	// Wait for grace period and idle timeout to expire
	time.Sleep(50 * time.Millisecond)

	// Manually run health checks
	pool.runHealthChecks()

	// Health check should detect the idle connection
	stats = pool.Stats()
	assert.GreaterOrEqual(t, stats.HealthCheckFailures, int64(1))
}

// TestConnectionPoolRunHealthChecksWithActiveStreams tests health checks skip connections with streams.
func TestConnectionPoolRunHealthChecksWithActiveStreams(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           16,
		MaxConnectionsPerPeer:   4,
		MaxStreamsPerConnection: 256,
		GracePeriod:             10 * time.Millisecond,
		IdleTimeout:             20 * time.Millisecond,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Track a peer with an active stream
	peerID := generateTestPeerID(t, 1)
	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	err = pool.RecordStreamOpen(peerID)
	require.NoError(t, err)

	// Wait for grace period and idle timeout to expire
	time.Sleep(50 * time.Millisecond)

	// Manually run health checks
	pool.runHealthChecks()

	// Should not increment failure count because stream is active
	stats := pool.Stats()
	assert.Equal(t, int64(0), stats.HealthCheckFailures)
}

// TestConnectionPoolRunHealthChecksWithinGracePeriod tests that connections in grace period are skipped.
func TestConnectionPoolRunHealthChecksWithinGracePeriod(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           16,
		MaxConnectionsPerPeer:   4,
		MaxStreamsPerConnection: 256,
		GracePeriod:             time.Hour, // Long grace period
		IdleTimeout:             time.Millisecond,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Track a peer
	peerID := generateTestPeerID(t, 1)
	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// Wait for idle timeout but not grace period
	time.Sleep(10 * time.Millisecond)

	// Manually run health checks
	pool.runHealthChecks()

	// Should not increment failure count because still in grace period
	stats := pool.Stats()
	assert.Equal(t, int64(0), stats.HealthCheckFailures)
}

// TestConnectionPoolHealthCheckLoopTriggersChecks tests the health check loop runs health checks.
func TestConnectionPoolHealthCheckLoopTriggersChecks(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           16,
		MaxConnectionsPerPeer:   4,
		MaxStreamsPerConnection: 256,
		GracePeriod:             5 * time.Millisecond,
		IdleTimeout:             10 * time.Millisecond,
		HealthCheckInterval:     20 * time.Millisecond, // Enable health check loop
		CleanupInterval:         time.Hour,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Track an idle peer
	peerID := generateTestPeerID(t, 1)
	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// Wait for health check to run
	time.Sleep(100 * time.Millisecond)

	// Health check loop should have detected the idle connection
	stats := pool.Stats()
	assert.GreaterOrEqual(t, stats.HealthCheckFailures, int64(1))
}

// TestConnectionPoolPriorityToWeight tests the priorityToWeight function with all priority levels.
func TestConnectionPoolPriorityToWeight(t *testing.T) {
	pool, err := NewConnectionPool(nil)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	tests := []struct {
		priority SessionPriority
		expected int
	}{
		{SessionPriorityLow, 10},
		{SessionPriorityNormal, 50},
		{SessionPriorityHigh, 100},
		{SessionPriorityCritical, 1000},
		{SessionPriority(99), 50},  // Unknown priority defaults to normal weight
		{SessionPriority(-1), 50},  // Invalid priority defaults to normal weight
		{SessionPriority(100), 50}, // Out of range defaults to normal weight
	}

	for _, tc := range tests {
		t.Run(tc.priority.String(), func(t *testing.T) {
			weight := pool.priorityToWeight(tc.priority)
			assert.Equal(t, tc.expected, weight)
		})
	}
}

// TestConnectionPoolCloseWithActiveConnections tests closing pool with active connections.
func TestConnectionPoolCloseWithActiveConnections(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           16,
		MaxConnectionsPerPeer:   4,
		MaxStreamsPerConnection: 256,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     10 * time.Millisecond,
		CleanupInterval:         10 * time.Millisecond,
	})
	require.NoError(t, err)

	// Track multiple peers with sessions and streams
	for i := 0; i < 5; i++ {
		peerID := generateTestPeerID(t, i)
		err := pool.TrackConnection(peerID)
		require.NoError(t, err)

		err = pool.RecordStreamOpen(peerID)
		require.NoError(t, err)

		err = pool.TagSession(peerID, "session", SessionPriorityHigh)
		require.NoError(t, err)
	}

	// Verify connections are tracked
	stats := pool.Stats()
	assert.Equal(t, 5, stats.ActivePeers)

	// Close should succeed
	err = pool.Close()
	assert.NoError(t, err)

	// Pool should be closed
	assert.True(t, pool.closed.Load())
}

// TestConnectionPoolUntagSessionWithPriorityTaggingDisabled tests UntagSession when tagging is disabled.
func TestConnectionPoolUntagSessionWithPriorityTaggingDisabled(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
		EnablePriorityTagging:   false, // Disabled
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 1)
	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// UntagSession should be a no-op when tagging is disabled
	pool.UntagSession(peerID, "some-session")

	// Should not panic and pool should still be functional
	assert.True(t, pool.ShouldReuseConnection(peerID))
}

// TestConnectionPoolMultipleHostsConnecting tests pool behavior with multiple hosts connecting.
func TestConnectionPoolMultipleHostsConnecting(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           16,
		MaxConnectionsPerPeer:   4,
		MaxStreamsPerConnection: 256,
		GracePeriod:             0,
		IdleTimeout:             time.Minute,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Minute,
		EnablePriorityTagging:   true,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	// Create main host with pool
	mainHost := createPoolTestHost(t, pool)
	defer func() { _ = mainHost.Close() }()

	// Create and connect multiple peer hosts
	const numPeers = 5
	peerHosts := make([]host.Host, numPeers)

	for i := 0; i < numPeers; i++ {
		peerHosts[i] = createPoolTestHost(t, nil)
		defer func(h host.Host) { _ = h.Close() }(peerHosts[i])

		peerInfo := peer.AddrInfo{
			ID:    peerHosts[i].ID(),
			Addrs: peerHosts[i].Addrs(),
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := mainHost.Connect(ctx, peerInfo)
		cancel()
		require.NoError(t, err)
	}

	// Wait for all connections to be established
	time.Sleep(100 * time.Millisecond)

	// All connections should be tracked
	stats := pool.Stats()
	assert.Equal(t, numPeers, stats.ActivePeers)
	assert.Equal(t, int64(numPeers), stats.TotalConnections)

	// Tag sessions with higher priorities (High and Critical will override default Normal)
	// Note: TagSession only updates priority if new priority is higher than current
	for i, h := range peerHosts {
		// Use High and Critical to ensure they override the default Normal priority
		priority := SessionPriorityHigh
		if i%2 == 0 {
			priority = SessionPriorityCritical
		}
		err := pool.TagSession(h.ID(), "session", priority)
		require.NoError(t, err)
		assert.Equal(t, priority, pool.GetPeerPriority(h.ID()))
	}

	// Disconnect all peers
	for _, h := range peerHosts {
		err := mainHost.Network().ClosePeer(h.ID())
		require.NoError(t, err)
	}

	time.Sleep(100 * time.Millisecond)

	// All connections should be untracked
	stats = pool.Stats()
	assert.Equal(t, 0, stats.ActivePeers)
}

// TestConnectionPoolRecalculatePriorityWithMultipleSessions tests priority recalculation.
func TestConnectionPoolRecalculatePriorityWithMultipleSessions(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{
		LowWatermark:            4,
		HighWatermark:           8,
		MaxConnectionsPerPeer:   2,
		MaxStreamsPerConnection: 10,
		GracePeriod:             0,
		IdleTimeout:             time.Hour,
		HealthCheckInterval:     0,
		CleanupInterval:         time.Hour,
		EnablePriorityTagging:   true,
	})
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	peerID := generateTestPeerID(t, 1)
	err = pool.TrackConnection(peerID)
	require.NoError(t, err)

	// Add multiple sessions with different priorities
	err = pool.TagSession(peerID, "session-low", SessionPriorityLow)
	require.NoError(t, err)

	err = pool.TagSession(peerID, "session-normal", SessionPriorityNormal)
	require.NoError(t, err)

	err = pool.TagSession(peerID, "session-high", SessionPriorityHigh)
	require.NoError(t, err)

	// Priority should be highest
	assert.Equal(t, SessionPriorityHigh, pool.GetPeerPriority(peerID))

	// Remove high priority session
	pool.UntagSession(peerID, "session-high")
	assert.Equal(t, SessionPriorityNormal, pool.GetPeerPriority(peerID))

	// Remove normal priority session
	pool.UntagSession(peerID, "session-normal")
	assert.Equal(t, SessionPriorityLow, pool.GetPeerPriority(peerID))

	// Remove low priority session - should go back to default (0 = Low from recalculate)
	pool.UntagSession(peerID, "session-low")
	assert.Equal(t, SessionPriorityLow, pool.GetPeerPriority(peerID))
}
