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

//go:build integration

package libp2p

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/libp2p/go-libp2p/core/peer"
)

// TestDefaultHostConfigWithPool tests DefaultHostConfigWithPool function.
func TestDefaultHostConfigWithPool(t *testing.T) {
	t.Run("returns config with pool enabled", func(t *testing.T) {
		cfg := DefaultHostConfigWithPool()
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if !cfg.EnableConnectionPool {
			t.Error("expected EnableConnectionPool to be true")
		}
		if !cfg.EnableNoise {
			t.Error("expected EnableNoise to be true")
		}
		if !cfg.EnableTLS {
			t.Error("expected EnableTLS to be true")
		}
		if cfg.EnableRelay {
			t.Error("expected EnableRelay to be false")
		}
		if cfg.EnablePubSub {
			t.Error("expected EnablePubSub to be false")
		}
		if len(cfg.ListenAddrs) != 1 || cfg.ListenAddrs[0] != "/ip4/0.0.0.0/tcp/0" {
			t.Error("expected default listen address")
		}
	})

	t.Run("creates host with pool", func(t *testing.T) {
		ctx := context.Background()
		cfg := DefaultHostConfigWithPool()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasConnectionPool() {
			t.Error("expected host to have connection pool")
		}
		if host.ConnectionPool() == nil {
			t.Error("expected ConnectionPool to return non-nil")
		}
	})
}

// TestDefaultHostConfigWithQoS tests DefaultHostConfigWithQoS function.
func TestDefaultHostConfigWithQoS(t *testing.T) {
	t.Run("returns config with QoS enabled", func(t *testing.T) {
		cfg := DefaultHostConfigWithQoS()
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if !cfg.EnableQoS {
			t.Error("expected EnableQoS to be true")
		}
		if !cfg.EnableNoise {
			t.Error("expected EnableNoise to be true")
		}
		if !cfg.EnableTLS {
			t.Error("expected EnableTLS to be true")
		}
		if cfg.EnableRelay {
			t.Error("expected EnableRelay to be false")
		}
		if cfg.EnablePubSub {
			t.Error("expected EnablePubSub to be false")
		}
		if cfg.EnableConnectionPool {
			t.Error("expected EnableConnectionPool to be false")
		}
	})

	t.Run("creates host with QoS", func(t *testing.T) {
		ctx := context.Background()
		cfg := DefaultHostConfigWithQoS()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasQoS() {
			t.Error("expected host to have QoS")
		}
		if host.QoSManager() == nil {
			t.Error("expected QoSManager to return non-nil")
		}
	})
}

// TestDefaultHostConfigWithPubSub tests DefaultHostConfigWithPubSub function.
func TestDefaultHostConfigWithPubSub(t *testing.T) {
	t.Run("returns config with PubSub enabled", func(t *testing.T) {
		cfg := DefaultHostConfigWithPubSub()
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if !cfg.EnablePubSub {
			t.Error("expected EnablePubSub to be true")
		}
		if cfg.PubSubConfig == nil {
			t.Error("expected PubSubConfig to be non-nil")
		}
		if !cfg.EnableNoise {
			t.Error("expected EnableNoise to be true")
		}
		if !cfg.EnableTLS {
			t.Error("expected EnableTLS to be true")
		}
		if cfg.EnableRelay {
			t.Error("expected EnableRelay to be false")
		}
	})

	t.Run("PubSubConfig has default values", func(t *testing.T) {
		cfg := DefaultHostConfigWithPubSub()
		if cfg.PubSubConfig.EnableGossipSub != true {
			t.Error("expected EnableGossipSub to be true in default config")
		}
	})
}

// TestDefaultHostConfigWithRelay tests DefaultHostConfigWithRelay function.
func TestDefaultHostConfigWithRelay(t *testing.T) {
	t.Run("returns config with relay enabled", func(t *testing.T) {
		cfg := DefaultHostConfigWithRelay()
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if cfg.RelayConfig == nil {
			t.Error("expected RelayConfig to be non-nil")
		}
		if !cfg.RelayConfig.EnableRelay {
			t.Error("expected RelayConfig.EnableRelay to be true")
		}
		if !cfg.EnableNoise {
			t.Error("expected EnableNoise to be true")
		}
		if !cfg.EnableTLS {
			t.Error("expected EnableTLS to be true")
		}
		if cfg.EnablePubSub {
			t.Error("expected EnablePubSub to be false")
		}
	})

	t.Run("RelayConfig has default values", func(t *testing.T) {
		cfg := DefaultHostConfigWithRelay()
		defaultRelay := DefaultRelayConfig()
		if cfg.RelayConfig.ReservationTTL != defaultRelay.ReservationTTL {
			t.Error("expected default ReservationTTL")
		}
		if cfg.RelayConfig.ReservationRefreshInterval != defaultRelay.ReservationRefreshInterval {
			t.Error("expected default ReservationRefreshInterval")
		}
		if cfg.RelayConfig.MaxReservations != defaultRelay.MaxReservations {
			t.Error("expected default MaxReservations")
		}
	})
}

// TestDefaultHostConfigFull tests DefaultHostConfigFull function.
func TestDefaultHostConfigFull(t *testing.T) {
	t.Run("returns config with all features enabled", func(t *testing.T) {
		cfg := DefaultHostConfigFull()
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if !cfg.EnableNoise {
			t.Error("expected EnableNoise to be true")
		}
		if !cfg.EnableTLS {
			t.Error("expected EnableTLS to be true")
		}
		if !cfg.EnablePubSub {
			t.Error("expected EnablePubSub to be true")
		}
		if cfg.PubSubConfig == nil {
			t.Error("expected PubSubConfig to be non-nil")
		}
		if !cfg.EnableConnectionPool {
			t.Error("expected EnableConnectionPool to be true")
		}
		if !cfg.EnableQoS {
			t.Error("expected EnableQoS to be true")
		}
	})

	t.Run("creates host with all features", func(t *testing.T) {
		ctx := context.Background()
		cfg := DefaultHostConfigFull()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasConnectionPool() {
			t.Error("expected host to have connection pool")
		}
		if !host.HasQoS() {
			t.Error("expected host to have QoS")
		}
	})
}

// TestNewHostWithConnectionPool tests NewHost with connection pool configuration.
func TestNewHostWithConnectionPool(t *testing.T) {
	ctx := context.Background()

	t.Run("with EnableConnectionPool flag", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.EnableConnectionPool = true

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasConnectionPool() {
			t.Error("expected connection pool to be enabled")
		}
	})

	t.Run("with explicit ConnectionPool config", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.ConnectionPool = DefaultPoolConfig()
		cfg.ConnectionPool.LowWatermark = 32
		cfg.ConnectionPool.HighWatermark = 64

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasConnectionPool() {
			t.Error("expected connection pool to be enabled")
		}
	})
}

// TestNewHostWithQoS tests NewHost with QoS configuration.
func TestNewHostWithQoS(t *testing.T) {
	ctx := context.Background()

	t.Run("with EnableQoS flag", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.EnableQoS = true

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasQoS() {
			t.Error("expected QoS to be enabled")
		}
	})

	t.Run("with explicit QoS config", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.QoS = DefaultQoSConfig()
		cfg.QoS.MaxBandwidthIn = 1024 * 1024

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasQoS() {
			t.Error("expected QoS to be enabled")
		}
	})
}

// TestNewHostWithRelayConfig tests NewHost with advanced relay configuration.
func TestNewHostWithRelayConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("with RelayConfig takes precedence over EnableRelay", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.EnableRelay = false // This should be ignored
		cfg.RelayConfig = &RelayConfig{
			EnableRelay: true,
		}

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasRelay() {
			t.Error("expected relay to be enabled via RelayConfig")
		}
	})

	t.Run("relay addresses empty without reservations", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.RelayConfig = &RelayConfig{
			EnableRelay: true,
		}

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		addrs := host.GetRelayAddresses()
		if addrs == nil {
			t.Error("expected non-nil slice (empty is ok)")
		}
	})
}

// TestHostCloseWithComponents tests Close with various components enabled.
func TestHostCloseWithComponents(t *testing.T) {
	ctx := context.Background()

	t.Run("close with connection pool", func(t *testing.T) {
		cfg := DefaultHostConfigWithPool()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}

		if err := host.Close(); err != nil {
			t.Errorf("failed to close host with pool: %v", err)
		}
	})

	t.Run("close with QoS", func(t *testing.T) {
		cfg := DefaultHostConfigWithQoS()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}

		if err := host.Close(); err != nil {
			t.Errorf("failed to close host with QoS: %v", err)
		}
	})

	t.Run("close with relay", func(t *testing.T) {
		cfg := DefaultHostConfigWithRelay()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}

		if err := host.Close(); err != nil {
			t.Errorf("failed to close host with relay: %v", err)
		}
	})

	t.Run("close with all components", func(t *testing.T) {
		cfg := DefaultHostConfigFull()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}

		if err := host.Close(); err != nil {
			t.Errorf("failed to close host with all components: %v", err)
		}
	})
}

// TestHostConnectionPoolAccessors tests ConnectionPool and HasConnectionPool methods.
func TestHostConnectionPoolAccessors(t *testing.T) {
	ctx := context.Background()

	t.Run("without pool", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if host.HasConnectionPool() {
			t.Error("expected HasConnectionPool to return false")
		}
		if host.ConnectionPool() != nil {
			t.Error("expected ConnectionPool to return nil")
		}
	})

	t.Run("with pool", func(t *testing.T) {
		cfg := DefaultHostConfigWithPool()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasConnectionPool() {
			t.Error("expected HasConnectionPool to return true")
		}
		pool := host.ConnectionPool()
		if pool == nil {
			t.Error("expected ConnectionPool to return non-nil")
		}
	})
}

// TestHostQoSAccessors tests QoSManager and HasQoS methods.
func TestHostQoSAccessors(t *testing.T) {
	ctx := context.Background()

	t.Run("without QoS", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if host.HasQoS() {
			t.Error("expected HasQoS to return false")
		}
		if host.QoSManager() != nil {
			t.Error("expected QoSManager to return nil")
		}
	})

	t.Run("with QoS", func(t *testing.T) {
		cfg := DefaultHostConfigWithQoS()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasQoS() {
			t.Error("expected HasQoS to return true")
		}
		qm := host.QoSManager()
		if qm == nil {
			t.Error("expected QoSManager to return non-nil")
		}
	})
}

// TestHostRelayAccessors tests RelayManager, HasRelay, and GetRelayAddresses methods.
func TestHostRelayAccessors(t *testing.T) {
	ctx := context.Background()

	t.Run("without relay", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if host.HasRelay() {
			t.Error("expected HasRelay to return false")
		}
		if host.RelayManager() != nil {
			t.Error("expected RelayManager to return nil")
		}
		if host.GetRelayAddresses() != nil {
			t.Error("expected GetRelayAddresses to return nil when relay disabled")
		}
	})

	t.Run("with relay", func(t *testing.T) {
		cfg := DefaultHostConfigWithRelay()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasRelay() {
			t.Error("expected HasRelay to return true")
		}
		rm := host.RelayManager()
		if rm == nil {
			t.Error("expected RelayManager to return non-nil")
		}
		// GetRelayAddresses returns empty slice (no reservations yet)
		addrs := host.GetRelayAddresses()
		if addrs == nil {
			t.Error("expected GetRelayAddresses to return non-nil slice")
		}
	})
}

// TestHostTagSession tests TagSession method.
func TestHostTagSession(t *testing.T) {
	ctx := context.Background()

	t.Run("without pool returns nil", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		// Should return nil when no pool
		err = host.TagSession(peer.ID("test-peer"), "session-1", SessionPriorityHigh)
		if err != nil {
			t.Errorf("expected nil error without pool, got: %v", err)
		}
	})

	t.Run("with pool and untracked peer", func(t *testing.T) {
		cfg := DefaultHostConfigWithPool()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		// Should return error for untracked peer
		err = host.TagSession(peer.ID("unknown-peer"), "session-1", SessionPriorityHigh)
		if err == nil {
			t.Error("expected error for untracked peer")
		}
	})

	t.Run("with pool and tracked peer", func(t *testing.T) {
		cfg := DefaultHostConfigWithPool()
		cfg.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}

		host1, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host1: %v", err)
		}
		defer func() { _ = host1.Close() }()

		host2, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host2: %v", err)
		}
		defer func() { _ = host2.Close() }()

		// Connect hosts
		addr := host1.AddrStrings()[0]
		_, err = host2.Connect(ctx, addr)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}

		// Wait for connection to be tracked
		time.Sleep(100 * time.Millisecond)

		// Tag session for connected peer
		err = host2.TagSession(host1.ID(), "session-1", SessionPriorityHigh)
		if err != nil {
			t.Errorf("failed to tag session: %v", err)
		}
	})
}

// TestHostUntagSession tests UntagSession method.
func TestHostUntagSession(t *testing.T) {
	ctx := context.Background()

	t.Run("without pool does nothing", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		// Should not panic
		host.UntagSession(peer.ID("test-peer"), "session-1")
	})

	t.Run("with pool and untracked peer", func(t *testing.T) {
		cfg := DefaultHostConfigWithPool()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		// Should not panic
		host.UntagSession(peer.ID("unknown-peer"), "session-1")
	})
}

// TestHostRecordActivity tests RecordActivity method.
func TestHostRecordActivity(t *testing.T) {
	ctx := context.Background()

	t.Run("without pool does nothing", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		// Should not panic
		host.RecordActivity(peer.ID("test-peer"))
	})

	t.Run("with pool and connected peer", func(t *testing.T) {
		cfg := DefaultHostConfigWithPool()
		cfg.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}

		host1, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host1: %v", err)
		}
		defer func() { _ = host1.Close() }()

		host2, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host2: %v", err)
		}
		defer func() { _ = host2.Close() }()

		// Connect hosts
		addr := host1.AddrStrings()[0]
		_, err = host2.Connect(ctx, addr)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}

		// Wait for connection
		time.Sleep(100 * time.Millisecond)

		// Record activity should not panic
		host2.RecordActivity(host1.ID())
	})
}

// TestHostConnectionPoolStats tests ConnectionPoolStats method.
func TestHostConnectionPoolStats(t *testing.T) {
	ctx := context.Background()

	t.Run("without pool returns zero stats", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		stats := host.ConnectionPoolStats()
		if stats.ActivePeers != 0 {
			t.Errorf("expected zero active peers, got %d", stats.ActivePeers)
		}
		if stats.TotalConnections != 0 {
			t.Errorf("expected zero total connections, got %d", stats.TotalConnections)
		}
	})

	t.Run("with pool returns stats", func(t *testing.T) {
		cfg := DefaultHostConfigWithPool()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		stats := host.ConnectionPoolStats()
		// Initially should be zero
		if stats.ActivePeers != 0 {
			t.Errorf("expected zero active peers initially, got %d", stats.ActivePeers)
		}
	})
}

// TestHostQoSStats tests QoSStats method.
func TestHostQoSStats(t *testing.T) {
	ctx := context.Background()

	t.Run("without QoS returns zero stats", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		stats := host.QoSStats()
		if stats.TotalBytesIn != 0 {
			t.Errorf("expected zero bytes in, got %d", stats.TotalBytesIn)
		}
		if stats.TotalBytesOut != 0 {
			t.Errorf("expected zero bytes out, got %d", stats.TotalBytesOut)
		}
	})

	t.Run("with QoS returns stats", func(t *testing.T) {
		cfg := DefaultHostConfigWithQoS()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		stats := host.QoSStats()
		// Initially should be zero
		if stats.TotalBytesIn != 0 {
			t.Errorf("expected zero bytes in initially, got %d", stats.TotalBytesIn)
		}
	})
}

// TestHostAllowIncoming tests AllowIncoming method.
func TestHostAllowIncoming(t *testing.T) {
	ctx := context.Background()

	t.Run("without QoS returns nil", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		err = host.AllowIncoming(ctx, peer.ID("test-peer"), 1024)
		if err != nil {
			t.Errorf("expected nil error without QoS, got: %v", err)
		}
	})

	t.Run("with QoS allows traffic", func(t *testing.T) {
		cfg := DefaultHostConfigWithQoS()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		// Default config has unlimited bandwidth
		err = host.AllowIncoming(ctx, peer.ID("test-peer"), 1024)
		if err != nil {
			t.Errorf("expected traffic to be allowed: %v", err)
		}
	})

	t.Run("with QoS bandwidth limit", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.QoS = &QoSConfig{
			MaxBandwidthIn: 100,
			BurstSize:      100,
		}

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		// First request should succeed
		err = host.AllowIncoming(ctx, peer.ID("test-peer"), 50)
		if err != nil {
			t.Errorf("first request should succeed: %v", err)
		}

		// Large request should fail
		err = host.AllowIncoming(ctx, peer.ID("test-peer"), 200)
		if err == nil {
			t.Error("expected bandwidth exceeded error")
		}
	})
}

// TestHostAllowOutgoing tests AllowOutgoing method.
func TestHostAllowOutgoing(t *testing.T) {
	ctx := context.Background()

	t.Run("without QoS returns nil", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		err = host.AllowOutgoing(ctx, peer.ID("test-peer"), 1024)
		if err != nil {
			t.Errorf("expected nil error without QoS, got: %v", err)
		}
	})

	t.Run("with QoS allows traffic", func(t *testing.T) {
		cfg := DefaultHostConfigWithQoS()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		err = host.AllowOutgoing(ctx, peer.ID("test-peer"), 1024)
		if err != nil {
			t.Errorf("expected traffic to be allowed: %v", err)
		}
	})

	t.Run("with QoS bandwidth limit", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.QoS = &QoSConfig{
			MaxBandwidthOut: 100,
			BurstSize:       100,
		}

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		// First request should succeed
		err = host.AllowOutgoing(ctx, peer.ID("test-peer"), 50)
		if err != nil {
			t.Errorf("first request should succeed: %v", err)
		}

		// Large request should fail
		err = host.AllowOutgoing(ctx, peer.ID("test-peer"), 200)
		if err == nil {
			t.Error("expected bandwidth exceeded error")
		}
	})
}

// TestHostWaitIncoming tests WaitIncoming method.
func TestHostWaitIncoming(t *testing.T) {
	ctx := context.Background()

	t.Run("without QoS returns nil", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		err = host.WaitIncoming(ctx, peer.ID("test-peer"), 1024)
		if err != nil {
			t.Errorf("expected nil error without QoS, got: %v", err)
		}
	})

	t.Run("with QoS waits for bandwidth", func(t *testing.T) {
		cfg := DefaultHostConfigWithQoS()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		err = host.WaitIncoming(ctx, peer.ID("test-peer"), 1024)
		if err != nil {
			t.Errorf("expected wait to succeed: %v", err)
		}
	})

	t.Run("with context cancellation", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.QoS = &QoSConfig{
			MaxBandwidthIn:      1,
			BurstSize:           1,
			BackpressureTimeout: 50 * time.Millisecond,
		}

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		err = host.WaitIncoming(cancelCtx, peer.ID("test-peer"), 10000)
		if err == nil {
			t.Error("expected error with cancelled context")
		}
	})
}

// TestHostWaitOutgoing tests WaitOutgoing method.
func TestHostWaitOutgoing(t *testing.T) {
	ctx := context.Background()

	t.Run("without QoS returns nil", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		err = host.WaitOutgoing(ctx, peer.ID("test-peer"), 1024)
		if err != nil {
			t.Errorf("expected nil error without QoS, got: %v", err)
		}
	})

	t.Run("with QoS waits for bandwidth", func(t *testing.T) {
		cfg := DefaultHostConfigWithQoS()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		err = host.WaitOutgoing(ctx, peer.ID("test-peer"), 1024)
		if err != nil {
			t.Errorf("expected wait to succeed: %v", err)
		}
	})

	t.Run("with context cancellation", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.QoS = &QoSConfig{
			MaxBandwidthOut:     1,
			BurstSize:           1,
			BackpressureTimeout: 50 * time.Millisecond,
		}

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		err = host.WaitOutgoing(cancelCtx, peer.ID("test-peer"), 10000)
		if err == nil {
			t.Error("expected error with cancelled context")
		}
	})
}

// TestHostEnqueueMessage tests EnqueueMessage method.
func TestHostEnqueueMessage(t *testing.T) {
	ctx := context.Background()

	t.Run("without QoS returns nil", func(t *testing.T) {
		cfg := DefaultHostConfig()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		err = host.EnqueueMessage([]byte("test"), peer.ID("test-peer"), transport.MsgTypeRound1)
		if err != nil {
			t.Errorf("expected nil error without QoS, got: %v", err)
		}
	})

	t.Run("with QoS enqueues message", func(t *testing.T) {
		cfg := DefaultHostConfigWithQoS()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		err = host.EnqueueMessage([]byte("test"), peer.ID("test-peer"), transport.MsgTypeRound1)
		if err != nil {
			t.Errorf("expected message to be enqueued: %v", err)
		}

		// Verify queue length increased
		stats := host.QoSStats()
		if stats.QueueLength != 1 {
			t.Errorf("expected queue length 1, got %d", stats.QueueLength)
		}
	})

	t.Run("with QoS queue full", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.QoS = &QoSConfig{
			QueueSize:            1,
			EnablePrioritization: true,
		}

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		// Fill the queue
		err = host.EnqueueMessage([]byte("test1"), peer.ID("test-peer"), transport.MsgTypeRound1)
		if err != nil {
			t.Fatalf("first enqueue should succeed: %v", err)
		}

		// Second should fail
		err = host.EnqueueMessage([]byte("test2"), peer.ID("test-peer"), transport.MsgTypeRound1)
		if err == nil {
			t.Error("expected queue full error")
		}
	})

	t.Run("different message types have different priorities", func(t *testing.T) {
		cfg := DefaultHostConfigWithQoS()

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		// Enqueue messages of different types
		msgTypes := []transport.MessageType{
			transport.MsgTypeJoin,
			transport.MsgTypeSessionInfo, // Critical
			transport.MsgTypeRound1,      // High
			transport.MsgTypeError,       // Critical
		}

		for _, msgType := range msgTypes {
			err = host.EnqueueMessage([]byte("test"), peer.ID("test-peer"), msgType)
			if err != nil {
				t.Errorf("failed to enqueue message type %d: %v", msgType, err)
			}
		}

		stats := host.QoSStats()
		if stats.QueueLength != len(msgTypes) {
			t.Errorf("expected queue length %d, got %d", len(msgTypes), stats.QueueLength)
		}
	})
}

// TestNewHostErrorPaths tests NewHost error handling paths.
func TestNewHostErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid pool config cleans up", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.ConnectionPool = &PoolConfig{
			LowWatermark:            0, // Invalid
			HighWatermark:           10,
			MaxConnectionsPerPeer:   1,
			MaxStreamsPerConnection: 1,
		}

		_, err := NewHost(ctx, cfg)
		if err == nil {
			t.Error("expected error with invalid pool config")
		}
	})

	t.Run("invalid QoS config cleans up", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.QoS = &QoSConfig{
			MaxBandwidthIn: -1, // Invalid
		}

		_, err := NewHost(ctx, cfg)
		if err == nil {
			t.Error("expected error with invalid QoS config")
		}
	})

	t.Run("invalid TLS config cleans up", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.TLSCertFile = "/nonexistent/cert.pem"
		cfg.TLSKeyFile = "/nonexistent/key.pem"

		_, err := NewHost(ctx, cfg)
		if err == nil {
			t.Error("expected error with invalid TLS config")
		}
	})

	t.Run("invalid CA only config cleans up", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.TLSCAFile = "/nonexistent/ca.pem"

		_, err := NewHost(ctx, cfg)
		if err == nil {
			t.Error("expected error with invalid CA config")
		}
	})
}

// TestHostWithPoolAndQoS tests host with both pool and QoS enabled.
func TestHostWithPoolAndQoS(t *testing.T) {
	ctx := context.Background()

	t.Run("both components work together", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.EnableConnectionPool = true
		cfg.EnableQoS = true
		cfg.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}

		host1, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host1: %v", err)
		}
		defer func() { _ = host1.Close() }()

		host2, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host2: %v", err)
		}
		defer func() { _ = host2.Close() }()

		if !host1.HasConnectionPool() {
			t.Error("expected host1 to have connection pool")
		}
		if !host1.HasQoS() {
			t.Error("expected host1 to have QoS")
		}

		// Connect hosts
		addr := host1.AddrStrings()[0]
		_, err = host2.Connect(ctx, addr)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}

		// Wait for connection
		time.Sleep(100 * time.Millisecond)

		// Check pool stats
		stats := host2.ConnectionPoolStats()
		if stats.TotalConnections == 0 {
			t.Error("expected at least one connection in pool stats")
		}

		// QoS operations should work
		err = host2.AllowOutgoing(ctx, host1.ID(), 100)
		if err != nil {
			t.Errorf("AllowOutgoing failed: %v", err)
		}
	})
}
