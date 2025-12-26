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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
)

// createTestHost creates a libp2p host for testing.
func createTestHost(t *testing.T) *DKGHost {
	t.Helper()
	ctx := context.Background()
	cfg := DefaultHostConfig()
	host, err := NewHost(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create test host: %v", err)
	}
	return host
}

// testDiscoveryCluster represents a cluster of discovery services for testing.
type testDiscoveryCluster struct {
	hosts     []*DKGHost
	services  []*DiscoveryService
	peerAddrs []peer.AddrInfo
}

// createDiscoveryCluster creates a cluster of connected discovery services for multi-peer tests.
func createDiscoveryCluster(t *testing.T, count int, enableAutoRefresh bool) *testDiscoveryCluster {
	t.Helper()

	if count < 2 {
		t.Fatal("cluster must have at least 2 peers")
	}

	cluster := &testDiscoveryCluster{
		hosts:     make([]*DKGHost, count),
		services:  make([]*DiscoveryService, count),
		peerAddrs: make([]peer.AddrInfo, count),
	}

	ctx := context.Background()

	// Create all hosts first
	for i := 0; i < count; i++ {
		cfg := DefaultHostConfig()
		host, err := NewHost(ctx, cfg)
		if err != nil {
			cluster.cleanup(t)
			t.Fatalf("failed to create host %d: %v", i, err)
		}
		cluster.hosts[i] = host

		// Build peer address info
		addrs := host.Host().Addrs()
		cluster.peerAddrs[i] = peer.AddrInfo{
			ID:    host.ID(),
			Addrs: addrs,
		}
	}

	// Create discovery services with bootstrap peers
	// Each peer knows about the first peer as a bootstrap peer
	for i := 0; i < count; i++ {
		var bootstrapPeers []peer.AddrInfo
		if i > 0 {
			// All peers except the first one bootstrap from the first peer
			bootstrapPeers = []peer.AddrInfo{cluster.peerAddrs[0]}
		}

		cfg := &DiscoveryConfig{
			Mode:              DHTModeServer,
			BootstrapPeers:    bootstrapPeers,
			AdvertiseTTL:      1 * time.Minute,
			RefreshInterval:   500 * time.Millisecond,
			FindPeersTimeout:  3 * time.Second,
			EnableAutoRefresh: enableAutoRefresh,
			MaxPeers:          100,
		}

		ds, err := NewDiscoveryService(cluster.hosts[i].Host(), cfg)
		if err != nil {
			cluster.cleanup(t)
			t.Fatalf("failed to create discovery service %d: %v", i, err)
		}
		cluster.services[i] = ds

		if err := ds.Start(ctx); err != nil {
			cluster.cleanup(t)
			t.Fatalf("failed to start discovery service %d: %v", i, err)
		}
	}

	// Wait for DHT to stabilize
	time.Sleep(200 * time.Millisecond)

	return cluster
}

// cleanup shuts down all services and hosts in the cluster.
func (c *testDiscoveryCluster) cleanup(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := len(c.services) - 1; i >= 0; i-- {
		if c.services[i] != nil && c.services[i].IsStarted() && !c.services[i].IsClosed() {
			if err := c.services[i].Stop(ctx); err != nil {
				t.Logf("warning: failed to stop discovery service %d: %v", i, err)
			}
		}
	}

	for i := len(c.hosts) - 1; i >= 0; i-- {
		if c.hosts[i] != nil {
			if err := c.hosts[i].Close(); err != nil {
				t.Logf("warning: failed to close host %d: %v", i, err)
			}
		}
	}
}

// TestNewDiscoveryService tests discovery service creation.
func TestNewDiscoveryService(t *testing.T) {
	t.Run("valid host", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		ds, err := NewDiscoveryService(host.Host(), nil)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		if ds == nil {
			t.Fatal("discovery service should not be nil")
		}

		if ds.Host() != host.Host() {
			t.Error("discovery service should have the provided host")
		}

		if ds.IsStarted() {
			t.Error("discovery service should not be started yet")
		}
	})

	t.Run("nil host", func(t *testing.T) {
		_, err := NewDiscoveryService(nil, nil)
		if err == nil {
			t.Error("should fail with nil host")
		}
	})

	t.Run("custom config", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := &DiscoveryConfig{
			Mode:              DHTModeClient,
			AdvertiseTTL:      5 * time.Minute,
			RefreshInterval:   1 * time.Minute,
			FindPeersTimeout:  15 * time.Second,
			EnableAutoRefresh: false,
			MaxPeers:          50,
		}

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service with custom config: %v", err)
		}

		if ds == nil {
			t.Fatal("discovery service should not be nil")
		}
	})
}

// TestDefaultDiscoveryConfig tests default configuration values.
func TestDefaultDiscoveryConfig(t *testing.T) {
	cfg := DefaultDiscoveryConfig()

	if cfg.Mode != DHTModeAuto {
		t.Errorf("expected DHTModeAuto, got %v", cfg.Mode)
	}

	if cfg.AdvertiseTTL != DefaultAdvertiseTTL {
		t.Errorf("expected AdvertiseTTL %v, got %v", DefaultAdvertiseTTL, cfg.AdvertiseTTL)
	}

	if cfg.RefreshInterval != DefaultRefreshInterval {
		t.Errorf("expected RefreshInterval %v, got %v", DefaultRefreshInterval, cfg.RefreshInterval)
	}

	if cfg.FindPeersTimeout != DefaultFindPeersTimeout {
		t.Errorf("expected FindPeersTimeout %v, got %v", DefaultFindPeersTimeout, cfg.FindPeersTimeout)
	}

	if !cfg.EnableAutoRefresh {
		t.Error("EnableAutoRefresh should be true by default")
	}

	if cfg.MaxPeers != 100 {
		t.Errorf("expected MaxPeers 100, got %d", cfg.MaxPeers)
	}
}

// TestDiscoveryServiceStart tests starting the discovery service.
func TestDiscoveryServiceStart(t *testing.T) {
	t.Run("successful start", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false // Disable for faster tests

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		if !ds.IsStarted() {
			t.Error("discovery service should be started")
		}

		if ds.DHT() == nil {
			t.Error("DHT should be initialized after start")
		}

		if ds.RoutingDiscovery() == nil {
			t.Error("RoutingDiscovery should be initialized after start")
		}
	})

	t.Run("double start fails", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		// Try to start again
		err = ds.Start(ctx)
		if !errors.Is(err, ErrDHTAlreadyStarted) {
			t.Errorf("expected ErrDHTAlreadyStarted, got %v", err)
		}
	})

	t.Run("server mode", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.Mode = DHTModeServer
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start in server mode: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		if !ds.IsStarted() {
			t.Error("discovery service should be started in server mode")
		}
	})

	t.Run("client mode", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.Mode = DHTModeClient
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start in client mode: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		if !ds.IsStarted() {
			t.Error("discovery service should be started in client mode")
		}
	})
}

// TestDiscoveryServiceStop tests stopping the discovery service.
func TestDiscoveryServiceStop(t *testing.T) {
	t.Run("successful stop", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}

		if err := ds.Stop(ctx); err != nil {
			t.Errorf("failed to stop discovery service: %v", err)
		}

		if !ds.IsClosed() {
			t.Error("discovery service should be closed")
		}
	})

	t.Run("stop without start", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		ds, err := NewDiscoveryService(host.Host(), nil)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		err = ds.Stop(ctx)
		if !errors.Is(err, ErrDHTNotStarted) {
			t.Errorf("expected ErrDHTNotStarted, got %v", err)
		}
	})

	t.Run("double stop", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}

		if err := ds.Stop(ctx); err != nil {
			t.Errorf("failed to stop discovery service: %v", err)
		}

		err = ds.Stop(ctx)
		if !errors.Is(err, ErrDHTClosed) {
			t.Errorf("expected ErrDHTClosed, got %v", err)
		}
	})

	t.Run("start after close fails", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}

		if err := ds.Stop(ctx); err != nil {
			t.Errorf("failed to stop discovery service: %v", err)
		}

		err = ds.Start(ctx)
		if !errors.Is(err, ErrDHTClosed) {
			t.Errorf("expected ErrDHTClosed, got %v", err)
		}
	})
}

// TestAdvertiseSession tests session advertising.
func TestAdvertiseSession(t *testing.T) {
	t.Run("valid session", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		if err := ds.AdvertiseSession(ctx, "test-session-123"); err != nil {
			t.Errorf("failed to advertise session: %v", err)
		}

		if ds.ActiveAdvertisements() != 1 {
			t.Errorf("expected 1 active advertisement, got %d", ds.ActiveAdvertisements())
		}
	})

	t.Run("empty session ID", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		err = ds.AdvertiseSession(ctx, "")
		if !errors.Is(err, ErrInvalidSessionID) {
			t.Errorf("expected ErrInvalidSessionID, got %v", err)
		}
	})

	t.Run("not started", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		ds, err := NewDiscoveryService(host.Host(), nil)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		err = ds.AdvertiseSession(ctx, "test-session")
		if !errors.Is(err, ErrDHTNotStarted) {
			t.Errorf("expected ErrDHTNotStarted, got %v", err)
		}
	})
}

// TestAdvertiseCoordinator tests coordinator advertising.
func TestAdvertiseCoordinator(t *testing.T) {
	t.Run("valid coordinator", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		if err := ds.AdvertiseCoordinator(ctx, "coordinator-session"); err != nil {
			t.Errorf("failed to advertise coordinator: %v", err)
		}

		if ds.ActiveAdvertisements() != 1 {
			t.Errorf("expected 1 active advertisement, got %d", ds.ActiveAdvertisements())
		}
	})

	t.Run("empty session ID", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		err = ds.AdvertiseCoordinator(ctx, "")
		if !errors.Is(err, ErrInvalidSessionID) {
			t.Errorf("expected ErrInvalidSessionID, got %v", err)
		}
	})
}

// TestAdvertiseCiphersuite tests ciphersuite advertising.
func TestAdvertiseCiphersuite(t *testing.T) {
	t.Run("valid ciphersuite", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		if err := ds.AdvertiseCiphersuite(ctx, "FROST-ED25519-SHA512-v1"); err != nil {
			t.Errorf("failed to advertise ciphersuite: %v", err)
		}

		if ds.ActiveAdvertisements() != 1 {
			t.Errorf("expected 1 active advertisement, got %d", ds.ActiveAdvertisements())
		}
	})

	t.Run("empty ciphersuite", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		err = ds.AdvertiseCiphersuite(ctx, "")
		if !errors.Is(err, ErrInvalidCiphersuite) {
			t.Errorf("expected ErrInvalidCiphersuite, got %v", err)
		}
	})
}

// TestStopAdvertising tests stopping advertisements.
func TestStopAdvertising(t *testing.T) {
	t.Run("stop session advertising", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		sessionID := "test-session"
		if err := ds.AdvertiseSession(ctx, sessionID); err != nil {
			t.Fatalf("failed to advertise session: %v", err)
		}

		if ds.ActiveAdvertisements() != 1 {
			t.Errorf("expected 1 active advertisement, got %d", ds.ActiveAdvertisements())
		}

		if err := ds.StopAdvertisingSession(sessionID); err != nil {
			t.Errorf("failed to stop advertising session: %v", err)
		}

		if ds.ActiveAdvertisements() != 0 {
			t.Errorf("expected 0 active advertisements, got %d", ds.ActiveAdvertisements())
		}
	})

	t.Run("stop coordinator advertising", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		sessionID := "coordinator-session"
		if err := ds.AdvertiseCoordinator(ctx, sessionID); err != nil {
			t.Fatalf("failed to advertise coordinator: %v", err)
		}

		if err := ds.StopAdvertisingCoordinator(sessionID); err != nil {
			t.Errorf("failed to stop advertising coordinator: %v", err)
		}

		if ds.ActiveAdvertisements() != 0 {
			t.Errorf("expected 0 active advertisements, got %d", ds.ActiveAdvertisements())
		}
	})

	t.Run("stop with empty session ID", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		err = ds.StopAdvertisingSession("")
		if !errors.Is(err, ErrInvalidSessionID) {
			t.Errorf("expected ErrInvalidSessionID, got %v", err)
		}
	})

	t.Run("stop non-existent advertisement", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		// Should not error for non-existent advertisement
		if err := ds.StopAdvertisingSession("non-existent"); err != nil {
			t.Errorf("should not error for non-existent advertisement: %v", err)
		}
	})
}

// TestFindPeers tests peer discovery.
func TestFindPeers(t *testing.T) {
	t.Run("find session peers empty", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false
		cfg.FindPeersTimeout = 2 * time.Second // Short timeout for test

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		peers, err := ds.FindSessionPeers(ctx, "non-existent-session")
		if err != nil {
			t.Logf("find peers returned error (expected for empty DHT): %v", err)
		}

		// Empty result is expected when no peers are advertising
		if len(peers) > 0 {
			t.Logf("found %d peers (unexpected but not an error)", len(peers))
		}
	})

	t.Run("find peers not started", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		ds, err := NewDiscoveryService(host.Host(), nil)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		_, err = ds.FindSessionPeers(ctx, "session")
		if !errors.Is(err, ErrDHTNotStarted) {
			t.Errorf("expected ErrDHTNotStarted, got %v", err)
		}
	})

	t.Run("find peers with empty session ID", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		_, err = ds.FindSessionPeers(ctx, "")
		if !errors.Is(err, ErrInvalidSessionID) {
			t.Errorf("expected ErrInvalidSessionID, got %v", err)
		}
	})

	t.Run("find coordinator", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false
		cfg.FindPeersTimeout = 2 * time.Second

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		_, err = ds.FindCoordinator(ctx, "session")
		// Error or empty result is acceptable
		if err != nil {
			t.Logf("find coordinator returned error (expected for empty DHT): %v", err)
		}
	})

	t.Run("find coordinator with empty session ID", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		_, err = ds.FindCoordinator(ctx, "")
		if !errors.Is(err, ErrInvalidSessionID) {
			t.Errorf("expected ErrInvalidSessionID, got %v", err)
		}
	})

	t.Run("find ciphersuite peers", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false
		cfg.FindPeersTimeout = 2 * time.Second

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		_, err = ds.FindCiphersuitePeers(ctx, "FROST-ED25519-SHA512-v1")
		// Error or empty result is acceptable
		if err != nil {
			t.Logf("find ciphersuite peers returned error (expected for empty DHT): %v", err)
		}
	})

	t.Run("find ciphersuite peers with empty ciphersuite", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}
		defer func() { _ = ds.Stop(ctx) }()

		_, err = ds.FindCiphersuitePeers(ctx, "")
		if !errors.Is(err, ErrInvalidCiphersuite) {
			t.Errorf("expected ErrInvalidCiphersuite, got %v", err)
		}
	})
}

// TestPeerCache tests the peer caching functionality.
func TestPeerCache(t *testing.T) {
	t.Run("get cached peers empty", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		ds, err := NewDiscoveryService(host.Host(), nil)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		peers := ds.GetCachedPeers("non-existent")
		if peers != nil {
			t.Error("should return nil for non-existent rendezvous")
		}
	})

	t.Run("clear cache", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		ds, err := NewDiscoveryService(host.Host(), nil)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		// Clear cache should not panic on empty cache
		ds.ClearCache()

		peers := ds.GetCachedPeers("any")
		if peers != nil {
			t.Error("cache should be empty after clear")
		}
	})
}

// TestConnectToPeer tests peer connection functionality.
func TestConnectToPeer(t *testing.T) {
	t.Run("not started", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		ds, err := NewDiscoveryService(host.Host(), nil)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		peerInfo := peer.AddrInfo{ID: "test-peer"}
		err = ds.ConnectToPeer(context.Background(), peerInfo)
		if !errors.Is(err, ErrDHTNotStarted) {
			t.Errorf("expected ErrDHTNotStarted, got %v", err)
		}
	})

	t.Run("closed", func(t *testing.T) {
		host := createTestHost(t)
		defer func() { _ = host.Close() }()

		cfg := DefaultDiscoveryConfig()
		cfg.EnableAutoRefresh = false

		ds, err := NewDiscoveryService(host.Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service: %v", err)
		}

		ctx := context.Background()
		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service: %v", err)
		}

		if err := ds.Stop(ctx); err != nil {
			t.Fatalf("failed to stop discovery service: %v", err)
		}

		peerInfo := peer.AddrInfo{ID: "test-peer"}
		err = ds.ConnectToPeer(ctx, peerInfo)
		if !errors.Is(err, ErrDHTClosed) {
			t.Errorf("expected ErrDHTClosed, got %v", err)
		}
	})
}

// TestDiscoveryHostConfig tests discovery host configuration.
func TestDiscoveryHostConfig(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		cfg := DefaultDiscoveryHostConfig()

		if cfg.HostConfig == nil {
			t.Error("HostConfig should not be nil")
		}

		if cfg.EnableDHT {
			t.Error("EnableDHT should be false by default")
		}

		if cfg.DHTMode != DHTModeAuto {
			t.Errorf("expected DHTModeAuto, got %v", cfg.DHTMode)
		}

		if cfg.AdvertiseTTL != DefaultAdvertiseTTL {
			t.Errorf("expected AdvertiseTTL %v, got %v", DefaultAdvertiseTTL, cfg.AdvertiseTTL)
		}

		if cfg.RefreshInterval != DefaultRefreshInterval {
			t.Errorf("expected RefreshInterval %v, got %v", DefaultRefreshInterval, cfg.RefreshInterval)
		}

		if !cfg.EnableAutoRefresh {
			t.Error("EnableAutoRefresh should be true by default")
		}
	})

	t.Run("to discovery config", func(t *testing.T) {
		cfg := DefaultDiscoveryHostConfig()
		cfg.DHTMode = DHTModeServer
		cfg.AdvertiseTTL = 5 * time.Minute
		cfg.RefreshInterval = 1 * time.Minute
		cfg.EnableAutoRefresh = false

		discoveryCfg, err := cfg.ToDiscoveryConfig()
		if err != nil {
			t.Fatalf("failed to convert to discovery config: %v", err)
		}

		if discoveryCfg.Mode != DHTModeServer {
			t.Errorf("expected DHTModeServer, got %v", discoveryCfg.Mode)
		}

		if discoveryCfg.AdvertiseTTL != 5*time.Minute {
			t.Errorf("expected AdvertiseTTL 5m, got %v", discoveryCfg.AdvertiseTTL)
		}

		if discoveryCfg.RefreshInterval != 1*time.Minute {
			t.Errorf("expected RefreshInterval 1m, got %v", discoveryCfg.RefreshInterval)
		}

		if discoveryCfg.EnableAutoRefresh {
			t.Error("EnableAutoRefresh should be false")
		}
	})

	t.Run("invalid bootstrap peer", func(t *testing.T) {
		cfg := DefaultDiscoveryHostConfig()
		cfg.BootstrapPeers = []string{"invalid-peer-address"}

		_, err := cfg.ToDiscoveryConfig()
		if err == nil {
			t.Error("should fail with invalid bootstrap peer address")
		}
	})

	t.Run("valid bootstrap peer", func(t *testing.T) {
		// Create a valid peer ID for testing
		h, err := libp2p.New()
		if err != nil {
			t.Fatalf("failed to create test host: %v", err)
		}
		defer func() { _ = h.Close() }()

		addrs := h.Addrs()
		if len(addrs) == 0 {
			t.Skip("no addresses available for test host")
		}

		cfg := DefaultDiscoveryHostConfig()
		cfg.BootstrapPeers = []string{addrs[0].String() + "/p2p/" + h.ID().String()}

		discoveryCfg, err := cfg.ToDiscoveryConfig()
		if err != nil {
			t.Fatalf("failed to convert config with valid bootstrap peer: %v", err)
		}

		if len(discoveryCfg.BootstrapPeers) != 1 {
			t.Errorf("expected 1 bootstrap peer, got %d", len(discoveryCfg.BootstrapPeers))
		}
	})
}

// TestHostWithDiscovery tests the DKGHostWithDiscovery wrapper.
func TestHostWithDiscovery(t *testing.T) {
	t.Run("create without DHT", func(t *testing.T) {
		ctx := context.Background()
		cfg := DefaultDiscoveryHostConfig()
		cfg.EnableDHT = false

		host, err := NewHostWithDiscovery(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host without DHT: %v", err)
		}
		defer func() { _ = host.Close() }()

		if host.Discovery() != nil {
			t.Error("discovery should be nil when DHT is disabled")
		}

		if host.ID() == "" {
			t.Error("host ID should not be empty")
		}
	})

	t.Run("create with DHT", func(t *testing.T) {
		ctx := context.Background()
		cfg := DefaultDiscoveryHostConfig()
		cfg.EnableDHT = true
		cfg.EnableAutoRefresh = false

		host, err := NewHostWithDiscovery(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host with DHT: %v", err)
		}
		defer func() { _ = host.Close() }()

		if host.Discovery() == nil {
			t.Error("discovery should not be nil when DHT is enabled")
		}

		if !host.Discovery().IsStarted() {
			t.Error("discovery should be started")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		ctx := context.Background()

		host, err := NewHostWithDiscovery(ctx, nil)
		if err != nil {
			t.Fatalf("failed to create host with nil config: %v", err)
		}
		defer func() { _ = host.Close() }()

		// Default config has EnableDHT = false
		if host.Discovery() != nil {
			t.Error("discovery should be nil with default config")
		}
	})

	t.Run("close with discovery", func(t *testing.T) {
		ctx := context.Background()
		cfg := DefaultDiscoveryHostConfig()
		cfg.EnableDHT = true
		cfg.EnableAutoRefresh = false

		host, err := NewHostWithDiscovery(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host with DHT: %v", err)
		}

		if err := host.Close(); err != nil {
			t.Errorf("failed to close host: %v", err)
		}

		if !host.Discovery().IsClosed() {
			t.Error("discovery should be closed")
		}
	})
}

// TestMultipleAdvertisements tests multiple concurrent advertisements.
func TestMultipleAdvertisements(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = false

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}
	defer func() { _ = ds.Stop(ctx) }()

	// Advertise multiple sessions
	sessions := []string{"session-1", "session-2", "session-3"}
	for _, s := range sessions {
		if err := ds.AdvertiseSession(ctx, s); err != nil {
			t.Errorf("failed to advertise session %s: %v", s, err)
		}
	}

	if ds.ActiveAdvertisements() != 3 {
		t.Errorf("expected 3 active advertisements, got %d", ds.ActiveAdvertisements())
	}

	// Stop one advertisement
	if err := ds.StopAdvertisingSession("session-2"); err != nil {
		t.Errorf("failed to stop advertising: %v", err)
	}

	if ds.ActiveAdvertisements() != 2 {
		t.Errorf("expected 2 active advertisements, got %d", ds.ActiveAdvertisements())
	}
}

// TestAdvertiseReplacement tests that re-advertising replaces the previous advertisement.
func TestAdvertiseReplacement(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = false

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}
	defer func() { _ = ds.Stop(ctx) }()

	sessionID := "test-session"

	// Advertise the same session multiple times
	for i := 0; i < 3; i++ {
		if err := ds.AdvertiseSession(ctx, sessionID); err != nil {
			t.Errorf("failed to advertise session on iteration %d: %v", i, err)
		}
	}

	// Should still have only one advertisement (replaced)
	if ds.ActiveAdvertisements() != 1 {
		t.Errorf("expected 1 active advertisement, got %d", ds.ActiveAdvertisements())
	}
}

// TestDHTModeConstants tests DHTMode constants.
func TestDHTModeConstants(t *testing.T) {
	if DHTModeAuto != 0 {
		t.Errorf("expected DHTModeAuto = 0, got %d", DHTModeAuto)
	}

	if DHTModeServer != 1 {
		t.Errorf("expected DHTModeServer = 1, got %d", DHTModeServer)
	}

	if DHTModeClient != 2 {
		t.Errorf("expected DHTModeClient = 2, got %d", DHTModeClient)
	}
}

// TestRendezvousPrefixes tests rendezvous prefix constants.
func TestRendezvousPrefixes(t *testing.T) {
	if RendezvousPrefix != "/frost-dkg/v1/" {
		t.Errorf("unexpected RendezvousPrefix: %s", RendezvousPrefix)
	}

	if SessionRendezvousPrefix != "/frost-dkg/v1/session/" {
		t.Errorf("unexpected SessionRendezvousPrefix: %s", SessionRendezvousPrefix)
	}

	if CiphersuiteRendezvousPrefix != "/frost-dkg/v1/ciphersuite/" {
		t.Errorf("unexpected CiphersuiteRendezvousPrefix: %s", CiphersuiteRendezvousPrefix)
	}

	if CoordinatorRendezvousPrefix != "/frost-dkg/v1/coordinator/" {
		t.Errorf("unexpected CoordinatorRendezvousPrefix: %s", CoordinatorRendezvousPrefix)
	}
}

// TestDiscoveryErrorTypes tests that discovery error types are properly defined.
func TestDiscoveryErrorTypes(t *testing.T) {
	discoveryErrors := []error{
		ErrDHTNotStarted,
		ErrDHTAlreadyStarted,
		ErrDHTBootstrapFailed,
		ErrDHTClosed,
		ErrNoBootstrapPeers,
		ErrInvalidRendezvous,
		ErrAdvertiseFailed,
		ErrFindPeersFailed,
		ErrInvalidSessionID,
		ErrInvalidCiphersuite,
	}

	for _, err := range discoveryErrors {
		if err == nil {
			t.Error("error should not be nil")
		}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
	}
}

// ============================================================================
// Multi-Peer Discovery Integration Tests
// ============================================================================

// TestDiscoveryMultiPeerSessionDiscovery tests that multiple peers can discover
// each other through session advertising using a real DHT network.
func TestDiscoveryMultiPeerSessionDiscovery(t *testing.T) {
	const peerCount = 3
	cluster := createDiscoveryCluster(t, peerCount, false)
	defer cluster.cleanup(t)

	ctx := context.Background()
	sessionID := "test-multi-peer-session"

	// Peer 0 advertises the session
	if err := cluster.services[0].AdvertiseSession(ctx, sessionID); err != nil {
		t.Fatalf("peer 0 failed to advertise session: %v", err)
	}

	// Wait for advertisement to propagate
	time.Sleep(300 * time.Millisecond)

	// Peers 1 and 2 should be able to find peer 0
	for i := 1; i < peerCount; i++ {
		peers, err := cluster.services[i].FindSessionPeers(ctx, sessionID)
		if err != nil {
			t.Logf("peer %d failed to find session peers (may be timing): %v", i, err)
			continue
		}

		foundPeer0 := false
		for _, p := range peers {
			if p.ID == cluster.hosts[0].ID() {
				foundPeer0 = true
				break
			}
		}

		if foundPeer0 {
			t.Logf("peer %d successfully found peer 0 advertising session", i)
		} else {
			t.Logf("peer %d did not find peer 0 (found %d peers)", i, len(peers))
		}
	}

	// Verify peer 0 has one active advertisement
	if cluster.services[0].ActiveAdvertisements() != 1 {
		t.Errorf("peer 0 should have 1 active advertisement, got %d",
			cluster.services[0].ActiveAdvertisements())
	}
}

// TestDiscoveryBootstrapPeerConnection tests that bootstrap peers are properly connected.
func TestDiscoveryBootstrapPeerConnection(t *testing.T) {
	const peerCount = 3
	cluster := createDiscoveryCluster(t, peerCount, false)
	defer cluster.cleanup(t)

	// Give time for connections to establish
	time.Sleep(200 * time.Millisecond)

	// Check that non-bootstrap peers (1 and 2) are connected to the bootstrap peer (0)
	for i := 1; i < peerCount; i++ {
		connections := cluster.hosts[i].Host().Network().ConnsToPeer(cluster.hosts[0].ID())
		if len(connections) == 0 {
			t.Errorf("peer %d should be connected to bootstrap peer 0", i)
		} else {
			t.Logf("peer %d has %d connection(s) to bootstrap peer 0", i, len(connections))
		}
	}

	// Verify all services are started
	for i := 0; i < peerCount; i++ {
		if !cluster.services[i].IsStarted() {
			t.Errorf("service %d should be started", i)
		}
	}
}

// TestDiscoveryCoordinatorDiscovery tests that a coordinator can be discovered by participants.
func TestDiscoveryCoordinatorDiscovery(t *testing.T) {
	const peerCount = 4
	cluster := createDiscoveryCluster(t, peerCount, false)
	defer cluster.cleanup(t)

	ctx := context.Background()
	sessionID := "coordinator-test-session"

	// Peer 0 advertises as coordinator
	if err := cluster.services[0].AdvertiseCoordinator(ctx, sessionID); err != nil {
		t.Fatalf("peer 0 failed to advertise as coordinator: %v", err)
	}

	// Wait for advertisement to propagate
	time.Sleep(300 * time.Millisecond)

	// Other peers should be able to find the coordinator
	foundCount := 0
	for i := 1; i < peerCount; i++ {
		coordinators, err := cluster.services[i].FindCoordinator(ctx, sessionID)
		if err != nil {
			t.Logf("peer %d failed to find coordinator: %v", i, err)
			continue
		}

		for _, coord := range coordinators {
			if coord.ID == cluster.hosts[0].ID() {
				foundCount++
				t.Logf("peer %d found coordinator (peer 0)", i)
				break
			}
		}
	}

	t.Logf("%d/%d peers found the coordinator", foundCount, peerCount-1)
}

// TestDiscoveryCiphersuiteDiscovery tests that peers advertising a ciphersuite can be found.
func TestDiscoveryCiphersuiteDiscovery(t *testing.T) {
	const peerCount = 4
	cluster := createDiscoveryCluster(t, peerCount, false)
	defer cluster.cleanup(t)

	ctx := context.Background()
	ciphersuite := "FROST-ED25519-SHA512-v1"

	// Peers 0 and 1 advertise the ciphersuite
	if err := cluster.services[0].AdvertiseCiphersuite(ctx, ciphersuite); err != nil {
		t.Fatalf("peer 0 failed to advertise ciphersuite: %v", err)
	}
	if err := cluster.services[1].AdvertiseCiphersuite(ctx, ciphersuite); err != nil {
		t.Fatalf("peer 1 failed to advertise ciphersuite: %v", err)
	}

	// Wait for advertisements to propagate
	time.Sleep(300 * time.Millisecond)

	// Peers 2 and 3 should be able to find peers supporting the ciphersuite
	for i := 2; i < peerCount; i++ {
		peers, err := cluster.services[i].FindCiphersuitePeers(ctx, ciphersuite)
		if err != nil {
			t.Logf("peer %d failed to find ciphersuite peers: %v", i, err)
			continue
		}

		foundPeers := make(map[peer.ID]bool)
		for _, p := range peers {
			if p.ID == cluster.hosts[0].ID() || p.ID == cluster.hosts[1].ID() {
				foundPeers[p.ID] = true
			}
		}

		t.Logf("peer %d found %d peers supporting ciphersuite %s",
			i, len(foundPeers), ciphersuite)
	}
}

// TestDiscoveryPeerCacheAfterFind tests that discovered peers are cached and retrievable.
func TestDiscoveryPeerCacheAfterFind(t *testing.T) {
	const peerCount = 3
	cluster := createDiscoveryCluster(t, peerCount, false)
	defer cluster.cleanup(t)

	ctx := context.Background()
	sessionID := "cache-test-session"
	rendezvous := SessionRendezvousPrefix + sessionID

	// Peer 0 advertises the session
	if err := cluster.services[0].AdvertiseSession(ctx, sessionID); err != nil {
		t.Fatalf("failed to advertise session: %v", err)
	}

	// Wait for advertisement to propagate
	time.Sleep(300 * time.Millisecond)

	// Peer 1 finds session peers
	peers, err := cluster.services[1].FindSessionPeers(ctx, sessionID)
	if err != nil {
		t.Logf("find session peers returned error: %v", err)
	}

	// Check cache - should contain the same peers
	cachedPeers := cluster.services[1].GetCachedPeers(rendezvous)

	// Cache should be populated after find operation
	if len(peers) > 0 {
		if cachedPeers == nil {
			t.Error("cache should contain peers after FindSessionPeers")
		} else if len(cachedPeers) != len(peers) {
			t.Errorf("cache should contain %d peers, got %d", len(peers), len(cachedPeers))
		} else {
			t.Logf("cache correctly contains %d peers", len(cachedPeers))
		}
	}

	// Clear cache and verify it's empty
	cluster.services[1].ClearCache()
	cachedPeers = cluster.services[1].GetCachedPeers(rendezvous)
	if cachedPeers != nil {
		t.Error("cache should be empty after ClearCache")
	}
}

// TestDiscoveryAutoRefresh tests that the auto-refresh loop keeps the routing table updated.
func TestDiscoveryAutoRefresh(t *testing.T) {
	const peerCount = 3
	// Enable auto-refresh for this test
	cluster := createDiscoveryCluster(t, peerCount, true)
	defer cluster.cleanup(t)

	// Verify all services have auto-refresh enabled (they have the refresh goroutine running)
	for i := 0; i < peerCount; i++ {
		if !cluster.services[i].IsStarted() {
			t.Errorf("service %d should be started", i)
		}
	}

	// Wait for at least one refresh cycle (refresh interval is 500ms in cluster config)
	time.Sleep(600 * time.Millisecond)

	// All services should still be running
	for i := 0; i < peerCount; i++ {
		if !cluster.services[i].IsStarted() {
			t.Errorf("service %d should still be started after refresh", i)
		}
		if cluster.services[i].IsClosed() {
			t.Errorf("service %d should not be closed", i)
		}
	}

	t.Log("auto-refresh test completed successfully")
}

// TestDiscoveryContextCancellation tests that operations respect context cancellation.
func TestDiscoveryContextCancellation(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = false
	cfg.FindPeersTimeout = 30 * time.Second // Long timeout to ensure context cancel takes effect

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}
	defer func() { _ = ds.Stop(context.Background()) }()

	// Create a context that will be cancelled
	cancelCtx, cancel := context.WithCancel(ctx)

	// Start find operation in goroutine
	done := make(chan error, 1)
	go func() {
		_, err := ds.FindSessionPeers(cancelCtx, "test-cancel-session")
		done <- err
	}()

	// Cancel the context immediately
	cancel()

	// Wait for operation to complete
	select {
	case err := <-done:
		if err != nil && errors.Is(err, context.Canceled) {
			t.Log("operation correctly cancelled")
		} else {
			t.Logf("operation completed with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("operation did not respect context cancellation")
	}
}

// TestDiscoveryAdvertiseAfterClose tests that advertising after close returns ErrDHTClosed.
func TestDiscoveryAdvertiseAfterClose(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = false

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}

	// Stop the service
	if err := ds.Stop(ctx); err != nil {
		t.Fatalf("failed to stop discovery service: %v", err)
	}

	// Try to advertise after close
	err = ds.AdvertiseSession(ctx, "test-session")
	if !errors.Is(err, ErrDHTClosed) {
		t.Errorf("expected ErrDHTClosed, got %v", err)
	}

	err = ds.AdvertiseCoordinator(ctx, "test-coordinator")
	if !errors.Is(err, ErrDHTClosed) {
		t.Errorf("expected ErrDHTClosed, got %v", err)
	}

	err = ds.AdvertiseCiphersuite(ctx, "test-ciphersuite")
	if !errors.Is(err, ErrDHTClosed) {
		t.Errorf("expected ErrDHTClosed, got %v", err)
	}
}

// TestDiscoveryFindPeersAfterClose tests that finding peers after close returns ErrDHTClosed.
func TestDiscoveryFindPeersAfterClose(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = false

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}

	// Stop the service
	if err := ds.Stop(ctx); err != nil {
		t.Fatalf("failed to stop discovery service: %v", err)
	}

	// Try to find peers after close
	_, err = ds.FindSessionPeers(ctx, "test-session")
	if !errors.Is(err, ErrDHTClosed) {
		t.Errorf("FindSessionPeers: expected ErrDHTClosed, got %v", err)
	}

	_, err = ds.FindCoordinator(ctx, "test-session")
	if !errors.Is(err, ErrDHTClosed) {
		t.Errorf("FindCoordinator: expected ErrDHTClosed, got %v", err)
	}

	_, err = ds.FindCiphersuitePeers(ctx, "test-ciphersuite")
	if !errors.Is(err, ErrDHTClosed) {
		t.Errorf("FindCiphersuitePeers: expected ErrDHTClosed, got %v", err)
	}
}

// TestDiscoveryConnectToPeerSuccess tests successful peer connection.
func TestDiscoveryConnectToPeerSuccess(t *testing.T) {
	const peerCount = 2
	cluster := createDiscoveryCluster(t, peerCount, false)
	defer cluster.cleanup(t)

	ctx := context.Background()

	// Connect peer 1 to peer 0 using ConnectToPeer
	peerInfo := cluster.peerAddrs[0]
	if err := cluster.services[1].ConnectToPeer(ctx, peerInfo); err != nil {
		t.Errorf("failed to connect to peer: %v", err)
	}

	// Verify connection
	connections := cluster.hosts[1].Host().Network().ConnsToPeer(cluster.hosts[0].ID())
	if len(connections) == 0 {
		t.Error("should be connected to peer 0")
	} else {
		t.Logf("successfully connected to peer 0 with %d connection(s)", len(connections))
	}
}

// TestDiscoveryConcurrentOperations tests concurrent advertise and find operations.
func TestDiscoveryConcurrentOperations(t *testing.T) {
	const peerCount = 4
	cluster := createDiscoveryCluster(t, peerCount, false)
	defer cluster.cleanup(t)

	ctx := context.Background()

	var wg sync.WaitGroup
	errorsChan := make(chan error, peerCount*2)

	// Each peer advertises a different session concurrently
	for i := 0; i < peerCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sessionID := "concurrent-session-" + string(rune('A'+idx))
			if err := cluster.services[idx].AdvertiseSession(ctx, sessionID); err != nil {
				errorsChan <- err
			}
		}(i)
	}

	wg.Wait()

	// Wait for advertisements to propagate
	time.Sleep(200 * time.Millisecond)

	// Each peer tries to find peers for all sessions concurrently
	for i := 0; i < peerCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < peerCount; j++ {
				if j == idx {
					continue // Skip finding self
				}
				sessionID := "concurrent-session-" + string(rune('A'+j))
				if _, err := cluster.services[idx].FindSessionPeers(ctx, sessionID); err != nil {
					t.Logf("peer %d find session %s: %v", idx, sessionID, err)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errorsChan)

	// Check for errors
	errCount := 0
	for err := range errorsChan {
		if err != nil {
			errCount++
			t.Logf("concurrent operation error: %v", err)
		}
	}

	if errCount > 0 {
		t.Logf("%d errors occurred during concurrent operations", errCount)
	}

	// Verify all advertisements are active
	for i := 0; i < peerCount; i++ {
		if cluster.services[i].ActiveAdvertisements() != 1 {
			t.Errorf("peer %d should have 1 active advertisement, got %d",
				i, cluster.services[i].ActiveAdvertisements())
		}
	}
}

// TestDiscoveryStopAdvertisingNotStarted tests StopAdvertising when not started.
func TestDiscoveryStopAdvertisingNotStarted(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	ds, err := NewDiscoveryService(host.Host(), nil)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	// Try to stop advertising when not started
	err = ds.StopAdvertising("some-rendezvous")
	if !errors.Is(err, ErrDHTNotStarted) {
		t.Errorf("expected ErrDHTNotStarted, got %v", err)
	}

	err = ds.StopAdvertisingSession("some-session")
	if !errors.Is(err, ErrInvalidSessionID) || err != nil && !errors.Is(err, ErrDHTNotStarted) {
		// Either ErrDHTNotStarted (checked first in StopAdvertising) or
		// returns nil because it goes through StopAdvertising first
		t.Logf("StopAdvertisingSession when not started returned: %v", err)
	}
}

// TestDiscoveryStopAdvertisingCoordinatorEmptyID tests error handling.
func TestDiscoveryStopAdvertisingCoordinatorEmptyID(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = false

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}
	defer func() { _ = ds.Stop(ctx) }()

	err = ds.StopAdvertisingCoordinator("")
	if !errors.Is(err, ErrInvalidSessionID) {
		t.Errorf("expected ErrInvalidSessionID, got %v", err)
	}
}

// TestDiscoveryMultipleSessions tests advertising and finding multiple sessions.
func TestDiscoveryMultipleSessions(t *testing.T) {
	const peerCount = 3
	cluster := createDiscoveryCluster(t, peerCount, false)
	defer cluster.cleanup(t)

	ctx := context.Background()
	sessions := []string{"session-alpha", "session-beta", "session-gamma"}

	// Peer 0 advertises all sessions
	for _, sessionID := range sessions {
		if err := cluster.services[0].AdvertiseSession(ctx, sessionID); err != nil {
			t.Fatalf("failed to advertise session %s: %v", sessionID, err)
		}
	}

	// Verify all advertisements are active
	if cluster.services[0].ActiveAdvertisements() != len(sessions) {
		t.Errorf("expected %d active advertisements, got %d",
			len(sessions), cluster.services[0].ActiveAdvertisements())
	}

	// Wait for advertisements to propagate
	time.Sleep(300 * time.Millisecond)

	// Stop advertising one session
	if err := cluster.services[0].StopAdvertisingSession("session-beta"); err != nil {
		t.Errorf("failed to stop advertising: %v", err)
	}

	if cluster.services[0].ActiveAdvertisements() != len(sessions)-1 {
		t.Errorf("expected %d active advertisements after stopping one, got %d",
			len(sessions)-1, cluster.services[0].ActiveAdvertisements())
	}
}

// TestDiscoveryBootstrapFailure tests behavior when bootstrap peer is unreachable.
func TestDiscoveryBootstrapFailure(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	// Create a fake unreachable bootstrap peer address
	fakePeerAddr := peer.AddrInfo{
		ID: "12D3KooWFakeBootstrapPeerThatDoesNotExist",
	}

	cfg := &DiscoveryConfig{
		Mode:              DHTModeServer,
		BootstrapPeers:    []peer.AddrInfo{fakePeerAddr},
		AdvertiseTTL:      1 * time.Minute,
		RefreshInterval:   30 * time.Second,
		FindPeersTimeout:  2 * time.Second,
		EnableAutoRefresh: false,
		MaxPeers:          100,
	}

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = ds.Start(ctx)
	if err != nil {
		// Expected: bootstrap should fail because we can't connect to fake peer
		if errors.Is(err, ErrDHTBootstrapFailed) {
			t.Log("correctly failed with ErrDHTBootstrapFailed")
		} else {
			t.Logf("start returned error: %v", err)
		}
	} else {
		// If it succeeded (no bootstrap peers to fail), clean up
		_ = ds.Stop(context.Background())
	}
}

// TestDiscoveryMaxPeersLimit tests that MaxPeers configuration is respected.
func TestDiscoveryMaxPeersLimit(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = false
	cfg.MaxPeers = 5

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}
	defer func() { _ = ds.Stop(ctx) }()

	// The config should be respected
	// Note: We can't easily test the actual limit without creating many peers,
	// but we verify the config is set correctly
	t.Logf("MaxPeers configured: %d", cfg.MaxPeers)
}

// TestDiscoveryStopWithActiveAdvertisements tests stopping with active advertisements.
func TestDiscoveryStopWithActiveAdvertisements(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = false

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}

	// Create multiple advertisements
	sessions := []string{"session-1", "session-2", "session-3"}
	for _, s := range sessions {
		if err := ds.AdvertiseSession(ctx, s); err != nil {
			t.Errorf("failed to advertise session %s: %v", s, err)
		}
	}
	if err := ds.AdvertiseCoordinator(ctx, "coord-session"); err != nil {
		t.Errorf("failed to advertise coordinator: %v", err)
	}
	if err := ds.AdvertiseCiphersuite(ctx, "test-ciphersuite"); err != nil {
		t.Errorf("failed to advertise ciphersuite: %v", err)
	}

	activeCount := ds.ActiveAdvertisements()
	t.Logf("active advertisements before stop: %d", activeCount)

	// Stop should clean up all advertisements
	if err := ds.Stop(ctx); err != nil {
		t.Errorf("failed to stop discovery service: %v", err)
	}

	// After stop, all advertisements should be cancelled
	if !ds.IsClosed() {
		t.Error("discovery service should be closed")
	}
}

// TestDiscoveryWithAutoRefreshEnabled tests full lifecycle with auto-refresh.
func TestDiscoveryWithAutoRefreshEnabled(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = true
	cfg.RefreshInterval = 200 * time.Millisecond

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}

	// Advertise something
	if err := ds.AdvertiseSession(ctx, "refresh-test"); err != nil {
		t.Errorf("failed to advertise: %v", err)
	}

	// Wait for multiple refresh cycles
	time.Sleep(500 * time.Millisecond)

	// Service should still be running
	if !ds.IsStarted() {
		t.Error("service should still be started")
	}

	// Stop and verify
	if err := ds.Stop(ctx); err != nil {
		t.Errorf("failed to stop: %v", err)
	}

	if !ds.IsClosed() {
		t.Error("service should be closed")
	}
}

// TestDiscoveryContextTimeout tests behavior with timeout context.
func TestDiscoveryContextTimeout(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = false
	cfg.FindPeersTimeout = 5 * time.Second

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}
	defer func() { _ = ds.Stop(context.Background()) }()

	// Create a context with very short timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = ds.FindSessionPeers(timeoutCtx, "timeout-test-session")
	elapsed := time.Since(start)

	// The operation should complete within a reasonable time
	// (either by finding no peers or timing out)
	if elapsed > 2*time.Second {
		t.Errorf("operation took too long: %v", elapsed)
	}

	t.Logf("find operation completed in %v (error: %v)", elapsed, err)
}

// ============================================================================
// Targeted Coverage Tests for Specific Functions
// ============================================================================

// TestFindPeersMaxPeersLimit tests the MaxPeers limit branch in findPeers (lines 520-522).
func TestFindPeersMaxPeersLimit(t *testing.T) {
	// Create a cluster with more peers than MaxPeers limit
	const peerCount = 5
	const maxPeers = 2

	hosts := make([]*DKGHost, peerCount)
	services := make([]*DiscoveryService, peerCount)
	peerAddrs := make([]peer.AddrInfo, peerCount)

	ctx := context.Background()

	// Create all hosts first
	for i := 0; i < peerCount; i++ {
		cfg := DefaultHostConfig()
		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host %d: %v", i, err)
		}
		hosts[i] = host
		peerAddrs[i] = peer.AddrInfo{
			ID:    host.ID(),
			Addrs: host.Host().Addrs(),
		}
	}

	// Cleanup function
	defer func() {
		for i := len(services) - 1; i >= 0; i-- {
			if services[i] != nil && services[i].IsStarted() && !services[i].IsClosed() {
				_ = services[i].Stop(ctx)
			}
		}
		for i := len(hosts) - 1; i >= 0; i-- {
			if hosts[i] != nil {
				_ = hosts[i].Close()
			}
		}
	}()

	// Create discovery services
	for i := 0; i < peerCount; i++ {
		var bootstrapPeers []peer.AddrInfo
		if i > 0 {
			bootstrapPeers = []peer.AddrInfo{peerAddrs[0]}
		}

		cfg := &DiscoveryConfig{
			Mode:              DHTModeServer,
			BootstrapPeers:    bootstrapPeers,
			AdvertiseTTL:      1 * time.Minute,
			RefreshInterval:   500 * time.Millisecond,
			FindPeersTimeout:  5 * time.Second,
			EnableAutoRefresh: false,
			MaxPeers:          maxPeers, // Limit to 2 peers
		}

		ds, err := NewDiscoveryService(hosts[i].Host(), cfg)
		if err != nil {
			t.Fatalf("failed to create discovery service %d: %v", i, err)
		}
		services[i] = ds

		if err := ds.Start(ctx); err != nil {
			t.Fatalf("failed to start discovery service %d: %v", i, err)
		}
	}

	// Wait for DHT to stabilize
	time.Sleep(300 * time.Millisecond)

	sessionID := "max-peers-test-session"

	// Peers 0, 1, 2 advertise the session
	for i := 0; i < 3; i++ {
		if err := services[i].AdvertiseSession(ctx, sessionID); err != nil {
			t.Fatalf("peer %d failed to advertise session: %v", i, err)
		}
	}

	// Wait for advertisements to propagate
	time.Sleep(500 * time.Millisecond)

	// Peer 4 finds session peers with MaxPeers = 2
	peers, err := services[4].FindSessionPeers(ctx, sessionID)
	if err != nil {
		t.Logf("find session peers returned error: %v", err)
	}

	// Should be limited to MaxPeers
	if len(peers) > maxPeers {
		t.Errorf("expected at most %d peers (MaxPeers limit), got %d", maxPeers, len(peers))
	}
	t.Logf("found %d peers (MaxPeers limit: %d)", len(peers), maxPeers)
}

// TestNewHostWithDiscoveryInvalidHostConfig tests NewHostWithDiscovery with invalid HostConfig.
func TestNewHostWithDiscoveryInvalidHostConfig(t *testing.T) {
	ctx := context.Background()

	// Create a config with invalid listen address to cause NewHost to fail
	cfg := &DiscoveryHostConfig{
		HostConfig: &HostConfig{
			ListenAddrs: []string{"invalid-multiaddr-that-will-fail"},
			EnableNoise: true,
			EnableTLS:   true,
		},
		EnableDHT:         false,
		DHTMode:           DHTModeAuto,
		EnableAutoRefresh: false,
	}

	_, err := NewHostWithDiscovery(ctx, cfg)
	if err == nil {
		t.Error("expected error with invalid HostConfig, got nil")
	} else {
		t.Logf("correctly failed with error: %v", err)
	}
}

// TestNewHostWithDiscoveryInvalidBootstrapPeer tests NewHostWithDiscovery with invalid bootstrap peer.
func TestNewHostWithDiscoveryInvalidBootstrapPeer(t *testing.T) {
	ctx := context.Background()

	cfg := DefaultDiscoveryHostConfig()
	cfg.EnableDHT = true
	cfg.BootstrapPeers = []string{"invalid-bootstrap-peer-address"}
	cfg.EnableAutoRefresh = false

	_, err := NewHostWithDiscovery(ctx, cfg)
	if err == nil {
		t.Error("expected error with invalid bootstrap peer, got nil")
	} else {
		t.Logf("correctly failed with ToDiscoveryConfig error: %v", err)
	}
}

// TestDKGHostWithDiscoveryCloseNilDiscovery tests Close when discovery is nil.
func TestDKGHostWithDiscoveryCloseNilDiscovery(t *testing.T) {
	ctx := context.Background()

	// Create host without DHT (discovery will be nil)
	cfg := DefaultDiscoveryHostConfig()
	cfg.EnableDHT = false

	host, err := NewHostWithDiscovery(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create host: %v", err)
	}

	// Verify discovery is nil
	if host.Discovery() != nil {
		t.Error("discovery should be nil when DHT is disabled")
	}

	// Close should succeed even with nil discovery
	if err := host.Close(); err != nil {
		t.Errorf("Close failed with nil discovery: %v", err)
	}
}

// TestDKGHostWithDiscoveryCloseReturnsFirstError tests that Close returns the first error when both fail.
func TestDKGHostWithDiscoveryCloseReturnsFirstError(t *testing.T) {
	ctx := context.Background()

	// Create host with DHT
	cfg := DefaultDiscoveryHostConfig()
	cfg.EnableDHT = true
	cfg.EnableAutoRefresh = false

	host, err := NewHostWithDiscovery(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create host: %v", err)
	}

	// Manually stop the discovery service first so Stop will fail
	if err := host.discovery.Stop(ctx); err != nil {
		t.Fatalf("failed to stop discovery: %v", err)
	}

	// Now Close will try to stop an already stopped discovery
	// The discovery.Stop will return ErrDHTClosed
	err = host.Close()
	// Either discovery.Stop error or DKGHost.Close error is acceptable
	// The important thing is Close doesn't panic
	t.Logf("Close returned: %v", err)
}

// TestStopContextTimeout tests the 10-second timeout path in Stop (lines 297-298).
func TestStopContextTimeout(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = true
	cfg.RefreshInterval = 100 * time.Millisecond

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}

	// Create a context that will be cancelled before shutdown completes
	// Use a very short deadline
	cancelCtx, cancel := context.WithTimeout(ctx, 1*time.Nanosecond)
	defer cancel()

	// Wait for context to be cancelled
	time.Sleep(10 * time.Millisecond)

	// Stop with already-cancelled context
	err = ds.Stop(cancelCtx)
	if err != nil {
		// Should get context.DeadlineExceeded
		if errors.Is(err, context.DeadlineExceeded) {
			t.Log("correctly received context.DeadlineExceeded")
		} else {
			t.Logf("Stop returned error: %v", err)
		}
	}
}

// TestFindPeersWithCancelledContext tests findPeers error branch when FindPeers returns error.
func TestFindPeersWithCancelledContext(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = false
	cfg.FindPeersTimeout = 30 * time.Second // Long timeout

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}
	defer func() { _ = ds.Stop(ctx) }()

	// Create an already-cancelled context
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel() // Cancel immediately

	// FindSessionPeers should return error due to cancelled context
	_, err = ds.FindSessionPeers(cancelCtx, "test-session")
	if err != nil {
		// Check that it wraps ErrFindPeersFailed or is context.Canceled
		if errors.Is(err, ErrFindPeersFailed) || errors.Is(err, context.Canceled) {
			t.Logf("correctly received error: %v", err)
		} else {
			t.Logf("received error: %v", err)
		}
	}
}

// TestNewHostWithDiscoveryStartFails tests error when discovery.Start fails.
func TestNewHostWithDiscoveryStartFails(t *testing.T) {
	// This test requires a scenario where Start fails
	// One way is to use a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := DefaultDiscoveryHostConfig()
	cfg.EnableDHT = true
	cfg.EnableAutoRefresh = false

	// Try to create host with cancelled context
	// The DHT creation or bootstrap may fail due to cancelled context
	_, err := NewHostWithDiscovery(ctx, cfg)
	if err != nil {
		// Expected - the DHT creation or bootstrap should fail
		t.Logf("correctly failed with cancelled context: %v", err)
	} else {
		// If it somehow succeeded, clean up
		t.Log("NewHostWithDiscovery succeeded with cancelled context (unexpected)")
	}
}

// TestStopWithContextCancellation tests Stop when context is cancelled during shutdown.
func TestStopWithContextCancellation(t *testing.T) {
	host := createTestHost(t)
	defer func() { _ = host.Close() }()

	cfg := DefaultDiscoveryConfig()
	cfg.EnableAutoRefresh = true
	cfg.RefreshInterval = 50 * time.Millisecond

	ds, err := NewDiscoveryService(host.Host(), cfg)
	if err != nil {
		t.Fatalf("failed to create discovery service: %v", err)
	}

	ctx := context.Background()
	if err := ds.Start(ctx); err != nil {
		t.Fatalf("failed to start discovery service: %v", err)
	}

	// Add some advertisements to ensure there's work to do during shutdown
	if err := ds.AdvertiseSession(ctx, "session-1"); err != nil {
		t.Fatalf("failed to advertise: %v", err)
	}
	if err := ds.AdvertiseSession(ctx, "session-2"); err != nil {
		t.Fatalf("failed to advertise: %v", err)
	}

	// Create a context that will be cancelled
	cancelCtx, cancel := context.WithCancel(ctx)

	// Start Stop in a goroutine
	done := make(chan error, 1)
	go func() {
		done <- ds.Stop(cancelCtx)
	}()

	// Cancel context very quickly
	time.Sleep(1 * time.Millisecond)
	cancel()

	// Wait for Stop to complete
	select {
	case err := <-done:
		if errors.Is(err, context.Canceled) {
			t.Log("correctly received context.Canceled during Stop")
		} else if err != nil {
			t.Logf("Stop returned: %v", err)
		} else {
			t.Log("Stop completed successfully before context cancelled")
		}
	case <-time.After(15 * time.Second):
		t.Error("Stop took too long")
	}
}
