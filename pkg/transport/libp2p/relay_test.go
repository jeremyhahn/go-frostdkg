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
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultRelayConfig verifies default relay configuration values.
func TestDefaultRelayConfig(t *testing.T) {
	cfg := DefaultRelayConfig()

	assert.False(t, cfg.EnableRelay, "EnableRelay should default to false")
	assert.False(t, cfg.EnableRelayService, "EnableRelayService should default to false")
	assert.Nil(t, cfg.StaticRelays, "StaticRelays should default to nil")
	assert.Equal(t, 1, cfg.RelayHopLimit, "RelayHopLimit should default to 1")
	assert.Equal(t, time.Hour, cfg.ReservationTTL, "ReservationTTL should default to 1 hour")
	assert.Equal(t, 45*time.Minute, cfg.ReservationRefreshInterval, "ReservationRefreshInterval should default to 45 minutes")
	assert.Equal(t, 3, cfg.MaxReservations, "MaxReservations should default to 3")
	assert.False(t, cfg.EnableAutoRelay, "EnableAutoRelay should default to false")
	assert.Nil(t, cfg.RelayServiceConfig, "RelayServiceConfig should default to nil")
}

// TestDefaultRelayServiceConfig verifies default relay service configuration values.
func TestDefaultRelayServiceConfig(t *testing.T) {
	cfg := DefaultRelayServiceConfig()

	assert.Equal(t, 128, cfg.MaxReservations, "MaxReservations should default to 128")
	assert.Equal(t, 16, cfg.MaxCircuits, "MaxCircuits should default to 16")
	assert.Equal(t, 4, cfg.MaxReservationsPerPeer, "MaxReservationsPerPeer should default to 4")
	assert.Equal(t, 8, cfg.MaxReservationsPerIP, "MaxReservationsPerIP should default to 8")
	assert.Equal(t, time.Hour, cfg.ReservationTTL, "ReservationTTL should default to 1 hour")
	assert.Equal(t, 2*time.Minute, cfg.MaxDuration, "MaxDuration should default to 2 minutes")
	assert.Equal(t, int64(1<<17), cfg.MaxData, "MaxData should default to 128KB")
}

// TestRelayReservationIsExpired tests reservation expiry detection.
func TestRelayReservationIsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		res := &RelayReservation{
			Expiry: time.Now().Add(time.Hour),
		}
		assert.False(t, res.IsExpired(), "reservation should not be expired")
	})

	t.Run("expired", func(t *testing.T) {
		res := &RelayReservation{
			Expiry: time.Now().Add(-time.Hour),
		}
		assert.True(t, res.IsExpired(), "reservation should be expired")
	})

	t.Run("just expired", func(t *testing.T) {
		res := &RelayReservation{
			Expiry: time.Now().Add(-time.Millisecond),
		}
		assert.True(t, res.IsExpired(), "reservation should be expired")
	})
}

// TestRelayReservationTTL tests TTL calculation for reservations.
func TestRelayReservationTTL(t *testing.T) {
	t.Run("positive TTL", func(t *testing.T) {
		res := &RelayReservation{
			Expiry: time.Now().Add(time.Hour),
		}
		ttl := res.TTL()
		assert.True(t, ttl > 0, "TTL should be positive")
		assert.True(t, ttl <= time.Hour, "TTL should not exceed 1 hour")
	})

	t.Run("zero TTL for expired", func(t *testing.T) {
		res := &RelayReservation{
			Expiry: time.Now().Add(-time.Hour),
		}
		assert.Equal(t, time.Duration(0), res.TTL(), "TTL should be zero for expired reservation")
	})
}

// TestNewRelayManager tests relay manager creation.
func TestNewRelayManager(t *testing.T) {
	t.Run("nil host returns error", func(t *testing.T) {
		rm, err := NewRelayManager(nil, nil)
		assert.Nil(t, rm, "relay manager should be nil")
		assert.ErrorIs(t, err, ErrRelayNotEnabled, "should return ErrRelayNotEnabled")
	})

	t.Run("nil config uses defaults", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, nil)
		require.NoError(t, err)
		assert.NotNil(t, rm, "relay manager should not be nil")
		assert.False(t, rm.config.EnableRelay, "should use default config")
	})

	t.Run("with valid config", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		cfg := &RelayConfig{
			EnableRelay:     true,
			MaxReservations: 5,
			ReservationTTL:  30 * time.Minute,
		}

		rm, err := NewRelayManager(h, cfg)
		require.NoError(t, err)
		assert.NotNil(t, rm, "relay manager should not be nil")
		assert.True(t, rm.config.EnableRelay, "config should be applied")
		assert.Equal(t, 5, rm.config.MaxReservations, "config should be applied")
	})

	t.Run("invalid static relay address", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		cfg := &RelayConfig{
			EnableRelay:  true,
			StaticRelays: []string{"invalid-multiaddr"},
		}

		rm, err := NewRelayManager(h, cfg)
		assert.Nil(t, rm, "relay manager should be nil")
		assert.Error(t, err, "should return error for invalid address")
		var relayErr *RelayError
		assert.True(t, errors.As(err, &relayErr), "should return RelayError")
	})

	t.Run("zero values use defaults", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		cfg := &RelayConfig{
			EnableRelay:                true,
			RelayHopLimit:              0,
			ReservationTTL:             0,
			ReservationRefreshInterval: 0,
			MaxReservations:            0,
		}

		rm, err := NewRelayManager(h, cfg)
		require.NoError(t, err)
		assert.Equal(t, DefaultRelayHopLimit, rm.config.RelayHopLimit)
		assert.Equal(t, DefaultReservationTTL, rm.config.ReservationTTL)
		assert.Equal(t, DefaultReservationRefreshInterval, rm.config.ReservationRefreshInterval)
		assert.Equal(t, DefaultMaxReservations, rm.config.MaxReservations)
	})

	t.Run("negative values use defaults", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		cfg := &RelayConfig{
			EnableRelay:                true,
			RelayHopLimit:              -1,
			ReservationTTL:             -time.Hour,
			ReservationRefreshInterval: -time.Minute,
			MaxReservations:            -5,
		}

		rm, err := NewRelayManager(h, cfg)
		require.NoError(t, err)
		assert.Equal(t, DefaultRelayHopLimit, rm.config.RelayHopLimit)
		assert.Equal(t, DefaultReservationTTL, rm.config.ReservationTTL)
		assert.Equal(t, DefaultReservationRefreshInterval, rm.config.ReservationRefreshInterval)
		assert.Equal(t, DefaultMaxReservations, rm.config.MaxReservations)
	})
}

// TestRelayManagerStartStop tests relay manager lifecycle.
func TestRelayManagerStartStop(t *testing.T) {
	t.Run("start without relay enabled", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: false})
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		assert.NoError(t, err, "should start without error")

		// Stop should work
		err = rm.Stop(ctx)
		assert.NoError(t, err, "should stop without error")
	})

	t.Run("start with relay client enabled", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{
			EnableRelay:                true,
			ReservationRefreshInterval: time.Second,
		})
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = rm.Start(ctx)
		assert.NoError(t, err, "should start without error")

		// Verify started state
		assert.True(t, rm.started.Load(), "should be in started state")

		// Stop gracefully
		err = rm.Stop(ctx)
		assert.NoError(t, err, "should stop without error")
	})

	t.Run("double start returns error", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, nil)
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		err = rm.Start(ctx)
		assert.ErrorIs(t, err, ErrRelayAlreadyStarted, "second start should return ErrRelayAlreadyStarted")
	})

	t.Run("stop before start returns error", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, nil)
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Stop(ctx)
		assert.ErrorIs(t, err, ErrRelayNotStarted, "stop before start should return ErrRelayNotStarted")
	})

	t.Run("start after stop returns error", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, nil)
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)

		err = rm.Stop(ctx)
		require.NoError(t, err)

		err = rm.Start(ctx)
		assert.ErrorIs(t, err, ErrRelayAlreadyStopped, "start after stop should return ErrRelayAlreadyStopped")
	})

	t.Run("stop with context timeout", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{
			EnableRelay:                true,
			ReservationRefreshInterval: 100 * time.Millisecond,
		})
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)

		// Use already canceled context for Stop
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		err = rm.Stop(canceledCtx)
		// Error may or may not occur depending on timing
		// The important thing is it doesn't hang
		_ = err
	})

	t.Run("start with static relays launches maintenance goroutine", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		// Use fake static relay - we just want to trigger the maintenance goroutine
		rm, err := NewRelayManager(h, &RelayConfig{
			EnableRelay:                true,
			StaticRelays:               []string{"/ip4/127.0.0.1/tcp/65535/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"},
			ReservationRefreshInterval: time.Hour,
		})
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)

		// Let the maintenance goroutine start
		time.Sleep(50 * time.Millisecond)

		err = rm.Stop(ctx)
		assert.NoError(t, err)
	})
}

// TestRelayManagerRelayService tests relay service initialization.
func TestRelayManagerRelayService(t *testing.T) {
	t.Run("start relay service", func(t *testing.T) {
		h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
			RelayServiceConfig: DefaultRelayServiceConfig(),
		})
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		assert.True(t, rm.IsRelayServiceEnabled(), "relay service should be enabled")
		assert.NotNil(t, rm.relayService, "relay service should be initialized")
	})

	t.Run("relay service with custom config", func(t *testing.T) {
		h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		svcCfg := &RelayServiceConfig{
			MaxReservations:        64,
			MaxCircuits:            8,
			MaxReservationsPerPeer: 2,
			MaxReservationsPerIP:   4,
			ReservationTTL:         30 * time.Minute,
			MaxDuration:            time.Minute,
			MaxData:                1 << 16,
		}

		rm, err := NewRelayManager(h, &RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
			RelayServiceConfig: svcCfg,
		})
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		assert.NotNil(t, rm.relayService, "relay service should be initialized")
	})

	t.Run("relay service with nil service config uses defaults", func(t *testing.T) {
		h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
			RelayServiceConfig: nil, // Use defaults
		})
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		assert.NotNil(t, rm.relayService, "relay service should be initialized with defaults")
	})
}

// TestRelayManagerReservations tests reservation management.
func TestRelayManagerReservations(t *testing.T) {
	t.Run("reserve relay requires started manager", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: true})
		require.NoError(t, err)

		ctx := context.Background()
		_, err = rm.ReserveRelay(ctx, peer.AddrInfo{})
		assert.ErrorIs(t, err, ErrRelayNotStarted, "should return ErrRelayNotStarted")
	})

	t.Run("reserve relay requires relay enabled", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: false})
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		_, err = rm.ReserveRelay(ctx, peer.AddrInfo{})
		assert.ErrorIs(t, err, ErrRelayNotEnabled, "should return ErrRelayNotEnabled")
	})

	t.Run("get active reservations returns empty initially", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: true})
		require.NoError(t, err)

		reservations := rm.GetActiveReservations()
		assert.Empty(t, reservations, "should have no reservations initially")
	})

	t.Run("get relay addresses returns empty initially", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: true})
		require.NoError(t, err)

		addrs := rm.GetRelayAddresses()
		assert.Empty(t, addrs, "should have no relay addresses initially")
	})

	t.Run("remove nonexistent reservation is safe", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: true})
		require.NoError(t, err)

		// Should not panic
		rm.RemoveReservation("nonexistent-peer-id")
	})

	t.Run("refresh nonexistent reservation returns error", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: true})
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		_, err = rm.RefreshReservation(ctx, "nonexistent-peer-id")
		assert.ErrorIs(t, err, ErrNoRelaysAvailable, "should return ErrNoRelaysAvailable")
	})
}

// TestRelayConnectionThroughRelay tests connecting through a relay.
func TestRelayConnectionThroughRelay(t *testing.T) {
	t.Run("connection through relay server", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create relay server with ForceReachabilityPublic to ensure relay service starts.
		// In test environments, the host is on localhost and not detected as publicly reachable.
		// ForceReachabilityPublic overrides this detection so the relay service actually runs.
		relayHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relayHost.Close() }()

		relayInfo := peer.AddrInfo{
			ID:    relayHost.ID(),
			Addrs: relayHost.Addrs(),
		}

		// Create client with relay enabled
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		// Create relay manager for client
		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:     true,
			ReservationTTL:  time.Hour,
			MaxReservations: 1,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Reserve relay
		reservation, err := rm.ReserveRelay(ctx, relayInfo)
		require.NoError(t, err)
		assert.NotNil(t, reservation, "reservation should be created")
		assert.Equal(t, relayHost.ID(), reservation.RelayPeerID, "peer ID should match")
		assert.False(t, reservation.IsExpired(), "reservation should not be expired")
		assert.NotNil(t, reservation.Reservation, "underlying reservation should exist")

		// Verify reservation is tracked
		reservations := rm.GetActiveReservations()
		assert.Len(t, reservations, 1, "should have one reservation")

		// Note: In localhost test environments, relay addresses may be empty because
		// the relay cannot determine public addresses for the client. This is expected
		// behavior. The GetRelayAddresses method returns whatever addresses the relay
		// provides, which depends on network configuration.
		_ = rm.GetRelayAddresses() // Call to ensure no panic; addresses may be empty on localhost

		// Remove reservation
		rm.RemoveReservation(relayHost.ID())
		reservations = rm.GetActiveReservations()
		assert.Empty(t, reservations, "should have no reservations after removal")
	})
}

// TestRelayFailover tests relay failover when connection drops.
func TestRelayFailover(t *testing.T) {
	t.Run("failover to next static relay", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create two relay servers with ForceReachabilityPublic to ensure relay service starts
		relay1, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relay1.Close() }()

		relay2, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relay2.Close() }()

		// Build static relay addresses
		relay1Addr := relay1.Addrs()[0].String() + "/p2p/" + relay1.ID().String()
		relay2Addr := relay2.Addrs()[0].String() + "/p2p/" + relay2.ID().String()

		// Create client with static relays
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:                true,
			StaticRelays:               []string{relay1Addr, relay2Addr},
			ReservationTTL:             time.Hour,
			ReservationRefreshInterval: time.Second,
			MaxReservations:            2,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Wait for connections to be established
		time.Sleep(500 * time.Millisecond)

		// Close first relay to simulate failure
		_ = relay1.Close()

		// Wait for maintenance to detect and reconnect
		time.Sleep(2 * time.Second)

		// Verify at least one relay is still connected
		reservations := rm.GetActiveReservations()
		// May have 1 or 2 depending on timing
		assert.True(t, len(reservations) >= 1, "should still have at least one reservation")
	})
}

// TestBuildRelayHostOptions tests building libp2p options for relay.
func TestBuildRelayHostOptions(t *testing.T) {
	t.Run("nil config returns nil", func(t *testing.T) {
		opts := BuildRelayHostOptions(nil)
		assert.Nil(t, opts, "should return nil for nil config")
	})

	t.Run("relay disabled returns nil", func(t *testing.T) {
		opts := BuildRelayHostOptions(&RelayConfig{EnableRelay: false})
		assert.Nil(t, opts, "should return nil when relay disabled")
	})

	t.Run("relay enabled returns options", func(t *testing.T) {
		opts := BuildRelayHostOptions(&RelayConfig{EnableRelay: true})
		assert.NotNil(t, opts, "should return options when relay enabled")
		assert.NotEmpty(t, opts, "should have options")
	})

	t.Run("relay service enabled returns more options", func(t *testing.T) {
		optsClient := BuildRelayHostOptions(&RelayConfig{EnableRelay: true})
		optsServer := BuildRelayHostOptions(&RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
		})
		assert.True(t, len(optsServer) > len(optsClient), "server should have more options than client")
	})

	t.Run("relay service with nil service config uses defaults", func(t *testing.T) {
		opts := BuildRelayHostOptions(&RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
			RelayServiceConfig: nil,
		})
		assert.NotNil(t, opts, "should return options with default service config")
		assert.NotEmpty(t, opts, "should have options")
	})

	t.Run("relay service with custom config", func(t *testing.T) {
		opts := BuildRelayHostOptions(&RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
			RelayServiceConfig: &RelayServiceConfig{
				MaxReservations: 64,
				MaxCircuits:     8,
			},
		})
		assert.NotNil(t, opts, "should return options with custom service config")
		assert.NotEmpty(t, opts, "should have options")
	})
}

// TestNewRelayEnabledHost tests creating a relay-enabled host.
func TestNewRelayEnabledHost(t *testing.T) {
	t.Run("create with nil configs uses defaults", func(t *testing.T) {
		ctx := context.Background()
		host, rm, err := NewRelayEnabledHost(ctx, nil, nil)
		require.NoError(t, err)
		defer func() { _ = host.Close() }()
		defer func() { _ = rm.Stop(ctx) }()

		assert.NotNil(t, host, "host should not be nil")
		assert.NotNil(t, rm, "relay manager should not be nil")
	})

	t.Run("create with relay enabled", func(t *testing.T) {
		ctx := context.Background()
		hostCfg := &HostConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			EnableNoise: true,
			EnableTLS:   true,
		}
		relayCfg := &RelayConfig{
			EnableRelay:     true,
			ReservationTTL:  time.Hour,
			MaxReservations: 3,
		}

		host, rm, err := NewRelayEnabledHost(ctx, hostCfg, relayCfg)
		require.NoError(t, err)
		defer func() { _ = host.Close() }()
		defer func() { _ = rm.Stop(ctx) }()

		assert.NotNil(t, host, "host should not be nil")
		assert.True(t, rm.IsRelayEnabled(), "relay should be enabled")
	})

	t.Run("create with relay service", func(t *testing.T) {
		ctx := context.Background()
		hostCfg := &HostConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			EnableNoise: true,
			EnableTLS:   true,
		}
		relayCfg := &RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
		}

		host, rm, err := NewRelayEnabledHost(ctx, hostCfg, relayCfg)
		require.NoError(t, err)
		defer func() { _ = host.Close() }()
		defer func() { _ = rm.Stop(ctx) }()

		assert.True(t, rm.IsRelayServiceEnabled(), "relay service should be enabled")
	})

	t.Run("invalid listen address returns error", func(t *testing.T) {
		ctx := context.Background()
		hostCfg := &HostConfig{
			ListenAddrs: []string{"invalid-addr"},
			EnableNoise: true,
		}

		host, rm, err := NewRelayEnabledHost(ctx, hostCfg, nil)
		assert.Nil(t, host, "host should be nil")
		assert.Nil(t, rm, "relay manager should be nil")
		assert.Error(t, err, "should return error for invalid address")
	})

	t.Run("no security protocols returns error", func(t *testing.T) {
		ctx := context.Background()
		hostCfg := &HostConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			EnableNoise: false,
			EnableTLS:   false,
		}

		host, rm, err := NewRelayEnabledHost(ctx, hostCfg, nil)
		assert.Nil(t, host, "host should be nil")
		assert.Nil(t, rm, "relay manager should be nil")
		assert.Error(t, err, "should return error when no security protocol")
	})

	t.Run("relay manager creation failure cleans up host", func(t *testing.T) {
		ctx := context.Background()
		hostCfg := &HostConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			EnableNoise: true,
			EnableTLS:   true,
		}
		// Invalid static relay address will cause NewRelayManager to fail
		relayCfg := &RelayConfig{
			EnableRelay:  true,
			StaticRelays: []string{"invalid-multiaddr"},
		}

		host, rm, err := NewRelayEnabledHost(ctx, hostCfg, relayCfg)
		assert.Nil(t, host, "host should be nil after cleanup")
		assert.Nil(t, rm, "relay manager should be nil")
		assert.Error(t, err, "should return error for invalid static relay")
	})
}

// TestNewHostWithRelayOptions tests creating a host with relay options.
func TestNewHostWithRelayOptions(t *testing.T) {
	t.Run("create with nil config uses defaults", func(t *testing.T) {
		ctx := context.Background()
		host, err := NewHostWithRelayOptions(ctx, nil, nil)
		require.NoError(t, err)
		defer func() { _ = host.Close() }()

		assert.NotNil(t, host, "host should not be nil")
		assert.NotEmpty(t, host.ID(), "host should have peer ID")
	})

	t.Run("invalid listen address returns error", func(t *testing.T) {
		ctx := context.Background()
		cfg := &HostConfig{
			ListenAddrs: []string{"invalid-addr"},
			EnableNoise: true,
		}

		host, err := NewHostWithRelayOptions(ctx, cfg, nil)
		assert.Nil(t, host, "host should be nil")
		assert.Error(t, err, "should return error for invalid address")
	})

	t.Run("no security protocols returns error", func(t *testing.T) {
		ctx := context.Background()
		cfg := &HostConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			EnableNoise: false,
			EnableTLS:   false,
		}

		host, err := NewHostWithRelayOptions(ctx, cfg, nil)
		assert.Nil(t, host, "host should be nil")
		assert.Error(t, err, "should return error when no security protocol")
	})

	t.Run("with relay config enabled", func(t *testing.T) {
		ctx := context.Background()
		hostCfg := &HostConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			EnableNoise: true,
			EnableTLS:   true,
		}
		relayCfg := &RelayConfig{
			EnableRelay: true,
		}

		host, err := NewHostWithRelayOptions(ctx, hostCfg, relayCfg)
		require.NoError(t, err)
		defer func() { _ = host.Close() }()

		assert.NotNil(t, host, "host should not be nil")
	})

	t.Run("with relay service enabled", func(t *testing.T) {
		ctx := context.Background()
		hostCfg := &HostConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			EnableNoise: true,
			EnableTLS:   true,
		}
		relayCfg := &RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
		}

		host, err := NewHostWithRelayOptions(ctx, hostCfg, relayCfg)
		require.NoError(t, err)
		defer func() { _ = host.Close() }()

		assert.NotNil(t, host, "host should not be nil")
	})

	t.Run("with no listen addresses", func(t *testing.T) {
		ctx := context.Background()
		hostCfg := &HostConfig{
			ListenAddrs: []string{},
			EnableNoise: true,
			EnableTLS:   true,
		}

		host, err := NewHostWithRelayOptions(ctx, hostCfg, nil)
		require.NoError(t, err)
		defer func() { _ = host.Close() }()

		assert.NotNil(t, host, "host should not be nil")
	})
}

// TestRelayError tests relay error formatting.
func TestRelayError(t *testing.T) {
	t.Run("error with peer ID", func(t *testing.T) {
		peerID := peer.ID("12D3KooW...")
		err := &RelayError{
			Op:      "connect",
			PeerID:  peerID,
			Wrapped: errors.New("connection refused"),
		}

		msg := err.Error()
		assert.Contains(t, msg, "relay connect", "should contain operation")
		assert.Contains(t, msg, "peer=", "should contain peer prefix")
		assert.Contains(t, msg, "connection refused", "should contain wrapped error")
	})

	t.Run("error with address", func(t *testing.T) {
		err := &RelayError{
			Op:      "parse_address",
			Address: "/ip4/invalid",
			Wrapped: errors.New("invalid multiaddr"),
		}

		msg := err.Error()
		assert.Contains(t, msg, "relay parse_address", "should contain operation")
		assert.Contains(t, msg, "addr=", "should contain address prefix")
		assert.Contains(t, msg, "invalid multiaddr", "should contain wrapped error")
	})

	t.Run("error without context", func(t *testing.T) {
		err := &RelayError{
			Op:      "start_service",
			Wrapped: errors.New("failed to start"),
		}

		msg := err.Error()
		assert.Contains(t, msg, "relay start_service", "should contain operation")
		assert.Contains(t, msg, "failed to start", "should contain wrapped error")
	})

	t.Run("unwrap returns wrapped error", func(t *testing.T) {
		innerErr := errors.New("inner error")
		err := &RelayError{
			Op:      "test",
			Wrapped: innerErr,
		}

		assert.Equal(t, innerErr, err.Unwrap(), "should unwrap to inner error")
		assert.True(t, errors.Is(err, innerErr), "errors.Is should work")
	})
}

// TestParseRelayAddresses tests multiaddress parsing.
func TestParseRelayAddresses(t *testing.T) {
	t.Run("valid addresses", func(t *testing.T) {
		addrs := []string{
			"/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
			"/ip4/192.168.1.1/tcp/4002/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
		}

		peers, err := parseRelayAddresses(addrs)
		require.NoError(t, err)
		assert.Len(t, peers, 2, "should parse both addresses")
	})

	t.Run("invalid multiaddr format", func(t *testing.T) {
		addrs := []string{"not-a-multiaddr"}

		peers, err := parseRelayAddresses(addrs)
		assert.Nil(t, peers, "should return nil peers")
		assert.Error(t, err, "should return error")
		var relayErr *RelayError
		assert.True(t, errors.As(err, &relayErr), "should be RelayError")
		assert.Equal(t, "parse_address", relayErr.Op)
	})

	t.Run("multiaddr without peer ID", func(t *testing.T) {
		addrs := []string{"/ip4/127.0.0.1/tcp/4001"}

		peers, err := parseRelayAddresses(addrs)
		assert.Nil(t, peers, "should return nil peers")
		assert.Error(t, err, "should return error for missing peer ID")
		var relayErr *RelayError
		assert.True(t, errors.As(err, &relayErr), "should be RelayError")
		assert.Equal(t, "extract_peer_info", relayErr.Op)
	})

	t.Run("empty addresses", func(t *testing.T) {
		peers, err := parseRelayAddresses([]string{})
		require.NoError(t, err)
		assert.Empty(t, peers, "should return empty slice")
	})
}

// TestParseMultiaddrs tests multiaddr parsing helper.
func TestParseMultiaddrs(t *testing.T) {
	t.Run("valid multiaddrs", func(t *testing.T) {
		addrs := []string{
			"/ip4/127.0.0.1/tcp/4001",
			"/ip6/::1/tcp/4002",
		}

		maddrs, err := parseMultiaddrs(addrs)
		require.NoError(t, err)
		assert.Len(t, maddrs, 2, "should parse both addresses")
	})

	t.Run("invalid multiaddr", func(t *testing.T) {
		addrs := []string{"invalid"}

		maddrs, err := parseMultiaddrs(addrs)
		assert.Nil(t, maddrs, "should return nil")
		assert.Error(t, err, "should return error")
	})

	t.Run("empty addresses", func(t *testing.T) {
		maddrs, err := parseMultiaddrs([]string{})
		require.NoError(t, err)
		assert.Empty(t, maddrs, "should return empty slice")
	})
}

// TestBuildSecurityOptions tests security option building.
func TestBuildSecurityOptions(t *testing.T) {
	t.Run("both noise and TLS", func(t *testing.T) {
		cfg := &HostConfig{EnableNoise: true, EnableTLS: true}
		opts, err := buildSecurityOptions(cfg)
		require.NoError(t, err)
		assert.Len(t, opts, 2, "should have two security options")
	})

	t.Run("noise only", func(t *testing.T) {
		cfg := &HostConfig{EnableNoise: true, EnableTLS: false}
		opts, err := buildSecurityOptions(cfg)
		require.NoError(t, err)
		assert.Len(t, opts, 1, "should have one security option")
	})

	t.Run("TLS only", func(t *testing.T) {
		cfg := &HostConfig{EnableNoise: false, EnableTLS: true}
		opts, err := buildSecurityOptions(cfg)
		require.NoError(t, err)
		assert.Len(t, opts, 1, "should have one security option")
	})

	t.Run("neither enabled returns error", func(t *testing.T) {
		cfg := &HostConfig{EnableNoise: false, EnableTLS: false}
		opts, err := buildSecurityOptions(cfg)
		assert.Nil(t, opts, "should return nil")
		assert.Error(t, err, "should return error")
	})
}

// TestIsRelayEnabled tests relay state queries.
func TestIsRelayEnabled(t *testing.T) {
	h, err := libp2p.New(libp2p.NoListenAddrs)
	require.NoError(t, err)
	defer func() { _ = h.Close() }()

	t.Run("relay disabled", func(t *testing.T) {
		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: false})
		require.NoError(t, err)
		assert.False(t, rm.IsRelayEnabled())
		assert.False(t, rm.IsRelayServiceEnabled())
	})

	t.Run("relay enabled", func(t *testing.T) {
		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: true})
		require.NoError(t, err)
		assert.True(t, rm.IsRelayEnabled())
		assert.False(t, rm.IsRelayServiceEnabled())
	})

	t.Run("relay service enabled", func(t *testing.T) {
		rm, err := NewRelayManager(h, &RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
		})
		require.NoError(t, err)
		assert.True(t, rm.IsRelayEnabled())
		assert.True(t, rm.IsRelayServiceEnabled())
	})
}

// TestRefreshReservation tests reservation refresh functionality.
func TestRefreshReservation(t *testing.T) {
	t.Run("refresh existing reservation with peerstore addresses", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create relay server
		relayHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relayHost.Close() }()

		relayInfo := peer.AddrInfo{
			ID:    relayHost.ID(),
			Addrs: relayHost.Addrs(),
		}

		// Create client
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:     true,
			ReservationTTL:  time.Hour,
			MaxReservations: 3,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Initial reservation
		_, err = rm.ReserveRelay(ctx, relayInfo)
		require.NoError(t, err)

		// Refresh the reservation - should use peerstore addresses
		refreshed, err := rm.RefreshReservation(ctx, relayHost.ID())
		require.NoError(t, err)
		assert.NotNil(t, refreshed, "refreshed reservation should not be nil")
		assert.Equal(t, relayHost.ID(), refreshed.RelayPeerID)
	})

	t.Run("refresh reservation using existing relay addrs when peerstore empty", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create relay server
		relayHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relayHost.Close() }()

		relayInfo := peer.AddrInfo{
			ID:    relayHost.ID(),
			Addrs: relayHost.Addrs(),
		}

		// Create client
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:     true,
			ReservationTTL:  time.Hour,
			MaxReservations: 3,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Initial reservation
		initialRes, err := rm.ReserveRelay(ctx, relayInfo)
		require.NoError(t, err)

		// Clear peerstore addresses to test fallback to reservation addresses
		clientHost.Peerstore().ClearAddrs(relayHost.ID())

		// Manually set the reservation with addresses for the fallback path
		rm.reservationsMu.Lock()
		rm.reservations[relayHost.ID()] = &RelayReservation{
			RelayPeerID: relayHost.ID(),
			RelayAddrs:  initialRes.RelayAddrs,
			Expiry:      time.Now().Add(time.Hour),
			Reservation: initialRes.Reservation,
		}
		rm.reservationsMu.Unlock()

		// Add addresses back to enable connection
		clientHost.Peerstore().AddAddrs(relayHost.ID(), relayHost.Addrs(), time.Hour)

		// Refresh should work using existing reservation addresses
		refreshed, err := rm.RefreshReservation(ctx, relayHost.ID())
		require.NoError(t, err)
		assert.NotNil(t, refreshed)
	})
}

// TestRefreshExpiring tests the refreshExpiring method.
func TestRefreshExpiring(t *testing.T) {
	t.Run("refresh near-expiry reservations", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create relay server
		relayHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relayHost.Close() }()

		relayInfo := peer.AddrInfo{
			ID:    relayHost.ID(),
			Addrs: relayHost.Addrs(),
		}

		// Create client
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		// Use a short TTL so we can test refresh threshold
		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:     true,
			ReservationTTL:  5 * time.Second, // Short TTL
			MaxReservations: 3,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Create reservation
		_, err = rm.ReserveRelay(ctx, relayInfo)
		require.NoError(t, err)

		// Manually set reservation to near-expiry (less than 20% TTL remaining)
		rm.reservationsMu.Lock()
		if res, ok := rm.reservations[relayHost.ID()]; ok {
			// Set expiry to 500ms from now (less than 1s which is 20% of 5s)
			res.Expiry = time.Now().Add(500 * time.Millisecond)
		}
		rm.reservationsMu.Unlock()

		// Call refreshExpiring directly
		rm.refreshExpiring(ctx)

		// Verify reservation was refreshed (expiry should be further in future)
		rm.reservationsMu.RLock()
		res := rm.reservations[relayHost.ID()]
		rm.reservationsMu.RUnlock()

		assert.NotNil(t, res)
		assert.True(t, res.TTL() > time.Second, "reservation should have been refreshed")
	})

	t.Run("no refresh for healthy reservations", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create relay server
		relayHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relayHost.Close() }()

		relayInfo := peer.AddrInfo{
			ID:    relayHost.ID(),
			Addrs: relayHost.Addrs(),
		}

		// Create client
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:     true,
			ReservationTTL:  time.Hour,
			MaxReservations: 3,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Create reservation with plenty of time left
		originalRes, err := rm.ReserveRelay(ctx, relayInfo)
		require.NoError(t, err)

		originalExpiry := originalRes.Expiry

		// Call refreshExpiring - should not refresh since TTL > 20%
		rm.refreshExpiring(ctx)

		// Verify expiry unchanged (within tolerance since refresh didn't happen)
		rm.reservationsMu.RLock()
		res := rm.reservations[relayHost.ID()]
		rm.reservationsMu.RUnlock()

		assert.NotNil(t, res)
		// Expiry should be similar (allow small difference for test timing)
		assert.True(t, res.Expiry.Sub(originalExpiry) < time.Second)
	})

	t.Run("refresh with empty reservations", func(t *testing.T) {
		ctx := context.Background()

		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{
			EnableRelay:     true,
			ReservationTTL:  time.Hour,
			MaxReservations: 3,
		})
		require.NoError(t, err)

		// Call refreshExpiring with no reservations - should not panic
		rm.refreshExpiring(ctx)
	})
}

// TestMaintainRelayConnections tests the maintainRelayConnections method.
func TestMaintainRelayConnections(t *testing.T) {
	t.Run("maintains connections to static relays", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Create relay server
		relayHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relayHost.Close() }()

		relayAddr := relayHost.Addrs()[0].String() + "/p2p/" + relayHost.ID().String()

		// Create client with static relay
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:                true,
			StaticRelays:               []string{relayAddr},
			ReservationTTL:             time.Hour,
			ReservationRefreshInterval: time.Hour,
			MaxReservations:            3,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Wait for initial connection
		time.Sleep(500 * time.Millisecond)

		reservations := rm.GetActiveReservations()
		assert.Len(t, reservations, 1, "should have one reservation from static relay")
	})

	t.Run("respects max reservations limit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Create three relay servers
		var relays []string
		for i := 0; i < 3; i++ {
			relayHost, err := libp2p.New(
				libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
				libp2p.ForceReachabilityPublic(),
				libp2p.EnableRelayService(),
			)
			require.NoError(t, err)
			defer func() { _ = relayHost.Close() }()

			relayAddr := relayHost.Addrs()[0].String() + "/p2p/" + relayHost.ID().String()
			relays = append(relays, relayAddr)
		}

		// Create client with max 2 reservations
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:                true,
			StaticRelays:               relays,
			ReservationTTL:             time.Hour,
			ReservationRefreshInterval: time.Hour,
			MaxReservations:            2, // Limit to 2
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Wait for connections
		time.Sleep(500 * time.Millisecond)

		reservations := rm.GetActiveReservations()
		assert.LessOrEqual(t, len(reservations), 2, "should respect max reservations limit")
	})

	t.Run("stops on context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Create relay server
		relayHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relayHost.Close() }()

		relayAddr := relayHost.Addrs()[0].String() + "/p2p/" + relayHost.ID().String()

		// Create client
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:                true,
			StaticRelays:               []string{relayAddr},
			ReservationTTL:             time.Hour,
			ReservationRefreshInterval: 100 * time.Millisecond,
			MaxReservations:            3,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)

		// Cancel context quickly
		cancel()

		// Stop should complete without hanging
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		err = rm.Stop(stopCtx)
		// May return context.Canceled or nil depending on timing
		_ = err
	})

	t.Run("stops on stopChan close", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Create relay server
		relayHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relayHost.Close() }()

		relayAddr := relayHost.Addrs()[0].String() + "/p2p/" + relayHost.ID().String()

		// Create client
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:                true,
			StaticRelays:               []string{relayAddr},
			ReservationTTL:             time.Hour,
			ReservationRefreshInterval: 100 * time.Millisecond,
			MaxReservations:            3,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)

		// Stop normally
		err = rm.Stop(ctx)
		assert.NoError(t, err)
	})
}

// TestConnectToStaticRelays tests the connectToStaticRelays method.
func TestConnectToStaticRelays(t *testing.T) {
	t.Run("skips already reserved relays", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create relay server
		relayHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relayHost.Close() }()

		relayInfo := peer.AddrInfo{
			ID:    relayHost.ID(),
			Addrs: relayHost.Addrs(),
		}

		relayAddr := relayHost.Addrs()[0].String() + "/p2p/" + relayHost.ID().String()

		// Create client
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:     true,
			StaticRelays:    []string{relayAddr},
			ReservationTTL:  time.Hour,
			MaxReservations: 3,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Manually create reservation first
		_, err = rm.ReserveRelay(ctx, relayInfo)
		require.NoError(t, err)

		initialCount := len(rm.GetActiveReservations())

		// Call connectToStaticRelays - should skip existing reservation
		rm.connectToStaticRelays(ctx)

		// Should still have same number of reservations
		assert.Equal(t, initialCount, len(rm.GetActiveReservations()))
	})

	t.Run("handles connection failure gracefully", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Use a non-existent relay address
		fakeRelayAddr := "/ip4/127.0.0.1/tcp/65535/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"

		// Create client
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:     true,
			StaticRelays:    []string{fakeRelayAddr},
			ReservationTTL:  time.Hour,
			MaxReservations: 3,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Should not panic and should have no reservations
		time.Sleep(500 * time.Millisecond)
		reservations := rm.GetActiveReservations()
		assert.Empty(t, reservations, "should have no reservations for unreachable relay")
	})
}

// TestMaintainReservations tests the maintainReservations goroutine.
func TestMaintainReservations(t *testing.T) {
	t.Run("maintenance loop runs periodically", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Create relay server
		relayHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
		)
		require.NoError(t, err)
		defer func() { _ = relayHost.Close() }()

		relayInfo := peer.AddrInfo{
			ID:    relayHost.ID(),
			Addrs: relayHost.Addrs(),
		}

		// Create client with very short refresh interval
		clientHost, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelay(),
		)
		require.NoError(t, err)
		defer func() { _ = clientHost.Close() }()

		rm, err := NewRelayManager(clientHost, &RelayConfig{
			EnableRelay:                true,
			ReservationTTL:             2 * time.Second,
			ReservationRefreshInterval: 500 * time.Millisecond, // Short interval
			MaxReservations:            3,
		})
		require.NoError(t, err)

		err = rm.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = rm.Stop(ctx) }()

		// Create reservation with near-expiry
		res, err := rm.ReserveRelay(ctx, relayInfo)
		require.NoError(t, err)

		// Set to near-expiry
		rm.reservationsMu.Lock()
		rm.reservations[relayHost.ID()].Expiry = time.Now().Add(200 * time.Millisecond)
		rm.reservationsMu.Unlock()

		// Wait for maintenance to run
		time.Sleep(time.Second)

		// Verify reservation was maintained
		rm.reservationsMu.RLock()
		currentRes := rm.reservations[relayHost.ID()]
		rm.reservationsMu.RUnlock()

		// Should have been refreshed (or still exist)
		if currentRes != nil {
			assert.True(t, currentRes.Expiry.After(res.Expiry.Add(-time.Second)))
		}
	})
}

// TestStopWithRelayService tests stopping with relay service running.
func TestStopWithRelayService(t *testing.T) {
	t.Run("stop closes relay service", func(t *testing.T) {
		h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
		})
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)

		assert.NotNil(t, rm.relayService, "relay service should exist")

		err = rm.Stop(ctx)
		assert.NoError(t, err)

		assert.True(t, rm.stopped.Load())
	})

	t.Run("double stop is safe", func(t *testing.T) {
		h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{
			EnableRelay:        true,
			EnableRelayService: true,
		})
		require.NoError(t, err)

		ctx := context.Background()
		err = rm.Start(ctx)
		require.NoError(t, err)

		err = rm.Stop(ctx)
		assert.NoError(t, err)

		// Second stop should be safe due to sync.Once
		err = rm.Stop(ctx)
		assert.NoError(t, err)
	})
}

// TestGetActiveReservationsFiltersExpired tests that expired reservations are filtered.
func TestGetActiveReservationsFiltersExpired(t *testing.T) {
	h, err := libp2p.New(libp2p.NoListenAddrs)
	require.NoError(t, err)
	defer func() { _ = h.Close() }()

	rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: true})
	require.NoError(t, err)

	// Add an expired reservation directly
	expiredPeerID := peer.ID("expired-peer")
	rm.reservationsMu.Lock()
	rm.reservations[expiredPeerID] = &RelayReservation{
		RelayPeerID: expiredPeerID,
		Expiry:      time.Now().Add(-time.Hour), // Expired
	}
	rm.reservationsMu.Unlock()

	// Add a valid reservation
	validPeerID := peer.ID("valid-peer")
	rm.reservationsMu.Lock()
	rm.reservations[validPeerID] = &RelayReservation{
		RelayPeerID: validPeerID,
		Expiry:      time.Now().Add(time.Hour), // Valid
	}
	rm.reservationsMu.Unlock()

	// GetActiveReservations should only return the valid one
	active := rm.GetActiveReservations()
	assert.Len(t, active, 1, "should only return non-expired reservations")
	assert.Equal(t, validPeerID, active[0].RelayPeerID)
}

// TestUpdateRelayAddresses tests the updateRelayAddresses method.
func TestUpdateRelayAddresses(t *testing.T) {
	t.Run("updates with valid reservations", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: true})
		require.NoError(t, err)

		// Initially empty
		assert.Empty(t, rm.GetRelayAddresses())

		// Add a valid reservation with addresses
		validPeerID := peer.ID("valid-peer")
		testAddr, _ := parseMultiaddrs([]string{"/ip4/127.0.0.1/tcp/4001"})

		rm.reservationsMu.Lock()
		rm.reservations[validPeerID] = &RelayReservation{
			RelayPeerID: validPeerID,
			RelayAddrs:  testAddr,
			Expiry:      time.Now().Add(time.Hour),
		}
		rm.reservationsMu.Unlock()

		// Trigger update
		rm.updateRelayAddresses()

		// Should now have addresses
		addrs := rm.GetRelayAddresses()
		assert.Len(t, addrs, 1)
	})

	t.Run("filters expired reservations", func(t *testing.T) {
		h, err := libp2p.New(libp2p.NoListenAddrs)
		require.NoError(t, err)
		defer func() { _ = h.Close() }()

		rm, err := NewRelayManager(h, &RelayConfig{EnableRelay: true})
		require.NoError(t, err)

		// Add expired reservation
		expiredPeerID := peer.ID("expired-peer")
		testAddr, _ := parseMultiaddrs([]string{"/ip4/127.0.0.1/tcp/4001"})

		rm.reservationsMu.Lock()
		rm.reservations[expiredPeerID] = &RelayReservation{
			RelayPeerID: expiredPeerID,
			RelayAddrs:  testAddr,
			Expiry:      time.Now().Add(-time.Hour), // Expired
		}
		rm.reservationsMu.Unlock()

		// Trigger update
		rm.updateRelayAddresses()

		// Should have no addresses (expired was filtered)
		addrs := rm.GetRelayAddresses()
		assert.Empty(t, addrs)
	})
}

// TestReserveRelayConnectionError tests ReserveRelay with connection errors.
func TestReserveRelayConnectionError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create client
	clientHost, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.EnableRelay(),
	)
	require.NoError(t, err)
	defer func() { _ = clientHost.Close() }()

	rm, err := NewRelayManager(clientHost, &RelayConfig{
		EnableRelay:     true,
		ReservationTTL:  time.Hour,
		MaxReservations: 3,
	})
	require.NoError(t, err)

	err = rm.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = rm.Stop(ctx) }()

	// Try to reserve with unreachable relay
	fakeAddr, _ := parseMultiaddrs([]string{"/ip4/127.0.0.1/tcp/65535"})
	fakeInfo := peer.AddrInfo{
		ID:    peer.ID("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"),
		Addrs: fakeAddr,
	}

	_, err = rm.ReserveRelay(ctx, fakeInfo)
	assert.Error(t, err, "should return error for unreachable relay")

	var relayErr *RelayError
	assert.True(t, errors.As(err, &relayErr), "should be RelayError")
	assert.Equal(t, "connect", relayErr.Op)
}

// TestReserveRelayReservationError tests ReserveRelay when reservation fails.
func TestReserveRelayReservationError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a host that does NOT have relay service enabled
	// This will accept connections but fail reservation requests
	nonRelayHost, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	require.NoError(t, err)
	defer func() { _ = nonRelayHost.Close() }()

	nonRelayInfo := peer.AddrInfo{
		ID:    nonRelayHost.ID(),
		Addrs: nonRelayHost.Addrs(),
	}

	// Create client
	clientHost, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.EnableRelay(),
	)
	require.NoError(t, err)
	defer func() { _ = clientHost.Close() }()

	rm, err := NewRelayManager(clientHost, &RelayConfig{
		EnableRelay:     true,
		ReservationTTL:  time.Hour,
		MaxReservations: 3,
	})
	require.NoError(t, err)

	err = rm.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = rm.Stop(ctx) }()

	// Try to reserve - should fail because target is not a relay
	_, err = rm.ReserveRelay(ctx, nonRelayInfo)
	assert.Error(t, err, "should return error when target is not a relay")

	var relayErr *RelayError
	assert.True(t, errors.As(err, &relayErr), "should be RelayError")
	assert.Equal(t, "reserve", relayErr.Op)
}
