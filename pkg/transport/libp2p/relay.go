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
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	ma "github.com/multiformats/go-multiaddr"
)

// Relay error types for typed error handling.
var (
	// ErrRelayNotEnabled indicates relay functionality is not enabled.
	ErrRelayNotEnabled = errors.New("relay: not enabled")

	// ErrRelayNotStarted indicates the relay manager has not been started.
	ErrRelayNotStarted = errors.New("relay: manager not started")

	// ErrRelayAlreadyStarted indicates the relay manager is already running.
	ErrRelayAlreadyStarted = errors.New("relay: manager already started")

	// ErrRelayAlreadyStopped indicates the relay manager has already stopped.
	ErrRelayAlreadyStopped = errors.New("relay: manager already stopped")

	// ErrNoRelaysAvailable indicates no relay nodes are available.
	ErrNoRelaysAvailable = errors.New("relay: no relays available")

	// ErrRelayConnectionFailed indicates a connection to a relay failed.
	ErrRelayConnectionFailed = errors.New("relay: connection failed")

	// ErrRelayReservationFailed indicates a relay reservation failed.
	ErrRelayReservationFailed = errors.New("relay: reservation failed")

	// ErrRelayReservationExpired indicates a relay reservation has expired.
	ErrRelayReservationExpired = errors.New("relay: reservation expired")

	// ErrInvalidRelayAddress indicates an invalid relay multiaddress.
	ErrInvalidRelayAddress = errors.New("relay: invalid address")

	// ErrRelayHopLimitExceeded indicates the relay hop limit was exceeded.
	ErrRelayHopLimitExceeded = errors.New("relay: hop limit exceeded")
)

// Default relay configuration values.
const (
	// DefaultRelayHopLimit is the default maximum number of relay hops.
	DefaultRelayHopLimit = 1

	// DefaultReservationTTL is the default reservation time-to-live.
	DefaultReservationTTL = time.Hour

	// DefaultReservationRefreshInterval is the default interval for refreshing reservations.
	DefaultReservationRefreshInterval = 45 * time.Minute

	// DefaultMaxReservations is the default maximum number of reservations.
	DefaultMaxReservations = 3
)

// RelayConfig contains configuration for circuit relay functionality.
type RelayConfig struct {
	// EnableRelay enables relay client functionality for NAT traversal.
	EnableRelay bool

	// EnableRelayService enables this node to act as a relay server.
	EnableRelayService bool

	// StaticRelays is a list of known relay multiaddresses to use.
	// Format: /ip4/x.x.x.x/tcp/port/p2p/QmPeerID
	StaticRelays []string

	// RelayHopLimit is the maximum number of relay hops allowed (default: 1).
	RelayHopLimit int

	// ReservationTTL is the duration for relay reservations (default: 1 hour).
	ReservationTTL time.Duration

	// ReservationRefreshInterval is how often to refresh reservations (default: 45 minutes).
	ReservationRefreshInterval time.Duration

	// MaxReservations is the maximum number of active reservations (default: 3).
	MaxReservations int

	// EnableAutoRelay enables automatic relay discovery via DHT (requires DHT enabled).
	EnableAutoRelay bool

	// RelayServiceConfig contains relay server configuration (when EnableRelayService is true).
	RelayServiceConfig *RelayServiceConfig
}

// RelayServiceConfig contains configuration for relay server functionality.
type RelayServiceConfig struct {
	// MaxReservations is the maximum number of reservations to accept.
	MaxReservations int

	// MaxCircuits is the maximum number of active relay circuits.
	MaxCircuits int

	// MaxReservationsPerPeer is the maximum reservations per peer.
	MaxReservationsPerPeer int

	// MaxReservationsPerIP is the maximum reservations per IP address.
	MaxReservationsPerIP int

	// ReservationTTL is the time-to-live for reservations.
	ReservationTTL time.Duration

	// MaxDuration is the maximum duration for a single relay connection.
	MaxDuration time.Duration

	// MaxData is the maximum data transferred per relay connection (bytes).
	MaxData int64
}

// DefaultRelayConfig returns a default relay configuration.
func DefaultRelayConfig() *RelayConfig {
	return &RelayConfig{
		EnableRelay:                false,
		EnableRelayService:         false,
		StaticRelays:               nil,
		RelayHopLimit:              DefaultRelayHopLimit,
		ReservationTTL:             DefaultReservationTTL,
		ReservationRefreshInterval: DefaultReservationRefreshInterval,
		MaxReservations:            DefaultMaxReservations,
		EnableAutoRelay:            false,
		RelayServiceConfig:         nil,
	}
}

// DefaultRelayServiceConfig returns a default relay service configuration.
func DefaultRelayServiceConfig() *RelayServiceConfig {
	return &RelayServiceConfig{
		MaxReservations:        128,
		MaxCircuits:            16,
		MaxReservationsPerPeer: 4,
		MaxReservationsPerIP:   8,
		ReservationTTL:         time.Hour,
		MaxDuration:            2 * time.Minute,
		MaxData:                1 << 17, // 128KB
	}
}

// RelayReservation represents an active relay reservation.
type RelayReservation struct {
	RelayPeerID peer.ID
	RelayAddrs  []ma.Multiaddr
	Expiry      time.Time
	Reservation *client.Reservation
}

// IsExpired returns true if the reservation has expired.
func (r *RelayReservation) IsExpired() bool {
	return time.Now().After(r.Expiry)
}

// TTL returns the remaining time-to-live for the reservation.
func (r *RelayReservation) TTL() time.Duration {
	remaining := time.Until(r.Expiry)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// RelayManager manages circuit relay connections for NAT traversal.
type RelayManager struct {
	host   host.Host
	config *RelayConfig

	// Relay server (when acting as relay)
	relayService *relay.Relay

	// Active reservations
	reservations   map[peer.ID]*RelayReservation
	reservationsMu sync.RWMutex

	// Static relay peers
	staticRelayPeers []peer.AddrInfo

	// Lifecycle management
	started  atomic.Bool
	stopped  atomic.Bool
	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// Relay address cache for advertisement
	relayAddrs   []ma.Multiaddr
	relayAddrsMu sync.RWMutex
}

// NewRelayManager creates a new relay manager for the given host.
func NewRelayManager(h host.Host, config *RelayConfig) (*RelayManager, error) {
	if h == nil {
		return nil, ErrRelayNotEnabled
	}

	if config == nil {
		config = DefaultRelayConfig()
	}

	// Apply defaults for zero values to prevent panics
	if config.RelayHopLimit <= 0 {
		config.RelayHopLimit = DefaultRelayHopLimit
	}
	if config.ReservationTTL <= 0 {
		config.ReservationTTL = DefaultReservationTTL
	}
	if config.ReservationRefreshInterval <= 0 {
		config.ReservationRefreshInterval = DefaultReservationRefreshInterval
	}
	if config.MaxReservations <= 0 {
		config.MaxReservations = DefaultMaxReservations
	}

	rm := &RelayManager{
		host:         h,
		config:       config,
		reservations: make(map[peer.ID]*RelayReservation),
		stopChan:     make(chan struct{}),
	}

	// Parse static relay addresses
	if len(config.StaticRelays) > 0 {
		staticPeers, err := parseRelayAddresses(config.StaticRelays)
		if err != nil {
			return nil, err
		}
		rm.staticRelayPeers = staticPeers
	}

	return rm, nil
}

// Start initializes the relay manager and establishes relay connections.
func (rm *RelayManager) Start(ctx context.Context) error {
	if rm.stopped.Load() {
		return ErrRelayAlreadyStopped
	}

	if rm.started.Swap(true) {
		return ErrRelayAlreadyStarted
	}

	// Start relay service if configured
	if rm.config.EnableRelayService {
		if err := rm.startRelayService(); err != nil {
			rm.started.Store(false)
			return err
		}
	}

	// Connect to static relays if configured
	if rm.config.EnableRelay && len(rm.staticRelayPeers) > 0 {
		rm.wg.Add(1)
		go rm.maintainRelayConnections(ctx)
	}

	// Start reservation maintenance
	if rm.config.EnableRelay {
		rm.wg.Add(1)
		go rm.maintainReservations(ctx)
	}

	return nil
}

// Stop gracefully shuts down the relay manager.
func (rm *RelayManager) Stop(ctx context.Context) error {
	var stopErr error

	rm.stopOnce.Do(func() {
		if !rm.started.Load() {
			stopErr = ErrRelayNotStarted
			return
		}

		rm.stopped.Store(true)
		close(rm.stopChan)

		// Wait for goroutines with context timeout
		done := make(chan struct{})
		go func() {
			rm.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-ctx.Done():
			stopErr = ctx.Err()
		}

		// Close relay service if running
		if rm.relayService != nil {
			if err := rm.relayService.Close(); err != nil && stopErr == nil {
				stopErr = err
			}
		}
	})

	return stopErr
}

// GetRelayAddresses returns the relay addresses for this node.
func (rm *RelayManager) GetRelayAddresses() []ma.Multiaddr {
	rm.relayAddrsMu.RLock()
	defer rm.relayAddrsMu.RUnlock()
	addrs := make([]ma.Multiaddr, len(rm.relayAddrs))
	copy(addrs, rm.relayAddrs)
	return addrs
}

// GetActiveReservations returns all active relay reservations.
func (rm *RelayManager) GetActiveReservations() []*RelayReservation {
	rm.reservationsMu.RLock()
	defer rm.reservationsMu.RUnlock()

	reservations := make([]*RelayReservation, 0, len(rm.reservations))
	for _, r := range rm.reservations {
		if !r.IsExpired() {
			reservations = append(reservations, r)
		}
	}
	return reservations
}

// ReserveRelay creates a reservation with the specified relay peer.
func (rm *RelayManager) ReserveRelay(ctx context.Context, relayInfo peer.AddrInfo) (*RelayReservation, error) {
	if !rm.config.EnableRelay {
		return nil, ErrRelayNotEnabled
	}

	if !rm.started.Load() {
		return nil, ErrRelayNotStarted
	}

	// Connect to relay if not already connected
	if err := rm.host.Connect(ctx, relayInfo); err != nil {
		return nil, &RelayError{
			Op:      "connect",
			PeerID:  relayInfo.ID,
			Wrapped: err,
		}
	}

	// Request reservation
	reservation, err := client.Reserve(ctx, rm.host, relayInfo)
	if err != nil {
		return nil, &RelayError{
			Op:      "reserve",
			PeerID:  relayInfo.ID,
			Wrapped: err,
		}
	}

	// Create relay reservation record
	relayReservation := &RelayReservation{
		RelayPeerID: relayInfo.ID,
		RelayAddrs:  reservation.Addrs,
		Expiry:      time.Now().Add(rm.config.ReservationTTL),
		Reservation: reservation,
	}

	// Store reservation
	rm.reservationsMu.Lock()
	rm.reservations[relayInfo.ID] = relayReservation
	rm.reservationsMu.Unlock()

	// Update relay addresses
	rm.updateRelayAddresses()

	return relayReservation, nil
}

// RefreshReservation refreshes an existing relay reservation.
func (rm *RelayManager) RefreshReservation(ctx context.Context, relayPeerID peer.ID) (*RelayReservation, error) {
	rm.reservationsMu.RLock()
	existing, ok := rm.reservations[relayPeerID]
	rm.reservationsMu.RUnlock()

	if !ok {
		return nil, ErrNoRelaysAvailable
	}

	// Get relay info from peerstore
	relayAddrs := rm.host.Peerstore().Addrs(relayPeerID)
	if len(relayAddrs) == 0 {
		relayAddrs = existing.RelayAddrs
	}

	relayInfo := peer.AddrInfo{
		ID:    relayPeerID,
		Addrs: relayAddrs,
	}

	return rm.ReserveRelay(ctx, relayInfo)
}

// RemoveReservation removes and cleans up a relay reservation.
func (rm *RelayManager) RemoveReservation(relayPeerID peer.ID) {
	rm.reservationsMu.Lock()
	delete(rm.reservations, relayPeerID)
	rm.reservationsMu.Unlock()

	rm.updateRelayAddresses()
}

// IsRelayEnabled returns true if relay client is enabled.
func (rm *RelayManager) IsRelayEnabled() bool {
	return rm.config.EnableRelay
}

// IsRelayServiceEnabled returns true if relay server is enabled.
func (rm *RelayManager) IsRelayServiceEnabled() bool {
	return rm.config.EnableRelayService
}

// startRelayService starts the relay server.
func (rm *RelayManager) startRelayService() error {
	svcConfig := rm.config.RelayServiceConfig
	if svcConfig == nil {
		svcConfig = DefaultRelayServiceConfig()
	}

	opts := []relay.Option{
		relay.WithLimit(&relay.RelayLimit{
			Duration: svcConfig.MaxDuration,
			Data:     svcConfig.MaxData,
		}),
		relay.WithResources(relay.Resources{
			Limit:                  &relay.RelayLimit{Duration: svcConfig.MaxDuration, Data: svcConfig.MaxData},
			ReservationTTL:         svcConfig.ReservationTTL,
			MaxReservations:        svcConfig.MaxReservations,
			MaxCircuits:            svcConfig.MaxCircuits,
			MaxReservationsPerPeer: svcConfig.MaxReservationsPerPeer,
			MaxReservationsPerIP:   svcConfig.MaxReservationsPerIP,
		}),
	}

	relayService, err := relay.New(rm.host, opts...)
	if err != nil {
		return &RelayError{
			Op:      "start_service",
			Wrapped: err,
		}
	}

	rm.relayService = relayService
	return nil
}

// maintainRelayConnections maintains connections to static relays.
func (rm *RelayManager) maintainRelayConnections(ctx context.Context) {
	defer rm.wg.Done()

	// Initial connection attempt
	rm.connectToStaticRelays(ctx)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopChan:
			return
		case <-ticker.C:
			rm.connectToStaticRelays(ctx)
		}
	}
}

// connectToStaticRelays connects to configured static relays.
func (rm *RelayManager) connectToStaticRelays(ctx context.Context) {
	for _, relayInfo := range rm.staticRelayPeers {
		// Skip if already reserved
		rm.reservationsMu.RLock()
		_, exists := rm.reservations[relayInfo.ID]
		rm.reservationsMu.RUnlock()

		if exists {
			continue
		}

		// Check reservation count
		rm.reservationsMu.RLock()
		count := len(rm.reservations)
		rm.reservationsMu.RUnlock()

		if count >= rm.config.MaxReservations {
			break
		}

		// Attempt reservation with timeout
		reserveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := rm.ReserveRelay(reserveCtx, relayInfo)
		cancel()

		if err != nil {
			continue
		}
	}
}

// maintainReservations refreshes reservations before they expire.
func (rm *RelayManager) maintainReservations(ctx context.Context) {
	defer rm.wg.Done()

	ticker := time.NewTicker(rm.config.ReservationRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopChan:
			return
		case <-ticker.C:
			rm.refreshExpiring(ctx)
		}
	}
}

// refreshExpiring refreshes reservations that are close to expiring.
func (rm *RelayManager) refreshExpiring(ctx context.Context) {
	rm.reservationsMu.RLock()
	toRefresh := make([]peer.ID, 0)
	for peerID, res := range rm.reservations {
		// Refresh if less than 20% TTL remaining
		threshold := rm.config.ReservationTTL / 5
		if res.TTL() < threshold {
			toRefresh = append(toRefresh, peerID)
		}
	}
	rm.reservationsMu.RUnlock()

	for _, peerID := range toRefresh {
		refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, _ = rm.RefreshReservation(refreshCtx, peerID)
		cancel()
	}
}

// updateRelayAddresses updates the cached relay addresses.
func (rm *RelayManager) updateRelayAddresses() {
	rm.reservationsMu.RLock()
	defer rm.reservationsMu.RUnlock()

	addrs := make([]ma.Multiaddr, 0)
	for _, res := range rm.reservations {
		if !res.IsExpired() {
			addrs = append(addrs, res.RelayAddrs...)
		}
	}

	rm.relayAddrsMu.Lock()
	rm.relayAddrs = addrs
	rm.relayAddrsMu.Unlock()
}

// parseRelayAddresses parses multiaddress strings into peer.AddrInfo.
func parseRelayAddresses(addrs []string) ([]peer.AddrInfo, error) {
	peers := make([]peer.AddrInfo, 0, len(addrs))

	for _, addr := range addrs {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			return nil, &RelayError{
				Op:      "parse_address",
				Address: addr,
				Wrapped: err,
			}
		}

		info, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			return nil, &RelayError{
				Op:      "extract_peer_info",
				Address: addr,
				Wrapped: err,
			}
		}

		peers = append(peers, *info)
	}

	return peers, nil
}

// RelayError represents a relay-specific error with context.
type RelayError struct {
	Op      string
	PeerID  peer.ID
	Address string
	Wrapped error
}

// Error returns the error message.
func (e *RelayError) Error() string {
	if e.PeerID != "" {
		return "relay " + e.Op + " (peer=" + e.PeerID.String() + "): " + e.Wrapped.Error()
	}
	if e.Address != "" {
		return "relay " + e.Op + " (addr=" + e.Address + "): " + e.Wrapped.Error()
	}
	return "relay " + e.Op + ": " + e.Wrapped.Error()
}

// Unwrap returns the wrapped error.
func (e *RelayError) Unwrap() error {
	return e.Wrapped
}

// BuildRelayHostOptions returns libp2p options for relay functionality.
func BuildRelayHostOptions(config *RelayConfig) []libp2p.Option {
	if config == nil || !config.EnableRelay {
		return nil
	}

	opts := make([]libp2p.Option, 0)

	// Enable relay client
	opts = append(opts, libp2p.EnableRelay())

	// Enable relay service if configured
	if config.EnableRelayService {
		svcConfig := config.RelayServiceConfig
		if svcConfig == nil {
			svcConfig = DefaultRelayServiceConfig()
		}

		relayOpts := []relay.Option{
			relay.WithLimit(&relay.RelayLimit{
				Duration: svcConfig.MaxDuration,
				Data:     svcConfig.MaxData,
			}),
			relay.WithResources(relay.Resources{
				Limit:                  &relay.RelayLimit{Duration: svcConfig.MaxDuration, Data: svcConfig.MaxData},
				ReservationTTL:         svcConfig.ReservationTTL,
				MaxReservations:        svcConfig.MaxReservations,
				MaxCircuits:            svcConfig.MaxCircuits,
				MaxReservationsPerPeer: svcConfig.MaxReservationsPerPeer,
				MaxReservationsPerIP:   svcConfig.MaxReservationsPerIP,
			}),
		}
		opts = append(opts, libp2p.EnableRelayService(relayOpts...))
	}

	// Enable hole punching for direct connection upgrades
	opts = append(opts, libp2p.EnableHolePunching())

	return opts
}

// NewRelayEnabledHost creates a libp2p host with relay functionality enabled.
func NewRelayEnabledHost(ctx context.Context, hostCfg *HostConfig, relayCfg *RelayConfig) (*DKGHost, *RelayManager, error) {
	if hostCfg == nil {
		hostCfg = DefaultHostConfig()
	}

	if relayCfg == nil {
		relayCfg = DefaultRelayConfig()
	}

	// Create host with relay options
	dkgHost, err := NewHostWithRelayOptions(ctx, hostCfg, relayCfg)
	if err != nil {
		return nil, nil, err
	}

	// Create relay manager
	relayManager, err := NewRelayManager(dkgHost.Host(), relayCfg)
	if err != nil {
		_ = dkgHost.Close()
		return nil, nil, err
	}

	// Start relay manager
	if err := relayManager.Start(ctx); err != nil {
		_ = dkgHost.Close()
		return nil, nil, err
	}

	return dkgHost, relayManager, nil
}

// NewHostWithRelayOptions creates a DKG host with additional relay options.
func NewHostWithRelayOptions(ctx context.Context, cfg *HostConfig, relayCfg *RelayConfig) (*DKGHost, error) {
	if cfg == nil {
		cfg = DefaultHostConfig()
	}

	// Generate private key if not provided
	privKey := cfg.PrivateKey
	if privKey == nil {
		var err error
		privKey, _, err = crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return nil, &RelayError{
				Op:      "generate_key",
				Wrapped: err,
			}
		}
	}

	// Build libp2p options
	opts := []libp2p.Option{
		libp2p.Identity(privKey),
	}

	// Add listen addresses
	if len(cfg.ListenAddrs) > 0 {
		multiaddrs, err := parseMultiaddrs(cfg.ListenAddrs)
		if err != nil {
			return nil, err
		}
		opts = append(opts, libp2p.ListenAddrs(multiaddrs...))
	}

	// Configure security protocols
	securityOpts, err := buildSecurityOptions(cfg)
	if err != nil {
		return nil, err
	}
	opts = append(opts, securityOpts...)

	// Add relay options
	relayOpts := BuildRelayHostOptions(relayCfg)
	opts = append(opts, relayOpts...)

	// Create the host
	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, &RelayError{
			Op:      "create_host",
			Wrapped: err,
		}
	}

	return &DKGHost{
		host:    h,
		privKey: privKey,
	}, nil
}

// parseMultiaddrs parses multiaddress strings into multiaddr objects.
func parseMultiaddrs(addrs []string) ([]ma.Multiaddr, error) {
	multiaddrs := make([]ma.Multiaddr, 0, len(addrs))
	for _, addr := range addrs {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			return nil, &RelayError{
				Op:      "parse_multiaddr",
				Address: addr,
				Wrapped: err,
			}
		}
		multiaddrs = append(multiaddrs, maddr)
	}
	return multiaddrs, nil
}

// buildSecurityOptions builds libp2p security options based on configuration.
func buildSecurityOptions(cfg *HostConfig) ([]libp2p.Option, error) {
	opts := make([]libp2p.Option, 0)

	if cfg.EnableNoise && cfg.EnableTLS {
		opts = append(opts, libp2p.Security(noise.ID, noise.New))
		opts = append(opts, libp2p.Security(libp2ptls.ID, libp2ptls.New))
	} else if cfg.EnableNoise {
		opts = append(opts, libp2p.Security(noise.ID, noise.New))
	} else if cfg.EnableTLS {
		opts = append(opts, libp2p.Security(libp2ptls.ID, libp2ptls.New))
	} else {
		return nil, errors.New("at least one security protocol must be enabled")
	}

	return opts, nil
}
