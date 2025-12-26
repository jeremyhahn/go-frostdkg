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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
)

// Discovery error types.
var (
	// ErrDHTNotStarted indicates the DHT has not been started.
	ErrDHTNotStarted = errors.New("discovery: DHT not started")

	// ErrDHTAlreadyStarted indicates the DHT is already running.
	ErrDHTAlreadyStarted = errors.New("discovery: DHT already started")

	// ErrDHTBootstrapFailed indicates DHT bootstrap failed.
	ErrDHTBootstrapFailed = errors.New("discovery: DHT bootstrap failed")

	// ErrDHTClosed indicates the DHT has been closed.
	ErrDHTClosed = errors.New("discovery: DHT closed")

	// ErrNoBootstrapPeers indicates no bootstrap peers were provided.
	ErrNoBootstrapPeers = errors.New("discovery: no bootstrap peers provided")

	// ErrInvalidRendezvous indicates an invalid rendezvous string.
	ErrInvalidRendezvous = errors.New("discovery: invalid rendezvous string")

	// ErrAdvertiseFailed indicates advertising failed.
	ErrAdvertiseFailed = errors.New("discovery: advertise failed")

	// ErrFindPeersFailed indicates peer discovery failed.
	ErrFindPeersFailed = errors.New("discovery: find peers failed")

	// ErrInvalidSessionID indicates an invalid session ID.
	ErrInvalidSessionID = errors.New("discovery: invalid session ID")

	// ErrInvalidCiphersuite indicates an invalid ciphersuite.
	ErrInvalidCiphersuite = errors.New("discovery: invalid ciphersuite")
)

// Note: ErrPeerNotFound is already defined in connpool.go

// DHTMode represents the DHT operating mode.
type DHTMode int

const (
	// DHTModeAuto allows the DHT to automatically determine mode.
	DHTModeAuto DHTMode = iota

	// DHTModeServer runs the DHT in server mode (full DHT participant).
	DHTModeServer

	// DHTModeClient runs the DHT in client mode (queries only).
	DHTModeClient
)

const (
	// DefaultAdvertiseTTL is the default TTL for DHT advertisements.
	DefaultAdvertiseTTL = 10 * time.Minute

	// DefaultRefreshInterval is the default interval for peer refresh.
	DefaultRefreshInterval = 30 * time.Second

	// DefaultFindPeersTimeout is the default timeout for finding peers.
	DefaultFindPeersTimeout = 30 * time.Second

	// RendezvousPrefix is the prefix for all DKG rendezvous points.
	RendezvousPrefix = "/frost-dkg/v1/"

	// SessionRendezvousPrefix is the prefix for session-specific rendezvous.
	SessionRendezvousPrefix = RendezvousPrefix + "session/"

	// CiphersuiteRendezvousPrefix is the prefix for ciphersuite-specific rendezvous.
	CiphersuiteRendezvousPrefix = RendezvousPrefix + "ciphersuite/"

	// CoordinatorRendezvousPrefix is the prefix for coordinator discovery.
	CoordinatorRendezvousPrefix = RendezvousPrefix + "coordinator/"
)

// DiscoveryConfig contains configuration for the DHT discovery service.
type DiscoveryConfig struct {
	// Mode specifies the DHT operating mode.
	Mode DHTMode

	// BootstrapPeers are the initial peers to connect to for DHT bootstrap.
	BootstrapPeers []peer.AddrInfo

	// AdvertiseTTL is the TTL for DHT advertisements.
	AdvertiseTTL time.Duration

	// RefreshInterval is the interval for automatic peer refresh.
	RefreshInterval time.Duration

	// FindPeersTimeout is the timeout for finding peers.
	FindPeersTimeout time.Duration

	// EnableAutoRefresh enables automatic peer discovery refresh.
	EnableAutoRefresh bool

	// MaxPeers is the maximum number of peers to discover per query.
	MaxPeers int
}

// DefaultDiscoveryConfig returns a default discovery configuration.
func DefaultDiscoveryConfig() *DiscoveryConfig {
	return &DiscoveryConfig{
		Mode:              DHTModeAuto,
		BootstrapPeers:    []peer.AddrInfo{},
		AdvertiseTTL:      DefaultAdvertiseTTL,
		RefreshInterval:   DefaultRefreshInterval,
		FindPeersTimeout:  DefaultFindPeersTimeout,
		EnableAutoRefresh: true,
		MaxPeers:          100,
	}
}

// DiscoveryService provides DHT-based peer discovery for DKG sessions.
type DiscoveryService struct {
	host      host.Host
	dht       *dht.IpfsDHT
	discovery *drouting.RoutingDiscovery
	config    *DiscoveryConfig

	// Active advertisements
	advertisements   map[string]context.CancelFunc
	advertisementsMu sync.RWMutex

	// Discovered peers cache
	discoveredPeers   map[string][]peer.AddrInfo
	discoveredPeersMu sync.RWMutex

	// Lifecycle management
	started  atomic.Bool
	closed   atomic.Bool
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewDiscoveryService creates a new DHT-based discovery service.
func NewDiscoveryService(h host.Host, cfg *DiscoveryConfig) (*DiscoveryService, error) {
	if h == nil {
		return nil, errors.New("discovery: host is nil")
	}

	if cfg == nil {
		cfg = DefaultDiscoveryConfig()
	}

	return &DiscoveryService{
		host:            h,
		config:          cfg,
		advertisements:  make(map[string]context.CancelFunc),
		discoveredPeers: make(map[string][]peer.AddrInfo),
		stopChan:        make(chan struct{}),
	}, nil
}

// Start initializes the DHT and begins discovery operations.
func (ds *DiscoveryService) Start(ctx context.Context) error {
	if ds.closed.Load() {
		return ErrDHTClosed
	}

	if ds.started.Swap(true) {
		return ErrDHTAlreadyStarted
	}

	// Create DHT with appropriate mode
	var dhtOpts []dht.Option
	switch ds.config.Mode {
	case DHTModeServer:
		dhtOpts = append(dhtOpts, dht.Mode(dht.ModeServer))
	case DHTModeClient:
		dhtOpts = append(dhtOpts, dht.Mode(dht.ModeClient))
	default:
		dhtOpts = append(dhtOpts, dht.Mode(dht.ModeAutoServer))
	}

	kadDHT, err := dht.New(ctx, ds.host, dhtOpts...)
	if err != nil {
		ds.started.Store(false)
		return fmt.Errorf("%w: %v", ErrDHTBootstrapFailed, err)
	}
	ds.dht = kadDHT

	// Bootstrap the DHT
	if err := ds.bootstrap(ctx); err != nil {
		_ = ds.dht.Close()
		ds.started.Store(false)
		return err
	}

	// Create routing discovery
	ds.discovery = drouting.NewRoutingDiscovery(ds.dht)

	// Start auto-refresh if enabled
	if ds.config.EnableAutoRefresh {
		ds.wg.Add(1)
		go ds.refreshLoop()
	}

	return nil
}

// bootstrap connects to bootstrap peers and initializes the DHT.
func (ds *DiscoveryService) bootstrap(ctx context.Context) error {
	// Bootstrap the DHT routing table
	if err := ds.dht.Bootstrap(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrDHTBootstrapFailed, err)
	}

	// Connect to bootstrap peers if provided
	if len(ds.config.BootstrapPeers) > 0 {
		var wg sync.WaitGroup
		var successCount atomic.Int32

		for _, peerInfo := range ds.config.BootstrapPeers {
			wg.Add(1)
			go func(pi peer.AddrInfo) {
				defer wg.Done()
				if err := ds.host.Connect(ctx, pi); err == nil {
					successCount.Add(1)
				}
			}(peerInfo)
		}

		wg.Wait()

		// At least one bootstrap peer connection is recommended
		if successCount.Load() == 0 && len(ds.config.BootstrapPeers) > 0 {
			return fmt.Errorf("%w: could not connect to any bootstrap peers", ErrDHTBootstrapFailed)
		}
	}

	return nil
}

// Stop gracefully shuts down the discovery service.
func (ds *DiscoveryService) Stop(ctx context.Context) error {
	if !ds.started.Load() {
		return ErrDHTNotStarted
	}

	if ds.closed.Swap(true) {
		return ErrDHTClosed
	}

	// Signal shutdown
	close(ds.stopChan)

	// Cancel all active advertisements
	ds.advertisementsMu.Lock()
	for _, cancel := range ds.advertisements {
		cancel()
	}
	ds.advertisements = make(map[string]context.CancelFunc)
	ds.advertisementsMu.Unlock()

	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		ds.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return errors.New("discovery: shutdown timeout")
	}

	// Close the DHT
	if ds.dht != nil {
		return ds.dht.Close()
	}

	return nil
}

// refreshLoop periodically refreshes the DHT routing table.
func (ds *DiscoveryService) refreshLoop() {
	defer ds.wg.Done()

	ticker := time.NewTicker(ds.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ds.stopChan:
			return
		case <-ticker.C:
			if ds.dht != nil {
				// Refresh the routing table
				<-ds.dht.RefreshRoutingTable()
			}
		}
	}
}

// AdvertiseSession advertises this peer as available for a specific DKG session.
func (ds *DiscoveryService) AdvertiseSession(ctx context.Context, sessionID string) error {
	if !ds.started.Load() {
		return ErrDHTNotStarted
	}

	if ds.closed.Load() {
		return ErrDHTClosed
	}

	if sessionID == "" {
		return ErrInvalidSessionID
	}

	rendezvous := SessionRendezvousPrefix + sessionID
	return ds.advertise(ctx, rendezvous)
}

// AdvertiseCoordinator advertises this peer as a DKG coordinator for a session.
func (ds *DiscoveryService) AdvertiseCoordinator(ctx context.Context, sessionID string) error {
	if !ds.started.Load() {
		return ErrDHTNotStarted
	}

	if ds.closed.Load() {
		return ErrDHTClosed
	}

	if sessionID == "" {
		return ErrInvalidSessionID
	}

	rendezvous := CoordinatorRendezvousPrefix + sessionID
	return ds.advertise(ctx, rendezvous)
}

// AdvertiseCiphersuite advertises this peer as supporting a specific ciphersuite.
func (ds *DiscoveryService) AdvertiseCiphersuite(ctx context.Context, ciphersuite string) error {
	if !ds.started.Load() {
		return ErrDHTNotStarted
	}

	if ds.closed.Load() {
		return ErrDHTClosed
	}

	if ciphersuite == "" {
		return ErrInvalidCiphersuite
	}

	rendezvous := CiphersuiteRendezvousPrefix + ciphersuite
	return ds.advertise(ctx, rendezvous)
}

// advertise performs the actual DHT advertisement.
func (ds *DiscoveryService) advertise(ctx context.Context, rendezvous string) error {
	if rendezvous == "" {
		return ErrInvalidRendezvous
	}

	// Create a cancelable context for this advertisement
	advCtx, cancel := context.WithCancel(ctx)

	// Store the cancel function
	ds.advertisementsMu.Lock()
	if existingCancel, exists := ds.advertisements[rendezvous]; exists {
		existingCancel() // Cancel existing advertisement
	}
	ds.advertisements[rendezvous] = cancel
	ds.advertisementsMu.Unlock()

	// Advertise with TTL
	ttl := ds.config.AdvertiseTTL
	dutil.Advertise(advCtx, ds.discovery, rendezvous, discovery.TTL(ttl))

	return nil
}

// StopAdvertising stops advertising for a specific rendezvous point.
func (ds *DiscoveryService) StopAdvertising(rendezvous string) error {
	if !ds.started.Load() {
		return ErrDHTNotStarted
	}

	ds.advertisementsMu.Lock()
	defer ds.advertisementsMu.Unlock()

	if cancel, exists := ds.advertisements[rendezvous]; exists {
		cancel()
		delete(ds.advertisements, rendezvous)
		return nil
	}

	return nil
}

// StopAdvertisingSession stops advertising for a specific session.
func (ds *DiscoveryService) StopAdvertisingSession(sessionID string) error {
	if sessionID == "" {
		return ErrInvalidSessionID
	}
	return ds.StopAdvertising(SessionRendezvousPrefix + sessionID)
}

// StopAdvertisingCoordinator stops advertising as a coordinator for a session.
func (ds *DiscoveryService) StopAdvertisingCoordinator(sessionID string) error {
	if sessionID == "" {
		return ErrInvalidSessionID
	}
	return ds.StopAdvertising(CoordinatorRendezvousPrefix + sessionID)
}

// FindSessionPeers finds peers advertising a specific DKG session.
func (ds *DiscoveryService) FindSessionPeers(ctx context.Context, sessionID string) ([]peer.AddrInfo, error) {
	if !ds.started.Load() {
		return nil, ErrDHTNotStarted
	}

	if ds.closed.Load() {
		return nil, ErrDHTClosed
	}

	if sessionID == "" {
		return nil, ErrInvalidSessionID
	}

	rendezvous := SessionRendezvousPrefix + sessionID
	return ds.findPeers(ctx, rendezvous)
}

// FindCoordinator finds the coordinator for a specific DKG session.
func (ds *DiscoveryService) FindCoordinator(ctx context.Context, sessionID string) ([]peer.AddrInfo, error) {
	if !ds.started.Load() {
		return nil, ErrDHTNotStarted
	}

	if ds.closed.Load() {
		return nil, ErrDHTClosed
	}

	if sessionID == "" {
		return nil, ErrInvalidSessionID
	}

	rendezvous := CoordinatorRendezvousPrefix + sessionID
	return ds.findPeers(ctx, rendezvous)
}

// FindCiphersuitePeers finds peers supporting a specific ciphersuite.
func (ds *DiscoveryService) FindCiphersuitePeers(ctx context.Context, ciphersuite string) ([]peer.AddrInfo, error) {
	if !ds.started.Load() {
		return nil, ErrDHTNotStarted
	}

	if ds.closed.Load() {
		return nil, ErrDHTClosed
	}

	if ciphersuite == "" {
		return nil, ErrInvalidCiphersuite
	}

	rendezvous := CiphersuiteRendezvousPrefix + ciphersuite
	return ds.findPeers(ctx, rendezvous)
}

// findPeers performs the actual peer discovery.
func (ds *DiscoveryService) findPeers(ctx context.Context, rendezvous string) ([]peer.AddrInfo, error) {
	if rendezvous == "" {
		return nil, ErrInvalidRendezvous
	}

	// Create timeout context
	findCtx, cancel := context.WithTimeout(ctx, ds.config.FindPeersTimeout)
	defer cancel()

	// Find peers
	peerChan, err := ds.discovery.FindPeers(findCtx, rendezvous)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFindPeersFailed, err)
	}

	// Collect discovered peers
	var peers []peer.AddrInfo
	for p := range peerChan {
		if p.ID == ds.host.ID() {
			continue // Skip self
		}
		if len(p.Addrs) > 0 {
			peers = append(peers, p)
		}
		if len(peers) >= ds.config.MaxPeers {
			break
		}
	}

	// Cache discovered peers
	ds.discoveredPeersMu.Lock()
	ds.discoveredPeers[rendezvous] = peers
	ds.discoveredPeersMu.Unlock()

	return peers, nil
}

// GetCachedPeers returns cached peers for a rendezvous point.
func (ds *DiscoveryService) GetCachedPeers(rendezvous string) []peer.AddrInfo {
	ds.discoveredPeersMu.RLock()
	defer ds.discoveredPeersMu.RUnlock()

	if peers, exists := ds.discoveredPeers[rendezvous]; exists {
		// Return a copy to avoid race conditions
		result := make([]peer.AddrInfo, len(peers))
		copy(result, peers)
		return result
	}
	return nil
}

// ClearCache clears the discovered peers cache.
func (ds *DiscoveryService) ClearCache() {
	ds.discoveredPeersMu.Lock()
	defer ds.discoveredPeersMu.Unlock()
	ds.discoveredPeers = make(map[string][]peer.AddrInfo)
}

// ConnectToPeer attempts to connect to a discovered peer.
func (ds *DiscoveryService) ConnectToPeer(ctx context.Context, peerInfo peer.AddrInfo) error {
	if !ds.started.Load() {
		return ErrDHTNotStarted
	}

	if ds.closed.Load() {
		return ErrDHTClosed
	}

	return ds.host.Connect(ctx, peerInfo)
}

// IsStarted returns true if the discovery service is started.
func (ds *DiscoveryService) IsStarted() bool {
	return ds.started.Load()
}

// IsClosed returns true if the discovery service is closed.
func (ds *DiscoveryService) IsClosed() bool {
	return ds.closed.Load()
}

// DHT returns the underlying Kademlia DHT instance.
func (ds *DiscoveryService) DHT() *dht.IpfsDHT {
	return ds.dht
}

// Host returns the underlying libp2p host.
func (ds *DiscoveryService) Host() host.Host {
	return ds.host
}

// RoutingDiscovery returns the underlying routing discovery instance.
func (ds *DiscoveryService) RoutingDiscovery() *drouting.RoutingDiscovery {
	return ds.discovery
}

// ActiveAdvertisements returns the count of active advertisements.
func (ds *DiscoveryService) ActiveAdvertisements() int {
	ds.advertisementsMu.RLock()
	defer ds.advertisementsMu.RUnlock()
	return len(ds.advertisements)
}

// DiscoveryHostConfig extends HostConfig with DHT discovery options.
type DiscoveryHostConfig struct {
	*HostConfig

	// EnableDHT enables DHT-based peer discovery.
	EnableDHT bool

	// DHTMode specifies the DHT operating mode.
	DHTMode DHTMode

	// BootstrapPeers are the initial peers for DHT bootstrap.
	BootstrapPeers []string

	// AdvertiseTTL is the TTL for DHT advertisements.
	AdvertiseTTL time.Duration

	// RefreshInterval is the interval for automatic peer refresh.
	RefreshInterval time.Duration

	// EnableAutoRefresh enables automatic peer discovery refresh.
	EnableAutoRefresh bool
}

// DefaultDiscoveryHostConfig returns a default discovery host configuration.
func DefaultDiscoveryHostConfig() *DiscoveryHostConfig {
	return &DiscoveryHostConfig{
		HostConfig:        DefaultHostConfig(),
		EnableDHT:         false,
		DHTMode:           DHTModeAuto,
		BootstrapPeers:    []string{},
		AdvertiseTTL:      DefaultAdvertiseTTL,
		RefreshInterval:   DefaultRefreshInterval,
		EnableAutoRefresh: true,
	}
}

// ToDiscoveryConfig converts DiscoveryHostConfig to DiscoveryConfig.
func (dhc *DiscoveryHostConfig) ToDiscoveryConfig() (*DiscoveryConfig, error) {
	// Parse bootstrap peers
	bootstrapPeers := make([]peer.AddrInfo, 0, len(dhc.BootstrapPeers))
	for _, addr := range dhc.BootstrapPeers {
		addrInfo, err := peer.AddrInfoFromString(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid bootstrap peer address %s: %w", addr, err)
		}
		bootstrapPeers = append(bootstrapPeers, *addrInfo)
	}

	return &DiscoveryConfig{
		Mode:              dhc.DHTMode,
		BootstrapPeers:    bootstrapPeers,
		AdvertiseTTL:      dhc.AdvertiseTTL,
		RefreshInterval:   dhc.RefreshInterval,
		FindPeersTimeout:  DefaultFindPeersTimeout,
		EnableAutoRefresh: dhc.EnableAutoRefresh,
		MaxPeers:          100,
	}, nil
}

// DKGHostWithDiscovery wraps a DKGHost with DHT discovery capabilities.
type DKGHostWithDiscovery struct {
	*DKGHost
	discovery *DiscoveryService
}

// NewHostWithDiscovery creates a new DKG host with DHT discovery enabled.
func NewHostWithDiscovery(ctx context.Context, cfg *DiscoveryHostConfig) (*DKGHostWithDiscovery, error) {
	if cfg == nil {
		cfg = DefaultDiscoveryHostConfig()
	}

	// Create the base host
	host, err := NewHost(ctx, cfg.HostConfig)
	if err != nil {
		return nil, err
	}

	result := &DKGHostWithDiscovery{
		DKGHost: host,
	}

	// Initialize discovery if enabled
	if cfg.EnableDHT {
		discoveryCfg, err := cfg.ToDiscoveryConfig()
		if err != nil {
			_ = host.Close()
			return nil, err
		}

		discovery, err := NewDiscoveryService(host.Host(), discoveryCfg)
		if err != nil {
			_ = host.Close()
			return nil, err
		}

		if err := discovery.Start(ctx); err != nil {
			_ = host.Close()
			return nil, err
		}

		result.discovery = discovery
	}

	return result, nil
}

// Discovery returns the discovery service, or nil if not enabled.
func (dh *DKGHostWithDiscovery) Discovery() *DiscoveryService {
	return dh.discovery
}

// Close shuts down the host and discovery service.
func (dh *DKGHostWithDiscovery) Close() error {
	var errs []error

	if dh.discovery != nil {
		if err := dh.discovery.Stop(context.Background()); err != nil {
			errs = append(errs, err)
		}
	}

	if err := dh.DKGHost.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
