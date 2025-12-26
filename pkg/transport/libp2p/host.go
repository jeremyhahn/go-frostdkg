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
	"crypto/tls"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// DKGHost wraps a libp2p host with DKG-specific functionality.
type DKGHost struct {
	host         host.Host
	privKey      crypto.PrivKey
	tlsConfig    *tls.Config
	connPool     *ConnectionPool
	qosManager   *QoSManager
	relayManager *RelayManager
}

// HostConfig contains configuration for creating a DKG libp2p host.
type HostConfig struct {
	// ListenAddrs are the multiaddrs to listen on.
	// Example: ["/ip4/0.0.0.0/tcp/0", "/ip6/::/tcp/0"]
	ListenAddrs []string

	// PrivateKey is the host's identity private key.
	// If nil, a new key will be generated.
	PrivateKey crypto.PrivKey

	// EnableNoise enables Noise protocol for encryption (default: true).
	EnableNoise bool

	// EnableTLS enables TLS 1.3 for encryption (default: true).
	EnableTLS bool

	// EnableRelay enables basic relay client functionality (default: false).
	// For advanced relay configuration, use RelayConfig instead.
	EnableRelay bool

	// RelayConfig contains advanced relay configuration for NAT traversal.
	// If set, EnableRelay is ignored and settings from RelayConfig are used.
	// Includes support for relay client, relay service, static relays,
	// reservation management, and relay failover.
	RelayConfig *RelayConfig

	// EnablePubSub enables GossipSub-based PubSub (default: false).
	// When enabled, use NewPubSubManager to create a PubSub manager for broadcast messaging.
	EnablePubSub bool

	// PubSubConfig is the configuration for PubSub when EnablePubSub is true.
	// If nil, DefaultPubSubConfig() is used.
	PubSubConfig *PubSubConfig

	// TLS configuration (optional) - allows integration with standard transport.Config
	// If provided, enables certificate-based authentication on top of libp2p security.
	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string

	// ConnectionPool configures connection pooling and multiplexing.
	// If nil, connection pooling is disabled.
	ConnectionPool *PoolConfig

	// EnableConnectionPool enables connection pooling with default settings.
	// Ignored if ConnectionPool is set.
	EnableConnectionPool bool

	// QoS configures Quality of Service and bandwidth management.
	// If nil, QoS is disabled.
	QoS *QoSConfig

	// EnableQoS enables QoS with default settings.
	// Ignored if QoS is set.
	EnableQoS bool
}

// DefaultHostConfig returns a default host configuration.
func DefaultHostConfig() *HostConfig {
	return &HostConfig{
		ListenAddrs:  []string{"/ip4/0.0.0.0/tcp/0"},
		EnableNoise:  true,
		EnableTLS:    true,
		EnableRelay:  false,
		EnablePubSub: false,
	}
}

// DefaultHostConfigWithPool returns a default host configuration with connection pooling enabled.
func DefaultHostConfigWithPool() *HostConfig {
	return &HostConfig{
		ListenAddrs:          []string{"/ip4/0.0.0.0/tcp/0"},
		EnableNoise:          true,
		EnableTLS:            true,
		EnableRelay:          false,
		EnablePubSub:         false,
		EnableConnectionPool: true,
	}
}

// DefaultHostConfigWithQoS returns a default host configuration with QoS enabled.
func DefaultHostConfigWithQoS() *HostConfig {
	return &HostConfig{
		ListenAddrs:  []string{"/ip4/0.0.0.0/tcp/0"},
		EnableNoise:  true,
		EnableTLS:    true,
		EnableRelay:  false,
		EnablePubSub: false,
		EnableQoS:    true,
	}
}

// DefaultHostConfigWithPubSub returns a default host configuration with PubSub enabled.
func DefaultHostConfigWithPubSub() *HostConfig {
	return &HostConfig{
		ListenAddrs:  []string{"/ip4/0.0.0.0/tcp/0"},
		EnableNoise:  true,
		EnableTLS:    true,
		EnableRelay:  false,
		EnablePubSub: true,
		PubSubConfig: DefaultPubSubConfig(),
	}
}

// DefaultHostConfigWithRelay returns a default host configuration with relay enabled.
func DefaultHostConfigWithRelay() *HostConfig {
	return &HostConfig{
		ListenAddrs:  []string{"/ip4/0.0.0.0/tcp/0"},
		EnableNoise:  true,
		EnableTLS:    true,
		EnablePubSub: false,
		RelayConfig: &RelayConfig{
			EnableRelay:                true,
			ReservationTTL:             DefaultRelayConfig().ReservationTTL,
			ReservationRefreshInterval: DefaultRelayConfig().ReservationRefreshInterval,
			MaxReservations:            DefaultRelayConfig().MaxReservations,
		},
	}
}

// DefaultHostConfigFull returns a default host configuration with all features enabled.
func DefaultHostConfigFull() *HostConfig {
	return &HostConfig{
		ListenAddrs:          []string{"/ip4/0.0.0.0/tcp/0"},
		EnableNoise:          true,
		EnableTLS:            true,
		EnableRelay:          false,
		EnablePubSub:         true,
		PubSubConfig:         DefaultPubSubConfig(),
		EnableConnectionPool: true,
		EnableQoS:            true,
	}
}

// NewHostFromTransportConfig creates a DKG host from a standard transport.Config.
// This enables libp2p transport to use the same configuration structure as other transports.
func NewHostFromTransportConfig(ctx context.Context, cfg *transport.Config) (*DKGHost, error) {
	if cfg == nil {
		return nil, transport.ErrInvalidConfig
	}

	hostCfg := &HostConfig{
		ListenAddrs:  []string{cfg.Address},
		EnableNoise:  true,
		EnableTLS:    true,
		EnableRelay:  false,
		EnablePubSub: false,
	}

	// Configure TLS if provided
	if cfg.HasTLS() {
		hostCfg.TLSCertFile = cfg.TLSCertFile
		hostCfg.TLSKeyFile = cfg.TLSKeyFile
		hostCfg.TLSCAFile = cfg.TLSCAFile
	}

	return NewHost(ctx, hostCfg)
}

// NewHost creates a new DKG libp2p host with the given configuration.
func NewHost(ctx context.Context, cfg *HostConfig) (*DKGHost, error) {
	if cfg == nil {
		cfg = DefaultHostConfig()
	}

	// Generate private key if not provided
	privKey := cfg.PrivateKey
	if privKey == nil {
		var err error
		privKey, _, err = crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
	}

	// Build libp2p options
	opts := []libp2p.Option{
		libp2p.Identity(privKey),
	}

	// Add listen addresses
	if len(cfg.ListenAddrs) > 0 {
		multiaddrs := make([]ma.Multiaddr, 0, len(cfg.ListenAddrs))
		for _, addr := range cfg.ListenAddrs {
			maddr, err := ma.NewMultiaddr(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid listen address %s: %w", addr, err)
			}
			multiaddrs = append(multiaddrs, maddr)
		}
		opts = append(opts, libp2p.ListenAddrs(multiaddrs...))
	}

	// Configure security protocols
	// libp2p supports multiple security transports and negotiates the best one
	if cfg.EnableNoise && cfg.EnableTLS {
		// Enable both Noise and TLS (libp2p will negotiate)
		opts = append(opts, libp2p.Security(noise.ID, noise.New))
		opts = append(opts, libp2p.Security(libp2ptls.ID, libp2ptls.New))
	} else if cfg.EnableNoise {
		// Enable only Noise
		opts = append(opts, libp2p.Security(noise.ID, noise.New))
	} else if cfg.EnableTLS {
		// Enable only TLS
		opts = append(opts, libp2p.Security(libp2ptls.ID, libp2ptls.New))
	} else {
		return nil, fmt.Errorf("at least one security protocol must be enabled")
	}

	// Configure relay functionality
	// Advanced RelayConfig takes precedence over basic EnableRelay flag
	if cfg.RelayConfig != nil {
		relayOpts := BuildRelayHostOptions(cfg.RelayConfig)
		opts = append(opts, relayOpts...)
	} else if cfg.EnableRelay {
		opts = append(opts, libp2p.EnableRelay())
	}

	// Configure connection pool if enabled
	var connPool *ConnectionPool
	if cfg.ConnectionPool != nil || cfg.EnableConnectionPool {
		poolCfg := cfg.ConnectionPool
		if poolCfg == nil {
			poolCfg = DefaultPoolConfig()
		}

		var err error
		connPool, err = NewConnectionPool(poolCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create connection pool: %w", err)
		}

		// Add connection manager and resource manager options
		opts = append(opts, connPool.LibP2POptions()...)
	}

	// Configure QoS manager if enabled
	var qosManager *QoSManager
	if cfg.QoS != nil || cfg.EnableQoS {
		qosCfg := cfg.QoS
		if qosCfg == nil {
			qosCfg = DefaultQoSConfig()
		}

		var err error
		qosManager, err = NewQoSManager(qosCfg)
		if err != nil {
			if connPool != nil {
				_ = connPool.Close()
			}
			return nil, fmt.Errorf("failed to create QoS manager: %w", err)
		}
	}

	// Create the host
	h, err := libp2p.New(opts...)
	if err != nil {
		if connPool != nil {
			_ = connPool.Close()
		}
		if qosManager != nil {
			_ = qosManager.Close()
		}
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Register connection pool notifiee if pool is enabled
	if connPool != nil {
		h.Network().Notify(connPool.Notifiee())
	}

	// Create relay manager if relay is configured
	var relayManager *RelayManager
	if cfg.RelayConfig != nil && cfg.RelayConfig.EnableRelay {
		relayManager, err = NewRelayManager(h, cfg.RelayConfig)
		if err != nil {
			_ = h.Close()
			if connPool != nil {
				_ = connPool.Close()
			}
			if qosManager != nil {
				_ = qosManager.Close()
			}
			return nil, fmt.Errorf("failed to create relay manager: %w", err)
		}

		// Start relay manager
		if err := relayManager.Start(ctx); err != nil {
			_ = h.Close()
			if connPool != nil {
				_ = connPool.Close()
			}
			if qosManager != nil {
				_ = qosManager.Close()
			}
			return nil, fmt.Errorf("failed to start relay manager: %w", err)
		}
	}

	// Load TLS configuration if provided (for application-level TLS)
	// This is optional and provides an additional layer of certificate-based auth
	var tlsConf *tls.Config
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		// Server-side TLS config
		tlsConf, err = tlsconfig.ServerConfig(
			cfg.TLSCertFile,
			cfg.TLSKeyFile,
			cfg.TLSCAFile,
		)
		if err != nil {
			_ = h.Close()
			if connPool != nil {
				_ = connPool.Close()
			}
			if qosManager != nil {
				_ = qosManager.Close()
			}
			if relayManager != nil {
				_ = relayManager.Stop(ctx)
			}
			return nil, transport.NewTLSError("failed to load TLS configuration", err)
		}
	} else if cfg.TLSCAFile != "" {
		// Client-side TLS config (for verification only)
		tlsConf, err = tlsconfig.ClientConfig("", "", cfg.TLSCAFile, "")
		if err != nil {
			_ = h.Close()
			if connPool != nil {
				_ = connPool.Close()
			}
			if qosManager != nil {
				_ = qosManager.Close()
			}
			if relayManager != nil {
				_ = relayManager.Stop(ctx)
			}
			return nil, transport.NewTLSError("failed to load TLS CA configuration", err)
		}
	}

	return &DKGHost{
		host:         h,
		privKey:      privKey,
		tlsConfig:    tlsConf,
		connPool:     connPool,
		qosManager:   qosManager,
		relayManager: relayManager,
	}, nil
}

// Host returns the underlying libp2p host.
func (dh *DKGHost) Host() host.Host {
	return dh.host
}

// ID returns the peer ID of this host.
func (dh *DKGHost) ID() peer.ID {
	return dh.host.ID()
}

// Addrs returns the listen addresses of this host.
func (dh *DKGHost) Addrs() []ma.Multiaddr {
	return dh.host.Addrs()
}

// AddrStrings returns the listen addresses as strings with peer ID.
func (dh *DKGHost) AddrStrings() []string {
	addrs := make([]string, 0, len(dh.host.Addrs()))
	for _, addr := range dh.host.Addrs() {
		// Add peer ID to multiaddr
		fullAddr := addr.Encapsulate(ma.StringCast("/p2p/" + dh.host.ID().String()))
		addrs = append(addrs, fullAddr.String())
	}
	return addrs
}

// Close shuts down the host, connection pool, QoS manager, and relay manager.
func (dh *DKGHost) Close() error {
	var closeErr error

	if dh.relayManager != nil {
		ctx := context.Background()
		if err := dh.relayManager.Stop(ctx); err != nil && closeErr == nil {
			closeErr = err
		}
	}

	if dh.qosManager != nil {
		if err := dh.qosManager.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}

	if dh.connPool != nil {
		if err := dh.connPool.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}

	if err := dh.host.Close(); err != nil && closeErr == nil {
		closeErr = err
	}

	return closeErr
}

// Connect connects to a peer at the given multiaddr.
func (dh *DKGHost) Connect(ctx context.Context, addr string) (peer.ID, error) {
	maddr, err := ma.NewMultiaddr(addr)
	if err != nil {
		return "", fmt.Errorf("invalid multiaddr %s: %w", addr, err)
	}

	// Extract peer ID and address
	addrInfo, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return "", fmt.Errorf("failed to extract peer info from %s: %w", addr, err)
	}

	// Connect to peer
	if err := dh.host.Connect(ctx, *addrInfo); err != nil {
		return "", fmt.Errorf("failed to connect to peer %s: %w", addrInfo.ID, err)
	}

	return addrInfo.ID, nil
}

// PrivateKey returns the host's private key.
func (dh *DKGHost) PrivateKey() crypto.PrivKey {
	return dh.privKey
}

// TLSConfig returns the TLS configuration if configured.
// Returns nil if TLS is not configured.
func (dh *DKGHost) TLSConfig() *tls.Config {
	return dh.tlsConfig
}

// HasTLS returns true if TLS configuration is loaded.
func (dh *DKGHost) HasTLS() bool {
	return dh.tlsConfig != nil
}

// ConnectionPool returns the connection pool if enabled.
// Returns nil if connection pooling is disabled.
func (dh *DKGHost) ConnectionPool() *ConnectionPool {
	return dh.connPool
}

// HasConnectionPool returns true if connection pooling is enabled.
func (dh *DKGHost) HasConnectionPool() bool {
	return dh.connPool != nil
}

// QoSManager returns the QoS manager if enabled.
// Returns nil if QoS is disabled.
func (dh *DKGHost) QoSManager() *QoSManager {
	return dh.qosManager
}

// HasQoS returns true if QoS management is enabled.
func (dh *DKGHost) HasQoS() bool {
	return dh.qosManager != nil
}

// RelayManager returns the relay manager if enabled.
// Returns nil if relay is disabled.
func (dh *DKGHost) RelayManager() *RelayManager {
	return dh.relayManager
}

// HasRelay returns true if relay functionality is enabled.
func (dh *DKGHost) HasRelay() bool {
	return dh.relayManager != nil
}

// GetRelayAddresses returns the relay addresses for this host.
// Returns nil if relay is disabled.
func (dh *DKGHost) GetRelayAddresses() []ma.Multiaddr {
	if dh.relayManager == nil {
		return nil
	}
	return dh.relayManager.GetRelayAddresses()
}

// TagSession tags a connection with a session and priority for connection management.
// This is a convenience method that delegates to the connection pool.
// Returns nil if connection pooling is disabled.
func (dh *DKGHost) TagSession(peerID peer.ID, sessionID string, priority SessionPriority) error {
	if dh.connPool == nil {
		return nil
	}
	return dh.connPool.TagSession(peerID, sessionID, priority)
}

// UntagSession removes a session tag from a connection.
// This is a convenience method that delegates to the connection pool.
func (dh *DKGHost) UntagSession(peerID peer.ID, sessionID string) {
	if dh.connPool != nil {
		dh.connPool.UntagSession(peerID, sessionID)
	}
}

// RecordActivity records activity on a peer connection.
// This is a convenience method that delegates to the connection pool.
func (dh *DKGHost) RecordActivity(peerID peer.ID) {
	if dh.connPool != nil {
		dh.connPool.RecordActivity(peerID)
	}
}

// ConnectionPoolStats returns connection pool statistics.
// Returns zero stats if connection pooling is disabled.
func (dh *DKGHost) ConnectionPoolStats() PoolStats {
	if dh.connPool == nil {
		return PoolStats{}
	}
	return dh.connPool.Stats()
}

// QoSStats returns QoS statistics.
// Returns zero stats if QoS is disabled.
func (dh *DKGHost) QoSStats() QoSStats {
	if dh.qosManager == nil {
		return QoSStats{}
	}
	return dh.qosManager.Stats()
}

// AllowIncoming checks if incoming data is allowed by QoS policy.
// Returns nil if QoS is disabled.
func (dh *DKGHost) AllowIncoming(ctx context.Context, peerID peer.ID, size int) error {
	if dh.qosManager == nil {
		return nil
	}
	return dh.qosManager.AllowIncoming(ctx, peerID, size)
}

// AllowOutgoing checks if outgoing data is allowed by QoS policy.
// Returns nil if QoS is disabled.
func (dh *DKGHost) AllowOutgoing(ctx context.Context, peerID peer.ID, size int) error {
	if dh.qosManager == nil {
		return nil
	}
	return dh.qosManager.AllowOutgoing(ctx, peerID, size)
}

// WaitIncoming waits until incoming data is allowed by QoS policy.
// Returns nil if QoS is disabled.
func (dh *DKGHost) WaitIncoming(ctx context.Context, peerID peer.ID, size int) error {
	if dh.qosManager == nil {
		return nil
	}
	return dh.qosManager.WaitIncoming(ctx, peerID, size)
}

// WaitOutgoing waits until outgoing data is allowed by QoS policy.
// Returns nil if QoS is disabled.
func (dh *DKGHost) WaitOutgoing(ctx context.Context, peerID peer.ID, size int) error {
	if dh.qosManager == nil {
		return nil
	}
	return dh.qosManager.WaitOutgoing(ctx, peerID, size)
}

// EnqueueMessage adds a message to the QoS priority queue for sending.
// Returns nil if QoS is disabled.
func (dh *DKGHost) EnqueueMessage(data []byte, peerID peer.ID, msgType transport.MessageType) error {
	if dh.qosManager == nil {
		return nil
	}
	return dh.qosManager.EnqueueMessage(data, peerID, msgType)
}
