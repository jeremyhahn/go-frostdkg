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

// Package libp2p provides a peer-to-peer transport implementation using libp2p.
//
// # Overview
//
// This package implements the DKG transport layer using libp2p, a modular networking
// stack for peer-to-peer applications. It supports both coordinator and participant
// modes with built-in security, NAT traversal, and connection multiplexing.
//
// # Security
//
// The libp2p transport provides multiple layers of security:
//
//  1. Transport-level encryption: libp2p automatically uses secure protocols (Noise or TLS 1.3)
//     for all peer connections. This is enabled by default and provides:
//     - End-to-end encryption
//     - Peer identity verification
//     - Forward secrecy
//
//  2. Optional certificate-based TLS: Additional application-level TLS configuration
//     can be layered on top for environments requiring X.509 certificate validation:
//     - Server-side TLS with certificate and key
//     - Mutual TLS (mTLS) with client certificate verification
//     - Custom CA certificate support
//
// # TLS Configuration
//
// TLS support is optional and backward compatible. The transport works in three modes:
//
//  1. Default mode (no TLS config): Uses libp2p's built-in security (Noise/TLS 1.3)
//  2. Server TLS mode: Provides certificate-based authentication
//  3. Mutual TLS mode: Requires both server and client certificates
//
// Example with default security (Noise/TLS 1.3):
//
//	cfg := libp2p.DefaultHostConfig()
//	host, err := libp2p.NewHost(ctx, cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer host.Close()
//
// Example with server-side TLS:
//
//	cfg := libp2p.DefaultHostConfig()
//	cfg.TLSCertFile = "/path/to/server.crt"
//	cfg.TLSKeyFile = "/path/to/server.key"
//	host, err := libp2p.NewHost(ctx, cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer host.Close()
//
// Example with mutual TLS (mTLS):
//
//	cfg := libp2p.DefaultHostConfig()
//	cfg.TLSCertFile = "/path/to/server.crt"
//	cfg.TLSKeyFile = "/path/to/server.key"
//	cfg.TLSCAFile = "/path/to/ca.crt"
//	host, err := libp2p.NewHost(ctx, cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer host.Close()
//
// # Integration with transport.Config
//
// The libp2p transport integrates with the standard transport configuration system,
// allowing consistent TLS configuration across all transport implementations:
//
//	// Using transport.Config
//	cfg := transport.NewTLSConfig(
//	    transport.ProtocolLibp2p,
//	    "/ip4/0.0.0.0/tcp/9000",
//	    "server.crt",
//	    "server.key",
//	    "ca.crt",
//	)
//
//	host, err := libp2p.NewHostFromTransportConfig(ctx, cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer host.Close()
//
// # Coordinator Usage
//
// Create a coordinator that manages a DKG session:
//
//	sessionCfg := &transport.SessionConfig{
//	    Threshold:       2,
//	    NumParticipants: 3,
//	    Ciphersuite:     "FROST-ED25519-SHA512-v1",
//	    Timeout:         5 * time.Minute,
//	}
//
//	hostCfg := libp2p.DefaultHostConfig()
//	coordinator, err := libp2p.NewP2PCoordinator("session-1", sessionCfg, hostCfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer coordinator.Stop(ctx)
//
//	if err := coordinator.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Wait for participants to join
//	if err := coordinator.WaitForParticipants(ctx, 3); err != nil {
//	    log.Fatal(err)
//	}
//
// # Participant Usage
//
// Create a participant that connects to a coordinator:
//
//	hostCfg := libp2p.DefaultHostConfig()
//	participant, err := libp2p.NewP2PParticipant(hostCfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer participant.Disconnect()
//
//	// Connect to coordinator
//	coordinatorAddr := "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooW..."
//	if err := participant.Connect(ctx, coordinatorAddr); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Run DKG protocol
//	params := &transport.DKGParams{
//	    HostSeckey:     secretKey,
//	    HostPubkeys:    publicKeys,
//	    Threshold:      2,
//	    ParticipantIdx: 0,
//	    Random:         randomness,
//	}
//
//	result, err := participant.RunDKG(ctx, params)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Advanced Configuration
//
// Security Protocol Selection:
//
//	cfg := libp2p.DefaultHostConfig()
//	cfg.EnableNoise = true  // Enable Noise protocol
//	cfg.EnableTLS = true    // Enable TLS 1.3 protocol
//	// libp2p will negotiate the best available protocol
//
// Custom Listen Addresses:
//
//	cfg := libp2p.DefaultHostConfig()
//	cfg.ListenAddrs = []string{
//	    "/ip4/0.0.0.0/tcp/9000",
//	    "/ip6/::/tcp/9000",
//	}
//
// Relay Support for NAT Traversal:
//
//	cfg := libp2p.DefaultHostConfig()
//	cfg.EnableRelay = true
//
// # Performance Characteristics
//
// The libp2p transport is designed for peer-to-peer scenarios and provides:
//
//   - Connection multiplexing: Multiple streams over a single connection
//   - NAT traversal: Built-in relay and hole-punching support
//   - Low latency: Direct peer-to-peer connections when possible
//   - High throughput: Efficient message framing and streaming
//   - Minimal overhead: TLS configuration adds negligible performance cost
//
// Benchmark results (typical):
//   - Host creation: ~12ms
//   - Message framing: ~20μs per message
//   - TLS overhead: <1% compared to default security
//
// # Error Handling
//
// The package uses typed errors from the transport package:
//
//	err := participant.Connect(ctx, addr)
//	if errors.Is(err, transport.ErrConnectionTimeout) {
//	    // Handle timeout
//	}
//
// Common error types:
//   - transport.ErrInvalidConfig: Invalid configuration
//   - transport.ErrConnectionTimeout: Connection timeout
//   - transport.ErrNotConnected: Operation on disconnected peer
//   - transport.ErrSessionClosed: Operation on closed session
//   - transport.NewTLSError: TLS-related errors
//
// # Thread Safety
//
// All types in this package are safe for concurrent use:
//
//   - DKGHost: Thread-safe for all operations
//   - P2PCoordinator: Thread-safe message routing and participant management
//   - P2PParticipant: Thread-safe connection and message handling
//
// # Best Practices
//
//  1. Always close resources:
//     defer host.Close()
//     defer coordinator.Stop(ctx)
//     defer participant.Disconnect()
//
//  2. Use context for cancellation:
//     ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//     defer cancel()
//
//  3. Handle errors appropriately:
//     if err := coordinator.Start(ctx); err != nil {
//     log.Fatalf("failed to start coordinator: %v", err)
//     }
//
//  4. Configure TLS for production:
//     cfg.TLSCertFile = "/etc/dkg/certs/server.crt"
//     cfg.TLSKeyFile = "/etc/dkg/certs/server.key"
//     cfg.TLSCAFile = "/etc/dkg/certs/ca.crt"
//
//  5. Use proper peer addressing:
//     // Full multiaddr with peer ID
//     addr := "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooW..."
//
// # Compatibility
//
// This implementation is compatible with:
//   - libp2p protocol suite
//   - Other transport implementations (gRPC, HTTP, QUIC, etc.)
//   - Standard transport.Config configuration system
//   - Existing DKG session management
//
// The TLS support is fully backward compatible - existing code without
// TLS configuration will continue to work with libp2p's default security.
package libp2p
