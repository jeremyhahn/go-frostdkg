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

package libp2p_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/libp2p"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// Example_tlsBasic demonstrates basic TLS configuration with libp2p transport.
func Example_tlsBasic() {
	ctx := context.Background()

	// Generate self-signed certificate for testing
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create temporary directory for certificates
	tmpDir, err := os.MkdirTemp("", "libp2p-tls-example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		log.Fatal(err)
	}

	// Create host with TLS configuration
	cfg := libp2p.DefaultHostConfig()
	cfg.TLSCertFile = certFile
	cfg.TLSKeyFile = keyFile

	host, err := libp2p.NewHost(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = host.Close() }()

	// Verify TLS is configured
	if host.HasTLS() {
		fmt.Println("TLS is configured")
	}

	// Output: TLS is configured
}

// Example_tlsCoordinator demonstrates creating a coordinator with TLS.
func Example_tlsCoordinator() {
	ctx := context.Background()

	// Generate self-signed certificate
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		log.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "libp2p-coordinator-example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		log.Fatal(err)
	}

	// Create coordinator with TLS using transport.Config
	transportCfg := transport.NewTLSConfig(
		transport.ProtocolLibp2p,
		"/ip4/127.0.0.1/tcp/0",
		certFile,
		keyFile,
		"",
	)

	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
		Timeout:         5 * time.Minute,
	}

	coordinator, err := libp2p.NewP2PCoordinatorFromTransportConfig(
		"example-session",
		transportCfg,
		sessionCfg,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = coordinator.Stop(ctx) }()

	if err := coordinator.Start(ctx); err != nil {
		log.Fatal(err)
	}

	// Verify TLS is enabled
	if coordinator.TLSEnabled() {
		fmt.Println("Coordinator TLS enabled")
	}

	// Output: Coordinator TLS enabled
}

// Example_tlsParticipant demonstrates creating a participant with TLS.
func Example_tlsParticipant() {
	// Generate self-signed certificate for client
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		log.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "libp2p-participant-example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	certFile := filepath.Join(tmpDir, "client.crt")
	keyFile := filepath.Join(tmpDir, "client.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		log.Fatal(err)
	}

	// Create participant with TLS using transport.Config
	cfg := transport.NewTLSConfig(
		transport.ProtocolLibp2p,
		"",
		certFile,
		keyFile,
		certFile, // Use same cert as CA for testing
	)

	participant, err := libp2p.NewP2PParticipantFromTransportConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = participant.Disconnect() }()

	// Verify TLS is enabled
	if participant.TLSEnabled() {
		fmt.Println("Participant TLS enabled")
	}

	// Output: Participant TLS enabled
}

// Example_mutualTLS demonstrates mutual TLS (mTLS) configuration.
func Example_mutualTLS() {
	ctx := context.Background()

	// Generate server certificate
	serverCertPEM, serverKeyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Generate client certificate
	clientCertPEM, clientKeyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		log.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "libp2p-mtls-example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	serverCertFile := filepath.Join(tmpDir, "server.crt")
	serverKeyFile := filepath.Join(tmpDir, "server.key")
	clientCertFile := filepath.Join(tmpDir, "client.crt")
	clientKeyFile := filepath.Join(tmpDir, "client.key")
	caFile := filepath.Join(tmpDir, "ca.crt")

	// Write certificates
	if err := os.WriteFile(serverCertFile, serverCertPEM, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(serverKeyFile, serverKeyPEM, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(clientCertFile, clientCertPEM, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(clientKeyFile, clientKeyPEM, 0600); err != nil {
		log.Fatal(err)
	}
	// Use server cert as CA for testing
	if err := os.WriteFile(caFile, serverCertPEM, 0600); err != nil {
		log.Fatal(err)
	}

	// Create coordinator with mTLS
	coordinatorCfg := libp2p.DefaultHostConfig()
	coordinatorCfg.TLSCertFile = serverCertFile
	coordinatorCfg.TLSKeyFile = serverKeyFile
	coordinatorCfg.TLSCAFile = caFile // Verify client certificates

	host, err := libp2p.NewHost(ctx, coordinatorCfg)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = host.Close() }()

	if host.HasTLS() {
		fmt.Println("Mutual TLS configured")
	}

	// Output: Mutual TLS configured
}

// Example_noTLS demonstrates backward compatibility - no TLS configuration.
func Example_noTLS() {
	ctx := context.Background()

	// Create host without TLS configuration
	// libp2p will use its built-in security (Noise or TLS 1.3)
	cfg := libp2p.DefaultHostConfig()

	host, err := libp2p.NewHost(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = host.Close() }()

	// No application-level TLS configured
	if !host.HasTLS() {
		fmt.Println("Using libp2p built-in security")
	}

	// But host is still secure
	if host.ID() != "" {
		fmt.Println("Host is operational with default security")
	}

	// Output:
	// Using libp2p built-in security
	// Host is operational with default security
}

// Example_tlsConfiguration demonstrates various TLS configuration options.
func Example_tlsConfiguration() {
	ctx := context.Background()

	// Generate test certificates
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		log.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "libp2p-config-example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	certFile := filepath.Join(tmpDir, "cert.crt")
	keyFile := filepath.Join(tmpDir, "key.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		log.Fatal(err)
	}

	// Option 1: Using HostConfig directly
	hostCfg := libp2p.DefaultHostConfig()
	hostCfg.TLSCertFile = certFile
	hostCfg.TLSKeyFile = keyFile
	host1, _ := libp2p.NewHost(ctx, hostCfg)
	defer func() { _ = host1.Close() }()
	fmt.Println("Option 1: HostConfig - TLS:", host1.HasTLS())

	// Option 2: Using transport.Config
	transportCfg := transport.NewTLSConfig(
		transport.ProtocolLibp2p,
		"/ip4/0.0.0.0/tcp/0",
		certFile,
		keyFile,
		"",
	)
	host2, _ := libp2p.NewHostFromTransportConfig(ctx, transportCfg)
	defer func() { _ = host2.Close() }()
	fmt.Println("Option 2: transport.Config - TLS:", host2.HasTLS())

	// Option 3: Client mode (CA only)
	clientCfg := libp2p.DefaultHostConfig()
	clientCfg.TLSCAFile = certFile
	host3, _ := libp2p.NewHost(ctx, clientCfg)
	defer func() { _ = host3.Close() }()
	fmt.Println("Option 3: Client mode - TLS:", host3.HasTLS())

	// Output:
	// Option 1: HostConfig - TLS: true
	// Option 2: transport.Config - TLS: true
	// Option 3: Client mode - TLS: true
}
