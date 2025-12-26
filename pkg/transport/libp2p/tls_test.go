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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// TestHostTLSConfiguration tests TLS configuration for libp2p hosts.
func TestHostTLSConfiguration(t *testing.T) {
	ctx := context.Background()

	// Create temporary directory for certificates
	tmpDir := t.TempDir()

	// Generate self-signed certificates for testing
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %v", err)
	}

	certFile := filepath.Join(tmpDir, "test.crt")
	keyFile := filepath.Join(tmpDir, "test.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	t.Run("host without TLS config", func(t *testing.T) {
		cfg := DefaultHostConfig()
		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if host.HasTLS() {
			t.Error("host should not have TLS config")
		}
		if host.TLSConfig() != nil {
			t.Error("TLS config should be nil")
		}
	})

	t.Run("host with TLS cert and key", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.TLSCertFile = certFile
		cfg.TLSKeyFile = keyFile

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host with TLS: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasTLS() {
			t.Error("host should have TLS config")
		}
		if host.TLSConfig() == nil {
			t.Error("TLS config should not be nil")
		}
	})

	t.Run("host with TLS cert, key, and CA", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.TLSCertFile = certFile
		cfg.TLSKeyFile = keyFile
		cfg.TLSCAFile = certFile // Use same cert as CA for testing

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host with mTLS: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasTLS() {
			t.Error("host should have TLS config")
		}
		if host.TLSConfig() == nil {
			t.Error("TLS config should not be nil")
		}
	})

	t.Run("host with only CA (client mode)", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.TLSCAFile = certFile

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host with CA: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasTLS() {
			t.Error("host should have TLS config")
		}
		if host.TLSConfig() == nil {
			t.Error("TLS config should not be nil")
		}
	})

	t.Run("host with invalid cert file", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.TLSCertFile = filepath.Join(tmpDir, "nonexistent.crt")
		cfg.TLSKeyFile = keyFile

		_, err := NewHost(ctx, cfg)
		if err == nil {
			t.Error("should fail with invalid cert file")
		}
	})

	t.Run("host with invalid key file", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.TLSCertFile = certFile
		cfg.TLSKeyFile = filepath.Join(tmpDir, "nonexistent.key")

		_, err := NewHost(ctx, cfg)
		if err == nil {
			t.Error("should fail with invalid key file")
		}
	})

	t.Run("host with invalid CA file", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.TLSCAFile = filepath.Join(tmpDir, "nonexistent.ca")

		_, err := NewHost(ctx, cfg)
		if err == nil {
			t.Error("should fail with invalid CA file")
		}
	})
}

// TestHostFromTransportConfig tests creating a host from transport.Config.
func TestHostFromTransportConfig(t *testing.T) {
	ctx := context.Background()

	// Create temporary directory for certificates
	tmpDir := t.TempDir()

	// Generate self-signed certificates
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %v", err)
	}

	certFile := filepath.Join(tmpDir, "test.crt")
	keyFile := filepath.Join(tmpDir, "test.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	t.Run("nil transport config", func(t *testing.T) {
		_, err := NewHostFromTransportConfig(ctx, nil)
		if err != transport.ErrInvalidConfig {
			t.Errorf("expected ErrInvalidConfig, got %v", err)
		}
	})

	t.Run("transport config without TLS", func(t *testing.T) {
		cfg := transport.NewConfig()
		cfg.Protocol = transport.ProtocolLibp2p
		cfg.Address = "/ip4/127.0.0.1/tcp/0"

		host, err := NewHostFromTransportConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if host.HasTLS() {
			t.Error("host should not have TLS config")
		}
	})

	t.Run("transport config with TLS", func(t *testing.T) {
		cfg := transport.NewTLSConfig(
			transport.ProtocolLibp2p,
			"/ip4/127.0.0.1/tcp/0",
			certFile,
			keyFile,
			"",
		)

		host, err := NewHostFromTransportConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host with TLS: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasTLS() {
			t.Error("host should have TLS config")
		}
	})

	t.Run("transport config with mTLS", func(t *testing.T) {
		cfg := transport.NewTLSConfig(
			transport.ProtocolLibp2p,
			"/ip4/127.0.0.1/tcp/0",
			certFile,
			keyFile,
			certFile, // Use same cert as CA for testing
		)

		host, err := NewHostFromTransportConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host with mTLS: %v", err)
		}
		defer func() { _ = host.Close() }()

		if !host.HasTLS() {
			t.Error("host should have TLS config")
		}
	})
}

// TestCoordinatorFromTransportConfig tests creating a coordinator from transport.Config.
func TestCoordinatorFromTransportConfig(t *testing.T) {
	// Create temporary directory for certificates
	tmpDir := t.TempDir()

	// Generate self-signed certificates
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %v", err)
	}

	certFile := filepath.Join(tmpDir, "test.crt")
	keyFile := filepath.Join(tmpDir, "test.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	sessionID := "test-session"
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
		Timeout:         5 * time.Minute,
	}

	t.Run("nil transport config", func(t *testing.T) {
		_, err := NewP2PCoordinatorFromTransportConfig(sessionID, nil, sessionCfg)
		if err != transport.ErrInvalidConfig {
			t.Errorf("expected ErrInvalidConfig, got %v", err)
		}
	})

	t.Run("transport config without TLS", func(t *testing.T) {
		transportCfg := transport.NewConfig()
		transportCfg.Protocol = transport.ProtocolLibp2p
		transportCfg.Address = "/ip4/127.0.0.1/tcp/0"

		coordinator, err := NewP2PCoordinatorFromTransportConfig(sessionID, transportCfg, sessionCfg)
		if err != nil {
			t.Fatalf("failed to create coordinator: %v", err)
		}
		defer func() { _ = coordinator.Stop(context.Background()) }()

		if coordinator.HasTLS() {
			t.Error("coordinator should not have TLS config")
		}
	})

	t.Run("transport config with TLS", func(t *testing.T) {
		transportCfg := transport.NewTLSConfig(
			transport.ProtocolLibp2p,
			"/ip4/127.0.0.1/tcp/0",
			certFile,
			keyFile,
			"",
		)

		coordinator, err := NewP2PCoordinatorFromTransportConfig(sessionID, transportCfg, sessionCfg)
		if err != nil {
			t.Fatalf("failed to create coordinator with TLS: %v", err)
		}
		defer func() { _ = coordinator.Stop(context.Background()) }()

		if !coordinator.HasTLS() {
			t.Error("coordinator should have TLS config")
		}
		if !coordinator.TLSEnabled() {
			t.Error("TLS should be enabled")
		}
	})

	t.Run("transport config with mTLS", func(t *testing.T) {
		transportCfg := transport.NewTLSConfig(
			transport.ProtocolLibp2p,
			"/ip4/127.0.0.1/tcp/0",
			certFile,
			keyFile,
			certFile, // Use same cert as CA for testing
		)

		coordinator, err := NewP2PCoordinatorFromTransportConfig(sessionID, transportCfg, sessionCfg)
		if err != nil {
			t.Fatalf("failed to create coordinator with mTLS: %v", err)
		}
		defer func() { _ = coordinator.Stop(context.Background()) }()

		if !coordinator.HasTLS() {
			t.Error("coordinator should have TLS config")
		}
	})
}

// TestParticipantFromTransportConfig tests creating a participant from transport.Config.
func TestParticipantFromTransportConfig(t *testing.T) {
	// Create temporary directory for certificates
	tmpDir := t.TempDir()

	// Generate self-signed certificates
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %v", err)
	}

	certFile := filepath.Join(tmpDir, "test.crt")
	keyFile := filepath.Join(tmpDir, "test.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	t.Run("nil transport config", func(t *testing.T) {
		_, err := NewP2PParticipantFromTransportConfig(nil)
		if err != transport.ErrInvalidConfig {
			t.Errorf("expected ErrInvalidConfig, got %v", err)
		}
	})

	t.Run("transport config without TLS", func(t *testing.T) {
		cfg := transport.NewConfig()
		cfg.Protocol = transport.ProtocolLibp2p

		participant, err := NewP2PParticipantFromTransportConfig(cfg)
		if err != nil {
			t.Fatalf("failed to create participant: %v", err)
		}
		defer func() { _ = participant.Disconnect() }()

		if participant.HasTLS() {
			t.Error("participant should not have TLS config")
		}
	})

	t.Run("transport config with TLS", func(t *testing.T) {
		cfg := transport.NewTLSConfig(
			transport.ProtocolLibp2p,
			"/ip4/127.0.0.1/tcp/0",
			certFile,
			keyFile,
			"",
		)

		participant, err := NewP2PParticipantFromTransportConfig(cfg)
		if err != nil {
			t.Fatalf("failed to create participant with TLS: %v", err)
		}
		defer func() { _ = participant.Disconnect() }()

		if !participant.HasTLS() {
			t.Error("participant should have TLS config")
		}
		if !participant.TLSEnabled() {
			t.Error("TLS should be enabled")
		}
	})

	t.Run("transport config with mTLS", func(t *testing.T) {
		cfg := transport.NewTLSConfig(
			transport.ProtocolLibp2p,
			"/ip4/127.0.0.1/tcp/0",
			certFile,
			keyFile,
			certFile, // Use same cert as CA for testing
		)

		participant, err := NewP2PParticipantFromTransportConfig(cfg)
		if err != nil {
			t.Fatalf("failed to create participant with mTLS: %v", err)
		}
		defer func() { _ = participant.Disconnect() }()

		if !participant.HasTLS() {
			t.Error("participant should have TLS config")
		}
	})
}

// TestTLSBackwardCompatibility tests that TLS is optional and backward compatible.
func TestTLSBackwardCompatibility(t *testing.T) {
	ctx := context.Background()

	t.Run("host creation without TLS still works", func(t *testing.T) {
		cfg := DefaultHostConfig()
		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host without TLS: %v", err)
		}
		defer func() { _ = host.Close() }()

		// Verify libp2p security is still enabled (Noise and/or TLS 1.3)
		if host.ID() == "" {
			t.Error("host should have valid peer ID")
		}
	})

	t.Run("coordinator without TLS still works", func(t *testing.T) {
		sessionCfg := &transport.SessionConfig{
			Threshold:       2,
			NumParticipants: 3,
			Ciphersuite:     "FROST-ED25519-SHA512-v1",
			Timeout:         5 * time.Minute,
		}

		hostCfg := DefaultHostConfig()
		coordinator, err := NewP2PCoordinator("test-session", sessionCfg, hostCfg)
		if err != nil {
			t.Fatalf("failed to create coordinator without TLS: %v", err)
		}
		defer func() { _ = coordinator.Stop(ctx) }()

		if err := coordinator.Start(ctx); err != nil {
			t.Fatalf("failed to start coordinator: %v", err)
		}
	})

	t.Run("participant without TLS still works", func(t *testing.T) {
		hostCfg := DefaultHostConfig()
		participant, err := NewP2PParticipant(hostCfg)
		if err != nil {
			t.Fatalf("failed to create participant without TLS: %v", err)
		}
		defer func() { _ = participant.Disconnect() }()

		if participant.host == nil {
			t.Error("participant should have valid host")
		}
	})
}

// TestTLSSecurityProtocolNegotiation tests that libp2p security protocols are properly configured.
func TestTLSSecurityProtocolNegotiation(t *testing.T) {
	ctx := context.Background()

	t.Run("both Noise and TLS enabled", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.EnableNoise = true
		cfg.EnableTLS = true

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host: %v", err)
		}
		defer func() { _ = host.Close() }()

		if host.ID() == "" {
			t.Error("host should have valid peer ID")
		}
	})

	t.Run("only Noise enabled", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.EnableNoise = true
		cfg.EnableTLS = false

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host with Noise only: %v", err)
		}
		defer func() { _ = host.Close() }()

		if host.ID() == "" {
			t.Error("host should have valid peer ID")
		}
	})

	t.Run("only TLS enabled", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.EnableNoise = false
		cfg.EnableTLS = true

		host, err := NewHost(ctx, cfg)
		if err != nil {
			t.Fatalf("failed to create host with TLS only: %v", err)
		}
		defer func() { _ = host.Close() }()

		if host.ID() == "" {
			t.Error("host should have valid peer ID")
		}
	})

	t.Run("no security protocols enabled", func(t *testing.T) {
		cfg := DefaultHostConfig()
		cfg.EnableNoise = false
		cfg.EnableTLS = false

		_, err := NewHost(ctx, cfg)
		if err == nil {
			t.Error("should fail when no security protocols are enabled")
		}
	})
}

// BenchmarkHostCreationWithTLS benchmarks host creation with TLS.
func BenchmarkHostCreationWithTLS(b *testing.B) {
	ctx := context.Background()

	// Create temporary directory for certificates
	tmpDir := b.TempDir()

	// Generate self-signed certificates
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		b.Fatalf("failed to generate self-signed certificate: %v", err)
	}

	certFile := filepath.Join(tmpDir, "test.crt")
	keyFile := filepath.Join(tmpDir, "test.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		b.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		b.Fatalf("failed to write key file: %v", err)
	}

	cfg := DefaultHostConfig()
	cfg.TLSCertFile = certFile
	cfg.TLSKeyFile = keyFile

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host, err := NewHost(ctx, cfg)
		if err != nil {
			b.Fatalf("failed to create host: %v", err)
		}
		_ = host.Close()
	}
}

// BenchmarkHostCreationNoTLS benchmarks host creation without TLS for comparison.
func BenchmarkHostCreationNoTLS(b *testing.B) {
	ctx := context.Background()
	cfg := DefaultHostConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host, err := NewHost(ctx, cfg)
		if err != nil {
			b.Fatalf("failed to create host: %v", err)
		}
		_ = host.Close()
	}
}
