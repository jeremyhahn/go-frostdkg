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

package grpc

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/grpc/proto"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// Test fixtures

// skipUnixSocketTestOnWindows skips tests that require Unix socket connections.
// While Windows 10+ supports Unix domain sockets at the OS level, gRPC-go's
// implementation has compatibility issues on Windows that cause connection timeouts.
func skipUnixSocketTestOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket tests skipped on Windows due to gRPC-go compatibility issues")
	}
}

func generateTestCerts(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1"},
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("failed to generate test certificates: %v", err)
	}

	certFile = filepath.Join(dir, "test.crt")
	keyFile = filepath.Join(dir, "test.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	return certFile, keyFile
}

func generateTestParams(n, t, idx int) *transport.DKGParams {
	hostPubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		hostPubkeys[i] = make([]byte, transport.PublicKeySize)
		if _, err := rand.Read(hostPubkeys[i]); err != nil {
			panic(fmt.Sprintf("rand.Read failed: %v", err))
		}
	}

	hostSeckey := make([]byte, 32)
	if _, err := rand.Read(hostSeckey); err != nil {
		panic(fmt.Sprintf("rand.Read failed: %v", err))
	}

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		panic(fmt.Sprintf("rand.Read failed: %v", err))
	}

	return &transport.DKGParams{
		HostSeckey:     hostSeckey,
		HostPubkeys:    hostPubkeys,
		Threshold:      t,
		ParticipantIdx: idx,
		Random:         random,
	}
}

// GRPCServer tests

func TestNewGRPCServer(t *testing.T) {
	tests := []struct {
		name        string
		config      *transport.Config
		sessionCfg  *transport.SessionConfig
		expectError bool
	}{
		{
			name: "valid configuration",
			config: &transport.Config{
				Protocol: transport.ProtocolGRPC,
				Address:  "localhost:0",
			},
			sessionCfg: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			},
			expectError: false,
		},
		{
			name:        "nil config",
			config:      nil,
			sessionCfg:  &transport.SessionConfig{},
			expectError: true,
		},
		{
			name: "wrong protocol",
			config: &transport.Config{
				Protocol: transport.ProtocolHTTP,
				Address:  "localhost:0",
			},
			sessionCfg:  &transport.SessionConfig{},
			expectError: true,
		},
		{
			name: "invalid threshold",
			config: &transport.Config{
				Protocol: transport.ProtocolGRPC,
				Address:  "localhost:0",
			},
			sessionCfg: &transport.SessionConfig{
				Threshold:       4,
				NumParticipants: 3,
			},
			expectError: true,
		},
		{
			name: "invalid participant count",
			config: &transport.Config{
				Protocol: transport.ProtocolGRPC,
				Address:  "localhost:0",
			},
			sessionCfg: &transport.SessionConfig{
				Threshold:       1,
				NumParticipants: 0,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewGRPCServer(tt.config, tt.sessionCfg)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if server == nil {
				t.Errorf("expected non-nil server")
			}
		})
	}
}

func TestGRPCServerStartStop(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()

	// Test start
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	// Verify server is running
	if !server.running.Load() {
		t.Errorf("server should be running")
	}

	// Verify address is set
	addr := server.Address()
	if addr == "" {
		t.Errorf("server address should not be empty")
	}

	// Test stop
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop server: %v", err)
	}

	// Verify server is stopped
	if server.running.Load() {
		t.Errorf("server should be stopped")
	}
}

func TestGRPCServerWithTLS(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "grpc-tls-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	certFile, keyFile := generateTestCerts(t, tmpDir)

	config := &transport.Config{
		Protocol:    transport.ProtocolGRPC,
		Address:     "localhost:0",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server with TLS: %v", err)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop server: %v", err)
	}
}

func TestGRPCServerWaitForParticipants(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	t.Run("timeout waiting for participants", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := server.WaitForParticipants(ctx, 3)
		if err != transport.ErrSessionTimeout {
			t.Errorf("expected timeout error, got: %v", err)
		}
	})

	t.Run("invalid participant count", func(t *testing.T) {
		ctx := context.Background()

		err := server.WaitForParticipants(ctx, 0)
		if err != transport.ErrInvalidParticipantCount {
			t.Errorf("expected invalid participant count error, got: %v", err)
		}

		err = server.WaitForParticipants(ctx, 10)
		if err != transport.ErrInvalidParticipantCount {
			t.Errorf("expected invalid participant count error, got: %v", err)
		}
	})

	t.Run("immediate return when participants already connected", func(t *testing.T) {
		// Simulate participants connected
		server.participantCount.Store(3)

		ctx := context.Background()
		err := server.WaitForParticipants(ctx, 3)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// Test SessionID method
func TestGRPCServerSessionID(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		SessionID:       "test-session-123",
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if server.SessionID() != "test-session-123" {
		t.Errorf("SessionID() = %s, want test-session-123", server.SessionID())
	}
}

// Test helper methods
func TestGRPCServerHelpers(t *testing.T) {
	t.Run("getMaxMessageSize with custom value", func(t *testing.T) {
		config := &transport.Config{
			Protocol:       transport.ProtocolGRPC,
			Address:        "localhost:0",
			MaxMessageSize: 2048,
		}
		sessionCfg := &transport.SessionConfig{
			Threshold:       2,
			NumParticipants: 3,
		}

		server, err := NewGRPCServer(config, sessionCfg)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		if server.getMaxMessageSize() != 2048 {
			t.Errorf("getMaxMessageSize() = %d, want 2048", server.getMaxMessageSize())
		}
	})

	t.Run("getMaxMessageSize with default value", func(t *testing.T) {
		config := &transport.Config{
			Protocol: transport.ProtocolGRPC,
			Address:  "localhost:0",
		}
		sessionCfg := &transport.SessionConfig{
			Threshold:       2,
			NumParticipants: 3,
		}

		server, err := NewGRPCServer(config, sessionCfg)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		if server.getMaxMessageSize() != 1024*1024 {
			t.Errorf("getMaxMessageSize() = %d, want 1048576", server.getMaxMessageSize())
		}
	})

	t.Run("getKeepAliveInterval with custom value", func(t *testing.T) {
		config := &transport.Config{
			Protocol:          transport.ProtocolGRPC,
			Address:           "localhost:0",
			KeepAliveInterval: 60 * time.Second,
		}
		sessionCfg := &transport.SessionConfig{
			Threshold:       2,
			NumParticipants: 3,
		}

		server, err := NewGRPCServer(config, sessionCfg)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		if server.getKeepAliveInterval() != 60*time.Second {
			t.Errorf("getKeepAliveInterval() = %v, want 60s", server.getKeepAliveInterval())
		}
	})

	t.Run("getKeepAliveInterval with default value", func(t *testing.T) {
		config := &transport.Config{
			Protocol: transport.ProtocolGRPC,
			Address:  "localhost:0",
		}
		sessionCfg := &transport.SessionConfig{
			Threshold:       2,
			NumParticipants: 3,
		}

		server, err := NewGRPCServer(config, sessionCfg)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		if server.getKeepAliveInterval() != 30*time.Second {
			t.Errorf("getKeepAliveInterval() = %v, want 30s", server.getKeepAliveInterval())
		}
	})
}

// GRPCClient tests

func TestNewGRPCClient(t *testing.T) {
	tests := []struct {
		name        string
		config      *transport.Config
		expectError bool
	}{
		{
			name: "valid configuration",
			config: &transport.Config{
				Protocol:  transport.ProtocolGRPC,
				CodecType: "json",
			},
			expectError: false,
		},
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "wrong protocol",
			config: &transport.Config{
				Protocol: transport.ProtocolHTTP,
			},
			expectError: true,
		},
		{
			name: "default codec",
			config: &transport.Config{
				Protocol: transport.ProtocolGRPC,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewGRPCClient(tt.config)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if client == nil {
				t.Errorf("expected non-nil client")
			}
		})
	}
}

func TestGRPCClientConnectDisconnect(t *testing.T) {
	// Start a server
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create client
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Test connect
	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	if !client.connected.Load() {
		t.Errorf("client should be connected")
	}

	// Test disconnect
	if err := client.Disconnect(); err != nil {
		t.Fatalf("failed to disconnect: %v", err)
	}

	if client.connected.Load() {
		t.Errorf("client should be disconnected")
	}
}

func TestGRPCClientHelpers(t *testing.T) {
	t.Run("helper methods with custom values", func(t *testing.T) {
		clientCfg := &transport.Config{
			Protocol:          transport.ProtocolGRPC,
			MaxMessageSize:    2048,
			Timeout:           60 * time.Second,
			KeepAliveInterval: 45 * time.Second,
		}
		client, err := NewGRPCClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		if client.getMaxMessageSize() != 2048 {
			t.Errorf("getMaxMessageSize() = %d, want 2048", client.getMaxMessageSize())
		}

		if client.getTimeout() != 60*time.Second {
			t.Errorf("getTimeout() = %v, want 60s", client.getTimeout())
		}

		if client.getKeepAliveInterval() != 45*time.Second {
			t.Errorf("getKeepAliveInterval() = %v, want 45s", client.getKeepAliveInterval())
		}
	})

	t.Run("helper methods with default values", func(t *testing.T) {
		clientCfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		if client.getMaxMessageSize() != 1024*1024 {
			t.Errorf("getMaxMessageSize() = %d, want 1048576", client.getMaxMessageSize())
		}

		if client.getTimeout() != 30*time.Second {
			t.Errorf("getTimeout() = %v, want 30s", client.getTimeout())
		}

		if client.getKeepAliveInterval() != 30*time.Second {
			t.Errorf("getKeepAliveInterval() = %v, want 30s", client.getKeepAliveInterval())
		}
	})
}

func TestGRPCClientValidateParams(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	tests := []struct {
		name        string
		params      *transport.DKGParams
		expectError bool
	}{
		{
			name:        "nil params",
			params:      nil,
			expectError: true,
		},
		{
			name: "invalid host seckey length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 16),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			expectError: true,
		},
		{
			name: "invalid randomness length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         make([]byte, 16),
			},
			expectError: true,
		},
		{
			name: "invalid participant index",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: 5,
				Random:         make([]byte, 32),
			},
			expectError: true,
		},
		{
			name: "invalid threshold",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      0,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			expectError: true,
		},
		{
			name: "invalid host pubkey length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, 16)},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			expectError: true,
		},
		{
			name:        "valid params",
			params:      generateTestParams(3, 2, 0),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateParams(tt.params)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Unix socket tests

func TestNewUnixServer(t *testing.T) {
	tests := []struct {
		name        string
		config      *transport.Config
		sessionCfg  *transport.SessionConfig
		expectError bool
	}{
		{
			name: "valid configuration",
			config: &transport.Config{
				Protocol: transport.ProtocolUnix,
				Address:  "/tmp/test.sock",
			},
			sessionCfg: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			},
			expectError: false,
		},
		{
			name:        "nil config",
			config:      nil,
			sessionCfg:  &transport.SessionConfig{},
			expectError: true,
		},
		{
			name: "wrong protocol",
			config: &transport.Config{
				Protocol: transport.ProtocolGRPC,
				Address:  "/tmp/test.sock",
			},
			sessionCfg:  &transport.SessionConfig{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewUnixServer(tt.config, tt.sessionCfg)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if server == nil {
				t.Errorf("expected non-nil server")
			}
		})
	}
}

func TestUnixServerStartStop(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()

	// Test start
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}

	// Verify socket file exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Errorf("socket file should exist")
	}

	// Test stop
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop Unix server: %v", err)
	}

	// Verify socket file is removed
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Errorf("socket file should be removed")
	}
}

// Test Unix server methods
func TestUnixServerMethods(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		SessionID:       "unix-test-session",
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	// Test Address
	if server.Address() != socketPath {
		t.Errorf("Address() = %s, want %s", server.Address(), socketPath)
	}

	// Test SessionID
	if server.SessionID() != "unix-test-session" {
		t.Errorf("SessionID() = %s, want unix-test-session", server.SessionID())
	}

	// Test getMaxMessageSize
	if server.getMaxMessageSize() != 1024*1024 {
		t.Errorf("getMaxMessageSize() = %d, want 1048576", server.getMaxMessageSize())
	}
}

func TestNewUnixClient(t *testing.T) {
	tests := []struct {
		name        string
		config      *transport.Config
		expectError bool
	}{
		{
			name: "valid configuration",
			config: &transport.Config{
				Protocol:  transport.ProtocolUnix,
				CodecType: "json",
			},
			expectError: false,
		},
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "wrong protocol",
			config: &transport.Config{
				Protocol: transport.ProtocolGRPC,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewUnixClient(tt.config)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if client == nil {
				t.Errorf("expected non-nil client")
			}
		})
	}
}

func TestUnixClientConnectDisconnect(t *testing.T) {
	skipUnixSocketTestOnWindows(t)
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start Unix server
	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create Unix client
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create Unix client: %v", err)
	}

	// Test connect
	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, socketPath); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	if !client.connected.Load() {
		t.Errorf("client should be connected")
	}

	// Test disconnect
	if err := client.Disconnect(); err != nil {
		t.Fatalf("failed to disconnect: %v", err)
	}

	if client.connected.Load() {
		t.Errorf("client should be disconnected")
	}
}

// Test Unix client helper methods
func TestUnixClientHelpers(t *testing.T) {
	t.Run("helper methods with custom values", func(t *testing.T) {
		clientCfg := &transport.Config{
			Protocol:       transport.ProtocolUnix,
			MaxMessageSize: 2048,
			Timeout:        60 * time.Second,
		}
		client, err := NewUnixClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		if client.getMaxMessageSize() != 2048 {
			t.Errorf("getMaxMessageSize() = %d, want 2048", client.getMaxMessageSize())
		}

		if client.getTimeout() != 60*time.Second {
			t.Errorf("getTimeout() = %v, want 60s", client.getTimeout())
		}
	})

	t.Run("helper methods with default values", func(t *testing.T) {
		clientCfg := &transport.Config{
			Protocol: transport.ProtocolUnix,
		}
		client, err := NewUnixClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		if client.getMaxMessageSize() != 1024*1024 {
			t.Errorf("getMaxMessageSize() = %d, want 1048576", client.getMaxMessageSize())
		}

		if client.getTimeout() != 30*time.Second {
			t.Errorf("getTimeout() = %v, want 30s", client.getTimeout())
		}
	})
}

// Test Unix client validateParams
func TestUnixClientValidateParams(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	tests := []struct {
		name        string
		params      *transport.DKGParams
		expectError bool
	}{
		{
			name:        "nil params",
			params:      nil,
			expectError: true,
		},
		{
			name: "invalid host seckey length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 16),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			expectError: true,
		},
		{
			name: "invalid randomness length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         make([]byte, 16),
			},
			expectError: true,
		},
		{
			name: "negative participant index",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: -1,
				Random:         make([]byte, 32),
			},
			expectError: true,
		},
		{
			name: "participant index out of range",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
				ParticipantIdx: 5,
				Random:         make([]byte, 32),
			},
			expectError: true,
		},
		{
			name: "threshold too low",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      0,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			expectError: true,
		},
		{
			name: "threshold too high",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      5,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			expectError: true,
		},
		{
			name: "invalid host pubkey length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{make([]byte, 16)},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			},
			expectError: true,
		},
		{
			name:        "valid params",
			params:      generateTestParams(3, 2, 0),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateParams(tt.params)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Integration tests

func TestGRPCMessageExchange(t *testing.T) {
	// Start server
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create multiple clients
	numClients := 3
	clients := make([]*GRPCClient, numClients)
	for i := 0; i < numClients; i++ {
		clientCfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client %d: %v", i, err)
		}
		clients[i] = client
	}

	// Connect all clients
	for i, client := range clients {
		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := client.Connect(connectCtx, server.Address()); err != nil {
			t.Fatalf("failed to connect client %d: %v", i, err)
		}
		defer func() { _ = client.Disconnect() }()
	}

	// Wait for all participants
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start goroutines to send join messages
	var wg sync.WaitGroup
	for i, client := range clients {
		wg.Add(1)
		go func(idx int, c *GRPCClient) {
			defer wg.Done()

			params := generateTestParams(numClients, 2, idx)
			c.participantIdx = idx

			stream, err := c.client.ParticipantStream(waitCtx)
			if err != nil {
				t.Errorf("failed to create stream for client %d: %v", idx, err)
				return
			}
			c.stream = stream

			if err := c.sendJoin(params); err != nil {
				t.Errorf("failed to send join for client %d: %v", idx, err)
				return
			}

			// Read session info
			msg, err := stream.Recv()
			if err != nil {
				t.Errorf("failed to receive session info for client %d: %v", idx, err)
				return
			}

			if msg.Type != proto.MessageType_MSG_TYPE_SESSION_INFO {
				t.Errorf("expected session info message for client %d, got type %v", idx, msg.Type)
			}
		}(i, client)
	}

	wg.Wait()

	// Verify all participants are connected
	if err := server.WaitForParticipants(waitCtx, numClients); err != nil {
		t.Errorf("failed to wait for participants: %v", err)
	}

	count := int(server.participantCount.Load())
	if count != numClients {
		t.Errorf("expected %d participants, got %d", numClients, count)
	}
}

func TestConcurrentParticipants(t *testing.T) {
	// Start server
	config := &transport.Config{
		Protocol:  transport.ProtocolGRPC,
		Address:   "localhost:0",
		KeepAlive: true,
		Timeout:   10 * time.Second,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       3,
		NumParticipants: 5,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Connect 5 participants concurrently
	numClients := 5
	var wg sync.WaitGroup
	errors := make(chan error, numClients)
	done := make(chan struct{})

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			clientCfg := &transport.Config{
				Protocol: transport.ProtocolGRPC,
			}
			client, err := NewGRPCClient(clientCfg)
			if err != nil {
				errors <- fmt.Errorf("client %d: failed to create: %v", idx, err)
				return
			}

			connectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := client.Connect(connectCtx, server.Address()); err != nil {
				errors <- fmt.Errorf("client %d: failed to connect: %v", idx, err)
				return
			}
			defer func() { _ = client.Disconnect() }()

			params := generateTestParams(numClients, 3, idx)
			client.participantIdx = idx

			stream, err := client.client.ParticipantStream(connectCtx)
			if err != nil {
				errors <- fmt.Errorf("client %d: failed to create stream: %v", idx, err)
				return
			}
			client.stream = stream

			if err := client.sendJoin(params); err != nil {
				errors <- fmt.Errorf("client %d: failed to send join: %v", idx, err)
				return
			}

			// Wait for session info
			_, err = stream.Recv()
			if err != nil {
				errors <- fmt.Errorf("client %d: failed to receive session info: %v", idx, err)
				return
			}

			// Wait for signal to disconnect
			<-done
		}(i)
	}

	// Wait for all participants to connect
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.WaitForParticipants(waitCtx, numClients); err != nil {
		t.Errorf("failed to wait for participants: %v", err)
	}

	// Signal clients to disconnect
	close(done)

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("concurrent test error: %v", err)
	}
}

// Test full RunDKG flow for gRPC client
func TestGRPCClientRunDKG(t *testing.T) {
	// Start server
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create client
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Connect
	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Run DKG in goroutine
	params := generateTestParams(3, 2, 0)
	dkgCtx, dkgCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dkgCancel()

	var result *transport.DKGResult
	var dkgErr error
	done := make(chan struct{})

	go func() {
		result, dkgErr = client.RunDKG(dkgCtx, params)
		close(done)
	}()

	// Wait for result or timeout
	select {
	case <-done:
		if dkgErr != nil {
			t.Fatalf("RunDKG failed: %v", dkgErr)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.SessionID == "" {
			t.Error("expected non-empty session ID")
		}
		if len(result.SecretShare) != transport.SecretKeySize {
			t.Errorf("expected secret share size %d, got %d", transport.SecretKeySize, len(result.SecretShare))
		}
		if len(result.ThresholdPubkey) != transport.PublicKeySize {
			t.Errorf("expected threshold pubkey size %d, got %d", transport.PublicKeySize, len(result.ThresholdPubkey))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("RunDKG timed out")
	}
}

// Test RunDKG when not connected
func TestGRPCClientRunDKGNotConnected(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	params := generateTestParams(3, 2, 0)
	ctx := context.Background()

	_, err = client.RunDKG(ctx, params)
	if err != transport.ErrNotConnected {
		t.Errorf("RunDKG() not connected error = %v, want %v", err, transport.ErrNotConnected)
	}
}

// Test Unix client RunDKG
func TestUnixClientRunDKG(t *testing.T) {
	skipUnixSocketTestOnWindows(t)
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start Unix server
	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create Unix client
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create Unix client: %v", err)
	}

	// Connect
	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, socketPath); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Run DKG
	params := generateTestParams(3, 2, 0)
	dkgCtx, dkgCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dkgCancel()

	var result *transport.DKGResult
	var dkgErr error
	done := make(chan struct{})

	go func() {
		result, dkgErr = client.RunDKG(dkgCtx, params)
		close(done)
	}()

	// Wait for result or timeout
	select {
	case <-done:
		if dkgErr != nil {
			t.Fatalf("RunDKG failed: %v", dkgErr)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.SessionID == "" {
			t.Error("expected non-empty session ID")
		}
		if len(result.SecretShare) != transport.SecretKeySize {
			t.Errorf("expected secret share size %d, got %d", transport.SecretKeySize, len(result.SecretShare))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("RunDKG timed out")
	}
}

// Test Unix server WaitForParticipants
func TestUnixServerWaitForParticipants(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	t.Run("timeout waiting for participants", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := server.WaitForParticipants(ctx, 3)
		if err != transport.ErrSessionTimeout {
			t.Errorf("expected timeout error, got: %v", err)
		}
	})

	t.Run("invalid participant count", func(t *testing.T) {
		ctx := context.Background()

		err := server.WaitForParticipants(ctx, 0)
		if err != transport.ErrInvalidParticipantCount {
			t.Errorf("expected invalid participant count error, got: %v", err)
		}

		err = server.WaitForParticipants(ctx, 10)
		if err != transport.ErrInvalidParticipantCount {
			t.Errorf("expected invalid participant count error, got: %v", err)
		}
	})
}

// Test message relay for gRPC server
func TestGRPCServerMessageRelay(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create and connect 3 clients
	numClients := 3
	clients := make([]*GRPCClient, numClients)
	streams := make([]proto.DKGCoordinator_ParticipantStreamClient, numClients)

	for i := 0; i < numClients; i++ {
		clientCfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client %d: %v", i, err)
		}
		clients[i] = client

		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := client.Connect(connectCtx, server.Address()); err != nil {
			t.Fatalf("failed to connect client %d: %v", i, err)
		}
		defer func() { _ = client.Disconnect() }()

		stream, err := client.client.ParticipantStream(context.Background())
		if err != nil {
			t.Fatalf("failed to create stream for client %d: %v", i, err)
		}
		streams[i] = stream
		client.stream = stream

		// Send join message
		params := generateTestParams(numClients, 2, i)
		if err := client.sendJoin(params); err != nil {
			t.Fatalf("failed to send join for client %d: %v", i, err)
		}

		// Receive session info
		_, err = stream.Recv()
		if err != nil {
			t.Fatalf("failed to receive session info for client %d: %v", i, err)
		}
	}

	// Wait for all participants to connect
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.WaitForParticipants(waitCtx, numClients); err != nil {
		t.Fatalf("failed to wait for participants: %v", err)
	}

	// Test message relay - send a message from client 0
	testMsg := &proto.DKGMessage{
		SessionId: server.sessionID,
		Type:      proto.MessageType_MSG_TYPE_ROUND1,
		SenderIdx: 0,
		Payload:   []byte("test payload"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := streams[0].Send(testMsg); err != nil {
		t.Fatalf("failed to send test message: %v", err)
	}

	// Verify clients 1 and 2 receive the message
	receivedCount := 0
	for i := 1; i < numClients; i++ {
		recvCtx, recvCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer recvCancel()

		done := make(chan *proto.DKGMessage, 1)
		errChan := make(chan error, 1)

		go func(idx int) {
			msg, err := streams[idx].Recv()
			if err != nil {
				errChan <- err
				return
			}
			done <- msg
		}(i)

		select {
		case msg := <-done:
			if msg.Type != proto.MessageType_MSG_TYPE_ROUND1 {
				t.Errorf("client %d: expected ROUND1 message, got %v", i, msg.Type)
			}
			if msg.SenderIdx != 0 {
				t.Errorf("client %d: expected sender idx 0, got %d", i, msg.SenderIdx)
			}
			receivedCount++
		case err := <-errChan:
			t.Errorf("client %d: failed to receive message: %v", i, err)
		case <-recvCtx.Done():
			t.Errorf("client %d: timeout waiting for message", i)
		}
	}

	if receivedCount != numClients-1 {
		t.Errorf("expected %d clients to receive message, got %d", numClients-1, receivedCount)
	}
}

// Test Unix server message relay
func TestUnixServerMessageRelay(t *testing.T) {
	skipUnixSocketTestOnWindows(t)
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create and connect 3 clients
	numClients := 3
	clients := make([]*UnixClient, numClients)
	streams := make([]proto.DKGCoordinator_ParticipantStreamClient, numClients)

	for i := 0; i < numClients; i++ {
		clientCfg := &transport.Config{
			Protocol: transport.ProtocolUnix,
		}
		client, err := NewUnixClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client %d: %v", i, err)
		}
		clients[i] = client

		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := client.Connect(connectCtx, socketPath); err != nil {
			t.Fatalf("failed to connect client %d: %v", i, err)
		}
		defer func() { _ = client.Disconnect() }()

		stream, err := client.client.ParticipantStream(context.Background())
		if err != nil {
			t.Fatalf("failed to create stream for client %d: %v", i, err)
		}
		streams[i] = stream
		client.stream = stream

		// Send join message
		params := generateTestParams(numClients, 2, i)
		if err := client.sendJoin(params); err != nil {
			t.Fatalf("failed to send join for client %d: %v", i, err)
		}

		// Receive session info
		_, err = stream.Recv()
		if err != nil {
			t.Fatalf("failed to receive session info for client %d: %v", i, err)
		}
	}

	// Wait for all participants to connect
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.WaitForParticipants(waitCtx, numClients); err != nil {
		t.Fatalf("failed to wait for participants: %v", err)
	}

	// Test message relay - send a message from client 0
	testMsg := &proto.DKGMessage{
		SessionId: server.sessionID,
		Type:      proto.MessageType_MSG_TYPE_ROUND1,
		SenderIdx: 0,
		Payload:   []byte("test payload"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := streams[0].Send(testMsg); err != nil {
		t.Fatalf("failed to send test message: %v", err)
	}

	// Verify clients 1 and 2 receive the message
	receivedCount := 0
	for i := 1; i < numClients; i++ {
		recvCtx, recvCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer recvCancel()

		done := make(chan *proto.DKGMessage, 1)
		errChan := make(chan error, 1)

		go func(idx int) {
			msg, err := streams[idx].Recv()
			if err != nil {
				errChan <- err
				return
			}
			done <- msg
		}(i)

		select {
		case msg := <-done:
			if msg.Type != proto.MessageType_MSG_TYPE_ROUND1 {
				t.Errorf("client %d: expected ROUND1 message, got %v", i, msg.Type)
			}
			if msg.SenderIdx != 0 {
				t.Errorf("client %d: expected sender idx 0, got %d", i, msg.SenderIdx)
			}
			receivedCount++
		case err := <-errChan:
			t.Errorf("client %d: failed to receive message: %v", i, err)
		case <-recvCtx.Done():
			t.Errorf("client %d: timeout waiting for message", i)
		}
	}

	if receivedCount != numClients-1 {
		t.Errorf("expected %d clients to receive message, got %d", numClients-1, receivedCount)
	}
}

// Test ParticipantStream error handling
func TestGRPCServerParticipantStreamErrors(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Test duplicate participant
	t.Run("duplicate participant", func(t *testing.T) {
		// Create two clients with same participant index
		clientCfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client1, err := NewGRPCClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client 1: %v", err)
		}

		client2, err := NewGRPCClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client 2: %v", err)
		}

		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := client1.Connect(connectCtx, server.Address()); err != nil {
			t.Fatalf("failed to connect client 1: %v", err)
		}
		defer func() { _ = client1.Disconnect() }()

		if err := client2.Connect(connectCtx, server.Address()); err != nil {
			t.Fatalf("failed to connect client 2: %v", err)
		}
		defer func() { _ = client2.Disconnect() }()

		// Both try to join as participant 0
		stream1, err := client1.client.ParticipantStream(context.Background())
		if err != nil {
			t.Fatalf("failed to create stream 1: %v", err)
		}

		stream2, err := client2.client.ParticipantStream(context.Background())
		if err != nil {
			t.Fatalf("failed to create stream 2: %v", err)
		}

		params := generateTestParams(3, 2, 0)

		// Set streams for clients
		client1.stream = stream1
		client2.stream = stream2

		// First join should succeed
		if err := client1.sendJoin(params); err != nil {
			t.Fatalf("first join failed: %v", err)
		}

		// Receive session info for first client
		_, err = stream1.Recv()
		if err != nil {
			t.Fatalf("failed to receive session info: %v", err)
		}

		// Second join with same index should fail
		if err := client2.sendJoin(params); err != nil {
			t.Fatalf("second join send failed: %v", err)
		}

		// The stream should be closed with an error
		_, err = stream2.Recv()
		if err == nil {
			t.Error("expected error for duplicate participant, got nil")
		}
	})
}

// Benchmark tests

func BenchmarkGRPCServerStartStop(b *testing.B) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server, err := NewGRPCServer(config, sessionCfg)
		if err != nil {
			b.Fatalf("failed to create server: %v", err)
		}

		ctx := context.Background()
		if err := server.Start(ctx); err != nil {
			b.Fatalf("failed to start server: %v", err)
		}

		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = server.Stop(stopCtx)
		cancel()
	}
}

func BenchmarkGRPCClientConnect(b *testing.B) {
	// Start server once
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		b.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		b.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	serverAddr := server.Address()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clientCfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(clientCfg)
		if err != nil {
			b.Fatalf("failed to create client: %v", err)
		}

		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := client.Connect(connectCtx, serverAddr); err != nil {
			b.Fatalf("failed to connect: %v", err)
		}
		cancel()

		_ = client.Disconnect()
	}
}

// Test error conditions
func TestGRPCClientDisconnectNotConnected(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Try to disconnect when not connected
	if err := client.Disconnect(); err != transport.ErrNotConnected {
		t.Errorf("Disconnect() not connected error = %v, want %v", err, transport.ErrNotConnected)
	}
}

func TestGRPCClientConnectAlreadyConnected(t *testing.T) {
	// Start a server
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create and connect client
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Try to connect again
	if err := client.Connect(connectCtx, server.Address()); err != transport.ErrAlreadyConnected {
		t.Errorf("Connect() already connected error = %v, want %v", err, transport.ErrAlreadyConnected)
	}
}

func TestUnixClientDisconnectNotConnected(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Try to disconnect when not connected
	if err := client.Disconnect(); err != transport.ErrNotConnected {
		t.Errorf("Disconnect() not connected error = %v, want %v", err, transport.ErrNotConnected)
	}
}

func TestUnixClientConnectAlreadyConnected(t *testing.T) {
	skipUnixSocketTestOnWindows(t)
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start Unix server
	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create and connect Unix client
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create Unix client: %v", err)
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, socketPath); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Try to connect again
	if err := client.Connect(connectCtx, socketPath); err != transport.ErrAlreadyConnected {
		t.Errorf("Connect() already connected error = %v, want %v", err, transport.ErrAlreadyConnected)
	}
}

func TestGRPCServerStartAlreadyRunning(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()

	// Start server
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Try to start again
	if err := server.Start(ctx); err == nil {
		t.Error("Start() called twice should return error")
	}
}

func TestUnixServerStartAlreadyRunning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()

	// Start server
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Try to start again
	if err := server.Start(ctx); err == nil {
		t.Error("Start() called twice should return error")
	}
}

func TestGRPCServerStopNotRunning(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()

	// Stop without starting - should not error
	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() on non-running server returned error: %v", err)
	}
}

func TestUnixServerStopNotRunning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()

	// Stop without starting - should not error
	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() on non-running server returned error: %v", err)
	}
}

// Test wait for participants with session closed
func TestGRPCServerWaitForParticipantsSessionClosed(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	// Stop server in background after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = server.Stop(context.Background())
	}()

	// Wait for participants - should return session closed error
	if err := server.WaitForParticipants(ctx, 3); err != transport.ErrSessionClosed {
		t.Errorf("WaitForParticipants() after stop error = %v, want %v", err, transport.ErrSessionClosed)
	}
}

// Test Unix server WaitForParticipants with session closed
func TestUnixServerWaitForParticipantsSessionClosed(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}

	// Stop server in background after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = server.Stop(context.Background())
	}()

	// Wait for participants - should return session closed error
	if err := server.WaitForParticipants(ctx, 3); err != transport.ErrSessionClosed {
		t.Errorf("WaitForParticipants() after stop error = %v, want %v", err, transport.ErrSessionClosed)
	}
}

// Test Address before server start
func TestGRPCServerAddressBeforeStart(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:9999",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Address should return config address before start
	if server.Address() != "localhost:9999" {
		t.Errorf("Address() before start = %s, want localhost:9999", server.Address())
	}
}

// Test gRPC client with TLS
func TestGRPCClientConnectWithTLS(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "grpc-tls-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	certFile, keyFile := generateTestCerts(t, tmpDir)

	// Start TLS server
	config := &transport.Config{
		Protocol:    transport.ProtocolGRPC,
		Address:     "localhost:0",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create client with TLS
	clientCfg := &transport.Config{
		Protocol:  transport.ProtocolGRPC,
		TLSCAFile: certFile,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, server.Address()); err != nil {
		t.Fatalf("failed to connect with TLS: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	if !client.connected.Load() {
		t.Error("client should be connected")
	}
}

// Test waitForSessionInfo with error channel
func TestGRPCClientWaitForSessionInfoError(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Send error on error channel
	testErr := fmt.Errorf("test error")
	go func() {
		time.Sleep(10 * time.Millisecond)
		client.errorChan <- testErr
	}()

	ctx := context.Background()
	_, err = client.waitForSessionInfo(ctx)
	if err != testErr {
		t.Errorf("expected test error, got %v", err)
	}
}

// Test waitForSessionInfo with wrong message type
func TestGRPCClientWaitForSessionInfoWrongType(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Send wrong message type
	go func() {
		time.Sleep(10 * time.Millisecond)
		client.incomingChan <- &proto.DKGMessage{
			Type: proto.MessageType_MSG_TYPE_ROUND1,
		}
	}()

	ctx := context.Background()
	_, err = client.waitForSessionInfo(ctx)
	if err != transport.ErrUnexpectedMessage {
		t.Errorf("expected unexpected message error, got %v", err)
	}
}

// Test message relay with different message types
func TestGRPCServerRelayMessageTypes(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create and connect 3 clients
	numClients := 3
	clients := make([]*GRPCClient, numClients)
	streams := make([]proto.DKGCoordinator_ParticipantStreamClient, numClients)

	for i := 0; i < numClients; i++ {
		clientCfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client %d: %v", i, err)
		}
		clients[i] = client

		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := client.Connect(connectCtx, server.Address()); err != nil {
			t.Fatalf("failed to connect client %d: %v", i, err)
		}
		defer func() { _ = client.Disconnect() }()

		stream, err := client.client.ParticipantStream(context.Background())
		if err != nil {
			t.Fatalf("failed to create stream for client %d: %v", i, err)
		}
		streams[i] = stream
		client.stream = stream

		// Send join message
		params := generateTestParams(numClients, 2, i)
		if err := client.sendJoin(params); err != nil {
			t.Fatalf("failed to send join for client %d: %v", i, err)
		}

		// Receive session info
		_, err = stream.Recv()
		if err != nil {
			t.Fatalf("failed to receive session info for client %d: %v", i, err)
		}
	}

	// Test different message types
	messageTypes := []proto.MessageType{
		proto.MessageType_MSG_TYPE_ROUND1_AGG,
		proto.MessageType_MSG_TYPE_ROUND2,
		proto.MessageType_MSG_TYPE_ROUND2_AGG,
		proto.MessageType_MSG_TYPE_CERTIFICATE,
		proto.MessageType_MSG_TYPE_COMPLETE,
	}

	for _, msgType := range messageTypes {
		testMsg := &proto.DKGMessage{
			SessionId: server.sessionID,
			Type:      msgType,
			SenderIdx: 0,
			Payload:   []byte("test payload"),
			Timestamp: time.Now().UnixMilli(),
		}

		if err := streams[0].Send(testMsg); err != nil {
			t.Fatalf("failed to send message type %v: %v", msgType, err)
		}

		// Receive on other clients
		for i := 1; i < numClients; i++ {
			msg, err := streams[i].Recv()
			if err != nil {
				t.Fatalf("failed to receive message type %v on client %d: %v", msgType, i, err)
			}
			if msg.Type != msgType {
				t.Errorf("expected message type %v, got %v", msgType, msg.Type)
			}
		}
	}
}

// Test RunDKG with invalid params
func TestGRPCClientRunDKGInvalidParams(t *testing.T) {
	// Start server
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create client
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Connect
	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Try RunDKG with invalid params
	invalidParams := &transport.DKGParams{
		HostSeckey:     make([]byte, 16), // Wrong size
		HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	_, err = client.RunDKG(ctx, invalidParams)
	if err == nil {
		t.Error("expected error for invalid params")
	}
}

// Test Unix server ParticipantStream message relay
func TestUnixServerParticipantStreamMessageRelay(t *testing.T) {
	skipUnixSocketTestOnWindows(t)
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create 2 clients
	numClients := 2
	clients := make([]*UnixClient, numClients)
	streams := make([]proto.DKGCoordinator_ParticipantStreamClient, numClients)

	for i := 0; i < numClients; i++ {
		clientCfg := &transport.Config{
			Protocol: transport.ProtocolUnix,
		}
		client, err := NewUnixClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client %d: %v", i, err)
		}
		clients[i] = client

		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := client.Connect(connectCtx, socketPath); err != nil {
			t.Fatalf("failed to connect client %d: %v", i, err)
		}
		defer func() { _ = client.Disconnect() }()

		stream, err := client.client.ParticipantStream(context.Background())
		if err != nil {
			t.Fatalf("failed to create stream for client %d: %v", i, err)
		}
		streams[i] = stream
		client.stream = stream

		// Send join message
		params := generateTestParams(numClients, 2, i)
		if err := client.sendJoin(params); err != nil {
			t.Fatalf("failed to send join for client %d: %v", i, err)
		}

		// Receive session info
		_, err = stream.Recv()
		if err != nil {
			t.Fatalf("failed to receive session info for client %d: %v", i, err)
		}
	}

	// Test message relay
	testMsg := &proto.DKGMessage{
		SessionId: server.sessionID,
		Type:      proto.MessageType_MSG_TYPE_ROUND1,
		SenderIdx: 0,
		Payload:   []byte("test payload"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := streams[0].Send(testMsg); err != nil {
		t.Fatalf("failed to send test message: %v", err)
	}

	// Verify client 1 receives the message
	msg, err := streams[1].Recv()
	if err != nil {
		t.Fatalf("failed to receive message: %v", err)
	}
	if msg.Type != proto.MessageType_MSG_TYPE_ROUND1 {
		t.Errorf("expected ROUND1 message, got %v", msg.Type)
	}
}

// Test Unix server getMaxMessageSize with custom value
func TestUnixServerGetMaxMessageSize(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol:       transport.ProtocolUnix,
		Address:        socketPath,
		MaxMessageSize: 2048,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	if server.getMaxMessageSize() != 2048 {
		t.Errorf("getMaxMessageSize() = %d, want 2048", server.getMaxMessageSize())
	}
}

// Test Unix client RunDKG with not connected error
func TestUnixClientRunDKGNotConnected(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	params := generateTestParams(3, 2, 0)
	ctx := context.Background()

	_, err = client.RunDKG(ctx, params)
	if err != transport.ErrNotConnected {
		t.Errorf("RunDKG() not connected error = %v, want %v", err, transport.ErrNotConnected)
	}
}

// Test Unix waitForSessionInfo with error
func TestUnixClientWaitForSessionInfoError(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Send error on error channel
	testErr := fmt.Errorf("test error")
	go func() {
		time.Sleep(10 * time.Millisecond)
		client.errorChan <- testErr
	}()

	ctx := context.Background()
	_, err = client.waitForSessionInfo(ctx)
	if err != testErr {
		t.Errorf("expected test error, got %v", err)
	}
}

// Test Unix waitForSessionInfo with wrong message type
func TestUnixClientWaitForSessionInfoWrongType(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Send wrong message type
	go func() {
		time.Sleep(10 * time.Millisecond)
		client.incomingChan <- &proto.DKGMessage{
			Type: proto.MessageType_MSG_TYPE_ROUND1,
		}
	}()

	ctx := context.Background()
	_, err = client.waitForSessionInfo(ctx)
	if err != transport.ErrUnexpectedMessage {
		t.Errorf("expected unexpected message error, got %v", err)
	}
}

// Test Unix waitForSessionInfo with context timeout
func TestUnixClientWaitForSessionInfoTimeout(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = client.waitForSessionInfo(ctx)
	if err != transport.ErrSessionTimeout {
		t.Errorf("expected timeout error, got %v", err)
	}
}

// Test gRPC waitForSessionInfo with context timeout
func TestGRPCClientWaitForSessionInfoTimeout(t *testing.T) {
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = client.waitForSessionInfo(ctx)
	if err != transport.ErrSessionTimeout {
		t.Errorf("expected timeout error, got %v", err)
	}
}

// Test Unix ParticipantStream with message before join
func TestUnixServerParticipantStreamNoJoin(t *testing.T) {
	skipUnixSocketTestOnWindows(t)
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create client
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, socketPath); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	stream, err := client.client.ParticipantStream(context.Background())
	if err != nil {
		t.Fatalf("failed to create stream: %v", err)
	}
	client.stream = stream

	// Send a non-join message first - should get error
	testMsg := &proto.DKGMessage{
		SessionId: server.sessionID,
		Type:      proto.MessageType_MSG_TYPE_ROUND1,
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := stream.Send(testMsg); err != nil {
		t.Fatalf("failed to send message: %v", err)
	}

	// Should get error for unexpected message
	_, err = stream.Recv()
	if err == nil {
		t.Error("expected error for non-join first message")
	}
}

// Test gRPC ParticipantStream with duplicate participant
func TestGRPCServerParticipantStreamDuplicateParticipant(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create two clients
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client1, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client 1: %v", err)
	}

	client2, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client 2: %v", err)
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client1.Connect(connectCtx, server.Address()); err != nil {
		t.Fatalf("failed to connect client 1: %v", err)
	}
	defer func() { _ = client1.Disconnect() }()

	if err := client2.Connect(connectCtx, server.Address()); err != nil {
		t.Fatalf("failed to connect client 2: %v", err)
	}
	defer func() { _ = client2.Disconnect() }()

	// Both try to join as participant 0
	stream1, err := client1.client.ParticipantStream(context.Background())
	if err != nil {
		t.Fatalf("failed to create stream 1: %v", err)
	}
	client1.stream = stream1

	stream2, err := client2.client.ParticipantStream(context.Background())
	if err != nil {
		t.Fatalf("failed to create stream 2: %v", err)
	}
	client2.stream = stream2

	params := generateTestParams(3, 2, 0)

	// First join should succeed
	if err := client1.sendJoin(params); err != nil {
		t.Fatalf("first join failed: %v", err)
	}

	// Receive session info
	_, err = stream1.Recv()
	if err != nil {
		t.Fatalf("failed to receive session info: %v", err)
	}

	// Second join should fail
	if err := client2.sendJoin(params); err != nil {
		t.Fatalf("second join send failed: %v", err)
	}

	// Should get error
	_, err = stream2.Recv()
	if err == nil {
		t.Error("expected error for duplicate participant")
	}
}

// Test Unix ParticipantStream with shutdown
func TestUnixServerParticipantStreamShutdown(t *testing.T) {
	skipUnixSocketTestOnWindows(t)
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}

	// Create client and stream
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, socketPath); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	streamCtx := context.Background()
	stream, err := client.client.ParticipantStream(streamCtx)
	if err != nil {
		t.Fatalf("failed to create stream: %v", err)
	}

	// Stop server while stream is active
	_ = server.Stop(context.Background())

	// Stream should get error
	_, err = stream.Recv()
	if err == nil {
		t.Error("expected error after server shutdown")
	}
}

// Test relay message with CERT_EQ_SIGN and default case
func TestGRPCServerRelayMessageCertEqAndDefault(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create and connect 2 clients
	numClients := 2
	clients := make([]*GRPCClient, numClients)
	streams := make([]proto.DKGCoordinator_ParticipantStreamClient, numClients)

	for i := 0; i < numClients; i++ {
		clientCfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client %d: %v", i, err)
		}
		clients[i] = client

		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := client.Connect(connectCtx, server.Address()); err != nil {
			t.Fatalf("failed to connect client %d: %v", i, err)
		}
		defer func() { _ = client.Disconnect() }()

		stream, err := client.client.ParticipantStream(context.Background())
		if err != nil {
			t.Fatalf("failed to create stream for client %d: %v", i, err)
		}
		streams[i] = stream
		client.stream = stream

		// Send join message
		params := generateTestParams(numClients, 2, i)
		if err := client.sendJoin(params); err != nil {
			t.Fatalf("failed to send join for client %d: %v", i, err)
		}

		// Receive session info
		_, err = stream.Recv()
		if err != nil {
			t.Fatalf("failed to receive session info for client %d: %v", i, err)
		}
	}

	// Test CERT_EQ_SIGN message type
	testMsg := &proto.DKGMessage{
		SessionId: server.sessionID,
		Type:      proto.MessageType_MSG_TYPE_CERT_EQ_SIGN,
		SenderIdx: 0,
		Payload:   []byte("test payload"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := streams[0].Send(testMsg); err != nil {
		t.Fatalf("failed to send CERT_EQ_SIGN message: %v", err)
	}

	// Verify client 1 receives the message
	msg, err := streams[1].Recv()
	if err != nil {
		t.Fatalf("failed to receive CERT_EQ_SIGN message: %v", err)
	}
	if msg.Type != proto.MessageType_MSG_TYPE_CERT_EQ_SIGN {
		t.Errorf("expected CERT_EQ_SIGN message, got %v", msg.Type)
	}

	// Test ERROR message type (default case)
	errorMsg := &proto.DKGMessage{
		SessionId: server.sessionID,
		Type:      proto.MessageType_MSG_TYPE_ERROR,
		SenderIdx: 0,
		Payload:   []byte("error payload"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := streams[0].Send(errorMsg); err != nil {
		t.Fatalf("failed to send ERROR message: %v", err)
	}

	// Verify client 1 receives the message
	msg, err = streams[1].Recv()
	if err != nil {
		t.Fatalf("failed to receive ERROR message: %v", err)
	}
	if msg.Type != proto.MessageType_MSG_TYPE_ERROR {
		t.Errorf("expected ERROR message, got %v", msg.Type)
	}
}

// Test Unix RunDKG with invalid params
func TestUnixClientRunDKGInvalidParams(t *testing.T) {
	skipUnixSocketTestOnWindows(t)
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start Unix server
	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewUnixServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start Unix server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create Unix client
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewUnixClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create Unix client: %v", err)
	}

	// Connect
	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, socketPath); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Try RunDKG with invalid params
	invalidParams := &transport.DKGParams{
		HostSeckey:     make([]byte, 16), // Wrong size
		HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	_, err = client.RunDKG(ctx, invalidParams)
	if err == nil {
		t.Error("expected error for invalid params")
	}
}

// Test gRPC ParticipantStream message before join
func TestGRPCServerParticipantStreamNoJoin(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create client
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolGRPC,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	stream, err := client.client.ParticipantStream(context.Background())
	if err != nil {
		t.Fatalf("failed to create stream: %v", err)
	}
	client.stream = stream

	// Send a non-join message first - should get error
	testMsg := &proto.DKGMessage{
		SessionId: server.sessionID,
		Type:      proto.MessageType_MSG_TYPE_ROUND1,
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := stream.Send(testMsg); err != nil {
		t.Fatalf("failed to send message: %v", err)
	}

	// Should get error for unexpected message
	_, err = stream.Recv()
	if err == nil {
		t.Error("expected error for non-join first message")
	}
}

// Test gRPC Connect with unix protocol
func TestGRPCClientConnectUnixProtocol(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-socket-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start Unix server using GRPC protocol config
	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  socketPath,
	}
	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewGRPCServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create client with Unix protocol
	clientCfg := &transport.Config{
		Protocol: transport.ProtocolUnix,
	}
	client, err := NewGRPCClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, socketPath); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	if !client.connected.Load() {
		t.Error("client should be connected")
	}
}

// Test NewGRPCServer with nil session config
func TestNewGRPCServerNilSessionConfig(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolGRPC,
		Address:  "localhost:0",
	}

	_, err := NewGRPCServer(config, nil)
	if err == nil {
		t.Error("expected error for nil session config")
	}
}

// Test NewUnixServer with nil session config
func TestNewUnixServerNilSessionConfig(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolUnix,
		Address:  "/tmp/test.sock",
	}

	_, err := NewUnixServer(config, nil)
	if err == nil {
		t.Error("expected error for nil session config")
	}
}
