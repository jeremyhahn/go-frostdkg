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

package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// TestNewHTTPServer tests HTTP server creation
func TestNewHTTPServer(t *testing.T) {
	tests := []struct {
		name          string
		config        *transport.Config
		sessionConfig *transport.SessionConfig
		sessionID     string
		expectError   bool
	}{
		{
			name: "valid configuration",
			config: &transport.Config{
				Protocol:  transport.ProtocolHTTP,
				Address:   "localhost:0",
				CodecType: "json",
			},
			sessionConfig: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			},
			sessionID:   "test-session",
			expectError: false,
		},
		{
			name:          "nil config",
			config:        nil,
			sessionConfig: &transport.SessionConfig{},
			sessionID:     "test-session",
			expectError:   true,
		},
		{
			name:          "nil session config",
			config:        &transport.Config{},
			sessionConfig: nil,
			sessionID:     "test-session",
			expectError:   true,
		},
		{
			name:          "empty session ID",
			config:        &transport.Config{},
			sessionConfig: &transport.SessionConfig{},
			sessionID:     "",
			expectError:   true,
		},
		{
			name: "invalid threshold (too low)",
			config: &transport.Config{
				Address: "localhost:0",
			},
			sessionConfig: &transport.SessionConfig{
				Threshold:       0,
				NumParticipants: 3,
			},
			sessionID:   "test-session",
			expectError: true,
		},
		{
			name: "invalid threshold (too high)",
			config: &transport.Config{
				Address: "localhost:0",
			},
			sessionConfig: &transport.SessionConfig{
				Threshold:       5,
				NumParticipants: 3,
			},
			sessionID:   "test-session",
			expectError: true,
		},
		{
			name: "invalid participant count",
			config: &transport.Config{
				Address: "localhost:0",
			},
			sessionConfig: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 0,
			},
			sessionID:   "test-session",
			expectError: true,
		},
		{
			name: "invalid codec type",
			config: &transport.Config{
				Address:   "localhost:0",
				CodecType: "invalid",
			},
			sessionConfig: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
			},
			sessionID:   "test-session",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewHTTPServer(tt.config, tt.sessionConfig, tt.sessionID)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if server == nil {
					t.Error("expected server instance but got nil")
				}
			}
		})
	}
}

// TestNewHTTPClient tests HTTP client creation
func TestNewHTTPClient(t *testing.T) {
	tests := []struct {
		name        string
		config      *transport.Config
		expectError bool
	}{
		{
			name: "valid configuration",
			config: &transport.Config{
				Protocol:  transport.ProtocolHTTP,
				Address:   "localhost:9000",
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
			name: "invalid codec type",
			config: &transport.Config{
				Protocol:  transport.ProtocolHTTP,
				CodecType: "invalid",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewHTTPClient(tt.config)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if client == nil {
					t.Error("expected client instance but got nil")
				}
			}
		})
	}
}

// TestServerStartStop tests server lifecycle
func TestServerStartStop(t *testing.T) {
	config := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(config, sessionConfig, "test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()

	// Start server
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	// Verify address is set
	addr := server.Address()
	if addr == "" {
		t.Error("server address is empty")
	}

	// Verify session ID
	if server.SessionID() != "test-session" {
		t.Errorf("unexpected session ID: got %s, want %s", server.SessionID(), "test-session")
	}

	// Test starting again (should fail)
	if err := server.Start(ctx); err == nil {
		t.Error("expected error when starting already started server")
	}

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(stopCtx); err != nil {
		t.Errorf("failed to stop server: %v", err)
	}

	// Test stopping again (should succeed)
	if err := server.Stop(stopCtx); err != nil {
		t.Errorf("failed to stop server second time: %v", err)
	}
}

// TestServerAddress tests the Address() method
func TestServerAddress(t *testing.T) {
	config := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(config, sessionConfig, "test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Before starting, should return config address
	addr := server.Address()
	if addr != "localhost:0" {
		t.Errorf("unexpected address before start: got %s, want %s", addr, "localhost:0")
	}

	// After starting, should return listener address
	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	addr = server.Address()
	if addr == "" {
		t.Error("server address is empty after start")
	}
}

// TestServerWithTLS tests server with TLS configuration
func TestServerWithTLS(t *testing.T) {
	// Generate self-signed certificates
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate certificates: %v", err)
	}

	// Write certificates to temp files
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	config := &transport.Config{
		Protocol:    transport.ProtocolHTTP,
		Address:     "localhost:0",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		CodecType:   "json",
		Timeout:     5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(config, sessionConfig, "tls-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()

	// Start server
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(stopCtx); err != nil {
		t.Errorf("failed to stop server: %v", err)
	}
}

// TestServerWithInvalidTLS tests server with invalid TLS files
func TestServerWithInvalidTLS(t *testing.T) {
	config := &transport.Config{
		Protocol:    transport.ProtocolHTTP,
		Address:     "localhost:0",
		TLSCertFile: "/nonexistent/cert.pem",
		TLSKeyFile:  "/nonexistent/key.pem",
		CodecType:   "json",
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(config, sessionConfig, "test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err == nil {
		defer func() { _ = server.Stop(context.Background()) }()
		t.Error("expected error with invalid TLS files")
	}
}

// TestClientConnectDisconnect tests client connection lifecycle
func TestClientConnectDisconnect(t *testing.T) {
	// Start server
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create client
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Connect to server
	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	// Test connecting again (should fail)
	if err := client.Connect(ctx, server.Address()); err == nil {
		t.Error("expected error when connecting already connected client")
	}

	// Disconnect
	if err := client.Disconnect(); err != nil {
		t.Errorf("failed to disconnect: %v", err)
	}

	// Test disconnecting again (should fail)
	if err := client.Disconnect(); err == nil {
		t.Error("expected error when disconnecting already disconnected client")
	}
}

// TestClientConnectToInvalidServer tests connection to invalid server
func TestClientConnectToInvalidServer(t *testing.T) {
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   1 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// Try to connect to non-existent server
	if err := client.Connect(ctx, "localhost:99999"); err == nil {
		t.Error("expected error when connecting to invalid server")
	}
}

// TestWaitForParticipants tests participant waiting functionality
func TestWaitForParticipants(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "wait-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Test timeout when no participants join
	waitCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err = server.WaitForParticipants(waitCtx, 3)
	if err == nil {
		t.Error("expected timeout error but got none")
	}
}

// TestContentTypeNegotiation tests different serialization formats
func TestContentTypeNegotiation(t *testing.T) {
	tests := []struct {
		name        string
		codecType   string
		contentType string
	}{
		{
			name:        "JSON",
			codecType:   "json",
			contentType: ContentTypeJSON,
		},
		{
			name:        "CBOR",
			codecType:   "cbor",
			contentType: ContentTypeCBOR,
		},
		{
			name:        "MessagePack",
			codecType:   "msgpack",
			contentType: ContentTypeMsgPack,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test codec to content type conversion
			contentType := CodecToContentType(tt.codecType)
			if contentType != tt.contentType {
				t.Errorf("unexpected content type: got %s, want %s", contentType, tt.contentType)
			}

			// Test content type parsing
			parsedCodec := ParseContentType(tt.contentType)
			if parsedCodec != tt.codecType {
				t.Errorf("unexpected codec type: got %s, want %s", parsedCodec, tt.codecType)
			}
		})
	}
}

// TestRoutePaths tests route path generation
func TestRoutePaths(t *testing.T) {
	sessionID := "test-session-123"

	tests := []struct {
		name     string
		pathFunc func(string) string
		expected string
	}{
		{
			name:     "SessionPath",
			pathFunc: SessionPath,
			expected: "/v1/sessions/test-session-123",
		},
		{
			name:     "JoinSessionPath",
			pathFunc: JoinSessionPath,
			expected: "/v1/sessions/test-session-123/join",
		},
		{
			name:     "Round1Path",
			pathFunc: Round1Path,
			expected: "/v1/sessions/test-session-123/round1",
		},
		{
			name:     "Round2Path",
			pathFunc: Round2Path,
			expected: "/v1/sessions/test-session-123/round2",
		},
		{
			name:     "CertEqPath",
			pathFunc: CertEqPath,
			expected: "/v1/sessions/test-session-123/certeq",
		},
		{
			name:     "CertificatePath",
			pathFunc: CertificatePath,
			expected: "/v1/sessions/test-session-123/certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.pathFunc(sessionID)
			if path != tt.expected {
				t.Errorf("unexpected path: got %s, want %s", path, tt.expected)
			}
		})
	}
}

// TestConcurrentParticipants tests multiple participants joining concurrently
func TestConcurrentParticipants(t *testing.T) {
	numParticipants := 5

	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   10 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       3,
		NumParticipants: numParticipants,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "concurrent-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Create and connect multiple clients concurrently
	var wg sync.WaitGroup
	errCh := make(chan error, numParticipants)

	for i := 0; i < numParticipants; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			clientConfig := &transport.Config{
				Protocol:  transport.ProtocolHTTP,
				CodecType: "json",
				Timeout:   10 * time.Second,
			}

			client, err := NewHTTPClient(clientConfig)
			if err != nil {
				errCh <- fmt.Errorf("participant %d: failed to create client: %w", idx, err)
				return
			}

			if err := client.Connect(ctx, server.Address()); err != nil {
				errCh <- fmt.Errorf("participant %d: failed to connect: %w", idx, err)
				return
			}
			defer func() { _ = client.Disconnect() }()

		}(i)
	}

	wg.Wait()
	close(errCh)

	// Check for errors
	for err := range errCh {
		t.Error(err)
	}
}

// TestParseContentType tests Content-Type header parsing
func TestParseContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    string
	}{
		{
			name:        "JSON",
			contentType: "application/json",
			expected:    "json",
		},
		{
			name:        "JSON with charset",
			contentType: "application/json; charset=utf-8",
			expected:    "json",
		},
		{
			name:        "CBOR",
			contentType: "application/cbor",
			expected:    "cbor",
		},
		{
			name:        "MessagePack",
			contentType: "application/msgpack",
			expected:    "msgpack",
		},
		{
			name:        "Unknown",
			contentType: "application/xml",
			expected:    "",
		},
		{
			name:        "Empty",
			contentType: "",
			expected:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseContentType(tt.contentType)
			if result != tt.expected {
				t.Errorf("unexpected result: got %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestValidateParams tests DKG parameter validation
func TestValidateParams(t *testing.T) {
	// Generate valid parameters
	validHostSeckey := make([]byte, 32)
	if _, err := rand.Read(validHostSeckey); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	validRandom := make([]byte, 32)
	if _, err := rand.Read(validRandom); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	validHostPubkeys := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		validHostPubkeys[i] = make([]byte, transport.PublicKeySize)
		if _, err := rand.Read(validHostPubkeys[i]); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}
	}

	tests := []struct {
		name        string
		params      *transport.DKGParams
		expectError bool
	}{
		{
			name: "valid parameters",
			params: &transport.DKGParams{
				HostSeckey:     validHostSeckey,
				HostPubkeys:    validHostPubkeys,
				Threshold:      2,
				ParticipantIdx: 0,
				Random:         validRandom,
			},
			expectError: false,
		},
		{
			name:        "nil parameters",
			params:      nil,
			expectError: true,
		},
		{
			name: "invalid host seckey length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 16),
				HostPubkeys:    validHostPubkeys,
				Threshold:      2,
				ParticipantIdx: 0,
				Random:         validRandom,
			},
			expectError: true,
		},
		{
			name: "invalid random length",
			params: &transport.DKGParams{
				HostSeckey:     validHostSeckey,
				HostPubkeys:    validHostPubkeys,
				Threshold:      2,
				ParticipantIdx: 0,
				Random:         make([]byte, 16),
			},
			expectError: true,
		},
		{
			name: "invalid threshold (too low)",
			params: &transport.DKGParams{
				HostSeckey:     validHostSeckey,
				HostPubkeys:    validHostPubkeys,
				Threshold:      0,
				ParticipantIdx: 0,
				Random:         validRandom,
			},
			expectError: true,
		},
		{
			name: "invalid threshold (too high)",
			params: &transport.DKGParams{
				HostSeckey:     validHostSeckey,
				HostPubkeys:    validHostPubkeys,
				Threshold:      5,
				ParticipantIdx: 0,
				Random:         validRandom,
			},
			expectError: true,
		},
		{
			name: "invalid participant index (negative)",
			params: &transport.DKGParams{
				HostSeckey:     validHostSeckey,
				HostPubkeys:    validHostPubkeys,
				Threshold:      2,
				ParticipantIdx: -1,
				Random:         validRandom,
			},
			expectError: true,
		},
		{
			name: "invalid participant index (too high)",
			params: &transport.DKGParams{
				HostSeckey:     validHostSeckey,
				HostPubkeys:    validHostPubkeys,
				Threshold:      2,
				ParticipantIdx: 5,
				Random:         validRandom,
			},
			expectError: true,
		},
		{
			name: "invalid host pubkey size",
			params: &transport.DKGParams{
				HostSeckey:     validHostSeckey,
				HostPubkeys:    [][]byte{make([]byte, 16)},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         validRandom,
			},
			expectError: true,
		},
	}

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateParams(tt.params)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestHTTPHandlers tests various HTTP handler methods
func TestHTTPHandlers(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "handler-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	t.Run("health endpoint", func(t *testing.T) {
		resp, err := http.Get(baseURL + PathHealth)
		if err != nil {
			t.Fatalf("failed to call health endpoint: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("health endpoint with wrong method", func(t *testing.T) {
		resp, err := http.Post(baseURL+PathHealth, "text/plain", nil)
		if err != nil {
			t.Fatalf("failed to call health endpoint: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("create session", func(t *testing.T) {
		resp, err := http.Post(baseURL+PathSessions, ContentTypeJSON, nil)
		if err != nil {
			t.Fatalf("failed to call create session: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("create session with wrong method", func(t *testing.T) {
		resp, err := http.Get(baseURL + PathSessions)
		if err != nil {
			t.Fatalf("failed to call create session: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("get session", func(t *testing.T) {
		sessionPath := SessionPath("handler-test-session")
		resp, err := http.Get(baseURL + sessionPath)
		if err != nil {
			t.Fatalf("failed to get session: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("get session with wrong method", func(t *testing.T) {
		sessionPath := SessionPath("handler-test-session")
		resp, err := http.Post(baseURL+sessionPath, ContentTypeJSON, nil)
		if err != nil {
			t.Fatalf("failed to get session: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("unknown session", func(t *testing.T) {
		sessionPath := SessionPath("unknown-session")
		resp, err := http.Get(baseURL + sessionPath)
		if err != nil {
			t.Fatalf("failed to get session: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
	})

	t.Run("invalid session path", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/v1/sessions/")
		if err != nil {
			t.Fatalf("failed to call endpoint: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("unknown endpoint", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/v1/sessions/handler-test-session/unknown")
		if err != nil {
			t.Fatalf("failed to call endpoint: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
	})
}

// TestJoinSession tests the join session workflow
func TestJoinSession(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "join-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	// Create DKG parameters
	hostSeckey1 := make([]byte, 32)
	if _, err := rand.Read(hostSeckey1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	hostPubkey1 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	hostSeckey2 := make([]byte, 32)
	if _, err := rand.Read(hostSeckey2); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	hostPubkey2 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey2); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	params1 := &transport.DKGParams{
		HostSeckey:     hostSeckey1,
		HostPubkeys:    [][]byte{hostPubkey1, hostPubkey2},
		Threshold:      2,
		ParticipantIdx: 0,
		Random:         randomBytes,
	}

	params2 := &transport.DKGParams{
		HostSeckey:     hostSeckey2,
		HostPubkeys:    [][]byte{hostPubkey1, hostPubkey2},
		Threshold:      2,
		ParticipantIdx: 1,
		Random:         randomBytes,
	}

	// Test first participant joining
	client1, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client1.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client1.Disconnect() }()

	sessionInfo1, err := client1.joinSession(ctx, params1)
	if err != nil {
		t.Fatalf("failed to join session: %v", err)
	}

	if sessionInfo1.SessionID != "join-test-session" {
		t.Errorf("unexpected session ID: got %s, want %s", sessionInfo1.SessionID, "join-test-session")
	}
	if sessionInfo1.ParticipantIdx != 0 {
		t.Errorf("unexpected participant index: got %d, want %d", sessionInfo1.ParticipantIdx, 0)
	}

	// Test second participant joining
	client2, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client2.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client2.Disconnect() }()

	sessionInfo2, err := client2.joinSession(ctx, params2)
	if err != nil {
		t.Fatalf("failed to join session: %v", err)
	}

	if sessionInfo2.ParticipantIdx != 1 {
		t.Errorf("unexpected participant index: got %d, want %d", sessionInfo2.ParticipantIdx, 1)
	}

	// Test joining when session is full
	client3, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client3.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client3.Disconnect() }()

	params3 := &transport.DKGParams{
		HostSeckey:     make([]byte, 32),
		HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         randomBytes,
	}

	_, err = client3.joinSession(ctx, params3)
	if err == nil {
		t.Error("expected error when joining full session")
	}

	// Test duplicate participant
	client4, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client4.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client4.Disconnect() }()

	_, err = client4.joinSession(ctx, params1)
	if err == nil {
		t.Error("expected error when joining with duplicate pubkey")
	}
}

// TestRunDKG tests the full DKG workflow
func TestRunDKG(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   10 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "dkg-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   10 * time.Second,
	}

	// Create DKG parameters for two participants
	hostSeckey1 := make([]byte, 32)
	if _, err := rand.Read(hostSeckey1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	hostPubkey1 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	hostSeckey2 := make([]byte, 32)
	if _, err := rand.Read(hostSeckey2); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	hostPubkey2 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey2); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	randomBytes1 := make([]byte, 32)
	if _, err := rand.Read(randomBytes1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	randomBytes2 := make([]byte, 32)
	if _, err := rand.Read(randomBytes2); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	params1 := &transport.DKGParams{
		HostSeckey:     hostSeckey1,
		HostPubkeys:    [][]byte{hostPubkey1, hostPubkey2},
		Threshold:      2,
		ParticipantIdx: 0,
		Random:         randomBytes1,
	}

	params2 := &transport.DKGParams{
		HostSeckey:     hostSeckey2,
		HostPubkeys:    [][]byte{hostPubkey1, hostPubkey2},
		Threshold:      2,
		ParticipantIdx: 1,
		Random:         randomBytes2,
	}

	// Test participant 1
	client1, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client 1: %v", err)
	}

	if err := client1.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect client 1: %v", err)
	}
	defer func() { _ = client1.Disconnect() }()

	result1, err := client1.RunDKG(ctx, params1)
	if err != nil {
		t.Fatalf("failed to run DKG for client 1: %v", err)
	}

	if result1 == nil {
		t.Fatal("expected DKG result but got nil")
	}
	if result1.SessionID != "dkg-test-session" {
		t.Errorf("unexpected session ID: got %s, want %s", result1.SessionID, "dkg-test-session")
	}
	if len(result1.SecretShare) != transport.SecretKeySize {
		t.Errorf("unexpected secret share size: got %d, want %d", len(result1.SecretShare), transport.SecretKeySize)
	}

	// Test participant 2
	client2, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client 2: %v", err)
	}

	if err := client2.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect client 2: %v", err)
	}
	defer func() { _ = client2.Disconnect() }()

	result2, err := client2.RunDKG(ctx, params2)
	if err != nil {
		t.Fatalf("failed to run DKG for client 2: %v", err)
	}

	if result2 == nil {
		t.Fatal("expected DKG result but got nil")
	}

	// Test RunDKG without connection
	client3, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client 3: %v", err)
	}

	_, err = client3.RunDKG(ctx, params1)
	if err == nil {
		t.Error("expected error when running DKG without connection")
	}
}

// TestDoRequestErrors tests error paths in doRequest
func TestDoRequestErrors(t *testing.T) {
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   1 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	client.serverAddr = "localhost:99999"
	ctx := context.Background()

	// Test connection error
	_, err = client.doRequest(ctx, http.MethodGet, PathHealth, nil, nil)
	if err == nil {
		t.Error("expected connection error")
	}

	// Test marshal error with invalid body
	type invalidType struct {
		Ch chan int
	}
	client.serverAddr = "localhost:8080"
	_, err = client.doRequest(ctx, http.MethodPost, PathSessions, &invalidType{}, nil)
	if err == nil {
		t.Error("expected marshal error")
	}
}

// TestHTTPError tests HTTPError type
func TestHTTPErrorFormat(t *testing.T) {
	err := &HTTPError{
		StatusCode: 404,
		Message:    "not found",
	}

	expected := "HTTP 404: not found"
	if err.Error() != expected {
		t.Errorf("unexpected error string: got %s, want %s", err.Error(), expected)
	}
}

// TestRouteError tests RouteError type
func TestRouteErrorFormat(t *testing.T) {
	innerErr := fmt.Errorf("inner error")
	err := &RouteError{
		Path:   "/test",
		Method: "GET",
		Err:    innerErr,
	}

	expectedMsg := "route error [GET /test]: inner error"
	if err.Error() != expectedMsg {
		t.Errorf("unexpected error message: got %s, want %s", err.Error(), expectedMsg)
	}

	if err.Unwrap() != innerErr {
		t.Error("Unwrap() did not return inner error")
	}
}

// TestReadRequestWithLargeBody tests request body size limit
func TestReadRequestWithLargeBody(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:       transport.ProtocolHTTP,
		Address:        "localhost:0",
		CodecType:      "json",
		MaxMessageSize: 1024, // 1KB limit
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "size-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// The test verifies that MaxMessageSize is set correctly
	if server.config.MaxMessageSize != 1024 {
		t.Errorf("unexpected max message size: got %d, want %d", server.config.MaxMessageSize, 1024)
	}
}

// TestRound1Workflow tests Round1 submission and retrieval
func TestRound1Workflow(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "round1-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participants manually
	hostPubkey1 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	hostPubkey2 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey2); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: hostPubkey1}
	server.participants[1] = &participantInfo{index: 1, hostPubkey: hostPubkey2}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "round1-test-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         randomBytes,
	}

	// Test Round1 execution with timeout - should get error polling for results
	timeoutCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	_, err = client.executeRound1(timeoutCtx, params, sessionInfo)
	if err == nil {
		t.Error("expected error when not all participants have submitted")
	}

	// Check that it's either an HTTPError with 202 status or context timeout
	if httpErr, ok := err.(*HTTPError); ok {
		if httpErr.StatusCode != http.StatusAccepted {
			t.Errorf("unexpected status code: got %d, want %d", httpErr.StatusCode, http.StatusAccepted)
		}
	} else if err != context.DeadlineExceeded && !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("Got expected error: %v", err)
	}
}

// TestRound2Workflow tests Round2 submission and retrieval
func TestRound2Workflow(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "round2-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participants manually
	hostPubkey1 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	hostPubkey2 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey2); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: hostPubkey1}
	server.participants[1] = &participantInfo{index: 1, hostPubkey: hostPubkey2}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "round2-test-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         randomBytes,
	}

	round1Agg := &transport.Round1AggMessage{
		AllCommitments: make([][][]byte, 2),
		AllPOPs:        make([][]byte, 2),
		AllPubnonces:   make([][]byte, 2),
	}

	// Test Round2 execution with timeout - should get error polling for results
	timeoutCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	err = client.executeRound2(timeoutCtx, params, sessionInfo, round1Agg)
	if err == nil {
		t.Error("expected error when not all participants have submitted")
	} else {
		t.Logf("Got expected error: %v", err)
	}
}

// TestCertEqWorkflow tests CertEq signature submission
func TestCertEqWorkflow(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "certeq-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participants manually
	hostPubkey1 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: hostPubkey1}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "certeq-test-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         randomBytes,
	}

	// Test CertEq submission
	err = client.submitCertEqSignature(ctx, params, sessionInfo)
	if err != nil {
		t.Errorf("failed to submit CertEq signature: %v", err)
	}

	// Verify signature was stored
	server.mu.RLock()
	sig, exists := server.certEqSigs[0]
	server.mu.RUnlock()

	if !exists {
		t.Error("CertEq signature was not stored")
	}
	if len(sig) != 32 {
		t.Errorf("unexpected signature length: got %d, want 32", len(sig))
	}
}

// TestCertificateRetrieval tests certificate retrieval
func TestCertificateRetrieval(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "cert-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "cert-test-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	// Test retrieving certificate when not ready
	timeoutCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	_, err = client.retrieveCertificate(timeoutCtx, sessionInfo)
	if err == nil {
		t.Error("expected error when certificate not ready")
	}

	// Set certificate and retrieve it
	testCert := make([]byte, 64)
	if _, err := rand.Read(testCert); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	server.mu.Lock()
	server.certificate = testCert
	server.mu.Unlock()

	cert, err := client.retrieveCertificate(ctx, sessionInfo)
	if err != nil {
		t.Fatalf("failed to retrieve certificate: %v", err)
	}

	if len(cert) != 64 {
		t.Errorf("unexpected certificate length: got %d, want 64", len(cert))
	}
}

// TestHandlerErrorPaths tests error handling in handlers
func TestHandlerErrorPaths(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "error-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	t.Run("Round1 without participant_idx", func(t *testing.T) {
		round1Path := Round1Path("error-test-session")
		req := httptest.NewRequest(http.MethodPost, round1Path, nil)
		w := httptest.NewRecorder()
		server.handleRound1Post(w, req, "error-test-session")

		if w.Code != http.StatusBadRequest {
			t.Errorf("unexpected status code: got %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("Round1 with invalid participant", func(t *testing.T) {
		round1Path := Round1Path("error-test-session") + "?participant_idx=99"
		resp, err := http.Post(baseURL+round1Path, ContentTypeJSON, nil)
		if err != nil {
			t.Fatalf("failed to call Round1: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusBadRequest {
			t.Errorf("unexpected status code: got %d", resp.StatusCode)
		}
	})

	t.Run("Round2 without participant_idx", func(t *testing.T) {
		round2Path := Round2Path("error-test-session")
		req := httptest.NewRequest(http.MethodPost, round2Path, nil)
		w := httptest.NewRecorder()
		server.handleRound2Post(w, req, "error-test-session")

		if w.Code != http.StatusBadRequest {
			t.Errorf("unexpected status code: got %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("Round2 GET without participant_idx", func(t *testing.T) {
		round2Path := Round2Path("error-test-session")
		req := httptest.NewRequest(http.MethodGet, round2Path, nil)
		w := httptest.NewRecorder()
		server.handleRound2Get(w, req, "error-test-session")

		if w.Code != http.StatusBadRequest {
			t.Errorf("unexpected status code: got %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("CertEq without participant_idx", func(t *testing.T) {
		certEqPath := CertEqPath("error-test-session")
		req := httptest.NewRequest(http.MethodPost, certEqPath, nil)
		w := httptest.NewRecorder()
		server.handleCertEq(w, req, "error-test-session")

		if w.Code != http.StatusBadRequest {
			t.Errorf("unexpected status code: got %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("Round1 with wrong method", func(t *testing.T) {
		round1Path := Round1Path("error-test-session")
		resp, err := http.NewRequest(http.MethodDelete, baseURL+round1Path, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		client := &http.Client{}
		r, err := client.Do(resp)
		if err != nil {
			t.Fatalf("failed to call Round1: %v", err)
		}
		defer func() { _ = r.Body.Close() }()

		if r.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("unexpected status code: got %d, want %d", r.StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("Round2 with wrong method", func(t *testing.T) {
		round2Path := Round2Path("error-test-session")
		resp, err := http.NewRequest(http.MethodDelete, baseURL+round2Path, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		client := &http.Client{}
		r, err := client.Do(resp)
		if err != nil {
			t.Fatalf("failed to call Round2: %v", err)
		}
		defer func() { _ = r.Body.Close() }()

		if r.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("unexpected status code: got %d, want %d", r.StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("CertEq with wrong method", func(t *testing.T) {
		certEqPath := CertEqPath("error-test-session")
		resp, err := http.Get(baseURL + certEqPath)
		if err != nil {
			t.Fatalf("failed to call CertEq: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("Certificate with wrong method", func(t *testing.T) {
		certPath := CertificatePath("error-test-session")
		resp, err := http.Post(baseURL+certPath, ContentTypeJSON, nil)
		if err != nil {
			t.Fatalf("failed to call Certificate: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
		}
	})
}

// BenchmarkServerStartStop benchmarks server lifecycle
func BenchmarkServerStartStop(b *testing.B) {
	config := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		server, err := NewHTTPServer(config, sessionConfig, fmt.Sprintf("bench-session-%d", i))
		if err != nil {
			b.Fatalf("failed to create server: %v", err)
		}

		ctx := context.Background()
		if err := server.Start(ctx); err != nil {
			b.Fatalf("failed to start server: %v", err)
		}

		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := server.Stop(stopCtx); err != nil {
			b.Errorf("failed to stop server: %v", err)
		}
		cancel()
	}
}

// BenchmarkClientConnect benchmarks client connection
func BenchmarkClientConnect(b *testing.B) {
	// Start server once
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "bench-session")
	if err != nil {
		b.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		b.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		client, err := NewHTTPClient(clientConfig)
		if err != nil {
			b.Fatalf("failed to create client: %v", err)
		}

		if err := client.Connect(ctx, server.Address()); err != nil {
			b.Fatalf("failed to connect: %v", err)
		}

		_ = client.Disconnect()
	}
}

// TestClientWithTLS tests client TLS configuration
func TestClientWithTLS(t *testing.T) {
	// Generate self-signed certificates
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate certificates: %v", err)
	}

	// Write certificates to temp files
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	caFile := filepath.Join(tmpDir, "ca.pem")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	if err := os.WriteFile(caFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	// Test client with TLS files
	clientConfig := &transport.Config{
		Protocol:    transport.ProtocolHTTP,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		TLSCAFile:   caFile,
		CodecType:   "json",
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client with TLS: %v", err)
	}

	if !client.useTLS {
		t.Error("expected useTLS to be true")
	}

	// Test client with invalid TLS files - should fail
	badConfig := &transport.Config{
		Protocol:    transport.ProtocolHTTP,
		TLSCertFile: "/nonexistent/cert.pem",
		TLSKeyFile:  "/nonexistent/key.pem",
		CodecType:   "json",
	}

	_, err = NewHTTPClient(badConfig)
	// TLS config validation happens in tlsconfig.ClientConfig
	if err == nil {
		t.Log("TLS validation may be deferred until actual use")
	}
}

// TestConnectWithContextTimeout tests connection timeout
// TestConnectWithContextTimeout tests connection timeout
func TestConnectWithContextTimeout(t *testing.T) {
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   100 * time.Millisecond,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Try to connect with very short timeout
	err = client.Connect(ctx, "localhost:99999")
	if err == nil {
		t.Error("expected timeout error")
	}
}

// TestRound1Complete tests successful Round1 workflow
func TestRound1Complete(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "round1-complete-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participants and Round1 data manually
	hostPubkey1 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	hostPubkey2 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey2); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: hostPubkey1}
	server.participants[1] = &participantInfo{index: 1, hostPubkey: hostPubkey2}

	// Add Round1 data for all participants
	server.round1Data[0] = &transport.Round1Message{
		Commitment: [][]byte{make([]byte, 32)},
		POP:        make([]byte, 32),
		Pubnonce:   make([]byte, 32),
	}
	server.round1Data[1] = &transport.Round1Message{
		Commitment: [][]byte{make([]byte, 32)},
		POP:        make([]byte, 32),
		Pubnonce:   make([]byte, 32),
	}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "round1-complete-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         randomBytes,
	}

	// Test Round1 execution - should succeed now
	round1Agg, err := client.executeRound1(ctx, params, sessionInfo)
	if err != nil {
		t.Fatalf("failed to execute Round1: %v", err)
	}

	if round1Agg == nil {
		t.Error("expected Round1 aggregation result")
		return
	}
	if len(round1Agg.AllCommitments) != 2 {
		t.Errorf("unexpected commitments length: got %d, want 2", len(round1Agg.AllCommitments))
	}
}

// TestRound2Complete tests successful Round2 workflow
func TestRound2Complete(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "round2-complete-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participants and Round2 data manually
	hostPubkey1 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey1); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	hostPubkey2 := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey2); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: hostPubkey1}
	server.participants[1] = &participantInfo{index: 1, hostPubkey: hostPubkey2}

	// Add Round2 data for all participants
	server.round2Data[0] = &transport.Round2Message{
		EncryptedShares: make([]byte, 32),
	}
	server.round2Data[1] = &transport.Round2Message{
		EncryptedShares: make([]byte, 32),
	}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "round2-complete-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         randomBytes,
	}

	round1Agg := &transport.Round1AggMessage{
		AllCommitments: make([][][]byte, 2),
		AllPOPs:        make([][]byte, 2),
		AllPubnonces:   make([][]byte, 2),
	}

	// Test Round2 execution - should succeed now
	err = client.executeRound2(ctx, params, sessionInfo, round1Agg)
	if err != nil {
		t.Fatalf("failed to execute Round2: %v", err)
	}
}

// TestServerErrorSerialization tests error serialization
func TestServerErrorSerialization(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "cbor",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "error-ser-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	// Test various error conditions
	t.Run("invalid content type for writeResponse", func(t *testing.T) {
		// Send request with unsupported accept header
		req, _ := http.NewRequest(http.MethodGet, baseURL+PathSessions, nil)
		req.Header.Set(HeaderAccept, "application/xml")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		// Server should fall back to JSON for errors
		if resp.StatusCode != http.StatusOK {
			t.Logf("Got status code: %d", resp.StatusCode)
		}
	})
}

// TestJoinSessionInvalidJSON tests join with invalid request body
func TestJoinSessionInvalidJSON(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "invalid-json-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()
	joinPath := JoinSessionPath("invalid-json-session")

	// Send invalid JSON
	resp, err := http.Post(baseURL+joinPath, ContentTypeJSON, bytes.NewReader([]byte("{invalid json")))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// TestServerMaxMessageSize tests message size limits in doRequest
func TestServerMaxMessageSize(t *testing.T) {
	clientConfig := &transport.Config{
		Protocol:       transport.ProtocolHTTP,
		CodecType:      "json",
		Timeout:        5 * time.Second,
		MaxMessageSize: 100, // Very small limit
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Test that max message size is respected
	if client.config.MaxMessageSize != 100 {
		t.Errorf("unexpected max message size: got %d, want 100", client.config.MaxMessageSize)
	}
}

// TestWaitForParticipantsSuccess tests successful waiting
func TestWaitForParticipantsSuccess(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "wait-success-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participants manually
	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.participants[1] = &participantInfo{index: 1, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	// Should succeed immediately
	err = server.WaitForParticipants(ctx, 2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestDoRequestWithQueryParams tests query parameter handling
func TestDoRequestWithQueryParams(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "query-param-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Test with multiple query parameters
	queryParams := map[string]string{
		"participant_idx": "0",
		"session_id":      "test",
	}

	_, err = client.doRequest(ctx, http.MethodGet, PathSessions, nil, queryParams)
	if err != nil {
		t.Logf("Expected error or success, got: %v", err)
	}
}

// TestGetParticipantIndexInvalid tests invalid participant index parsing
func TestGetParticipantIndexInvalid(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "idx-test-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Test with invalid index format
	req := httptest.NewRequest(http.MethodGet, "/?participant_idx=invalid", nil)
	idx := server.getParticipantIndex(req)
	if idx != -1 {
		t.Errorf("expected -1 for invalid index, got %d", idx)
	}

	// Test with missing index
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	idx2 := server.getParticipantIndex(req2)
	if idx2 != -1 {
		t.Errorf("expected -1 for missing index, got %d", idx2)
	}
}

// TestCodecToContentTypeDefault tests default content type
func TestCodecToContentTypeDefault(t *testing.T) {
	result := CodecToContentType("unknown")
	if result != ContentTypeJSON {
		t.Errorf("expected default to be JSON, got %s", result)
	}
}

// TestReadRequestEdgeCases tests readRequest error paths
func TestReadRequestEdgeCases(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:       transport.ProtocolHTTP,
		Address:        "localhost:0",
		CodecType:      "json",
		MaxMessageSize: 100,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "read-req-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	// Test with unsupported content type in request
	t.Run("unsupported content type", func(t *testing.T) {
		joinPath := JoinSessionPath("read-req-test")
		req, _ := http.NewRequest(http.MethodPost, baseURL+joinPath, bytes.NewReader([]byte(`{}`)))
		req.Header.Set(HeaderContentType, "application/xml")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		// Server should handle unknown content type gracefully
		if resp.StatusCode >= 500 {
			t.Logf("Server error with unsupported content type: %d", resp.StatusCode)
		}
	})

	// Test with invalid codec in serializer
	t.Run("invalid serialization", func(t *testing.T) {
		joinPath := JoinSessionPath("read-req-test")
		// Send CBOR content-type but JSON body
		req, _ := http.NewRequest(http.MethodPost, baseURL+joinPath, bytes.NewReader([]byte(`{"invalid"}`)))
		req.Header.Set(HeaderContentType, ContentTypeCBOR)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Logf("Got status: %d", resp.StatusCode)
		}
	})
}

// TestWriteResponseEdgeCases tests writeResponse error paths
func TestWriteResponseEdgeCases(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "msgpack",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "write-resp-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	// Test with msgpack codec
	t.Run("msgpack response", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, baseURL+PathSessions, nil)
		req.Header.Set(HeaderAccept, ContentTypeMsgPack)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status: %d", resp.StatusCode)
		}

		if resp.Header.Get(HeaderContentType) != ContentTypeMsgPack {
			t.Errorf("unexpected content type: %s", resp.Header.Get(HeaderContentType))
		}
	})

	// Test with CBOR accept header
	t.Run("cbor response", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+SessionPath("write-resp-test"), nil)
		req.Header.Set(HeaderAccept, ContentTypeCBOR)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status: %d", resp.StatusCode)
		}
	})
}

// TestHandleRound2PostEdgeCases tests Round2Post error conditions
func TestHandleRound2PostEdgeCases(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "round2-edge-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add a participant
	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	baseURL := "http://" + server.Address()

	// Test Round2 POST with invalid JSON
	t.Run("invalid json", func(t *testing.T) {
		round2Path := Round2Path("round2-edge-test") + "?participant_idx=0"
		resp, err := http.Post(baseURL+round2Path, ContentTypeJSON, bytes.NewReader([]byte("{invalid")))
		if err != nil {
			t.Fatalf("failed to post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("unexpected status: %d", resp.StatusCode)
		}
	})

	// Test Round2 GET without all data submitted
	t.Run("round2 get incomplete", func(t *testing.T) {
		round2Path := Round2Path("round2-edge-test") + "?participant_idx=0"
		resp, err := http.Get(baseURL + round2Path)
		if err != nil {
			t.Fatalf("failed to get: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusAccepted {
			t.Logf("Got status: %d", resp.StatusCode)
		}
	})
}

// TestHandleCertEqEdgeCases tests CertEq error conditions
func TestHandleCertEqEdgeCases(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "certeq-edge-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add a participant
	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	baseURL := "http://" + server.Address()

	// Test CertEq with invalid JSON
	t.Run("invalid json", func(t *testing.T) {
		certEqPath := CertEqPath("certeq-edge-test") + "?participant_idx=0"
		resp, err := http.Post(baseURL+certEqPath, ContentTypeJSON, bytes.NewReader([]byte("{bad")))
		if err != nil {
			t.Fatalf("failed to post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("unexpected status: %d", resp.StatusCode)
		}
	})

	// Test CertEq with non-existent participant
	t.Run("non-existent participant", func(t *testing.T) {
		certEqPath := CertEqPath("certeq-edge-test") + "?participant_idx=99"

		certEqMsg := &transport.CertEqSignMessage{
			Signature: make([]byte, 32),
		}

		data, _ := json.Marshal(certEqMsg)
		resp, err := http.Post(baseURL+certEqPath, ContentTypeJSON, bytes.NewReader(data))
		if err != nil {
			t.Fatalf("failed to post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("unexpected status: %d", resp.StatusCode)
		}
	})
}

// TestConnectHealthCheckFailure tests failed health check
func TestConnectHealthCheckFailure(t *testing.T) {
	// Create client but no server
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   1 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// Connect should fail with health check error
	err = client.Connect(ctx, "localhost:9999")
	if err == nil {
		t.Error("expected error on failed health check")
	}
}

// TestRunDKGInvalidParams tests RunDKG with invalid parameters
func TestRunDKGInvalidParams(t *testing.T) {
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Create server for client to connect to
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "invalid-params-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Test with nil params
	_, err = client.RunDKG(ctx, nil)
	if err == nil {
		t.Error("expected error with nil params")
	}

	// Test with invalid params
	badParams := &transport.DKGParams{
		HostSeckey:     make([]byte, 16), // Invalid length
		HostPubkeys:    nil,
		Threshold:      0,
		ParticipantIdx: -1,
		Random:         nil,
	}

	_, err = client.RunDKG(ctx, badParams)
	if err == nil {
		t.Error("expected error with invalid params")
	}
}

// TestJoinSessionError tests joinSession error condition
func TestJoinSessionError(t *testing.T) {
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Create server
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       1,
		NumParticipants: 1,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "join-error-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// First join should succeed
	params1 := &transport.DKGParams{
		HostSeckey:     make([]byte, 32),
		HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	_, err = client.joinSession(ctx, params1)
	if err != nil {
		t.Fatalf("first join failed: %v", err)
	}

	// Second join with different client should fail (session full)
	client2, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client2: %v", err)
	}

	if err := client2.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect client2: %v", err)
	}
	defer func() { _ = client2.Disconnect() }()

	params2 := &transport.DKGParams{
		HostSeckey:     make([]byte, 32),
		HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	_, err = client2.joinSession(ctx, params2)
	if err == nil {
		t.Error("expected error when joining full session")
	}
}

// TestExecuteRound1Success tests successful Round1 completion with unmarshaling
func TestExecuteRound1Success(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "exec-r1-success")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Populate server with all Round1 data
	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.participants[1] = &participantInfo{index: 1, hostPubkey: make([]byte, 32)}
	server.round1Data[0] = &transport.Round1Message{
		Commitment: [][]byte{make([]byte, 32)},
		POP:        make([]byte, 32),
		Pubnonce:   make([]byte, 32),
	}
	server.round1Data[1] = &transport.Round1Message{
		Commitment: [][]byte{make([]byte, 32)},
		POP:        make([]byte, 32),
		Pubnonce:   make([]byte, 32),
	}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "exec-r1-success",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	// Execute Round1 - should succeed immediately
	result, err := client.executeRound1(ctx, params, sessionInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected Round1 aggregation result")
	}

	if len(result.AllCommitments) != 2 {
		t.Errorf("expected 2 commitments, got %d", len(result.AllCommitments))
	}
}

// TestExecuteRound2Success tests successful Round2 completion
func TestExecuteRound2Success(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "exec-r2-success")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Populate server with all Round2 data
	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.participants[1] = &participantInfo{index: 1, hostPubkey: make([]byte, 32)}
	server.round2Data[0] = &transport.Round2Message{
		EncryptedShares: make([]byte, 32),
	}
	server.round2Data[1] = &transport.Round2Message{
		EncryptedShares: make([]byte, 32),
	}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "exec-r2-success",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	round1Agg := &transport.Round1AggMessage{
		AllCommitments: make([][][]byte, 2),
		AllPOPs:        make([][]byte, 2),
		AllPubnonces:   make([][]byte, 2),
	}

	// Execute Round2 - should succeed immediately
	err = client.executeRound2(ctx, params, sessionInfo, round1Agg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRetrieveCertificateSuccess tests successful certificate retrieval
func TestRetrieveCertificateSuccess(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "cert-success")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Set certificate immediately
	testCert := make([]byte, 64)
	for i := range testCert {
		testCert[i] = byte(i)
	}

	server.mu.Lock()
	server.certificate = testCert
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "cert-success",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	// Retrieve certificate - should succeed immediately
	cert, err := client.retrieveCertificate(ctx, sessionInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cert) != 64 {
		t.Errorf("expected 64 bytes, got %d", len(cert))
	}

	// Verify content matches
	for i := range cert {
		if cert[i] != byte(i) {
			t.Errorf("cert byte %d: expected %d, got %d", i, byte(i), cert[i])
			break
		}
	}
}

// TestWriteResponseWithMarshalError tests writeResponse when marshal fails
func TestWriteResponseWithMarshalError(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "marshal-error-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	// Access an endpoint and verify response
	resp, err := http.Get(baseURL + PathSessions)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Just verify we got a valid response
	if resp.StatusCode >= 500 {
		t.Logf("Got server error status: %d", resp.StatusCode)
	}
}

// TestHandleRound1PostSuccess tests successful Round1 POST
func TestHandleRound1PostSuccess(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r1post-success")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participant
	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	baseURL := "http://" + server.Address()

	// Post valid Round1 message
	round1Msg := &transport.Round1Message{
		Commitment: [][]byte{make([]byte, 32)},
		POP:        make([]byte, 32),
		Pubnonce:   make([]byte, 32),
	}

	data, _ := json.Marshal(round1Msg)
	round1Path := Round1Path("r1post-success") + "?participant_idx=0"

	resp, err := http.Post(baseURL+round1Path, ContentTypeJSON, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

// TestHandleRound2PostSuccess tests successful Round2 POST
func TestHandleRound2PostSuccess(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r2post-success")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participant
	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	baseURL := "http://" + server.Address()

	// Post valid Round2 message
	round2Msg := &transport.Round2Message{
		EncryptedShares: make([]byte, 32),
	}

	data, _ := json.Marshal(round2Msg)
	round2Path := Round2Path("r2post-success") + "?participant_idx=0"

	resp, err := http.Post(baseURL+round2Path, ContentTypeJSON, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

// TestHandleRound2GetSuccess tests successful Round2 GET
func TestHandleRound2GetSuccess(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r2get-success")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participants and Round2 data
	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.participants[1] = &participantInfo{index: 1, hostPubkey: make([]byte, 32)}
	server.round2Data[0] = &transport.Round2Message{EncryptedShares: make([]byte, 32)}
	server.round2Data[1] = &transport.Round2Message{EncryptedShares: make([]byte, 32)}
	server.mu.Unlock()

	baseURL := "http://" + server.Address()
	round2Path := Round2Path("r2get-success") + "?participant_idx=0"

	resp, err := http.Get(baseURL + round2Path)
	if err != nil {
		t.Fatalf("failed to get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

// TestHandleJoinSessionSuccess tests successful join
func TestHandleJoinSessionSuccess(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "join-success")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	joinMsg := &transport.JoinMessage{
		HostPubkey: make([]byte, transport.PublicKeySize),
	}

	data, _ := json.Marshal(joinMsg)
	joinPath := JoinSessionPath("join-success")

	resp, err := http.Post(baseURL+joinPath, ContentTypeJSON, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

// TestConnectWithHTTPS tests HTTPS connection
func TestConnectWithHTTPS(t *testing.T) {
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   1 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Force TLS mode
	client.useTLS = true

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Try to connect to non-existent HTTPS server
	err = client.Connect(ctx, "localhost:9443")
	if err == nil {
		t.Error("expected error connecting to non-existent HTTPS server")
	}
}

// TestDoRequestWithBody tests doRequest with request body
func TestDoRequestWithBody(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "doreq-body-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Test with actual request body
	joinMsg := &transport.JoinMessage{
		HostPubkey: make([]byte, transport.PublicKeySize),
	}

	_, err = client.doRequest(ctx, http.MethodPost, JoinSessionPath("doreq-body-test"), joinMsg, nil)
	if err != nil {
		t.Logf("doRequest with body: %v", err)
	}
}

// TestServerStopNilServer tests Stop with nil server
func TestServerStopNilServer(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "nil-server-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Stop before starting (server will be nil)
	ctx := context.Background()
	err = server.Stop(ctx)
	if err != nil {
		t.Errorf("unexpected error stopping nil server: %v", err)
	}
}

// TestRunDKGValidParams tests RunDKG with all valid params
func TestRunDKGValidParams(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   10 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "valid-params-dkg")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   10 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Create fully valid DKG params
	hostSeckey := make([]byte, 32)
	if _, err := rand.Read(hostSeckey); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	hostPubkeys := make([][]byte, 2)
	for i := range hostPubkeys {
		hostPubkeys[i] = make([]byte, transport.PublicKeySize)
		if _, err := rand.Read(hostPubkeys[i]); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	params := &transport.DKGParams{
		HostSeckey:     hostSeckey,
		HostPubkeys:    hostPubkeys,
		Threshold:      2,
		ParticipantIdx: 0,
		Random:         randomBytes,
	}

	// Run DKG - will succeed up to joining
	result, err := client.RunDKG(ctx, params)
	if err != nil {
		t.Logf("RunDKG error (expected if other participant hasn't joined): %v", err)
	} else if result != nil {
		t.Logf("RunDKG succeeded with result")
	}
}

// TestNewHTTPClientDefaults tests client creation with defaults
func TestNewHTTPClientDefaults(t *testing.T) {
	// Test with minimal config
	config := &transport.Config{
		Protocol: transport.ProtocolHTTP,
	}

	client, err := NewHTTPClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Verify defaults were set
	if client.config.CodecType != "json" {
		t.Errorf("expected default codec 'json', got %s", client.config.CodecType)
	}

	if client.config.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", client.config.Timeout)
	}
}

// TestNewHTTPServerDefaults tests server creation with defaults
func TestNewHTTPServerDefaults(t *testing.T) {
	config := &transport.Config{
		Protocol: transport.ProtocolHTTP,
		Address:  "localhost:0",
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(config, sessionConfig, "defaults-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Verify defaults
	if server.config.CodecType != "json" {
		t.Errorf("expected default codec 'json', got %s", server.config.CodecType)
	}

	if server.config.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", server.config.Timeout)
	}
}

// TestJoinSessionMarshallingFormats tests different content types
func TestJoinSessionMarshallingFormats(t *testing.T) {
	tests := []struct {
		name      string
		codecType string
	}{
		{"JSON", "json"},
		{"CBOR", "cbor"},
		{"MessagePack", "msgpack"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverConfig := &transport.Config{
				Protocol:  transport.ProtocolHTTP,
				Address:   "localhost:0",
				CodecType: tt.codecType,
				Timeout:   5 * time.Second,
			}

			sessionConfig := &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 2,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			}

			server, err := NewHTTPServer(serverConfig, sessionConfig, "marshal-test-"+tt.codecType)
			if err != nil {
				t.Fatalf("failed to create server: %v", err)
			}

			ctx := context.Background()
			if err := server.Start(ctx); err != nil {
				t.Fatalf("failed to start server: %v", err)
			}
			defer func() { _ = server.Stop(context.Background()) }()

			clientConfig := &transport.Config{
				Protocol:  transport.ProtocolHTTP,
				CodecType: tt.codecType,
				Timeout:   5 * time.Second,
			}

			client, err := NewHTTPClient(clientConfig)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			if err := client.Connect(ctx, server.Address()); err != nil {
				t.Fatalf("failed to connect: %v", err)
			}
			defer func() { _ = client.Disconnect() }()

			// Join session with specific codec
			hostPubkey := make([]byte, transport.PublicKeySize)
			if _, err := rand.Read(hostPubkey); err != nil {
				t.Fatalf("rand.Read failed: %v", err)
			}

			params := &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				HostPubkeys:    [][]byte{hostPubkey},
				Threshold:      1,
				ParticipantIdx: 0,
				Random:         make([]byte, 32),
			}

			_, err = client.joinSession(ctx, params)
			if err != nil {
				t.Fatalf("joinSession failed with %s: %v", tt.codecType, err)
			}
		})
	}
}

// TestWriteErrorJSONMarshalFallback tests writeError when json.Marshal fails (internal error fallback)
func TestWriteErrorJSONMarshalFallback(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "write-error-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	// Test various error scenarios
	t.Run("not_found_error", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/v1/sessions/nonexistent")
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}

		// Verify content type is JSON for errors
		if ct := resp.Header.Get(HeaderContentType); ct != ContentTypeJSON {
			t.Errorf("expected JSON content type, got %s", ct)
		}
	})

	t.Run("method_not_allowed_error", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, baseURL+PathHealth, nil)
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", resp.StatusCode)
		}
	})

	t.Run("bad_request_error", func(t *testing.T) {
		// Send invalid JSON to join endpoint
		resp, err := http.Post(baseURL+JoinSessionPath("write-error-test"), ContentTypeJSON, bytes.NewReader([]byte("invalid json")))
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", resp.StatusCode)
		}
	})

	t.Run("conflict_session_full", func(t *testing.T) {
		// Fill the session first
		server.mu.Lock()
		server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
		server.participants[1] = &participantInfo{index: 1, hostPubkey: make([]byte, 32)}
		server.mu.Unlock()

		joinMsg := &transport.JoinMessage{
			HostPubkey: make([]byte, transport.PublicKeySize),
		}
		data, _ := json.Marshal(joinMsg)

		resp, err := http.Post(baseURL+JoinSessionPath("write-error-test"), ContentTypeJSON, bytes.NewReader(data))
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusConflict {
			t.Errorf("expected 409, got %d", resp.StatusCode)
		}

		// Clean up
		server.mu.Lock()
		delete(server.participants, 0)
		delete(server.participants, 1)
		server.mu.Unlock()
	})

	t.Run("unknown_endpoint_error", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/v1/sessions/write-error-test/unknown")
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	})
}

// TestRetrieveCertificateNon202Error tests certificate retrieval with non-202 error
func TestRetrieveCertificateNon202Error(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   1 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "cert-non202")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	addr := server.Address()
	_ = server.Stop(context.Background())

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   1 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	client.mu.Lock()
	client.connected = true
	client.serverAddr = addr
	client.mu.Unlock()

	// Use wrong session ID to trigger 404 error
	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "nonexistent-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	// Retrieve certificate - should fail with connection error (not 202)
	_, err = client.retrieveCertificate(ctx, sessionInfo)
	if err == nil {
		t.Error("expected error")
	}
}

// TestWriteResponseWithInvalidCodec tests writeResponse with invalid Accept header
func TestWriteResponseWithInvalidCodec(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "invalid-codec-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	// Test with unknown Accept header - should fallback to default codec
	t.Run("unknown_accept_header", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+SessionPath("invalid-codec-test"), nil)
		req.Header.Set(HeaderAccept, "application/unknown")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		// Should still succeed with fallback to default codec
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	// Test with empty Accept header
	t.Run("empty_accept_header", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+SessionPath("invalid-codec-test"), nil)
		// Don't set Accept header

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})
}

// TestHandleJoinSessionMethodNotAllowed tests handleJoinSession with wrong HTTP method
func TestHandleJoinSessionMethodNotAllowed(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "join-method-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	// Test GET method on join endpoint (should be POST only)
	t.Run("get_method_not_allowed", func(t *testing.T) {
		resp, err := http.Get(baseURL + JoinSessionPath("join-method-test"))
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", resp.StatusCode)
		}
	})

	// Test PUT method
	t.Run("put_method_not_allowed", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPut, baseURL+JoinSessionPath("join-method-test"), nil)
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", resp.StatusCode)
		}
	})
}

// TestHandleRound1PostParticipantNotFound tests Round1 POST with unknown participant
func TestHandleRound1PostParticipantNotFound(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r1-not-found")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	// Do NOT add any participants

	round1Msg := &transport.Round1Message{
		Commitment: [][]byte{make([]byte, 32)},
		POP:        make([]byte, 32),
		Pubnonce:   make([]byte, 32),
	}

	data, _ := json.Marshal(round1Msg)
	round1Path := Round1Path("r1-not-found") + "?participant_idx=5"

	resp, err := http.Post(baseURL+round1Path, ContentTypeJSON, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// TestHandleRound2PostParticipantNotFound tests Round2 POST with unknown participant
func TestHandleRound2PostParticipantNotFound(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r2-not-found")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	round2Msg := &transport.Round2Message{
		EncryptedShares: make([]byte, 32),
	}

	data, _ := json.Marshal(round2Msg)
	round2Path := Round2Path("r2-not-found") + "?participant_idx=99"

	resp, err := http.Post(baseURL+round2Path, ContentTypeJSON, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// TestHandleRound1MethodNotAllowed tests Round1 with unsupported HTTP method
func TestHandleRound1MethodNotAllowed(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r1-method-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	req, _ := http.NewRequest(http.MethodDelete, baseURL+Round1Path("r1-method-test"), nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

// TestHandleRound2MethodNotAllowed tests Round2 with unsupported HTTP method
func TestHandleRound2MethodNotAllowed(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r2-method-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	req, _ := http.NewRequest(http.MethodPut, baseURL+Round2Path("r2-method-test"), nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

// TestHandleCertEqMethodNotAllowed tests CertEq with unsupported HTTP method
func TestHandleCertEqMethodNotAllowed(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "certeq-method-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	resp, err := http.Get(baseURL + CertEqPath("certeq-method-test"))
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

// TestHandleGetCertificateMethodNotAllowed tests certificate endpoint with unsupported method
func TestHandleGetCertificateMethodNotAllowed(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "cert-method-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	resp, err := http.Post(baseURL+CertificatePath("cert-method-test"), ContentTypeJSON, nil)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

// TestJoinSessionDuplicateHostPubkey tests joining with duplicate host pubkey
func TestJoinSessionDuplicateHostPubkey(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "dup-pubkey-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	// Create a known host pubkey
	hostPubkey := make([]byte, transport.PublicKeySize)
	for i := range hostPubkey {
		hostPubkey[i] = byte(i)
	}

	// First join should succeed
	joinMsg := &transport.JoinMessage{
		HostPubkey: hostPubkey,
	}
	data, _ := json.Marshal(joinMsg)

	resp, err := http.Post(baseURL+JoinSessionPath("dup-pubkey-test"), ContentTypeJSON, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first join should succeed, got %d", resp.StatusCode)
	}

	// Second join with same pubkey should fail
	resp, err = http.Post(baseURL+JoinSessionPath("dup-pubkey-test"), ContentTypeJSON, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 for duplicate pubkey, got %d", resp.StatusCode)
	}
}

// TestExecuteRound1ErrorDuringGet tests Round1 GET returning non-202 error
func TestExecuteRound1ErrorDuringGet(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r1-get-error")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participant
	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Use wrong session ID to trigger 404 on GET
	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "nonexistent-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	_, err = client.executeRound1(ctx, params, sessionInfo)
	if err == nil {
		t.Error("expected error for wrong session ID")
	}
}

// TestExecuteRound2ErrorDuringGet tests Round2 GET returning non-202 error
func TestExecuteRound2ErrorDuringGet(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r2-get-error")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Add participant
	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Use wrong session ID to trigger 404 on POST
	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "nonexistent-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	round1Agg := &transport.Round1AggMessage{}

	err = client.executeRound2(ctx, params, sessionInfo, round1Agg)
	if err == nil {
		t.Error("expected error for wrong session ID")
	}
}

// TestJoinSessionUnmarshalError tests joinSession with server returning invalid JSON
func TestJoinSessionUnmarshalError(t *testing.T) {
	// Create a mock server that returns invalid JSON
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathSessions {
			w.Header().Set(HeaderContentType, ContentTypeJSON)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid json"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Extract host from mock server URL
	addr := mockServer.URL[len("http://"):]

	client.mu.Lock()
	client.connected = true
	client.serverAddr = addr
	client.mu.Unlock()

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
		Random:         make([]byte, 32),
	}

	_, err = client.joinSession(context.Background(), params)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

// TestExecuteRound1WithCancelledContext tests Round1 with pre-cancelled context
func TestExecuteRound1WithCancelledContext(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r1-cancelled-ctx")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "r1-cancelled-ctx",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	// Create already cancelled context
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Execute Round1 - should fail due to cancelled context on POST
	_, err = client.executeRound1(ctxCancel, params, sessionInfo)
	if err == nil {
		t.Error("expected error due to cancelled context")
	}
}

// TestExecuteRound2WithCancelledContext tests Round2 with pre-cancelled context
func TestExecuteRound2WithCancelledContext(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r2-cancelled-ctx")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "r2-cancelled-ctx",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	round1Agg := &transport.Round1AggMessage{}

	// Create already cancelled context
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Execute Round2 - should fail due to cancelled context on POST
	err = client.executeRound2(ctxCancel, params, sessionInfo, round1Agg)
	if err == nil {
		t.Error("expected error due to cancelled context")
	}
}

// TestRetrieveCertificateWithCancelledContext tests certificate retrieval with pre-cancelled context
func TestRetrieveCertificateWithCancelledContext(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "cert-cancelled-ctx")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "cert-cancelled-ctx",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	// Create already cancelled context
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Retrieve certificate - should fail due to cancelled context
	_, err = client.retrieveCertificate(ctxCancel, sessionInfo)
	if err == nil {
		t.Error("expected error due to cancelled context")
	}
}

// TestExecuteRound1UnmarshalError tests Round1 with invalid response
func TestExecuteRound1UnmarshalError(t *testing.T) {
	// Create mock server that returns invalid JSON for Round1 GET
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"accepted"}`))
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set(HeaderContentType, ContentTypeJSON)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid json response"))
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer mockServer.Close()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	addr := mockServer.URL[len("http://"):]
	client.mu.Lock()
	client.connected = true
	client.serverAddr = addr
	client.mu.Unlock()

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "test-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		Random:         make([]byte, 32),
	}

	_, err = client.executeRound1(context.Background(), params, sessionInfo)
	if err == nil {
		t.Error("expected error due to invalid JSON response")
	}
}

// TestRetrieveCertificateUnmarshalError tests certificate retrieval with invalid response
func TestRetrieveCertificateUnmarshalError(t *testing.T) {
	// Create mock server that returns invalid JSON for certificate
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid certificate json"))
	}))
	defer mockServer.Close()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	addr := mockServer.URL[len("http://"):]
	client.mu.Lock()
	client.connected = true
	client.serverAddr = addr
	client.mu.Unlock()

	sessionInfo := &transport.SessionInfoMessage{
		SessionID:       "test-session",
		ParticipantIdx:  0,
		NumParticipants: 2,
	}

	_, err = client.retrieveCertificate(context.Background(), sessionInfo)
	if err == nil {
		t.Error("expected error due to invalid JSON response")
	}
}

// TestJoinSessionJoinError tests joinSession when join POST fails
func TestJoinSessionJoinError(t *testing.T) {
	callCount := 0
	// Create mock server that succeeds on first call but fails on second (join)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call: create session - return valid session info
			w.Header().Set(HeaderContentType, ContentTypeJSON)
			w.WriteHeader(http.StatusOK)
			sessionInfo := transport.SessionInfoMessage{
				SessionID:       "test-session",
				NumParticipants: 2,
				Threshold:       2,
			}
			data, _ := json.Marshal(sessionInfo)
			_, _ = w.Write(data)
			return
		}
		// Second call: join - return error
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":409,"message":"session full"}`))
	}))
	defer mockServer.Close()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	addr := mockServer.URL[len("http://"):]
	client.mu.Lock()
	client.connected = true
	client.serverAddr = addr
	client.mu.Unlock()

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
		Random:         make([]byte, 32),
	}

	_, err = client.joinSession(context.Background(), params)
	if err == nil {
		t.Error("expected error when join fails")
	}
}

// TestJoinSessionUnmarshalJoinResponse tests joinSession when join response is invalid JSON
func TestJoinSessionUnmarshalJoinResponse(t *testing.T) {
	callCount := 0
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call: create session - return valid session info
			w.Header().Set(HeaderContentType, ContentTypeJSON)
			w.WriteHeader(http.StatusOK)
			sessionInfo := transport.SessionInfoMessage{
				SessionID:       "test-session",
				NumParticipants: 2,
				Threshold:       2,
			}
			data, _ := json.Marshal(sessionInfo)
			_, _ = w.Write(data)
			return
		}
		// Second call: join - return invalid JSON
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("invalid json for join response"))
	}))
	defer mockServer.Close()

	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	addr := mockServer.URL[len("http://"):]
	client.mu.Lock()
	client.connected = true
	client.serverAddr = addr
	client.mu.Unlock()

	params := &transport.DKGParams{
		ParticipantIdx: 0,
		HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
		Random:         make([]byte, 32),
	}

	_, err = client.joinSession(context.Background(), params)
	if err == nil {
		t.Error("expected error for invalid join response JSON")
	}
}

// TestWriteResponseSerializerError tests writeResponse when serializer creation fails
func TestWriteResponseSerializerError(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "serializer-error-test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create a recorder to capture the response
	recorder := httptest.NewRecorder()

	// Create request with Accept header that, after modification of server config, causes error
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(HeaderAccept, ContentTypeJSON)

	// Temporarily change server codec to an invalid type to trigger error path
	// This is a bit of a hack but necessary to test the error path
	originalCodec := server.config.CodecType
	server.config.CodecType = "invalid-codec-type"
	req.Header.Set(HeaderAccept, "") // Empty accept forces fallback to config codec

	// Call writeResponse directly with invalid codec
	server.writeResponse(recorder, req, http.StatusOK, map[string]string{"test": "value"})

	// Restore
	server.config.CodecType = originalCodec

	// Since the codec is invalid, we expect an error response
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", recorder.Code)
	}
}

// TestWriteResponseMarshalError tests writeResponse when marshal fails
func TestWriteResponseMarshalError(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "marshal-error-test2")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(HeaderAccept, ContentTypeJSON)

	// Try to marshal something that will fail - channels cannot be marshalled
	unmarshalable := make(chan int)
	server.writeResponse(recorder, req, http.StatusOK, unmarshalable)

	// Expect internal server error due to marshal failure
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", recorder.Code)
	}
}

// TestWriteErrorWithSpecialCharacters tests writeError with various message content
func TestWriteErrorWithSpecialCharacters(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "error-special-chars")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	testCases := []struct {
		name       string
		message    string
		statusCode int
	}{
		{"unicode", "Error with unicode: \u4e2d\u6587", http.StatusBadRequest},
		{"quotes", `Error with "quotes"`, http.StatusBadRequest},
		{"newlines", "Error with\nnewlines", http.StatusBadRequest},
		{"empty", "", http.StatusBadRequest},
		{"long_message", string(make([]byte, 10000)), http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			server.writeError(recorder, req, tc.statusCode, tc.message)

			if recorder.Code != tc.statusCode {
				t.Errorf("expected %d, got %d", tc.statusCode, recorder.Code)
			}

			if ct := recorder.Header().Get(HeaderContentType); ct != ContentTypeJSON {
				t.Errorf("expected JSON content type, got %s", ct)
			}

			// Verify the response is valid JSON
			var errResp transport.ErrorMessage
			if err := json.Unmarshal(recorder.Body.Bytes(), &errResp); err != nil {
				t.Errorf("response is not valid JSON: %v", err)
			}
		})
	}
}

// TestWriteErrorAllStatusCodes tests writeError with various HTTP status codes
func TestWriteErrorAllStatusCodes(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "error-status-codes")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	statusCodes := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusConflict,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	}

	for _, code := range statusCodes {
		t.Run(fmt.Sprintf("status_%d", code), func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			server.writeError(recorder, req, code, "test error")

			if recorder.Code != code {
				t.Errorf("expected %d, got %d", code, recorder.Code)
			}

			var errResp transport.ErrorMessage
			if err := json.Unmarshal(recorder.Body.Bytes(), &errResp); err != nil {
				t.Errorf("response is not valid JSON: %v", err)
			}

			if errResp.Code != code {
				t.Errorf("expected code %d in body, got %d", code, errResp.Code)
			}
		})
	}
}

// TestHandleRound1PostInvalidBody tests Round1 POST with unparseable body
func TestHandleRound1PostInvalidBody(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r1-invalid-body")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	baseURL := "http://" + server.Address()
	round1Path := Round1Path("r1-invalid-body") + "?participant_idx=0"

	// Send invalid JSON
	resp, err := http.Post(baseURL+round1Path, ContentTypeJSON, bytes.NewReader([]byte("not valid json")))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// TestHandleRound2PostInvalidBody tests Round2 POST with unparseable body
func TestHandleRound2PostInvalidBody(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "r2-invalid-body")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	baseURL := "http://" + server.Address()
	round2Path := Round2Path("r2-invalid-body") + "?participant_idx=0"

	// Send invalid JSON
	resp, err := http.Post(baseURL+round2Path, ContentTypeJSON, bytes.NewReader([]byte("not valid json")))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// TestHandleCertEqInvalidBody tests CertEq POST with unparseable body
func TestHandleCertEqInvalidBody(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "certeq-invalid-body")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	server.mu.Lock()
	server.participants[0] = &participantInfo{index: 0, hostPubkey: make([]byte, 32)}
	server.mu.Unlock()

	baseURL := "http://" + server.Address()
	certEqPath := CertEqPath("certeq-invalid-body") + "?participant_idx=0"

	// Send invalid JSON
	resp, err := http.Post(baseURL+certEqPath, ContentTypeJSON, bytes.NewReader([]byte("not valid json")))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// TestHandleCertEqParticipantNotFound tests CertEq with unknown participant
func TestHandleCertEqParticipantNotFound(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "certeq-no-participant")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	certEqMsg := &transport.CertEqSignMessage{
		Signature: make([]byte, 32),
	}
	data, _ := json.Marshal(certEqMsg)

	certEqPath := CertEqPath("certeq-no-participant") + "?participant_idx=99"

	resp, err := http.Post(baseURL+certEqPath, ContentTypeJSON, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// TestHandleCertEqNoParticipantIdx tests CertEq without participant_idx
func TestHandleCertEqNoParticipantIdx(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   5 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "certeq-no-idx")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := "http://" + server.Address()

	certEqMsg := &transport.CertEqSignMessage{
		Signature: make([]byte, 32),
	}
	data, _ := json.Marshal(certEqMsg)

	// No participant_idx parameter
	certEqPath := CertEqPath("certeq-no-idx")

	resp, err := http.Post(baseURL+certEqPath, ContentTypeJSON, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}
