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

package quic

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

const (
	testServerAddr = "127.0.0.1:0"
	testTimeout    = 10 * time.Second
)

// TestQUICServerCreation tests creating a QUIC server with various configurations.
func TestQUICServerCreation(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	tests := []struct {
		name        string
		config      *transport.Config
		sessionCfg  *transport.SessionConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid configuration",
			config: &transport.Config{
				Protocol:    transport.ProtocolQUIC,
				Address:     testServerAddr,
				TLSCertFile: certFile,
				TLSKeyFile:  keyFile,
				CodecType:   "json",
			},
			sessionCfg: &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			},
			wantErr: false,
		},
		{
			name:       "nil config",
			config:     nil,
			sessionCfg: &transport.SessionConfig{Threshold: 2, NumParticipants: 3},
			wantErr:    true,
		},
		{
			name: "nil session config",
			config: &transport.Config{
				Protocol:    transport.ProtocolQUIC,
				Address:     testServerAddr,
				TLSCertFile: certFile,
				TLSKeyFile:  keyFile,
			},
			sessionCfg: nil,
			wantErr:    true,
		},
		{
			name: "wrong protocol",
			config: &transport.Config{
				Protocol:    transport.ProtocolGRPC,
				Address:     testServerAddr,
				TLSCertFile: certFile,
				TLSKeyFile:  keyFile,
			},
			sessionCfg: &transport.SessionConfig{Threshold: 2, NumParticipants: 3},
			wantErr:    true,
		},
		{
			name: "invalid threshold",
			config: &transport.Config{
				Protocol:    transport.ProtocolQUIC,
				Address:     testServerAddr,
				TLSCertFile: certFile,
				TLSKeyFile:  keyFile,
			},
			sessionCfg: &transport.SessionConfig{
				Threshold:       5,
				NumParticipants: 3,
			},
			wantErr: true,
		},
		{
			name: "missing TLS certificate",
			config: &transport.Config{
				Protocol: transport.ProtocolQUIC,
				Address:  testServerAddr,
			},
			sessionCfg: &transport.SessionConfig{Threshold: 2, NumParticipants: 3},
			wantErr:    true,
		},
		{
			name: "unsupported codec",
			config: &transport.Config{
				Protocol:    transport.ProtocolQUIC,
				Address:     testServerAddr,
				TLSCertFile: certFile,
				TLSKeyFile:  keyFile,
				CodecType:   "unsupported",
			},
			sessionCfg: &transport.SessionConfig{Threshold: 2, NumParticipants: 3},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewQUICServer(tt.config, tt.sessionCfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewQUICServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && server == nil {
				t.Error("NewQUICServer() returned nil server")
			}
		})
	}
}

// TestQUICClientCreation tests creating a QUIC client with various configurations.
func TestQUICClientCreation(t *testing.T) {
	tests := []struct {
		name    string
		config  *transport.Config
		wantErr bool
	}{
		{
			name: "valid configuration",
			config: &transport.Config{
				Protocol:  transport.ProtocolQUIC,
				CodecType: "json",
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "wrong protocol",
			config: &transport.Config{
				Protocol: transport.ProtocolGRPC,
			},
			wantErr: true,
		},
		{
			name: "unsupported codec",
			config: &transport.Config{
				Protocol:  transport.ProtocolQUIC,
				CodecType: "unsupported",
			},
			wantErr: true,
		},
		{
			name: "default codec (json)",
			config: &transport.Config{
				Protocol: transport.ProtocolQUIC,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewQUICClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewQUICClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewQUICClient() returned nil client")
			}
		})
	}
}

// TestQUICServerStartStop tests starting and stopping the server.
func TestQUICServerStartStop(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	config := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     testServerAddr,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Timeout:     testTimeout,
	}

	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewQUICServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()

	// Test starting the server
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Verify server is running
	if !server.running.Load() {
		t.Error("Server should be running")
	}

	// Verify address is set
	addr := server.Address()
	if addr == "" {
		t.Error("Server address should not be empty")
	}

	// Test starting an already running server (should error)
	if err := server.Start(ctx); err == nil {
		t.Error("Starting an already running server should error")
	}

	// Test stopping the server
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(stopCtx); err != nil {
		t.Fatalf("Failed to stop server: %v", err)
	}

	// Verify server is stopped
	if server.running.Load() {
		t.Error("Server should be stopped")
	}
}

// TestQUICServerSessionID tests the SessionID method.
func TestQUICServerSessionID(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	tests := []struct {
		name      string
		sessionID string
	}{
		{
			name:      "auto-generated session ID",
			sessionID: "",
		},
		{
			name:      "custom session ID",
			sessionID: "custom-session-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &transport.Config{
				Protocol:    transport.ProtocolQUIC,
				Address:     testServerAddr,
				TLSCertFile: certFile,
				TLSKeyFile:  keyFile,
			}

			sessionCfg := &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				SessionID:       tt.sessionID,
			}

			server, err := NewQUICServer(config, sessionCfg)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			sessionID := server.SessionID()
			if sessionID == "" {
				t.Error("SessionID should not be empty")
			}

			if tt.sessionID != "" && sessionID != tt.sessionID {
				t.Errorf("Expected session ID %s, got %s", tt.sessionID, sessionID)
			}
		})
	}
}

// TestQUICClientConnect tests connecting and disconnecting a client.
func TestQUICClientConnect(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	// Start server
	server, serverAddr := startTestServer(t, certFile, keyFile)
	defer stopTestServer(t, server)

	// Create client
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolQUIC,
		CodecType: "json",
		Timeout:   testTimeout,
	}

	client, err := NewQUICClient(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Test connecting
	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Verify client is connected
	if !client.connected.Load() {
		t.Error("Client should be connected")
	}

	// Test connecting when already connected (should error)
	if err := client.Connect(ctx, serverAddr); err != transport.ErrAlreadyConnected {
		t.Errorf("Expected ErrAlreadyConnected, got: %v", err)
	}

	// Test disconnecting
	if err := client.Disconnect(); err != nil {
		t.Fatalf("Failed to disconnect: %v", err)
	}

	// Verify client is disconnected
	if client.connected.Load() {
		t.Error("Client should be disconnected")
	}

	// Test disconnecting when already disconnected (should error)
	if err := client.Disconnect(); err != transport.ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got: %v", err)
	}
}

// TestQUICClientConnectErrors tests error paths in client connection.
func TestQUICClientConnectErrors(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		config  *transport.Config
		wantErr bool
	}{
		{
			name: "invalid address",
			addr: "invalid:address:format",
			config: &transport.Config{
				Protocol: transport.ProtocolQUIC,
			},
			wantErr: true,
		},
		{
			name: "connection refused",
			addr: "127.0.0.1:1", // Unlikely to have service on port 1
			config: &transport.Config{
				Protocol: transport.ProtocolQUIC,
				Timeout:  100 * time.Millisecond,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewQUICClient(tt.config)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			err = client.Connect(ctx, tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connect() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestQUICMessageExchange tests basic message exchange between client and server.
func TestQUICMessageExchange(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	// Start server
	server, serverAddr := startTestServer(t, certFile, keyFile)
	defer stopTestServer(t, server)

	// Create and connect client
	client := createTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Create test DKG parameters
	params := createTestDKGParams(t, 0, 3, 2)

	// Send join message
	if err := client.sendJoin(params); err != nil {
		t.Fatalf("Failed to send join message: %v", err)
	}

	// Wait for session info
	sessionInfo, err := client.waitForSessionInfo(ctx)
	if err != nil {
		t.Fatalf("Failed to receive session info: %v", err)
	}

	// Verify session info
	if sessionInfo.Threshold != 2 {
		t.Errorf("Expected threshold 2, got %d", sessionInfo.Threshold)
	}
	if sessionInfo.NumParticipants != 3 {
		t.Errorf("Expected 3 participants, got %d", sessionInfo.NumParticipants)
	}
}

// TestQUICRunDKG tests the full DKG execution flow.
func TestQUICRunDKG(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	numParticipants := 3
	threshold := 2

	// Start server
	serverConfig := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     testServerAddr,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Timeout:     testTimeout,
	}

	sessionCfg := &transport.SessionConfig{
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
		SessionID:       "test-session-dkg",
	}

	server, err := NewQUICServer(serverConfig, sessionCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer stopTestServer(t, server)

	serverAddr := server.Address()

	// Run DKG with multiple participants concurrently
	var wg sync.WaitGroup
	results := make([]*transport.DKGResult, numParticipants)
	errChan := make(chan error, numParticipants)

	for i := 0; i < numParticipants; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			client := createTestClient(t)
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			if err := client.Connect(ctx, serverAddr); err != nil {
				errChan <- fmt.Errorf("participant %d connect failed: %v", idx, err)
				return
			}
			defer func() { _ = client.Disconnect() }()

			params := createTestDKGParams(t, idx, numParticipants, threshold)
			result, err := client.RunDKG(ctx, params)
			if err != nil {
				errChan <- fmt.Errorf("participant %d RunDKG failed: %v", idx, err)
				return
			}

			results[idx] = result
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		t.Error(err)
	}

	// Verify results
	for i, result := range results {
		if result == nil {
			t.Errorf("Participant %d: nil result", i)
			continue
		}

		if result.SessionID != "test-session-dkg" {
			t.Errorf("Participant %d: expected session ID 'test-session-dkg', got %s", i, result.SessionID)
		}

		if len(result.SecretShare) != transport.SecretKeySize {
			t.Errorf("Participant %d: invalid secret share length", i)
		}

		if len(result.ThresholdPubkey) != transport.PublicKeySize {
			t.Errorf("Participant %d: invalid threshold pubkey length", i)
		}

		if len(result.PublicShares) != numParticipants {
			t.Errorf("Participant %d: expected %d public shares, got %d", i, numParticipants, len(result.PublicShares))
		}
	}
}

// TestQUICRunDKGErrors tests error paths in RunDKG.
func TestQUICRunDKGErrors(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	server, serverAddr := startTestServer(t, certFile, keyFile)
	defer stopTestServer(t, server)

	tests := []struct {
		name      string
		setupFunc func(*QUICClient) error
		params    *transport.DKGParams
		wantErr   error
	}{
		{
			name: "not connected",
			setupFunc: func(c *QUICClient) error {
				return nil // Don't connect
			},
			params:  createTestDKGParams(t, 0, 3, 2),
			wantErr: transport.ErrNotConnected,
		},
		{
			name: "invalid params",
			setupFunc: func(c *QUICClient) error {
				ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
				defer cancel()
				return c.Connect(ctx, serverAddr)
			},
			params:  nil,
			wantErr: transport.ErrInvalidDKGParams,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := createTestClient(t)
			defer func() { _ = client.Disconnect() }()

			if err := tt.setupFunc(client); err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			_, err := client.RunDKG(ctx, tt.params)
			if err != tt.wantErr {
				t.Errorf("Expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestQUICConcurrentParticipants tests multiple participants connecting concurrently.
func TestQUICConcurrentParticipants(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	numParticipants := 5
	threshold := 3

	// Start server
	serverConfig := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     testServerAddr,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Timeout:     testTimeout,
	}

	sessionCfg := &transport.SessionConfig{
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewQUICServer(serverConfig, sessionCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer stopTestServer(t, server)

	serverAddr := server.Address()

	// Signal to keep clients connected until count is verified
	readyToDisconnect := make(chan struct{})

	// Create and connect multiple clients concurrently
	var wg sync.WaitGroup
	errChan := make(chan error, numParticipants)

	for i := 0; i < numParticipants; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			client := createTestClient(t)
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			if err := client.Connect(ctx, serverAddr); err != nil {
				errChan <- fmt.Errorf("participant %d connect failed: %v", idx, err)
				return
			}
			defer func() { _ = client.Disconnect() }()

			params := createTestDKGParams(t, idx, numParticipants, threshold)
			if err := client.sendJoin(params); err != nil {
				errChan <- fmt.Errorf("participant %d join failed: %v", idx, err)
				return
			}

			_, err := client.waitForSessionInfo(ctx)
			if err != nil {
				errChan <- fmt.Errorf("participant %d session info failed: %v", idx, err)
				return
			}

			// Wait before disconnecting
			<-readyToDisconnect
		}(i)
	}

	// Wait for all participants to join and receive session info
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.WaitForParticipants(waitCtx, numParticipants); err != nil {
		t.Errorf("Failed to wait for participants: %v", err)
	}

	// Verify participant count while they're still connected
	count := int(server.participantCount.Load())
	if count != numParticipants {
		t.Errorf("Expected %d participants, got %d", numParticipants, count)
	}

	// Signal clients to disconnect
	close(readyToDisconnect)

	// Wait for all clients to disconnect
	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		t.Error(err)
	}
}

// TestQUICWaitForParticipants tests waiting for participants.
func TestQUICWaitForParticipants(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	server, _ := startTestServer(t, certFile, keyFile)
	defer stopTestServer(t, server)

	tests := []struct {
		name      string
		n         int
		timeout   time.Duration
		wantErr   bool
		errType   error
		setupFunc func()
	}{
		{
			name:    "invalid count (0)",
			n:       0,
			timeout: 1 * time.Second,
			wantErr: true,
			errType: transport.ErrInvalidParticipantCount,
		},
		{
			name:    "invalid count (too high)",
			n:       10,
			timeout: 1 * time.Second,
			wantErr: true,
			errType: transport.ErrInvalidParticipantCount,
		},
		{
			name:    "timeout waiting",
			n:       3,
			timeout: 100 * time.Millisecond,
			wantErr: true,
			errType: transport.ErrSessionTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
			}

			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			err := server.WaitForParticipants(ctx, tt.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("WaitForParticipants() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errType != nil && err != tt.errType {
				t.Errorf("Expected error %v, got %v", tt.errType, err)
			}
		})
	}
}

// TestQUICWaitForSessionInfoTimeout tests timeout in waitForSessionInfo.
func TestQUICWaitForSessionInfoTimeout(t *testing.T) {
	client := createTestClient(t)

	// Create a context that expires immediately
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	time.Sleep(5 * time.Millisecond) // Ensure context expires

	_, err := client.waitForSessionInfo(ctx)
	if err != transport.ErrSessionTimeout {
		t.Errorf("Expected ErrSessionTimeout, got %v", err)
	}
}

// TestQUICWaitForSessionInfoError tests error channel in waitForSessionInfo.
func TestQUICWaitForSessionInfoError(t *testing.T) {
	client := createTestClient(t)

	go func() {
		time.Sleep(10 * time.Millisecond)
		client.errorChan <- transport.ErrInvalidMessage
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := client.waitForSessionInfo(ctx)
	if err != transport.ErrInvalidMessage {
		t.Errorf("Expected ErrInvalidMessage, got %v", err)
	}
}

// TestQUICWaitForSessionInfoWrongMessage tests unexpected message type.
func TestQUICWaitForSessionInfoWrongMessage(t *testing.T) {
	client := createTestClient(t)

	go func() {
		time.Sleep(10 * time.Millisecond)
		client.incomingChan <- &transport.Envelope{
			Type: transport.MsgTypeError, // Wrong type
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := client.waitForSessionInfo(ctx)
	if err != transport.ErrUnexpectedMessage {
		t.Errorf("Expected ErrUnexpectedMessage, got %v", err)
	}
}

// TestQUICDKGParamsValidation tests DKG parameter validation.
func TestQUICDKGParamsValidation(t *testing.T) {
	client := createTestClient(t)

	tests := []struct {
		name    string
		params  *transport.DKGParams
		wantErr error
	}{
		{
			name:    "nil params",
			params:  nil,
			wantErr: transport.ErrInvalidDKGParams,
		},
		{
			name: "invalid host secret key length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 16), // Should be 32
				Random:         make([]byte, 32),
				ParticipantIdx: 0,
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
			},
			wantErr: transport.ErrInvalidHostKey,
		},
		{
			name: "invalid randomness length",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				Random:         make([]byte, 16), // Should be 32
				ParticipantIdx: 0,
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
			},
			wantErr: transport.ErrInvalidRandomness,
		},
		{
			name: "invalid participant index (negative)",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				Random:         make([]byte, 32),
				ParticipantIdx: -1,
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
			},
			wantErr: transport.ErrInvalidParticipantIndex,
		},
		{
			name: "invalid participant index (too high)",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				Random:         make([]byte, 32),
				ParticipantIdx: 5,
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize)},
				Threshold:      1,
			},
			wantErr: transport.ErrInvalidParticipantIndex,
		},
		{
			name: "invalid threshold (too low)",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				Random:         make([]byte, 32),
				ParticipantIdx: 0,
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize), make([]byte, transport.PublicKeySize)},
				Threshold:      0,
			},
			wantErr: transport.ErrInvalidThreshold,
		},
		{
			name: "invalid threshold (too high)",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				Random:         make([]byte, 32),
				ParticipantIdx: 0,
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize), make([]byte, transport.PublicKeySize)},
				Threshold:      5,
			},
			wantErr: transport.ErrInvalidThreshold,
		},
		{
			name: "valid params",
			params: &transport.DKGParams{
				HostSeckey:     make([]byte, 32),
				Random:         make([]byte, 32),
				ParticipantIdx: 0,
				HostPubkeys:    [][]byte{make([]byte, transport.PublicKeySize), make([]byte, transport.PublicKeySize)},
				Threshold:      2,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateParams(tt.params)
			if err != tt.wantErr {
				t.Errorf("validateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestQUICHelperMethods tests getter helper methods.
func TestQUICHelperMethods(t *testing.T) {
	t.Run("server helpers with defaults", func(t *testing.T) {
		certFile, keyFile, cleanup := createTestCerts(t)
		defer cleanup()

		config := &transport.Config{
			Protocol:    transport.ProtocolQUIC,
			Address:     testServerAddr,
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
		}

		sessionCfg := &transport.SessionConfig{
			Threshold:       2,
			NumParticipants: 3,
		}

		server, err := NewQUICServer(config, sessionCfg)
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		if size := server.getMaxMessageSize(); size != 1024*1024 {
			t.Errorf("Expected default max message size 1048576, got %d", size)
		}

		if timeout := server.getTimeout(); timeout != int64(30*time.Second) {
			t.Errorf("Expected default timeout 30s, got %d", timeout)
		}

		if interval := server.getKeepAliveInterval(); interval != 30*time.Second {
			t.Errorf("Expected default keep-alive 30s, got %v", interval)
		}
	})

	t.Run("server helpers with custom values", func(t *testing.T) {
		certFile, keyFile, cleanup := createTestCerts(t)
		defer cleanup()

		config := &transport.Config{
			Protocol:          transport.ProtocolQUIC,
			Address:           testServerAddr,
			TLSCertFile:       certFile,
			TLSKeyFile:        keyFile,
			MaxMessageSize:    2048,
			Timeout:           10 * time.Second,
			KeepAliveInterval: 15 * time.Second,
		}

		sessionCfg := &transport.SessionConfig{
			Threshold:       2,
			NumParticipants: 3,
		}

		server, err := NewQUICServer(config, sessionCfg)
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		if size := server.getMaxMessageSize(); size != 2048 {
			t.Errorf("Expected max message size 2048, got %d", size)
		}

		if timeout := server.getTimeout(); timeout != int64(10*time.Second) {
			t.Errorf("Expected timeout 10s, got %d", timeout)
		}

		if interval := server.getKeepAliveInterval(); interval != 15*time.Second {
			t.Errorf("Expected keep-alive 15s, got %v", interval)
		}
	})

	t.Run("client helpers with defaults", func(t *testing.T) {
		config := &transport.Config{
			Protocol: transport.ProtocolQUIC,
		}

		client, err := NewQUICClient(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		if size := client.getMaxMessageSize(); size != 1024*1024 {
			t.Errorf("Expected default max message size 1048576, got %d", size)
		}

		if timeout := client.getTimeout(); timeout != 30*time.Second {
			t.Errorf("Expected default timeout 30s, got %v", timeout)
		}

		if interval := client.getKeepAliveInterval(); interval != 30*time.Second {
			t.Errorf("Expected default keep-alive 30s, got %v", interval)
		}
	})

	t.Run("client helpers with custom values", func(t *testing.T) {
		config := &transport.Config{
			Protocol:          transport.ProtocolQUIC,
			MaxMessageSize:    4096,
			Timeout:           5 * time.Second,
			KeepAliveInterval: 10 * time.Second,
		}

		client, err := NewQUICClient(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		if size := client.getMaxMessageSize(); size != 4096 {
			t.Errorf("Expected max message size 4096, got %d", size)
		}

		if timeout := client.getTimeout(); timeout != 5*time.Second {
			t.Errorf("Expected timeout 5s, got %v", timeout)
		}

		if interval := client.getKeepAliveInterval(); interval != 10*time.Second {
			t.Errorf("Expected keep-alive 10s, got %v", interval)
		}
	})
}

// TestQUICMultipleCodecs tests different serialization codecs.
func TestQUICMultipleCodecs(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	codecs := []string{"json", "msgpack", "cbor", "yaml", "bson"}

	for _, codec := range codecs {
		t.Run(codec, func(t *testing.T) {
			// Create server with codec
			serverConfig := &transport.Config{
				Protocol:    transport.ProtocolQUIC,
				Address:     testServerAddr,
				TLSCertFile: certFile,
				TLSKeyFile:  keyFile,
				CodecType:   codec,
				Timeout:     testTimeout,
			}

			sessionCfg := &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			}

			server, err := NewQUICServer(serverConfig, sessionCfg)
			if err != nil {
				t.Fatalf("Failed to create server with codec %s: %v", codec, err)
			}

			ctx := context.Background()
			if err := server.Start(ctx); err != nil {
				t.Fatalf("Failed to start server: %v", err)
			}
			defer stopTestServer(t, server)

			serverAddr := server.Address()

			// Create client with same codec
			clientConfig := &transport.Config{
				Protocol:  transport.ProtocolQUIC,
				CodecType: codec,
				Timeout:   testTimeout,
			}

			client, err := NewQUICClient(clientConfig)
			if err != nil {
				t.Fatalf("Failed to create client with codec %s: %v", codec, err)
			}

			connectCtx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			if err := client.Connect(connectCtx, serverAddr); err != nil {
				t.Fatalf("Failed to connect with codec %s: %v", codec, err)
			}
			defer func() { _ = client.Disconnect() }()

			// Test message exchange
			params := createTestDKGParams(t, 0, 3, 2)
			if err := client.sendJoin(params); err != nil {
				t.Fatalf("Failed to send join with codec %s: %v", codec, err)
			}

			sessionInfo, err := client.waitForSessionInfo(connectCtx)
			if err != nil {
				t.Fatalf("Failed to receive session info with codec %s: %v", codec, err)
			}

			if sessionInfo.SessionID == "" {
				t.Errorf("Session ID should not be empty for codec %s", codec)
			}
		})
	}
}

// TestQUICMessageSizeLimit tests message size validation.
func TestQUICMessageSizeLimit(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	// Create server with small message size limit
	serverConfig := &transport.Config{
		Protocol:       transport.ProtocolQUIC,
		Address:        testServerAddr,
		TLSCertFile:    certFile,
		TLSKeyFile:     keyFile,
		MaxMessageSize: 128, // Very small for testing
	}

	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
	}

	server, err := NewQUICServer(serverConfig, sessionCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer stopTestServer(t, server)

	// Verify the limit is set
	if limit := server.getMaxMessageSize(); limit != 128 {
		t.Errorf("Expected max message size 128, got %d", limit)
	}
}

// TestQUICServerStopMultipleTimes tests calling Stop multiple times.
func TestQUICServerStopMultipleTimes(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	server, _ := startTestServer(t, certFile, keyFile)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First stop
	if err := server.Stop(ctx); err != nil {
		t.Fatalf("First stop failed: %v", err)
	}

	// Second stop should not error
	if err := server.Stop(ctx); err != nil {
		t.Errorf("Second stop should not error, got: %v", err)
	}
}

// TestQUICServerStopTimeout tests stop with context timeout.
func TestQUICServerStopTimeout(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	server, _ := startTestServer(t, certFile, keyFile)

	// Create a context that's already expired
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(5 * time.Millisecond) // Ensure context expires

	err := server.Stop(ctx)
	// This might timeout or succeed depending on timing
	if err != nil && err != transport.ErrSessionTimeout {
		t.Errorf("Expected nil or ErrSessionTimeout, got: %v", err)
	}
}

// TestQUICServerAddressBeforeStart tests Address() before server starts.
func TestQUICServerAddressBeforeStart(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	config := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     "127.0.0.1:9999",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}

	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
	}

	server, err := NewQUICServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Address before start should return configured address
	addr := server.Address()
	if addr != "127.0.0.1:9999" {
		t.Errorf("Expected address '127.0.0.1:9999', got '%s'", addr)
	}
}

// TestQUICWaitForParticipantsAfterShutdown tests WaitForParticipants after shutdown.
func TestQUICWaitForParticipantsAfterShutdown(t *testing.T) {
	certFile, keyFile, cleanup := createTestCerts(t)
	defer cleanup()

	server, _ := startTestServer(t, certFile, keyFile)

	// Stop the server
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Stop(stopCtx)

	// Wait should fail with session closed
	ctx, cancel2 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel2()

	err := server.WaitForParticipants(ctx, 3)
	if err != transport.ErrSessionClosed {
		t.Errorf("Expected ErrSessionClosed, got %v", err)
	}
}

// Helper functions

// createTestCerts creates temporary test certificates.
func createTestCerts(t *testing.T) (certFile, keyFile string, cleanup func()) {
	t.Helper()

	hosts := []string{"127.0.0.1", "localhost"}
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(hosts, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate test certs: %v", err)
	}

	certFile = t.TempDir() + "/test.crt"
	keyFile = t.TempDir() + "/test.key"

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cleanup = func() {
		_ = os.Remove(certFile)
		_ = os.Remove(keyFile)
	}

	return certFile, keyFile, cleanup
}

// startTestServer creates and starts a test server.
func startTestServer(t *testing.T, certFile, keyFile string) (*QUICServer, string) {
	t.Helper()

	config := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     testServerAddr,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Timeout:     testTimeout,
	}

	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewQUICServer(config, sessionCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	return server, server.Address()
}

// stopTestServer stops a test server.
func stopTestServer(t *testing.T, server *QUICServer) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}
}

// createTestClient creates a test client.
func createTestClient(t *testing.T) *QUICClient {
	t.Helper()

	config := &transport.Config{
		Protocol:  transport.ProtocolQUIC,
		CodecType: "json",
		Timeout:   testTimeout,
	}

	client, err := NewQUICClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	return client
}

// createTestDKGParams creates test DKG parameters.
func createTestDKGParams(t *testing.T, idx, numParticipants, threshold int) *transport.DKGParams {
	t.Helper()

	hostSeckey := make([]byte, 32)
	if _, err := rand.Read(hostSeckey); err != nil {
		t.Fatalf("Failed to generate host secret key: %v", err)
	}

	randomness := make([]byte, 32)
	if _, err := rand.Read(randomness); err != nil {
		t.Fatalf("Failed to generate randomness: %v", err)
	}

	hostPubkeys := make([][]byte, numParticipants)
	for i := 0; i < numParticipants; i++ {
		pubkey := make([]byte, transport.PublicKeySize)
		if _, err := rand.Read(pubkey); err != nil {
			t.Fatalf("Failed to generate host pubkey: %v", err)
		}
		hostPubkeys[i] = pubkey
	}

	return &transport.DKGParams{
		HostSeckey:     hostSeckey,
		HostPubkeys:    hostPubkeys,
		Threshold:      threshold,
		ParticipantIdx: idx,
		Random:         randomness,
	}
}
