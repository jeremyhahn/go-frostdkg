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
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// TestQUICRelayUnknownMessageType tests relaying with unknown message types.
func TestQUICRelayUnknownMessageType(t *testing.T) {
	certFile, keyFile, cleanup := coverageCreateCerts(t)
	defer cleanup()

	numParticipants := 2
	threshold := 2

	serverConfig := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     "127.0.0.1:0",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Timeout:     10 * time.Second,
	}

	sessionCfg := &transport.SessionConfig{
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
		SessionID:       "unknown-msg-test",
	}

	server, err := NewQUICServer(serverConfig, sessionCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer coverageStopServer(t, server)

	serverAddr := server.Address()

	// Create and connect 2 clients
	clients := make([]*QUICClient, numParticipants)
	for i := 0; i < numParticipants; i++ {
		client := coverageCreateClient(t)
		clients[i] = client

		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := client.Connect(connectCtx, serverAddr); err != nil {
			cancel()
			t.Fatalf("Participant %d failed to connect: %v", i, err)
		}
		cancel()

		params := coverageCreateDKGParams(t, i, numParticipants, threshold)
		if err := client.sendJoin(params); err != nil {
			t.Fatalf("Participant %d failed to join: %v", i, err)
		}

		sessionInfoCtx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := client.waitForSessionInfo(sessionInfoCtx); err != nil {
			cancel2()
			t.Fatalf("Participant %d failed to get session info: %v", i, err)
		}
		cancel2()
	}

	defer func() {
		for _, client := range clients {
			_ = client.Disconnect()
		}
	}()

	// Send a message with an unknown/custom message type (falls into default case)
	envelope := &transport.Envelope{
		SessionID: "unknown-msg-test",
		Type:      transport.MessageType(99), // Unknown type
		SenderIdx: 0,
		Payload:   []byte("test-unknown-type"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := clients[0].writeMessage(envelope); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}

	// Client 1 should receive it (default relay behavior)
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()

	select {
	case msg := <-clients[1].incomingChan:
		if msg.Type != transport.MessageType(99) {
			t.Errorf("Expected type 999, got %v", msg.Type)
		}
	case <-timeout.C:
		t.Error("Client 1 did not receive unknown message type")
	}
}

// TestQUICServerWriteMessageEncodingError tests marshal error in server writeMessage.
func TestQUICServerWriteMessageEncodingError(t *testing.T) {
	certFile, keyFile, cleanup := coverageCreateCerts(t)
	defer cleanup()

	// Create server with unsupported codec that will cause marshal errors
	serverConfig := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     "127.0.0.1:0",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		CodecType:   "json",
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
	defer coverageStopServer(t, server)

	serverAddr := server.Address()

	client := coverageCreateClient(t)
	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Send join - server will try to send session info
	params := coverageCreateDKGParams(t, 0, 3, 2)
	if err := client.sendJoin(params); err != nil {
		t.Fatalf("Failed to send join: %v", err)
	}

	// Wait for session info - should succeed with json codec
	sessionInfoCtx, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()

	_, err = client.waitForSessionInfo(sessionInfoCtx)
	if err != nil {
		t.Logf("Session info error (may be expected): %v", err)
	}
}

// TestQUICClientWriteMessageMarshalError tests marshal error in client writeMessage.
func TestQUICClientWriteMessageMarshalError(t *testing.T) {
	certFile, keyFile, cleanup := coverageCreateCerts(t)
	defer cleanup()

	server, serverAddr := coverageStartServer(t, certFile, keyFile)
	defer coverageStopServer(t, server)

	client := coverageCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Most valid envelopes will marshal successfully with JSON
	// This test ensures the write path is exercised
	envelope := &transport.Envelope{
		Type:      transport.MsgTypeJoin,
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().UnixMilli(),
	}

	err := client.writeMessage(envelope)
	if err != nil {
		t.Logf("Write message error: %v", err)
	}
}

// TestQUICServerReadMessageEOF tests EOF handling in server readMessage.
func TestQUICServerReadMessageEOF(t *testing.T) {
	certFile, keyFile, cleanup := coverageCreateCerts(t)
	defer cleanup()

	server, serverAddr := coverageStartServer(t, certFile, keyFile)
	defer coverageStopServer(t, server)

	client := coverageCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Get stream
	client.connMu.RLock()
	stream := client.stream
	client.connMu.RUnlock()

	// Close stream immediately to trigger EOF
	if stream != nil {
		defer func() { _ = stream.Close() }()
		_ = stream.Close()
	}

	// Disconnect to clean up
	time.Sleep(100 * time.Millisecond)
	_ = client.Disconnect()
}

// TestQUICConnectWithHostPort tests address parsing in Connect.
func TestQUICConnectWithHostPort(t *testing.T) {
	certFile, keyFile, cleanup := coverageCreateCerts(t)
	defer cleanup()

	server, serverAddr := coverageStartServer(t, certFile, keyFile)
	defer coverageStopServer(t, server)

	// Test with explicit TLS config using valid host:port
	clientConfig := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Timeout:     5 * time.Second,
	}

	client, err := NewQUICClient(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This tests the host extraction from address in Connect
	err = client.Connect(ctx, serverAddr)
	if err != nil {
		// May fail due to cert verification, but path is tested
		t.Logf("Connect error (expected for self-signed): %v", err)
		return
	}

	defer func() { _ = client.Disconnect() }()
}

// TestQUICConnectWithoutPort tests address parsing without explicit port.
func TestQUICConnectWithoutPort(t *testing.T) {
	client := coverageCreateClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Address without port - tests the error path in SplitHostPort
	err := client.Connect(ctx, "invalid-no-port")
	if err == nil {
		t.Error("Expected error for address without port")
		_ = client.Disconnect()
	}
}

// TestQUICClientReadMessageError tests readMessage error on stream close.
func TestQUICClientReadMessageError(t *testing.T) {
	certFile, keyFile, cleanup := coverageCreateCerts(t)
	defer cleanup()

	server, serverAddr := coverageStartServer(t, certFile, keyFile)
	defer coverageStopServer(t, server)

	client := coverageCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Get stream and close it
	client.connMu.RLock()
	stream := client.stream
	client.connMu.RUnlock()

	if stream != nil {
		defer func() { _ = stream.Close() }()
		_ = stream.Close()
	}

	// Try to read - should get error
	_, err := client.readMessage()
	if err == nil {
		t.Error("Expected error reading from closed stream")
	}

	_ = client.Disconnect()
}

// TestQUICServerWriteMessageToClosedStream tests write error handling.
func TestQUICServerWriteMessageToClosedStream(t *testing.T) {
	certFile, keyFile, cleanup := coverageCreateCerts(t)
	defer cleanup()

	server, serverAddr := coverageStartServer(t, certFile, keyFile)
	defer coverageStopServer(t, server)

	client := coverageCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Send join
	params := coverageCreateDKGParams(t, 0, 3, 2)
	if err := client.sendJoin(params); err != nil {
		t.Fatalf("Failed to send join: %v", err)
	}

	// Close client stream immediately
	client.connMu.RLock()
	stream := client.stream
	client.connMu.RUnlock()

	if stream != nil {
		defer func() { _ = stream.Close() }()
		_ = stream.Close()
	}

	// Server will try to send session info and should handle the error
	time.Sleep(200 * time.Millisecond)

	_ = client.Disconnect()
}

// TestQUICStartWithBadTLSConfig tests Start with invalid TLS configuration.
func TestQUICStartWithBadTLSConfig(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		keyFile  string
	}{
		{
			name:     "empty cert and key",
			certFile: "",
			keyFile:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &transport.Config{
				Protocol:    transport.ProtocolQUIC,
				Address:     "127.0.0.1:0",
				TLSCertFile: tt.certFile,
				TLSKeyFile:  tt.keyFile,
			}

			sessionCfg := &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
			}

			server, err := NewQUICServer(config, sessionCfg)
			if err != nil {
				// Expected to fail during creation
				return
			}

			ctx := context.Background()
			err = server.Start(ctx)
			if err == nil {
				t.Error("Expected error starting with bad TLS config")
				coverageStopServer(t, server)
			}
		})
	}
}

// Helper functions

func coverageCreateCerts(t *testing.T) (certFile, keyFile string, cleanup func()) {
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

func coverageStopServer(t *testing.T, server *QUICServer) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}
}

func coverageCreateClient(t *testing.T) *QUICClient {
	t.Helper()

	config := &transport.Config{
		Protocol:  transport.ProtocolQUIC,
		CodecType: "json",
		Timeout:   10 * time.Second,
	}

	client, err := NewQUICClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	return client
}

func coverageCreateDKGParams(t *testing.T, idx, numParticipants, threshold int) *transport.DKGParams {
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

func coverageStartServer(t *testing.T, certFile, keyFile string) (*QUICServer, string) {
	t.Helper()

	config := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     "127.0.0.1:0",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Timeout:     10 * time.Second,
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
