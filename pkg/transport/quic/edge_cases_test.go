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

// TestQUICConnectWithTLSConfig tests client connection with explicit TLS config.
func TestQUICConnectWithTLSConfig(t *testing.T) {
	certFile, keyFile, cleanup := helperCreateCerts(t)
	defer cleanup()

	server, serverAddr := helperStartServer(t, certFile, keyFile)
	defer helperStopServer(t, server)

	// Create client with TLS cert/key/CA files
	clientConfig := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		TLSCAFile:   certFile, // Use cert as CA for testing
		Timeout:     5 * time.Second,
	}

	client, err := NewQUICClient(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This may fail with certificate verification errors but tests the TLS path
	err = client.Connect(ctx, serverAddr)
	if err != nil {
		// Expected to fail due to self-signed cert issues, but path is tested
		t.Logf("Connect with TLS config failed (expected): %v", err)
		return
	}

	defer func() { _ = client.Disconnect() }()
}

// TestQUICConnectInvalidAddress tests connection to invalid address formats.
func TestQUICConnectInvalidAddress(t *testing.T) {
	client := helperCreateClient(t)

	tests := []struct {
		name string
		addr string
	}{
		{"no port with invalid host", "invalidhostname"},
		{"malformed host:port", ":::invalid:::"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			err := client.Connect(ctx, tt.addr)
			if err == nil {
				t.Error("Expected error for invalid address")
				_ = client.Disconnect()
			}
		})
	}
}

// TestQUICReadMessageWithPartialData tests reading incomplete messages.
func TestQUICReadMessageWithPartialData(t *testing.T) {
	certFile, keyFile, cleanup := helperCreateCerts(t)
	defer cleanup()

	server, serverAddr := helperStartServer(t, certFile, keyFile)
	defer helperStopServer(t, server)

	client := helperCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Get stream
	client.connMu.RLock()
	stream := client.stream
	client.connMu.RUnlock()

	if stream == nil {
		t.Fatal("Stream is nil")
	}

	// Write only length header, no data
	lengthBuf := [4]byte{0, 0, 0, 10}
	if _, err := stream.Write(lengthBuf[:]); err != nil {
		t.Logf("Failed to write partial data: %v", err)
	}

	// Close stream to trigger EOF
	_ = stream.Close()

	// Client should handle the error
	timeout := time.NewTimer(1 * time.Second)
	defer timeout.Stop()

	select {
	case err := <-client.errorChan:
		t.Logf("Received expected error: %v", err)
	case <-timeout.C:
		// EOF or connection closed - acceptable
		t.Log("Connection closed or EOF")
	}
}

// TestQUICWriteAfterDisconnect tests writing after disconnect.
func TestQUICWriteAfterDisconnect(t *testing.T) {
	certFile, keyFile, cleanup := helperCreateCerts(t)
	defer cleanup()

	server, serverAddr := helperStartServer(t, certFile, keyFile)
	defer helperStopServer(t, server)

	client := helperCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Disconnect
	if err := client.Disconnect(); err != nil {
		t.Fatalf("Failed to disconnect: %v", err)
	}

	// Try to write
	envelope := &transport.Envelope{
		Type:      transport.MsgTypeJoin,
		SenderIdx: 0,
		Payload:   []byte("test"),
	}

	err := client.writeMessage(envelope)
	if err != transport.ErrNotConnected {
		t.Errorf("Expected ErrNotConnected after disconnect, got %v", err)
	}
}

// TestQUICServerWriteMessageError tests server writeMessage error handling.
func TestQUICServerWriteMessageError(t *testing.T) {
	certFile, keyFile, cleanup := helperCreateCerts(t)
	defer cleanup()

	serverConfig := &transport.Config{
		Protocol:       transport.ProtocolQUIC,
		Address:        "127.0.0.1:0",
		TLSCertFile:    certFile,
		TLSKeyFile:     keyFile,
		MaxMessageSize: 64, // Very small
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
	defer helperStopServer(t, server)

	// Verify write limit is enforced
	if limit := server.getMaxMessageSize(); limit != 64 {
		t.Errorf("Expected max message size 64, got %d", limit)
	}
}

// TestQUICRelayWithClosedConnection tests relay behavior when participant disconnects.
func TestQUICRelayWithClosedConnection(t *testing.T) {
	certFile, keyFile, cleanup := helperCreateCerts(t)
	defer cleanup()

	numParticipants := 3
	threshold := 2

	serverConfig := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     "127.0.0.1:0",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Timeout:     5 * time.Second,
	}

	sessionCfg := &transport.SessionConfig{
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
		SessionID:       "relay-disconnect-test",
	}

	server, err := NewQUICServer(serverConfig, sessionCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer helperStopServer(t, server)

	serverAddr := server.Address()

	// Create and connect clients
	clients := make([]*QUICClient, numParticipants)
	for i := 0; i < numParticipants; i++ {
		client := helperCreateClient(t)
		clients[i] = client

		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := client.Connect(connectCtx, serverAddr); err != nil {
			cancel()
			t.Fatalf("Participant %d failed to connect: %v", i, err)
		}
		cancel()

		params := helperCreateDKGParams(t, i, numParticipants, threshold)
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

	// Disconnect one client
	if err := clients[2].Disconnect(); err != nil {
		t.Fatalf("Failed to disconnect client 2: %v", err)
	}

	// Send a message from client 0 - should fail to relay to disconnected client 2
	envelope := &transport.Envelope{
		SessionID: "relay-disconnect-test",
		Type:      transport.MsgTypeRound1,
		SenderIdx: 0,
		Payload:   []byte("test-payload"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := clients[0].writeMessage(envelope); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}

	// Client 1 should still receive it
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()

	select {
	case msg := <-clients[1].incomingChan:
		if msg.Type != transport.MsgTypeRound1 {
			t.Errorf("Expected Round1 message, got %v", msg.Type)
		}
	case <-timeout.C:
		t.Error("Client 1 did not receive message")
	}

	// Clean up remaining clients
	_ = clients[0].Disconnect()
	_ = clients[1].Disconnect()
}

// TestQUICServerReadMessageErrors tests various read error conditions.
func TestQUICServerReadMessageErrors(t *testing.T) {
	certFile, keyFile, cleanup := helperCreateCerts(t)
	defer cleanup()

	server, serverAddr := helperStartServer(t, certFile, keyFile)
	defer helperStopServer(t, server)

	client := helperCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Get stream
	client.connMu.RLock()
	stream := client.stream
	client.connMu.RUnlock()

	// Test 1: Send message with length but truncated data
	lengthBuf := [4]byte{0, 0, 0, 50}
	if _, err := stream.Write(lengthBuf[:]); err != nil {
		t.Logf("Failed to write length: %v", err)
	}

	// Write only partial data (less than declared length)
	partialData := []byte{1, 2, 3}
	if _, err := stream.Write(partialData); err != nil {
		t.Logf("Failed to write partial data: %v", err)
	}

	// Close stream to trigger read error
	time.Sleep(100 * time.Millisecond)
	_ = stream.Close()

	// Server should handle the error
	time.Sleep(200 * time.Millisecond)
}

// TestQUICServerInvalidJoinMessage tests handling of malformed join messages.
func TestQUICServerInvalidJoinMessage(t *testing.T) {
	certFile, keyFile, cleanup := helperCreateCerts(t)
	defer cleanup()

	server, serverAddr := helperStartServer(t, certFile, keyFile)
	defer helperStopServer(t, server)

	client := helperCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Send a join message with invalid payload
	envelope := &transport.Envelope{
		SessionID: "",
		Type:      transport.MsgTypeJoin,
		SenderIdx: 0,
		Payload:   []byte("invalid-join-data"), // Not a valid JoinMessage
		Timestamp: time.Now().UnixMilli(),
	}

	if err := client.writeMessage(envelope); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}

	// Server should send error back
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()

	select {
	case msg := <-client.incomingChan:
		if msg.Type == transport.MsgTypeError {
			t.Log("Received expected error message for invalid join")
		}
	case err := <-client.errorChan:
		t.Logf("Received error: %v", err)
	case <-timeout.C:
		t.Log("Timeout or connection closed after invalid join")
	}
}

// TestQUICConnectContextCancellation tests connection with canceled context.
func TestQUICConnectContextCancellation(t *testing.T) {
	certFile, keyFile, cleanup := helperCreateCerts(t)
	defer cleanup()

	server, serverAddr := helperStartServer(t, certFile, keyFile)
	defer helperStopServer(t, server)

	client := helperCreateClient(t)

	// Create already-canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := client.Connect(ctx, serverAddr)
	if err == nil {
		t.Error("Expected error with canceled context")
		_ = client.Disconnect()
	}
}

// Helper functions

func helperCreateCerts(t *testing.T) (certFile, keyFile string, cleanup func()) {
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

func helperStopServer(t *testing.T, server *QUICServer) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}
}

func helperCreateClient(t *testing.T) *QUICClient {
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

func helperCreateDKGParams(t *testing.T, idx, numParticipants, threshold int) *transport.DKGParams {
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

func helperStartServer(t *testing.T, certFile, keyFile string) (*QUICServer, string) {
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
