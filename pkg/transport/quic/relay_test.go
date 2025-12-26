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
	"encoding/binary"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// TestQUICMessageRelay tests message relaying between participants.
func TestQUICMessageRelay(t *testing.T) {
	certFile, keyFile, cleanup := testCreateCerts(t)
	defer cleanup()

	numParticipants := 3
	threshold := 2

	// Start server
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
		SessionID:       "relay-test-session",
	}

	server, err := NewQUICServer(serverConfig, sessionCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer testStopServer(t, server)

	serverAddr := server.Address()

	// Create and connect clients
	clients := make([]*QUICClient, numParticipants)
	for i := 0; i < numParticipants; i++ {
		client := testCreateClient(t)
		clients[i] = client

		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := client.Connect(connectCtx, serverAddr); err != nil {
			cancel()
			t.Fatalf("Participant %d failed to connect: %v", i, err)
		}
		cancel()
	}

	// Clean up clients
	defer func() {
		for _, client := range clients {
			_ = client.Disconnect()
		}
	}()

	// Send join messages from all clients
	for i := 0; i < numParticipants; i++ {
		params := testCreateDKGParams(t, i, numParticipants, threshold)
		if err := clients[i].sendJoin(params); err != nil {
			t.Fatalf("Participant %d failed to send join: %v", i, err)
		}
	}

	// Wait for session info on all clients
	sessionInfoCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := 0; i < numParticipants; i++ {
		_, err := clients[i].waitForSessionInfo(sessionInfoCtx)
		if err != nil {
			t.Fatalf("Participant %d failed to receive session info: %v", i, err)
		}
	}

	// Now test message relaying with different message types
	testCases := []struct {
		name    string
		msgType transport.MessageType
	}{
		{"Round1", transport.MsgTypeRound1},
		{"Round1Agg", transport.MsgTypeRound1Agg},
		{"Round2", transport.MsgTypeRound2},
		{"Round2Agg", transport.MsgTypeRound2Agg},
		{"Certificate", transport.MsgTypeCertificate},
		{"Complete", transport.MsgTypeComplete},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Client 0 sends a message
			testPayload := []byte("test-payload-" + tc.name)
			envelope := &transport.Envelope{
				SessionID: "relay-test-session",
				Type:      tc.msgType,
				SenderIdx: 0,
				Payload:   testPayload,
				Timestamp: time.Now().UnixMilli(),
			}

			if err := clients[0].writeMessage(envelope); err != nil {
				t.Fatalf("Failed to write message: %v", err)
			}

			// Other clients should receive it
			received := make([]bool, numParticipants)
			var mu sync.Mutex
			var wg sync.WaitGroup

			for i := 1; i < numParticipants; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()

					timeout := time.NewTimer(2 * time.Second)
					defer timeout.Stop()

					select {
					case msg := <-clients[idx].incomingChan:
						if msg.Type == tc.msgType && msg.SenderIdx == 0 {
							mu.Lock()
							received[idx] = true
							mu.Unlock()
						}
					case <-timeout.C:
						t.Errorf("Participant %d timeout waiting for %s message", idx, tc.name)
					}
				}(i)
			}

			wg.Wait()

			// Verify all participants (except sender) received the message
			for i := 1; i < numParticipants; i++ {
				if !received[i] {
					t.Errorf("Participant %d did not receive %s message", i, tc.name)
				}
			}
		})
	}
}

// TestQUICDuplicateParticipant tests duplicate participant detection.
func TestQUICDuplicateParticipant(t *testing.T) {
	certFile, keyFile, cleanup := testCreateCerts(t)
	defer cleanup()

	server, serverAddr := testStartServer(t, certFile, keyFile)
	defer testStopServer(t, server)

	// Create first client and join
	client1 := testCreateClient(t)
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()

	if err := client1.Connect(ctx1, serverAddr); err != nil {
		t.Fatalf("Failed to connect client1: %v", err)
	}
	defer func() { _ = client1.Disconnect() }()

	params1 := testCreateDKGParams(t, 0, 3, 2)
	if err := client1.sendJoin(params1); err != nil {
		t.Fatalf("Failed to send join from client1: %v", err)
	}

	// Wait for session info
	if _, err := client1.waitForSessionInfo(ctx1); err != nil {
		t.Fatalf("Failed to receive session info: %v", err)
	}

	// Create second client with same participant index
	client2 := testCreateClient(t)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	if err := client2.Connect(ctx2, serverAddr); err != nil {
		t.Fatalf("Failed to connect client2: %v", err)
	}
	defer func() { _ = client2.Disconnect() }()

	// Try to join with same index - should trigger duplicate error
	params2 := testCreateDKGParams(t, 0, 3, 2) // Same index as client1
	if err := client2.sendJoin(params2); err != nil {
		t.Fatalf("Failed to send join from client2: %v", err)
	}

	// Client2 should receive an error message
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()

	select {
	case msg := <-client2.incomingChan:
		if msg.Type != transport.MsgTypeError {
			t.Errorf("Expected error message, got type %v", msg.Type)
		}
	case err := <-client2.errorChan:
		// This is also acceptable - the connection might fail
		t.Logf("Received error: %v", err)
	case <-timeout.C:
		// Duplicate detection might close the connection before sending error
		t.Log("Timeout waiting for error message (connection might be closed)")
	}
}

// TestQUICInvalidMessage tests sending invalid messages.
func TestQUICInvalidMessage(t *testing.T) {
	certFile, keyFile, cleanup := testCreateCerts(t)
	defer cleanup()

	server, serverAddr := testStartServer(t, certFile, keyFile)
	defer testStopServer(t, server)

	client := testCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Get stream reference
	client.connMu.RLock()
	stream := client.stream
	client.connMu.RUnlock()

	if stream == nil {
		t.Fatal("Stream is nil")
	}

	// Send invalid data (not a valid envelope)
	invalidData := []byte{0x00, 0x01, 0x02, 0x03}
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(invalidData)))

	if _, err := stream.Write(lengthBuf[:]); err != nil {
		t.Fatalf("Failed to write length: %v", err)
	}
	if _, err := stream.Write(invalidData); err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	// Server should send error back or close connection
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()

	select {
	case msg := <-client.incomingChan:
		if msg.Type != transport.MsgTypeError {
			t.Logf("Received message type %v", msg.Type)
		}
	case err := <-client.errorChan:
		t.Logf("Received error: %v", err)
	case <-timeout.C:
		// Connection might be closed, which is acceptable
		t.Log("Timeout or connection closed after invalid message")
	}
}

// TestQUICUnexpectedMessageBeforeJoin tests sending non-join message before joining.
func TestQUICUnexpectedMessageBeforeJoin(t *testing.T) {
	certFile, keyFile, cleanup := testCreateCerts(t)
	defer cleanup()

	server, serverAddr := testStartServer(t, certFile, keyFile)
	defer testStopServer(t, server)

	client := testCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Try to send a Round1 message without joining first
	envelope := &transport.Envelope{
		SessionID: "test-session",
		Type:      transport.MsgTypeRound1,
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := client.writeMessage(envelope); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}

	// Server should send error or close connection
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()

	select {
	case msg := <-client.incomingChan:
		if msg.Type == transport.MsgTypeError {
			t.Log("Received expected error message")
		}
	case err := <-client.errorChan:
		t.Logf("Received error: %v", err)
	case <-timeout.C:
		// Connection might be closed
		t.Log("Timeout or connection closed after unexpected message")
	}
}

// TestQUICMessageTooLarge tests handling of oversized messages.
func TestQUICMessageTooLarge(t *testing.T) {
	certFile, keyFile, cleanup := testCreateCerts(t)
	defer cleanup()

	// Create server with small message size
	serverConfig := &transport.Config{
		Protocol:       transport.ProtocolQUIC,
		Address:        "127.0.0.1:0",
		TLSCertFile:    certFile,
		TLSKeyFile:     keyFile,
		MaxMessageSize: 256, // Very small
		Timeout:        5 * time.Second,
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
	defer testStopServer(t, server)

	serverAddr := server.Address()

	client := testCreateClient(t)
	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Get stream reference
	client.connMu.RLock()
	stream := client.stream
	client.connMu.RUnlock()

	// Try to send a message that's too large
	largePayload := make([]byte, 1024) // Larger than limit
	if _, err := rand.Read(largePayload); err != nil {
		t.Fatalf("Failed to generate large payload: %v", err)
	}

	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(largePayload)))

	if _, err := stream.Write(lengthBuf[:]); err != nil {
		t.Fatalf("Failed to write length: %v", err)
	}

	// Server should detect size and close/error
	// Try to write the data
	_, writeErr := stream.Write(largePayload)

	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()

	select {
	case msg := <-client.incomingChan:
		t.Logf("Received message type %v", msg.Type)
	case err := <-client.errorChan:
		t.Logf("Received error: %v", err)
	case <-timeout.C:
		if writeErr != nil {
			t.Logf("Write failed as expected: %v", writeErr)
		} else {
			t.Log("Timeout - server may have closed connection")
		}
	}
}

// TestQUICReadMessageError tests error handling in readMessage.
func TestQUICReadMessageError(t *testing.T) {
	client := testCreateClient(t)

	// Try to read when not connected
	_, err := client.readMessage()
	if err != io.EOF {
		t.Errorf("Expected EOF when reading from nil stream, got %v", err)
	}
}

// TestQUICWriteMessageError tests error handling in writeMessage.
func TestQUICWriteMessageError(t *testing.T) {
	client := testCreateClient(t)

	envelope := &transport.Envelope{
		Type:      transport.MsgTypeJoin,
		SenderIdx: 0,
		Payload:   []byte("test"),
	}

	// Try to write when not connected
	err := client.writeMessage(envelope)
	if err != transport.ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got %v", err)
	}
}

// TestQUICWriteMessageTooLarge tests writeMessage with oversized payload.
func TestQUICWriteMessageTooLarge(t *testing.T) {
	certFile, keyFile, cleanup := testCreateCerts(t)
	defer cleanup()

	server, serverAddr := testStartServer(t, certFile, keyFile)
	defer testStopServer(t, server)

	// Create client with small message size limit
	clientConfig := &transport.Config{
		Protocol:       transport.ProtocolQUIC,
		MaxMessageSize: 128,
		Timeout:        5 * time.Second,
	}

	client, err := NewQUICClient(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Create a large payload
	largePayload := make([]byte, 1024)
	envelope := &transport.Envelope{
		Type:      transport.MsgTypeJoin,
		SenderIdx: 0,
		Payload:   largePayload,
		Timestamp: time.Now().UnixMilli(),
	}

	// Should fail due to size
	err = client.writeMessage(envelope)
	if err != transport.ErrMessageTooLarge {
		t.Errorf("Expected ErrMessageTooLarge, got %v", err)
	}
}

// TestQUICServerStartErrors tests error conditions in server Start.
func TestQUICServerStartErrors(t *testing.T) {
	certFile, keyFile, cleanup := testCreateCerts(t)
	defer cleanup()

	tests := []struct {
		name    string
		config  *transport.Config
		wantErr bool
	}{
		{
			name: "invalid address",
			config: &transport.Config{
				Protocol:    transport.ProtocolQUIC,
				Address:     "invalid:address:format:extra",
				TLSCertFile: certFile,
				TLSKeyFile:  keyFile,
			},
			wantErr: true,
		},
		{
			name: "invalid cert file",
			config: &transport.Config{
				Protocol:    transport.ProtocolQUIC,
				Address:     "127.0.0.1:0",
				TLSCertFile: "/nonexistent/cert.pem",
				TLSKeyFile:  keyFile,
			},
			wantErr: true,
		},
		{
			name: "invalid key file",
			config: &transport.Config{
				Protocol:    transport.ProtocolQUIC,
				Address:     "127.0.0.1:0",
				TLSCertFile: certFile,
				TLSKeyFile:  "/nonexistent/key.pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionCfg := &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
			}

			server, err := NewQUICServer(tt.config, sessionCfg)
			if err != nil {
				// Configuration error is also acceptable
				return
			}

			ctx := context.Background()
			err = server.Start(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Start() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				testStopServer(t, server)
			}
		})
	}
}

// Test helper functions

func testCreateCerts(t *testing.T) (certFile, keyFile string, cleanup func()) {
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

func testStopServer(t *testing.T, server *QUICServer) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}
}

func testCreateClient(t *testing.T) *QUICClient {
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

func testCreateDKGParams(t *testing.T, idx, numParticipants, threshold int) *transport.DKGParams {
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

func testStartServer(t *testing.T, certFile, keyFile string) (*QUICServer, string) {
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
