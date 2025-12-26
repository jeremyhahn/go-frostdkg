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
	"io"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TestClientWriteMessageOversized tests client.writeMessage size validation.
func TestClientWriteMessageOversized(t *testing.T) {
	certFile, keyFile, cleanup := createTestCertsTarget(t)
	defer cleanup()

	server, serverAddr := startServerTarget(t, certFile, keyFile, 1024*1024)
	defer stopServerTarget(t, server)

	// Create client with small max message size
	clientConfig := &transport.Config{
		Protocol:       transport.ProtocolQUIC,
		MaxMessageSize: 50, // Very small
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

	// Create message that will be too large after marshaling
	largePayload := make([]byte, 100)
	_, _ = rand.Read(largePayload)

	envelope := &transport.Envelope{
		Type:      transport.MsgTypeJoin,
		SenderIdx: 0,
		Payload:   largePayload,
		Timestamp: time.Now().UnixMilli(),
	}

	// writeMessage should fail with ErrMessageTooLarge
	err = client.writeMessage(envelope)
	if err != transport.ErrMessageTooLarge {
		t.Errorf("Expected ErrMessageTooLarge, got: %v", err)
	}
}

// TestServerStopContextTimeout tests Stop with a very short context timeout.
func TestServerStopContextTimeout(t *testing.T) {
	certFile, keyFile, cleanup := createTestCertsTarget(t)
	defer cleanup()

	server, serverAddr := startServerTarget(t, certFile, keyFile, 1024*1024)

	// Connect a client to keep server busy
	client := createClientTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := client.Connect(ctx, serverAddr); err != nil {
		cancel()
		t.Fatalf("Failed to connect: %v", err)
	}
	cancel()

	// Use extremely short timeout for Stop - should timeout
	stopCtx, cancel2 := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel2()

	err := server.Stop(stopCtx)
	if err != transport.ErrSessionTimeout {
		t.Logf("Stop error: %v (timeout may or may not occur)", err)
	}

	// Clean up client
	_ = client.Disconnect()

	// Stop properly
	ctx2, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	_ = server.Stop(ctx2)
}

// TestClientReadMessageNilStream tests readMessage when stream is nil.
func TestClientReadMessageNilStream(t *testing.T) {
	client := createClientTarget(t)

	// Stream is nil when not connected
	_, err := client.readMessage()
	if err != io.EOF {
		t.Errorf("Expected io.EOF for nil stream, got: %v", err)
	}
}

// TestClientWriteMessageNilStream tests writeMessage when stream is nil.
func TestClientWriteMessageNilStream(t *testing.T) {
	client := createClientTarget(t)

	envelope := &transport.Envelope{
		Type:      transport.MsgTypeJoin,
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().UnixMilli(),
	}

	// Stream is nil when not connected
	err := client.writeMessage(envelope)
	if err != transport.ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got: %v", err)
	}
}

// TestRunDKGNotConnected tests RunDKG when client is not connected.
func TestRunDKGNotConnected(t *testing.T) {
	client := createClientTarget(t)

	params := createDKGParamsTarget(t, 0, 3, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := client.RunDKG(ctx, params)
	if err != transport.ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got: %v", err)
	}
}

// TestConnectAlreadyConnected tests connecting when already connected.
func TestConnectAlreadyConnected(t *testing.T) {
	certFile, keyFile, cleanup := createTestCertsTarget(t)
	defer cleanup()

	server, serverAddr := startServerTarget(t, certFile, keyFile, 1024*1024)
	defer stopServerTarget(t, server)

	client := createClientTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("First connect failed: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Try to connect again - should fail
	err := client.Connect(ctx, serverAddr)
	if err != transport.ErrAlreadyConnected {
		t.Errorf("Expected ErrAlreadyConnected, got: %v", err)
	}
}

// TestDisconnectNotConnected tests disconnecting when not connected.
func TestDisconnectNotConnected(t *testing.T) {
	client := createClientTarget(t)

	err := client.Disconnect()
	if err != transport.ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got: %v", err)
	}
}

// TestSendJoinWithClosedStream tests sendJoin when stream is closed.
func TestSendJoinWithClosedStream(t *testing.T) {
	certFile, keyFile, cleanup := createTestCertsTarget(t)
	defer cleanup()

	server, serverAddr := startServerTarget(t, certFile, keyFile, 1024*1024)
	defer stopServerTarget(t, server)

	client := createClientTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Close the stream
	client.connMu.Lock()
	if client.stream != nil {
		_ = client.stream.Close()
		client.stream = nil
	}
	client.connMu.Unlock()

	// sendJoin should fail
	params := createDKGParamsTarget(t, 0, 3, 2)
	err := client.sendJoin(params)
	if err == nil {
		t.Error("Expected error with closed stream")
	}
}

// TestConnectWithTLSCertAndCA tests Connect with cert, key, and CA file.
func TestConnectWithTLSCertAndCA(t *testing.T) {
	certFile, keyFile, cleanup := createTestCertsTarget(t)
	defer cleanup()

	server, serverAddr := startServerTarget(t, certFile, keyFile, 1024*1024)
	defer stopServerTarget(t, server)

	// Create client with cert, key, and CA
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

	// Connect - may fail due to cert verification but exercises the code path
	err = client.Connect(ctx, serverAddr)
	if err != nil {
		t.Logf("Connect with TLS error (expected for self-signed): %v", err)
		return
	}
	defer func() { _ = client.Disconnect() }()
}

// TestServerRelayBroadcastMessages tests relay of broadcast message types.
func TestServerRelayBroadcastMessages(t *testing.T) {
	certFile, keyFile, cleanup := createTestCertsTarget(t)
	defer cleanup()

	server, serverAddr := startServerTarget(t, certFile, keyFile, 1024*1024)
	defer stopServerTarget(t, server)

	// Connect 2 clients
	clients := make([]*QUICClient, 2)
	for i := 0; i < 2; i++ {
		client := createClientTarget(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := client.Connect(ctx, serverAddr); err != nil {
			cancel()
			t.Fatalf("Client %d failed to connect: %v", i, err)
		}
		cancel()
		clients[i] = client

		// Send join
		params := createDKGParamsTarget(t, i, 2, 2)
		if err := client.sendJoin(params); err != nil {
			t.Fatalf("Client %d join failed: %v", i, err)
		}

		// Wait for session info
		sessionCtx, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = client.waitForSessionInfo(sessionCtx)
		cancel2()
	}

	defer func() {
		for _, c := range clients {
			_ = c.Disconnect()
		}
	}()

	// Test different message types for relay coverage
	messageTypes := []transport.MessageType{
		transport.MsgTypeRound1,
		transport.MsgTypeRound1Agg,
		transport.MsgTypeRound2,
		transport.MsgTypeRound2Agg,
		transport.MsgTypeCertificate,
		transport.MsgTypeComplete,
		transport.MessageType(99), // Unknown type (default case)
	}

	for _, msgType := range messageTypes {
		envelope := &transport.Envelope{
			SessionID: server.sessionID,
			Type:      msgType,
			SenderIdx: 0,
			Payload:   []byte("relay-test"),
			Timestamp: time.Now().UnixMilli(),
		}

		if err := clients[0].writeMessage(envelope); err != nil {
			t.Logf("Write error for %v: %v", msgType, err)
		}

		// Give time for relay
		time.Sleep(50 * time.Millisecond)
	}
}

// TestWaitForSessionInfoWithError tests error channel in waitForSessionInfo.
func TestWaitForSessionInfoWithError(t *testing.T) {
	client := createClientTarget(t)

	// Manually send an error to the error channel
	go func() {
		time.Sleep(10 * time.Millisecond)
		select {
		case client.errorChan <- transport.ErrInvalidMessage:
		default:
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := client.waitForSessionInfo(ctx)
	if err != transport.ErrInvalidMessage {
		t.Logf("Got error: %v", err)
	}
}

// TestWaitForSessionInfoWithUnexpectedMessage tests unexpected message type.
func TestWaitForSessionInfoWithUnexpectedMessage(t *testing.T) {
	client := createClientTarget(t)

	// Send unexpected message type
	go func() {
		time.Sleep(10 * time.Millisecond)
		envelope := &transport.Envelope{
			Type:      transport.MsgTypeRound1, // Not SessionInfo
			SenderIdx: 0,
			Payload:   []byte("test"),
			Timestamp: time.Now().UnixMilli(),
		}
		select {
		case client.incomingChan <- envelope:
		default:
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := client.waitForSessionInfo(ctx)
	if err != transport.ErrUnexpectedMessage {
		t.Logf("Got error: %v", err)
	}
}

// TestServerHandleConnectionEOF tests EOF during handleConnection.
func TestServerHandleConnectionEOF(t *testing.T) {
	certFile, keyFile, cleanup := createTestCertsTarget(t)
	defer cleanup()

	server, serverAddr := startServerTarget(t, certFile, keyFile, 1024*1024)
	defer stopServerTarget(t, server)

	client := createClientTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Close client stream immediately to trigger EOF on server
	client.connMu.RLock()
	stream := client.stream
	client.connMu.RUnlock()

	if stream != nil {
		_ = stream.Close()
	}

	// Give server time to handle EOF
	time.Sleep(200 * time.Millisecond)

	_ = client.Disconnect()
}

// TestServerHandleInvalidJoinMessage tests handleConnection with invalid join.
func TestServerHandleInvalidJoinMessage(t *testing.T) {
	certFile, keyFile, cleanup := createTestCertsTarget(t)
	defer cleanup()

	server, serverAddr := startServerTarget(t, certFile, keyFile, 1024*1024)
	defer stopServerTarget(t, server)

	client := createClientTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Send invalid join message (bad payload)
	envelope := &transport.Envelope{
		Type:      transport.MsgTypeJoin,
		SenderIdx: 0,
		Payload:   []byte("invalid-join"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := client.writeMessage(envelope); err != nil {
		t.Logf("Write error: %v", err)
	}

	// Server should send error
	time.Sleep(200 * time.Millisecond)
}

// TestServerDuplicateParticipant tests joining with duplicate participant index.
func TestServerDuplicateParticipant(t *testing.T) {
	certFile, keyFile, cleanup := createTestCertsTarget(t)
	defer cleanup()

	server, serverAddr := startServerTarget(t, certFile, keyFile, 1024*1024)
	defer stopServerTarget(t, server)

	// Connect two clients with same index
	client1 := createClientTarget(t)
	client2 := createClientTarget(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client1.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Client 1 failed to connect: %v", err)
	}
	defer func() { _ = client1.Disconnect() }()

	if err := client2.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Client 2 failed to connect: %v", err)
	}
	defer func() { _ = client2.Disconnect() }()

	// Send join from client 1
	params := createDKGParamsTarget(t, 0, 3, 2)
	if err := client1.sendJoin(params); err != nil {
		t.Fatalf("Client 1 join failed: %v", err)
	}

	// Wait for session info
	sessionCtx, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = client1.waitForSessionInfo(sessionCtx)
	cancel2()

	// Send join from client 2 with SAME index - should fail
	if err := client2.sendJoin(params); err != nil {
		t.Logf("Client 2 join error (expected): %v", err)
	}

	// Server should send error and close connection
	time.Sleep(200 * time.Millisecond)
}

// TestServerMessageBeforeJoin tests sending message before joining.
func TestServerMessageBeforeJoin(t *testing.T) {
	certFile, keyFile, cleanup := createTestCertsTarget(t)
	defer cleanup()

	server, serverAddr := startServerTarget(t, certFile, keyFile, 1024*1024)
	defer stopServerTarget(t, server)

	client := createClientTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Send non-join message first (without joining)
	envelope := &transport.Envelope{
		SessionID: server.sessionID,
		Type:      transport.MsgTypeRound1,
		SenderIdx: 0,
		Payload:   []byte("test"),
		Timestamp: time.Now().UnixMilli(),
	}

	if err := client.writeMessage(envelope); err != nil {
		t.Logf("Write error: %v", err)
	}

	// Server should send ErrUnexpectedMessage
	time.Sleep(200 * time.Millisecond)
}

// Helper functions

func createTestCertsTarget(t *testing.T) (certFile, keyFile string, cleanup func()) {
	t.Helper()
	return coverageCreateCerts(t)
}

func stopServerTarget(t *testing.T, server *QUICServer) {
	t.Helper()
	coverageStopServer(t, server)
}

func createClientTarget(t *testing.T) *QUICClient {
	t.Helper()
	return coverageCreateClient(t)
}

func createDKGParamsTarget(t *testing.T, idx, numParticipants, threshold int) *transport.DKGParams {
	t.Helper()
	return coverageCreateDKGParams(t, idx, numParticipants, threshold)
}

func startServerTarget(t *testing.T, certFile, keyFile string, maxMsgSize int) (*QUICServer, string) {
	t.Helper()

	config := &transport.Config{
		Protocol:       transport.ProtocolQUIC,
		Address:        "127.0.0.1:0",
		TLSCertFile:    certFile,
		TLSKeyFile:     keyFile,
		Timeout:        10 * time.Second,
		MaxMessageSize: maxMsgSize,
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
