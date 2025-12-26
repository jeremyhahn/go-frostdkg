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

// TestQUICServerStopBeforeStart tests Stop before Start.
func TestQUICServerStopBeforeStart(t *testing.T) {
	certFile, keyFile, cleanup := finalCreateCerts(t)
	defer cleanup()

	config := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     "127.0.0.1:0",
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

	// Stop before starting - should return without error
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop before Start should not error, got: %v", err)
	}
}

// TestQUICDisconnectError tests Disconnect when connection close fails.
func TestQUICDisconnectError(t *testing.T) {
	certFile, keyFile, cleanup := finalCreateCerts(t)
	defer cleanup()

	server, serverAddr := finalStartServer(t, certFile, keyFile)
	defer finalStopServer(t, server)

	client := finalCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Force close stream first
	client.connMu.Lock()
	if client.stream != nil {
		_ = client.stream.Close()
	}
	client.connMu.Unlock()

	// Disconnect should handle the error gracefully
	if err := client.Disconnect(); err != nil {
		t.Logf("Disconnect error (may be expected): %v", err)
	}
}

// TestQUICWriteAfterConnect tests successful write after connect.
func TestQUICWriteAfterConnect(t *testing.T) {
	certFile, keyFile, cleanup := finalCreateCerts(t)
	defer cleanup()

	server, serverAddr := finalStartServer(t, certFile, keyFile)
	defer finalStopServer(t, server)

	client := finalCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Write a valid join message
	params := finalCreateDKGParams(t, 0, 3, 2)
	if err := client.sendJoin(params); err != nil {
		t.Errorf("sendJoin after connect should succeed, got: %v", err)
	}

	// Wait briefly for server to process
	time.Sleep(100 * time.Millisecond)
}

// TestQUICConnectStreamError tests error when opening stream fails.
func TestQUICConnectStreamError(t *testing.T) {
	certFile, keyFile, cleanup := finalCreateCerts(t)
	defer cleanup()

	server, serverAddr := finalStartServer(t, certFile, keyFile)
	defer finalStopServer(t, server)

	client := finalCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connect successfully
	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Immediate disconnect
	if err := client.Disconnect(); err != nil {
		t.Logf("Disconnect error: %v", err)
	}
}

// TestQUICServerSendSessionInfoError tests sendSessionInfo error handling.
func TestQUICServerSendSessionInfoError(t *testing.T) {
	certFile, keyFile, cleanup := finalCreateCerts(t)
	defer cleanup()

	server, serverAddr := finalStartServer(t, certFile, keyFile)
	defer finalStopServer(t, server)

	client := finalCreateClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Send join
	params := finalCreateDKGParams(t, 0, 3, 2)
	if err := client.sendJoin(params); err != nil {
		t.Fatalf("Failed to send join: %v", err)
	}

	// Close stream immediately to cause sendSessionInfo to fail
	client.connMu.Lock()
	if client.stream != nil {
		_ = client.stream.Close()
	}
	client.connMu.Unlock()

	// Wait for server to attempt sending session info
	time.Sleep(200 * time.Millisecond)
}

// TestQUICRunDKGWithValidParams tests RunDKG with all valid parameters.
func TestQUICRunDKGWithValidParams(t *testing.T) {
	certFile, keyFile, cleanup := finalCreateCerts(t)
	defer cleanup()

	serverConfig := &transport.Config{
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
		SessionID:       "test-run-dkg",
	}

	server, err := NewQUICServer(serverConfig, sessionCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer finalStopServer(t, server)

	serverAddr := server.Address()

	// Create client
	client := finalCreateClient(t)
	connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(connectCtx, serverAddr); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Run DKG
	params := finalCreateDKGParams(t, 0, 3, 2)
	dkgCtx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	result, err := client.RunDKG(dkgCtx, params)
	if err != nil {
		t.Fatalf("RunDKG failed: %v", err)
	}

	if result == nil {
		t.Fatal("RunDKG returned nil result")
	}

	if result.SessionID != "test-run-dkg" {
		t.Errorf("Expected session ID 'test-run-dkg', got %s", result.SessionID)
	}
}

// TestQUICWaitForSessionInfoUnmarshalError tests unmarshal error in waitForSessionInfo.
func TestQUICWaitForSessionInfoUnmarshalError(t *testing.T) {
	client := finalCreateClient(t)

	// Send envelope with invalid payload
	go func() {
		time.Sleep(10 * time.Millisecond)
		client.incomingChan <- &transport.Envelope{
			Type:    transport.MsgTypeSessionInfo,
			Payload: []byte("invalid-json-data"),
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := client.waitForSessionInfo(ctx)
	if err == nil {
		t.Error("Expected unmarshal error for invalid session info")
	}
}

// TestQUICValidateParamsInvalidPubkeySize tests validateParams with invalid pubkey size.
func TestQUICValidateParamsInvalidPubkeySize(t *testing.T) {
	client := finalCreateClient(t)

	params := &transport.DKGParams{
		HostSeckey:     make([]byte, 32),
		Random:         make([]byte, 32),
		ParticipantIdx: 0,
		HostPubkeys:    [][]byte{make([]byte, 16)}, // Wrong size
		Threshold:      1,
	}

	err := client.validateParams(params)
	if err == nil {
		t.Error("Expected error for invalid pubkey size")
	}
}

// TestQUICServerCreateWithInvalidAddress tests server creation with invalid address.
func TestQUICServerCreateWithInvalidAddress(t *testing.T) {
	certFile, keyFile, cleanup := finalCreateCerts(t)
	defer cleanup()

	config := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     "", // Empty address
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}

	sessionCfg := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
	}

	server, err := NewQUICServer(config, sessionCfg)
	if err != nil {
		// Config error is acceptable
		return
	}

	ctx := context.Background()
	if err := server.Start(ctx); err == nil {
		// Empty address might default to 0.0.0.0, which can succeed
		finalStopServer(t, server)
	}
}

// TestQUICConnectOpenStreamError tests error path when OpenStreamSync fails.
func TestQUICConnectOpenStreamError(t *testing.T) {
	// This test is difficult to trigger without a mock, but we can test rapid connect/disconnect
	certFile, keyFile, cleanup := finalCreateCerts(t)
	defer cleanup()

	server, serverAddr := finalStartServer(t, certFile, keyFile)
	defer finalStopServer(t, server)

	client := finalCreateClient(t)

	// Use a very short timeout to potentially trigger stream open error
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	err := client.Connect(ctx, serverAddr)
	if err == nil {
		// Succeeded despite short timeout - disconnect
		_ = client.Disconnect()
	}
}

// Helper functions

func finalCreateCerts(t *testing.T) (certFile, keyFile string, cleanup func()) {
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

func finalStopServer(t *testing.T, server *QUICServer) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}
}

func finalCreateClient(t *testing.T) *QUICClient {
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

func finalCreateDKGParams(t *testing.T, idx, numParticipants, threshold int) *transport.DKGParams {
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

func finalStartServer(t *testing.T, certFile, keyFile string) (*QUICServer, string) {
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
