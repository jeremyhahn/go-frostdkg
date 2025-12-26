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
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TestFullDKGFlow tests complete DKG execution
func TestFullDKGFlow(t *testing.T) {
	numParticipants := 3
	threshold := 2

	// Start server
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   30 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "full-dkg-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Mock certificate for testing
	// In production this would be generated from the DKG process
	server.mu.Lock()
	server.certificate = []byte("mock-certificate-data")
	server.mu.Unlock()

	// Create participants
	hostPubkeys := make([][]byte, numParticipants)
	hostSeckeys := make([][]byte, numParticipants)
	randoms := make([][]byte, numParticipants)

	for i := 0; i < numParticipants; i++ {
		hostSeckeys[i] = make([]byte, 32)
		if _, err := rand.Read(hostSeckeys[i]); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		hostPubkeys[i] = make([]byte, transport.PublicKeySize)
		if _, err := rand.Read(hostPubkeys[i]); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		randoms[i] = make([]byte, 32)
		if _, err := rand.Read(randoms[i]); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}
	}

	// Run DKG concurrently
	var wg sync.WaitGroup
	errCh := make(chan error, numParticipants)
	resultCh := make(chan *transport.DKGResult, numParticipants)

	for i := 0; i < numParticipants; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			clientConfig := &transport.Config{
				Protocol:  transport.ProtocolHTTP,
				CodecType: "json",
				Timeout:   30 * time.Second,
			}

			client, err := NewHTTPClient(clientConfig)
			if err != nil {
				errCh <- err
				return
			}

			if err := client.Connect(ctx, server.Address()); err != nil {
				errCh <- err
				return
			}
			defer func() { _ = client.Disconnect() }()

			params := &transport.DKGParams{
				HostSeckey:     hostSeckeys[idx],
				HostPubkeys:    hostPubkeys,
				Threshold:      threshold,
				ParticipantIdx: idx,
				Random:         randoms[idx],
			}

			result, err := client.RunDKG(ctx, params)
			if err != nil {
				errCh <- err
				return
			}

			resultCh <- result
		}(i)
	}

	wg.Wait()
	close(errCh)
	close(resultCh)

	// Check for errors
	for err := range errCh {
		t.Errorf("participant error: %v", err)
	}

	// Collect results
	results := make([]*transport.DKGResult, 0, numParticipants)
	for result := range resultCh {
		results = append(results, result)
	}

	if len(results) != numParticipants {
		t.Errorf("unexpected number of results: got %d, want %d", len(results), numParticipants)
	}

	// Verify all results have the same session ID
	if len(results) > 0 {
		sessionID := results[0].SessionID
		for i, result := range results {
			if result.SessionID != sessionID {
				t.Errorf("participant %d: session ID mismatch: got %s, want %s", i, result.SessionID, sessionID)
			}

			if len(result.RecoveryData) == 0 {
				t.Errorf("participant %d: empty recovery data", i)
			}
		}
	}
}

// TestClientNotConnected tests running DKG without connecting first
func TestClientNotConnected(t *testing.T) {
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// Generate valid params
	hostSeckey := make([]byte, 32)
	if _, err := rand.Read(hostSeckey); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	hostPubkey := make([]byte, transport.PublicKeySize)
	if _, err := rand.Read(hostPubkey); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	params := &transport.DKGParams{
		HostSeckey:     hostSeckey,
		HostPubkeys:    [][]byte{hostPubkey},
		Threshold:      1,
		ParticipantIdx: 0,
		Random:         random,
	}

	// Try to run DKG without connecting
	_, err = client.RunDKG(ctx, params)
	if err != transport.ErrNotConnected {
		t.Errorf("expected ErrNotConnected, got %v", err)
	}
}

// TestClientAlreadyConnected tests double connection
func TestClientAlreadyConnected(t *testing.T) {
	// Start server
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "double-connect-session")
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
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// First connection
	if err := client.Connect(ctx, server.Address()); err != nil {
		t.Fatalf("failed to connect first time: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Second connection - should fail
	if err := client.Connect(ctx, server.Address()); err != transport.ErrAlreadyConnected {
		t.Errorf("expected ErrAlreadyConnected, got %v", err)
	}
}

// TestClientDisconnectNotConnected tests disconnecting when not connected
func TestClientDisconnectNotConnected(t *testing.T) {
	clientConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		CodecType: "json",
	}

	client, err := NewHTTPClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Try to disconnect when not connected
	if err := client.Disconnect(); err != transport.ErrNotConnected {
		t.Errorf("expected ErrNotConnected, got %v", err)
	}
}

// TestHTTPErrorType tests HTTPError implementation
func TestHTTPErrorType(t *testing.T) {
	err := &HTTPError{
		StatusCode: 404,
		Message:    "not found",
	}

	expected := "HTTP 404: not found"
	if err.Error() != expected {
		t.Errorf("unexpected error string: got %s, want %s", err.Error(), expected)
	}
}

// TestRouteError tests RouteError implementation
func TestRouteError(t *testing.T) {
	err := &RouteError{
		Path:   "/test/path",
		Method: "GET",
		Err:    transport.ErrSessionNotFound,
	}

	errStr := err.Error()
	if errStr == "" {
		t.Error("error string is empty")
	}

	unwrapped := err.Unwrap()
	if unwrapped != transport.ErrSessionNotFound {
		t.Errorf("unexpected unwrapped error: got %v, want %v", unwrapped, transport.ErrSessionNotFound)
	}
}

// TestServerDoubleStart tests starting server twice
func TestServerDoubleStart(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "double-start-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()

	// First start
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start first time: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	// Second start - should fail
	if err := server.Start(ctx); err == nil {
		t.Error("expected error on second start, got none")
	}
}

// TestServerDoubleStop tests stopping server twice
func TestServerDoubleStop(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "double-stop-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	stopCtx := context.Background()

	// First stop
	if err := server.Stop(stopCtx); err != nil {
		t.Errorf("failed to stop first time: %v", err)
	}

	// Second stop - should not error
	if err := server.Stop(stopCtx); err != nil {
		t.Errorf("unexpected error on second stop: %v", err)
	}
}

// TestCodecConversion tests codec type conversion edge cases
func TestCodecConversion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"unknown codec", "unknown", ContentTypeJSON},
		{"toml codec", "toml", ContentTypeJSON},
		{"yaml codec", "yaml", ContentTypeJSON},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CodecToContentType(tt.input)
			if result != tt.expected {
				t.Errorf("unexpected result: got %s, want %s", result, tt.expected)
			}
		})
	}
}
