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
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TestHTTPEndpoints tests all HTTP endpoints
func TestHTTPEndpoints(t *testing.T) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   10 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
		Timeout:         5 * time.Minute,
	}

	server, err := NewHTTPServer(serverConfig, sessionConfig, "test-endpoints-session")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = server.Stop(context.Background()) }()

	baseURL := fmt.Sprintf("http://%s", server.Address())

	// Test health endpoint
	t.Run("health check", func(t *testing.T) {
		resp, err := http.Get(baseURL + PathHealth)
		if err != nil {
			t.Fatalf("failed to check health: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	// Test create session (POST /sessions)
	t.Run("create session", func(t *testing.T) {
		resp, err := http.Post(baseURL+PathSessions, "application/json", nil)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var sessionInfo transport.SessionInfoMessage
		if err := json.NewDecoder(resp.Body).Decode(&sessionInfo); err != nil {
			t.Fatalf("failed to decode session info: %v", err)
		}

		if sessionInfo.SessionID != "test-endpoints-session" {
			t.Errorf("unexpected session ID: got %s, want %s", sessionInfo.SessionID, "test-endpoints-session")
		}
	})

	// Test get session (GET /sessions/{id})
	t.Run("get session", func(t *testing.T) {
		url := baseURL + SessionPath("test-endpoints-session")
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("failed to get session: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	// Test join session
	t.Run("join session", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			hostPubkey := make([]byte, transport.PublicKeySize)
			if _, err := rand.Read(hostPubkey); err != nil {
				t.Fatalf("failed to generate random hostPubkey: %v", err)
			}

			joinMsg := &transport.JoinMessage{
				HostPubkey: hostPubkey,
			}

			data, err := json.Marshal(joinMsg)
			if err != nil {
				t.Fatalf("failed to marshal join message: %v", err)
			}

			url := baseURL + JoinSessionPath("test-endpoints-session")
			resp, err := http.Post(url, "application/json", bytes.NewReader(data))
			if err != nil {
				t.Fatalf("failed to join session: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusCreated {
				t.Errorf("participant %d: unexpected status: got %d, want %d", i, resp.StatusCode, http.StatusCreated)
			}

			var sessionInfo transport.SessionInfoMessage
			if err := json.NewDecoder(resp.Body).Decode(&sessionInfo); err != nil {
				t.Fatalf("participant %d: failed to decode session info: %v", i, err)
			}

			if sessionInfo.ParticipantIdx != i {
				t.Errorf("participant %d: unexpected index: got %d, want %d", i, sessionInfo.ParticipantIdx, i)
			}
		}
	})

	// Test duplicate participant
	t.Run("duplicate participant", func(t *testing.T) {
		hostPubkey := make([]byte, transport.PublicKeySize)
		if _, err := rand.Read(hostPubkey); err != nil {
			t.Fatalf("failed to generate random hostPubkey: %v", err)
		}

		// First join
		joinMsg := &transport.JoinMessage{
			HostPubkey: hostPubkey,
		}
		data, _ := json.Marshal(joinMsg)
		url := baseURL + JoinSessionPath("test-endpoints-session")
		_, _ = http.Post(url, "application/json", bytes.NewReader(data))

		// Second join with same pubkey - should fail in a new server
		// But our current server is already full, so we'll test this in a separate test
	})

	// Test Round1 submission
	t.Run("round1 submission", func(t *testing.T) {
		round1Msg := &transport.Round1Message{
			Commitment: [][]byte{{1, 2, 3}},
			POP:        []byte{4, 5, 6},
			Pubnonce:   []byte{7, 8, 9},
		}

		data, err := json.Marshal(round1Msg)
		if err != nil {
			t.Fatalf("failed to marshal round1 message: %v", err)
		}

		for i := 0; i < 3; i++ {
			url := fmt.Sprintf("%s%s?participant_idx=%d", baseURL, Round1Path("test-endpoints-session"), i)
			resp, err := http.Post(url, "application/json", bytes.NewReader(data))
			if err != nil {
				t.Fatalf("participant %d: failed to submit round1: %v", i, err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusCreated {
				t.Errorf("participant %d: unexpected status: got %d, want %d", i, resp.StatusCode, http.StatusCreated)
			}
		}
	})

	// Test Round1 retrieval
	t.Run("round1 retrieval", func(t *testing.T) {
		url := baseURL + Round1Path("test-endpoints-session")
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("failed to get round1: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var round1Agg transport.Round1AggMessage
		if err := json.NewDecoder(resp.Body).Decode(&round1Agg); err != nil {
			t.Fatalf("failed to decode round1 agg: %v", err)
		}

		if len(round1Agg.AllCommitments) != 3 {
			t.Errorf("unexpected commitments count: got %d, want 3", len(round1Agg.AllCommitments))
		}
	})

	// Test Round2 submission
	t.Run("round2 submission", func(t *testing.T) {
		round2Msg := &transport.Round2Message{
			EncryptedShares: []byte{10, 11, 12},
		}

		data, err := json.Marshal(round2Msg)
		if err != nil {
			t.Fatalf("failed to marshal round2 message: %v", err)
		}

		for i := 0; i < 3; i++ {
			url := fmt.Sprintf("%s%s?participant_idx=%d", baseURL, Round2Path("test-endpoints-session"), i)
			resp, err := http.Post(url, "application/json", bytes.NewReader(data))
			if err != nil {
				t.Fatalf("participant %d: failed to submit round2: %v", i, err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusCreated {
				t.Errorf("participant %d: unexpected status: got %d, want %d", i, resp.StatusCode, http.StatusCreated)
			}
		}
	})

	// Test Round2 retrieval
	t.Run("round2 retrieval", func(t *testing.T) {
		url := fmt.Sprintf("%s%s?participant_idx=0", baseURL, Round2Path("test-endpoints-session"))
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("failed to get round2: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	// Test CertEq submission
	t.Run("certeq submission", func(t *testing.T) {
		certEqMsg := &transport.CertEqSignMessage{
			Signature: []byte{13, 14, 15},
		}

		data, err := json.Marshal(certEqMsg)
		if err != nil {
			t.Fatalf("failed to marshal certeq message: %v", err)
		}

		for i := 0; i < 3; i++ {
			url := fmt.Sprintf("%s%s?participant_idx=%d", baseURL, CertEqPath("test-endpoints-session"), i)
			resp, err := http.Post(url, "application/json", bytes.NewReader(data))
			if err != nil {
				t.Fatalf("participant %d: failed to submit certeq: %v", i, err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusCreated {
				t.Errorf("participant %d: unexpected status: got %d, want %d", i, resp.StatusCode, http.StatusCreated)
			}
		}
	})
}

// TestErrorHandling tests error conditions
func TestErrorHandling(t *testing.T) {
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

	baseURL := fmt.Sprintf("http://%s", server.Address())

	// Test health with wrong method
	t.Run("health wrong method", func(t *testing.T) {
		resp, err := http.Post(baseURL+PathHealth, "application/json", nil)
		if err != nil {
			t.Fatalf("failed to post health: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
		}
	})

	// Test session not found
	t.Run("session not found", func(t *testing.T) {
		url := baseURL + SessionPath("nonexistent")
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("failed to get session: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
	})

	// Test invalid JSON
	t.Run("invalid json", func(t *testing.T) {
		url := baseURL + JoinSessionPath("error-test-session")
		resp, err := http.Post(url, "application/json", bytes.NewReader([]byte("invalid json")))
		if err != nil {
			t.Fatalf("failed to post invalid json: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	// Test session full
	t.Run("session full", func(t *testing.T) {
		// Join with 2 participants (full session)
		for i := 0; i < 2; i++ {
			hostPubkey := make([]byte, transport.PublicKeySize)
			if _, err := rand.Read(hostPubkey); err != nil {
				t.Fatalf("failed to generate random hostPubkey: %v", err)
			}
			joinMsg := &transport.JoinMessage{HostPubkey: hostPubkey}
			data, _ := json.Marshal(joinMsg)
			url := baseURL + JoinSessionPath("error-test-session")
			_, _ = http.Post(url, "application/json", bytes.NewReader(data))
		}

		// Try to join again - should fail
		hostPubkey := make([]byte, transport.PublicKeySize)
		if _, err := rand.Read(hostPubkey); err != nil {
			t.Fatalf("failed to generate random hostPubkey: %v", err)
		}
		joinMsg := &transport.JoinMessage{HostPubkey: hostPubkey}
		data, _ := json.Marshal(joinMsg)
		url := baseURL + JoinSessionPath("error-test-session")
		resp, err := http.Post(url, "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatalf("failed to post join: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusConflict {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusConflict)
		}
	})

	// Test round1 without participant_idx
	t.Run("round1 no participant idx", func(t *testing.T) {
		round1Msg := &transport.Round1Message{
			Commitment: [][]byte{{1, 2, 3}},
			POP:        []byte{4, 5, 6},
			Pubnonce:   []byte{7, 8, 9},
		}
		data, _ := json.Marshal(round1Msg)
		url := baseURL + Round1Path("error-test-session")
		resp, err := http.Post(url, "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatalf("failed to post round1: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	// Test round1 not ready
	t.Run("round1 not ready", func(t *testing.T) {
		url := baseURL + Round1Path("error-test-session")
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("failed to get round1: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusAccepted)
		}
	})

	// Test certificate not ready
	t.Run("certificate not ready", func(t *testing.T) {
		url := baseURL + CertificatePath("error-test-session")
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("failed to get certificate: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusAccepted)
		}
	})
}

// TestDifferentSerializationFormats tests CBOR and MessagePack
func TestDifferentSerializationFormats(t *testing.T) {
	formats := []struct {
		name        string
		codecType   string
		contentType string
	}{
		{"JSON", "json", "application/json"},
		{"CBOR", "cbor", "application/cbor"},
		{"MessagePack", "msgpack", "application/msgpack"},
	}

	for _, fmt := range formats {
		t.Run(fmt.name, func(t *testing.T) {
			serverConfig := &transport.Config{
				Protocol:  transport.ProtocolHTTP,
				Address:   "localhost:0",
				CodecType: fmt.codecType,
				Timeout:   5 * time.Second,
			}

			sessionConfig := &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
			}

			server, err := NewHTTPServer(serverConfig, sessionConfig, "format-test-"+fmt.name)
			if err != nil {
				t.Fatalf("failed to create server: %v", err)
			}

			ctx := context.Background()
			if err := server.Start(ctx); err != nil {
				t.Fatalf("failed to start server: %v", err)
			}
			defer func() { _ = server.Stop(context.Background()) }()

			// Test with client using the same format
			clientConfig := &transport.Config{
				Protocol:  transport.ProtocolHTTP,
				CodecType: fmt.codecType,
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
		})
	}
}

// BenchmarkEndpointPerformance benchmarks endpoint performance
func BenchmarkEndpointPerformance(b *testing.B) {
	serverConfig := &transport.Config{
		Protocol:  transport.ProtocolHTTP,
		Address:   "localhost:0",
		CodecType: "json",
		Timeout:   30 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 1000, // Large session
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

	baseURL := fmt.Sprintf("http://%s", server.Address())

	b.ResetTimer()

	b.Run("health check", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			resp, err := http.Get(baseURL + PathHealth)
			if err != nil {
				b.Fatalf("failed to check health: %v", err)
			}
			_ = resp.Body.Close()
		}
	})

	b.Run("get session", func(b *testing.B) {
		url := baseURL + SessionPath("bench-session")
		for i := 0; i < b.N; i++ {
			resp, err := http.Get(url)
			if err != nil {
				b.Fatalf("failed to get session: %v", err)
			}
			_ = resp.Body.Close()
		}
	})
}
