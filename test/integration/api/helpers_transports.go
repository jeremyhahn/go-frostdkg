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

package api

import (
	"fmt"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/grpc"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/http"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/quic"
)

// CreateGRPCCoordinator creates a gRPC-based coordinator for testing.
func CreateGRPCCoordinator(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
	certs *TLSCertificates,
) (transport.Coordinator, string, error) {
	port := AllocatePort()
	address := fmt.Sprintf("localhost:%d", port)

	config := &transport.Config{
		Protocol:    transport.ProtocolGRPC,
		Address:     address,
		TLSCertFile: certs.CertFile,
		TLSKeyFile:  certs.KeyFile,
		TLSCAFile:   certs.CAFile,
		CodecType:   "json",
		Ciphersuite: ciphersuite,
		Timeout:     30 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		SessionID:       sessionID,
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     ciphersuite,
		Timeout:         5 * time.Minute,
	}

	server, err := grpc.NewGRPCServer(config, sessionConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create gRPC server: %w", err)
	}

	return server, address, nil
}

// CreateGRPCParticipants creates n gRPC-based participants for testing.
func CreateGRPCParticipants(n int, certs *TLSCertificates, ciphersuite string) ([]transport.Participant, error) {
	if n < 1 {
		return nil, fmt.Errorf("n must be >= 1")
	}

	participants := make([]transport.Participant, n)

	for i := 0; i < n; i++ {
		config := &transport.Config{
			Protocol:    transport.ProtocolGRPC,
			TLSCertFile: certs.CertFile,
			TLSKeyFile:  certs.KeyFile,
			TLSCAFile:   certs.CAFile,
			CodecType:   "json",
			Ciphersuite: ciphersuite,
			Timeout:     30 * time.Second,
		}

		client, err := grpc.NewGRPCClient(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create gRPC client %d: %w", i, err)
		}

		participants[i] = client
	}

	return participants, nil
}

// CreateHTTPCoordinator creates an HTTP-based coordinator for testing.
func CreateHTTPCoordinator(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
	certs *TLSCertificates,
) (transport.Coordinator, string, error) {
	port := AllocatePort()
	address := fmt.Sprintf("localhost:%d", port)

	config := &transport.Config{
		Protocol:    transport.ProtocolHTTP,
		Address:     address,
		TLSCertFile: certs.CertFile,
		TLSKeyFile:  certs.KeyFile,
		TLSCAFile:   certs.CAFile,
		CodecType:   "json",
		Ciphersuite: ciphersuite,
		Timeout:     30 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     ciphersuite,
		Timeout:         5 * time.Minute,
	}

	server, err := http.NewHTTPServer(config, sessionConfig, sessionID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create HTTP server: %w", err)
	}

	return server, address, nil
}

// CreateHTTPParticipants creates n HTTP-based participants for testing.
func CreateHTTPParticipants(n int, certs *TLSCertificates, ciphersuite string) ([]transport.Participant, error) {
	if n < 1 {
		return nil, fmt.Errorf("n must be >= 1")
	}

	participants := make([]transport.Participant, n)

	for i := 0; i < n; i++ {
		config := &transport.Config{
			Protocol:    transport.ProtocolHTTP,
			TLSCertFile: certs.CertFile,
			TLSKeyFile:  certs.KeyFile,
			TLSCAFile:   certs.CAFile,
			CodecType:   "json",
			Ciphersuite: ciphersuite,
			Timeout:     30 * time.Second,
		}

		client, err := http.NewHTTPClient(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP client %d: %w", i, err)
		}

		participants[i] = client
	}

	return participants, nil
}

// CreateQUICCoordinator creates a QUIC-based coordinator for testing.
func CreateQUICCoordinator(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
	certs *TLSCertificates,
) (transport.Coordinator, string, error) {
	port := AllocatePort()
	address := fmt.Sprintf("localhost:%d", port)

	config := &transport.Config{
		Protocol:    transport.ProtocolQUIC,
		Address:     address,
		TLSCertFile: certs.CertFile,
		TLSKeyFile:  certs.KeyFile,
		TLSCAFile:   certs.CAFile,
		CodecType:   "json",
		Ciphersuite: ciphersuite,
		Timeout:     30 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		SessionID:       sessionID,
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     ciphersuite,
		Timeout:         5 * time.Minute,
	}

	server, err := quic.NewQUICServer(config, sessionConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create QUIC server: %w", err)
	}

	return server, address, nil
}

// CreateQUICParticipants creates n QUIC-based participants for testing.
func CreateQUICParticipants(n int, certs *TLSCertificates, ciphersuite string) ([]transport.Participant, error) {
	if n < 1 {
		return nil, fmt.Errorf("n must be >= 1")
	}

	participants := make([]transport.Participant, n)

	for i := 0; i < n; i++ {
		config := &transport.Config{
			Protocol:    transport.ProtocolQUIC,
			TLSCertFile: certs.CertFile,
			TLSKeyFile:  certs.KeyFile,
			TLSCAFile:   certs.CAFile,
			CodecType:   "json",
			Ciphersuite: ciphersuite,
			Timeout:     30 * time.Second,
		}

		client, err := quic.NewQUICClient(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create QUIC client %d: %w", i, err)
		}

		participants[i] = client
	}

	return participants, nil
}

// CreateUnixCoordinator creates a Unix socket-based coordinator for testing.
func CreateUnixCoordinator(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
) (transport.Coordinator, string, error) {
	// Use a unique socket path in /tmp
	socketPath := fmt.Sprintf("/tmp/frostdkg-test-%s.sock", sessionID)

	config := &transport.Config{
		Protocol:    transport.ProtocolUnix,
		Address:     socketPath,
		CodecType:   "json",
		Ciphersuite: ciphersuite,
		Timeout:     30 * time.Second,
	}

	sessionConfig := &transport.SessionConfig{
		SessionID:       sessionID,
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     ciphersuite,
		Timeout:         5 * time.Minute,
	}

	// Unix sockets use gRPC transport
	server, err := grpc.NewGRPCServer(config, sessionConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create Unix socket server: %w", err)
	}

	return server, socketPath, nil
}

// CreateUnixParticipants creates n Unix socket-based participants for testing.
func CreateUnixParticipants(n int, ciphersuite string) ([]transport.Participant, error) {
	if n < 1 {
		return nil, fmt.Errorf("n must be >= 1")
	}

	participants := make([]transport.Participant, n)

	for i := 0; i < n; i++ {
		config := &transport.Config{
			Protocol:    transport.ProtocolUnix,
			CodecType:   "json",
			Ciphersuite: ciphersuite,
			Timeout:     30 * time.Second,
		}

		// Unix sockets use gRPC transport
		client, err := grpc.NewGRPCClient(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create Unix socket client %d: %w", i, err)
		}

		participants[i] = client
	}

	return participants, nil
}
