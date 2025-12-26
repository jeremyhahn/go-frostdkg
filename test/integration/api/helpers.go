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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/memory"
)

var (
	// Port allocator for tests
	nextPort = atomic.Int32{}
)

func init() {
	// Use a random starting port in range [20000, 50000) to avoid conflicts
	// when multiple test packages run in parallel. Each package gets a
	// different random starting range.
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback to time-based if crypto/rand fails
		nextPort.Store(20000 + int32(time.Now().UnixNano()%30000))
	} else {
		// Use random value in range [20000, 50000)
		randomOffset := int32(binary.LittleEndian.Uint32(buf[:]) % 30000)
		nextPort.Store(20000 + randomOffset)
	}
}

// AllocatePort returns the next available test port.
func AllocatePort() int {
	return int(nextPort.Add(1))
}

// GenerateSessionID creates a unique session ID for testing.
func GenerateSessionID() string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("test-session-%d", timestamp)
}

// GenerateHostKeys generates n host key pairs for testing.
// Returns (seckeys, pubkeys, error).
// The secret keys are 32-byte Ed25519 seeds, and public keys are 32-byte Ed25519 public keys.
func GenerateHostKeys(n int) ([][]byte, [][]byte, error) {
	if n < 1 {
		return nil, nil, fmt.Errorf("n must be >= 1")
	}

	seckeys := make([][]byte, n)
	pubkeys := make([][]byte, n)

	for i := 0; i < n; i++ {
		pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate key for participant %d: %w", i, err)
		}

		// Ed25519 private key is 64 bytes: first 32 bytes are the seed
		// The transport layer expects 32-byte secret keys
		seckeys[i] = privkey.Seed()
		pubkeys[i] = pubkey
	}

	return seckeys, pubkeys, nil
}

// GenerateDKGParams creates DKG parameters for testing.
func GenerateDKGParams(
	participantIdx int,
	threshold int,
	hostSeckeys [][]byte,
	hostPubkeys [][]byte,
) (*transport.DKGParams, error) {
	if participantIdx < 0 || participantIdx >= len(hostSeckeys) {
		return nil, fmt.Errorf("invalid participant index: %d", participantIdx)
	}

	if len(hostSeckeys) != len(hostPubkeys) {
		return nil, fmt.Errorf("seckeys and pubkeys length mismatch")
	}

	if threshold < 1 || threshold > len(hostSeckeys) {
		return nil, fmt.Errorf("invalid threshold: %d", threshold)
	}

	// Generate random bytes for DKG
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("failed to generate randomness: %w", err)
	}

	return &transport.DKGParams{
		HostSeckey:     hostSeckeys[participantIdx],
		HostPubkeys:    hostPubkeys,
		Threshold:      threshold,
		ParticipantIdx: participantIdx,
		Random:         random,
	}, nil
}

// CreateMemoryCoordinator creates a memory-based coordinator for testing.
func CreateMemoryCoordinator(
	sessionID string,
	threshold int,
	numParticipants int,
	ciphersuite string,
) (transport.Coordinator, error) {
	config := &transport.SessionConfig{
		Threshold:       threshold,
		NumParticipants: numParticipants,
		Ciphersuite:     ciphersuite,
		Timeout:         5 * time.Minute,
	}

	return memory.NewMemoryCoordinator(sessionID, config)
}

// CreateMemoryParticipants creates n memory-based participants for testing.
func CreateMemoryParticipants(n int, coordinator *memory.MemoryCoordinator) ([]transport.Participant, error) {
	if n < 1 {
		return nil, fmt.Errorf("n must be >= 1")
	}

	participants := make([]transport.Participant, n)

	for i := 0; i < n; i++ {
		participantID := fmt.Sprintf("participant-%d", i)
		p, err := memory.NewMemoryParticipant(participantID)
		if err != nil {
			return nil, fmt.Errorf("failed to create participant %d: %w", i, err)
		}

		// Set coordinator for memory transport
		p.SetCoordinator(coordinator)
		participants[i] = p
	}

	return participants, nil
}

// TLSCertificates holds test TLS certificate files.
type TLSCertificates struct {
	CertFile string
	KeyFile  string
	CAFile   string
	TempDir  string
}

// GenerateTestCertificates creates test TLS certificates in a temporary directory.
func GenerateTestCertificates() (*TLSCertificates, error) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "frostdkg-test-certs-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Generate CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"FROST DKG Test CA"},
			CommonName:   "FROST DKG Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Write CA certificate
	caFile := filepath.Join(tempDir, "ca.pem")
	caOut, err := os.Create(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA file: %w", err)
	}
	if err := pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
		caOut.Close()
		return nil, fmt.Errorf("failed to write CA certificate: %w", err)
	}
	caOut.Close()

	// Generate server certificate
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"FROST DKG Test"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Write server certificate
	certFile := filepath.Join(tempDir, "server.pem")
	certOut, err := os.Create(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert file: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}); err != nil {
		certOut.Close()
		return nil, fmt.Errorf("failed to write server certificate: %w", err)
	}
	certOut.Close()

	// Write server key
	keyFile := filepath.Join(tempDir, "server-key.pem")
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create key file: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	}); err != nil {
		keyOut.Close()
		return nil, fmt.Errorf("failed to write server key: %w", err)
	}
	keyOut.Close()

	return &TLSCertificates{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
		TempDir:  tempDir,
	}, nil
}

// Cleanup removes the temporary certificate directory.
func (c *TLSCertificates) Cleanup() error {
	if c.TempDir != "" {
		return os.RemoveAll(c.TempDir)
	}
	return nil
}

// CleanupFunc is a function that performs cleanup operations.
type CleanupFunc func() error

// CleanupManager manages cleanup functions for tests.
type CleanupManager struct {
	cleanups []CleanupFunc
}

// NewCleanupManager creates a new cleanup manager.
func NewCleanupManager() *CleanupManager {
	return &CleanupManager{
		cleanups: make([]CleanupFunc, 0),
	}
}

// Add adds a cleanup function.
func (cm *CleanupManager) Add(fn CleanupFunc) {
	if fn != nil {
		cm.cleanups = append(cm.cleanups, fn)
	}
}

// AddCoordinator adds cleanup for a coordinator.
func (cm *CleanupManager) AddCoordinator(coord transport.Coordinator) {
	cm.Add(func() error {
		return coord.Stop(context.Background())
	})
}

// AddParticipant adds cleanup for a participant.
func (cm *CleanupManager) AddParticipant(p transport.Participant) {
	cm.Add(func() error {
		return p.Disconnect()
	})
}

// AddCertificates adds cleanup for test certificates.
func (cm *CleanupManager) AddCertificates(certs *TLSCertificates) {
	cm.Add(func() error {
		return certs.Cleanup()
	})
}

// Cleanup runs all cleanup functions in reverse order.
func (cm *CleanupManager) Cleanup() error {
	var firstErr error

	// Run cleanups in reverse order
	for i := len(cm.cleanups) - 1; i >= 0; i-- {
		if err := cm.cleanups[i](); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// WaitWithTimeout waits for a condition with timeout.
func WaitWithTimeout(ctx context.Context, timeout time.Duration, condition func() bool) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if condition() {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for condition: %w", ctx.Err())
		case <-ticker.C:
			// Continue checking
		}
	}
}
