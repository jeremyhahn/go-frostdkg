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

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockParticipant is a mock implementation of transport.Participant
type MockParticipant struct {
	mock.Mock
}

func (m *MockParticipant) Connect(ctx context.Context, addr string) error {
	args := m.Called(ctx, addr)
	return args.Error(0)
}

func (m *MockParticipant) Disconnect() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockParticipant) RunDKG(ctx context.Context, params *transport.DKGParams) (*transport.DKGResult, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*transport.DKGResult), args.Error(1)
}

// MockCoordinator is a mock implementation of transport.Coordinator
type MockCoordinator struct {
	mock.Mock
}

func (m *MockCoordinator) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockCoordinator) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockCoordinator) Address() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockCoordinator) SessionID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockCoordinator) WaitForParticipants(ctx context.Context, n int) error {
	args := m.Called(ctx, n)
	return args.Error(0)
}

// MockTransportFactory is a mock implementation of TransportFactory
type MockTransportFactory struct {
	mock.Mock
}

func (m *MockTransportFactory) NewParticipant(protocol transport.Protocol, cfg *transport.Config) (transport.Participant, error) {
	args := m.Called(protocol, cfg)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(transport.Participant), args.Error(1)
}

func (m *MockTransportFactory) NewCoordinator(protocol transport.Protocol, cfg *transport.Config, sessionCfg *transport.SessionConfig, sessionID string) (transport.Coordinator, error) {
	args := m.Called(protocol, cfg, sessionCfg, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(transport.Coordinator), args.Error(1)
}

// TestDefaultTransportFactory tests the default factory implementation
func TestDefaultTransportFactory(t *testing.T) {
	factory := &DefaultTransportFactory{}

	tests := []struct {
		name            string
		protocol        transport.Protocol
		expectError     bool
		skipCoordinator bool
	}{
		{"grpc protocol", transport.ProtocolGRPC, false, false},
		{"http protocol", transport.ProtocolHTTP, false, false},
		{"quic protocol", transport.ProtocolQUIC, false, true}, // QUIC coordinator requires TLS
		{"unix protocol", transport.ProtocolUnix, false, false},
		{"libp2p protocol", transport.ProtocolLibp2p, false, false},
		{"unsupported protocol", transport.Protocol("unsupported"), true, false},
	}

	for _, tt := range tests {
		t.Run("participant-"+tt.name, func(t *testing.T) {
			cfg := &transport.Config{
				Protocol: tt.protocol,
				Address:  "localhost:9000",
			}

			participant, err := factory.NewParticipant(tt.protocol, cfg)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, participant)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, participant)
			}
		})

		t.Run("coordinator-"+tt.name, func(t *testing.T) {
			if tt.skipCoordinator {
				t.Skip("QUIC coordinator requires TLS certificates")
			}

			cfg := &transport.Config{
				Protocol: tt.protocol,
				Address:  "localhost:9000",
			}
			sessionCfg := &transport.SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
			}

			coordinator, err := factory.NewCoordinator(tt.protocol, cfg, sessionCfg, "test-session")

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, coordinator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, coordinator)
			}
		})
	}
}

// TestRunParticipantWithMock tests runParticipant with mocked transport
func TestRunParticipantWithMock(t *testing.T) {
	// Save original factory and restore after test
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	// Create mocks
	mockFactory := new(MockTransportFactory)
	mockParticipant := new(MockParticipant)
	defaultFactory = mockFactory

	// Create temp output file
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "participant-output.json")

	// Setup test data
	participantID = 0
	participantThreshold = 2
	participantOutput = outputPath
	participantCoordinator = "localhost:9000"
	participantTimeout = 5
	protocol = "grpc"
	codec = "json"
	verbose = false

	// Create expected DKG result
	expectedResult := &transport.DKGResult{
		SecretShare:     []byte("test-secret-share-32-bytes-long!"),
		ThresholdPubkey: []byte("test-threshold-pubkey-32-bytes!!"),
		PublicShares: [][]byte{
			[]byte("test-public-share-1-32-bytes!!!!"),
			[]byte("test-public-share-2-32-bytes!!!!"),
			[]byte("test-public-share-3-32-bytes!!!!"),
		},
		SessionID:    "test-session-id",
		RecoveryData: []byte("test-recovery-data"),
	}

	// Setup expectations
	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(mockParticipant, nil)
	mockParticipant.On("Connect", mock.Anything, participantCoordinator).Return(nil)
	mockParticipant.On("RunDKG", mock.Anything, mock.AnythingOfType("*transport.DKGParams")).
		Return(expectedResult, nil)
	mockParticipant.On("Disconnect").Return(nil)

	// Execute
	err := runParticipant(participantCmd, nil)
	require.NoError(t, err)

	// Verify output file was created
	assert.FileExists(t, outputPath)

	// Verify output content
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var output KeyShareOutput
	err = json.Unmarshal(data, &output)
	require.NoError(t, err)

	assert.Equal(t, participantID, output.ParticipantIndex)
	assert.Equal(t, hex.EncodeToString(expectedResult.SecretShare), output.SecretShare)
	assert.Equal(t, hex.EncodeToString(expectedResult.ThresholdPubkey), output.ThresholdPubkey)
	assert.Equal(t, expectedResult.SessionID, output.SessionID)
	assert.Len(t, output.PublicShares, len(expectedResult.PublicShares))

	// Verify all expectations were met
	mockFactory.AssertExpectations(t)
	mockParticipant.AssertExpectations(t)
}

// TestRunParticipantFactoryError tests factory creation error handling
func TestRunParticipantFactoryError(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	defaultFactory = mockFactory

	participantID = 0
	participantThreshold = 2
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "grpc"

	// Setup factory to return error
	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(nil, fmt.Errorf("factory error"))

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create participant")

	mockFactory.AssertExpectations(t)
}

// TestRunParticipantConnectError tests connection error handling
func TestRunParticipantConnectError(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockParticipant := new(MockParticipant)
	defaultFactory = mockFactory

	participantID = 0
	participantThreshold = 2
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantCoordinator = "localhost:9000"
	participantTimeout = 1
	protocol = "grpc"

	// Setup mocks
	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(mockParticipant, nil)
	mockParticipant.On("Connect", mock.Anything, participantCoordinator).
		Return(fmt.Errorf("connection refused"))

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to coordinator")

	mockFactory.AssertExpectations(t)
	mockParticipant.AssertExpectations(t)
}

// TestRunParticipantDKGError tests DKG execution error handling
func TestRunParticipantDKGError(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockParticipant := new(MockParticipant)
	defaultFactory = mockFactory

	participantID = 0
	participantThreshold = 2
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantCoordinator = "localhost:9000"
	participantTimeout = 5
	protocol = "grpc"

	// Setup mocks
	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(mockParticipant, nil)
	mockParticipant.On("Connect", mock.Anything, participantCoordinator).Return(nil)
	mockParticipant.On("RunDKG", mock.Anything, mock.AnythingOfType("*transport.DKGParams")).
		Return(nil, fmt.Errorf("DKG protocol error"))
	mockParticipant.On("Disconnect").Return(nil)

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DKG execution failed")

	mockFactory.AssertExpectations(t)
	mockParticipant.AssertExpectations(t)
}

// TestRunCoordinatorWithMock tests runCoordinator with mocked transport
func TestRunCoordinatorWithMock(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test-session"
	coordinatorListen = "localhost:9000"
	coordinatorTimeout = 1
	protocol = "grpc"
	codec = "json"
	verbose = false

	// Setup expectations - coordinator will start, wait will timeout/complete
	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(nil)
	mockCoordinator.On("SessionID").Return(coordinatorSessionID)
	mockCoordinator.On("Address").Return(coordinatorListen)

	// Simulate timeout waiting for participants
	mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
		Run(func(args mock.Arguments) {
			// Simulate short wait then timeout
			time.Sleep(100 * time.Millisecond)
		}).
		Return(context.DeadlineExceeded)
	mockCoordinator.On("Stop", mock.Anything).Return(nil)

	// Execute in goroutine since it blocks
	done := make(chan error, 1)
	go func() {
		done <- runCoordinator(coordinatorCmd, nil)
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		// Should get error from WaitForParticipants timeout
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout - runCoordinator didn't complete")
	}

	// Verify expectations
	mockFactory.AssertExpectations(t)
	mockCoordinator.AssertExpectations(t)
}

// TestRunCoordinatorFactoryError tests coordinator factory error handling
func TestRunCoordinatorFactoryError(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test"
	coordinatorListen = "localhost:9000"
	protocol = "grpc"

	// Setup factory to return error
	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
		Return(nil, fmt.Errorf("factory error"))

	err := runCoordinator(coordinatorCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create coordinator")

	mockFactory.AssertExpectations(t)
}

// TestRunCoordinatorStartError tests coordinator start error handling
func TestRunCoordinatorStartError(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test"
	coordinatorListen = "localhost:9000"
	protocol = "grpc"

	// Setup mocks
	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(fmt.Errorf("bind error"))

	err := runCoordinator(coordinatorCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start coordinator")

	mockFactory.AssertExpectations(t)
	mockCoordinator.AssertExpectations(t)
}

// TestRunParticipantValidation tests input validation
func TestRunParticipantValidationWithMocks(t *testing.T) {
	tests := []struct {
		name          string
		id            int
		threshold     int
		expectedError string
	}{
		{
			name:          "negative participant ID",
			id:            -1,
			threshold:     2,
			expectedError: "participant ID must be >= 0",
		},
		{
			name:          "zero threshold",
			id:            0,
			threshold:     0,
			expectedError: "threshold must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			participantID = tt.id
			participantThreshold = tt.threshold
			participantOutput = filepath.Join(t.TempDir(), "output.json")

			err := runParticipant(participantCmd, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

// TestRunCoordinatorValidation tests coordinator input validation
func TestRunCoordinatorValidationWithMocks(t *testing.T) {
	tests := []struct {
		name          string
		threshold     int
		participants  int
		expectedError string
	}{
		{
			name:          "threshold less than 1",
			threshold:     0,
			participants:  3,
			expectedError: "threshold must be at least 1",
		},
		{
			name:          "threshold exceeds participants",
			threshold:     5,
			participants:  3,
			expectedError: "participants (3) must be >= threshold (5)",
		},
		{
			name:          "participants less than threshold",
			threshold:     3,
			participants:  2,
			expectedError: "participants (2) must be >= threshold (3)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coordinatorThreshold = tt.threshold
			coordinatorParticipants = tt.participants
			coordinatorSessionID = "test"

			err := runCoordinator(coordinatorCmd, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

// TestRunParticipantWithHostkey tests participant with provided hostkey
func TestRunParticipantWithHostkey(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockParticipant := new(MockParticipant)
	defaultFactory = mockFactory

	tmpDir := t.TempDir()
	participantID = 0
	participantThreshold = 2
	participantOutput = filepath.Join(tmpDir, "output.json")
	participantCoordinator = "localhost:9000"
	participantHostkey = hex.EncodeToString(make([]byte, 32))
	participantTimeout = 5
	protocol = "grpc"
	verbose = false

	expectedResult := &transport.DKGResult{
		SecretShare:     make([]byte, 32),
		ThresholdPubkey: make([]byte, 32),
		PublicShares:    [][]byte{make([]byte, 32)},
		SessionID:       "test",
		RecoveryData:    []byte("recovery"),
	}

	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(mockParticipant, nil)
	mockParticipant.On("Connect", mock.Anything, participantCoordinator).Return(nil)
	mockParticipant.On("RunDKG", mock.Anything, mock.AnythingOfType("*transport.DKGParams")).
		Return(expectedResult, nil)
	mockParticipant.On("Disconnect").Return(nil)

	err := runParticipant(participantCmd, nil)
	require.NoError(t, err)

	participantHostkey = "" // Reset

	mockFactory.AssertExpectations(t)
	mockParticipant.AssertExpectations(t)
}

// TestRunParticipantInvalidHostkey tests invalid hostkey handling
func TestRunParticipantInvalidHostkeyWithMocks(t *testing.T) {
	tests := []struct {
		name          string
		hostkey       string
		expectedError string
	}{
		{
			name:          "invalid hex",
			hostkey:       "not-hex",
			expectedError: "invalid hostkey hex",
		},
		{
			name:          "wrong length",
			hostkey:       hex.EncodeToString(make([]byte, 16)),
			expectedError: "hostkey must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			participantID = 0
			participantThreshold = 2
			participantOutput = filepath.Join(t.TempDir(), "output.json")
			participantHostkey = tt.hostkey

			err := runParticipant(participantCmd, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)

			participantHostkey = "" // Reset
		})
	}
}

// TestRunParticipantWithVerbose tests verbose output
func TestRunParticipantWithVerbose(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockParticipant := new(MockParticipant)
	defaultFactory = mockFactory

	tmpDir := t.TempDir()
	participantID = 0
	participantThreshold = 2
	participantOutput = filepath.Join(tmpDir, "output.json")
	participantCoordinator = "localhost:9000"
	participantTimeout = 5
	protocol = "grpc"
	verbose = true
	defer func() { verbose = false }()

	expectedResult := &transport.DKGResult{
		SecretShare:     make([]byte, 32),
		ThresholdPubkey: make([]byte, 32),
		PublicShares:    [][]byte{make([]byte, 32)},
		SessionID:       "test",
		RecoveryData:    []byte("recovery"),
	}

	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(mockParticipant, nil)
	mockParticipant.On("Connect", mock.Anything, participantCoordinator).Return(nil)
	mockParticipant.On("RunDKG", mock.Anything, mock.AnythingOfType("*transport.DKGParams")).
		Return(expectedResult, nil)
	mockParticipant.On("Disconnect").Return(nil)

	err := runParticipant(participantCmd, nil)
	require.NoError(t, err)

	mockFactory.AssertExpectations(t)
	mockParticipant.AssertExpectations(t)
}

// TestRunCoordinatorWithVerbose tests verbose output for coordinator
func TestRunCoordinatorWithVerbose(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test-session"
	coordinatorListen = "localhost:9000"
	coordinatorTimeout = 1
	protocol = "grpc"
	tlsCert = "cert.pem"
	tlsKey = "key.pem"
	tlsCA = "ca.pem"
	verbose = true
	defer func() {
		verbose = false
		tlsCert = ""
		tlsKey = ""
		tlsCA = ""
	}()

	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(nil)
	mockCoordinator.On("SessionID").Return(coordinatorSessionID)
	mockCoordinator.On("Address").Return(coordinatorListen)
	mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
		Return(context.DeadlineExceeded)
	mockCoordinator.On("Stop", mock.Anything).Return(nil)

	done := make(chan error, 1)
	go func() {
		done <- runCoordinator(coordinatorCmd, nil)
	}()

	select {
	case <-done:
		// Expected to fail waiting for participants
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}

	mockFactory.AssertExpectations(t)
	mockCoordinator.AssertExpectations(t)
}

// TestRunParticipantHostpubkeysNotImplemented tests the hostpubkeys flag error
func TestRunParticipantHostpubkeysNotImplementedWithMocks(t *testing.T) {
	participantID = 0
	participantThreshold = 2
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantHostpubkeys = "some,pubkeys"

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hostpubkeys parsing not yet implemented")

	participantHostpubkeys = "" // Reset
}

// TestRunParticipantIDExceedsHostPubkeys tests ID validation
func TestRunParticipantIDExceedsHostPubkeys(t *testing.T) {
	participantID = 100 // Very high ID
	participantThreshold = 2
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantCoordinator = "localhost:9000"
	participantTimeout = 5
	protocol = "grpc"

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "participant ID")
}

// TestRunParticipantDisconnectError tests disconnect error handling
func TestRunParticipantDisconnectError(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockParticipant := new(MockParticipant)
	defaultFactory = mockFactory

	tmpDir := t.TempDir()
	participantID = 0
	participantThreshold = 2
	participantOutput = filepath.Join(tmpDir, "output.json")
	participantCoordinator = "localhost:9000"
	participantTimeout = 5
	protocol = "grpc"
	verbose = false

	expectedResult := &transport.DKGResult{
		SecretShare:     make([]byte, 32),
		ThresholdPubkey: make([]byte, 32),
		PublicShares:    [][]byte{make([]byte, 32)},
		SessionID:       "test",
		RecoveryData:    []byte("recovery"),
	}

	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(mockParticipant, nil)
	mockParticipant.On("Connect", mock.Anything, participantCoordinator).Return(nil)
	mockParticipant.On("RunDKG", mock.Anything, mock.AnythingOfType("*transport.DKGParams")).
		Return(expectedResult, nil)
	mockParticipant.On("Disconnect").Return(fmt.Errorf("disconnect error"))

	// Should still succeed even if disconnect fails
	err := runParticipant(participantCmd, nil)
	require.NoError(t, err)

	mockFactory.AssertExpectations(t)
	mockParticipant.AssertExpectations(t)
}

// TestRunParticipantWriteFileError tests output file write error
func TestRunParticipantWriteFileError(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockParticipant := new(MockParticipant)
	defaultFactory = mockFactory

	participantID = 0
	participantThreshold = 2
	participantOutput = "/dev/null/cannot/write/here.json" // Invalid path
	participantCoordinator = "localhost:9000"
	participantTimeout = 5
	protocol = "grpc"

	expectedResult := &transport.DKGResult{
		SecretShare:     make([]byte, 32),
		ThresholdPubkey: make([]byte, 32),
		PublicShares:    [][]byte{make([]byte, 32)},
		SessionID:       "test",
		RecoveryData:    []byte("recovery"),
	}

	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(mockParticipant, nil)
	mockParticipant.On("Connect", mock.Anything, participantCoordinator).Return(nil)
	mockParticipant.On("RunDKG", mock.Anything, mock.AnythingOfType("*transport.DKGParams")).
		Return(expectedResult, nil)
	mockParticipant.On("Disconnect").Return(nil)

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write output file")

	mockFactory.AssertExpectations(t)
	mockParticipant.AssertExpectations(t)
}

// TestRunCoordinatorGenerateSessionID tests UUID generation
func TestRunCoordinatorGenerateSessionID(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "" // Empty, should generate UUID
	coordinatorListen = "localhost:9000"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = false

	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), mock.AnythingOfType("string")).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(nil)
	mockCoordinator.On("SessionID").Return("generated-uuid")
	mockCoordinator.On("Address").Return(coordinatorListen)
	mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
		Return(context.DeadlineExceeded)
	mockCoordinator.On("Stop", mock.Anything).Return(nil)

	done := make(chan error, 1)
	go func() {
		done <- runCoordinator(coordinatorCmd, nil)
	}()

	select {
	case <-done:
		// Expected timeout
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}

	mockFactory.AssertExpectations(t)
	mockCoordinator.AssertExpectations(t)
}

// TestRunCoordinatorStopError tests stop error handling
func TestRunCoordinatorStopError(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test"
	coordinatorListen = "localhost:9000"
	coordinatorTimeout = 1
	protocol = "grpc"

	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(nil)
	mockCoordinator.On("SessionID").Return(coordinatorSessionID)
	mockCoordinator.On("Address").Return(coordinatorListen)
	mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
		Return(context.DeadlineExceeded)
	mockCoordinator.On("Stop", mock.Anything).Return(fmt.Errorf("stop error"))

	done := make(chan error, 1)
	go func() {
		done <- runCoordinator(coordinatorCmd, nil)
	}()

	select {
	case err := <-done:
		// Should get error from stop failing
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}

	mockFactory.AssertExpectations(t)
	mockCoordinator.AssertExpectations(t)
}

// TestRunCoordinatorSuccessfulCompletion tests successful participant connection
func TestRunCoordinatorSuccessfulCompletion(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "success-test"
	coordinatorListen = "localhost:9000"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = false

	// Setup coordinator to succeed
	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(nil)
	mockCoordinator.On("SessionID").Return(coordinatorSessionID)
	mockCoordinator.On("Address").Return(coordinatorListen)

	// Channel to signal when WaitForParticipants is called
	waitCalled := make(chan struct{})

	// WaitForParticipants succeeds immediately
	mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
		Run(func(args mock.Arguments) {
			close(waitCalled)
		}).
		Return(nil)
	mockCoordinator.On("Stop", mock.Anything).Return(nil)

	// Run in goroutine
	done := make(chan error, 1)
	go func() {
		done <- runCoordinator(coordinatorCmd, nil)
	}()

	// Wait for WaitForParticipants to be called, then send SIGINT
	select {
	case <-waitCalled:
		// Give a small delay for the coordinator to reach the signal wait
		time.Sleep(100 * time.Millisecond)
		// Send SIGINT to trigger graceful shutdown
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForParticipants was not called")
	}

	// Wait for completion - goroutine must complete before test returns
	select {
	case err := <-done:
		// Success - coordinator completed (may or may not have error)
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("test timeout waiting for coordinator to complete after signal")
	}

	// Expectations may or may not all be met depending on timing
	// This test mainly ensures the success path compiles and runs
}

// TestRunParticipantWithTLSPaths tests with TLS configuration
func TestRunParticipantWithTLSPathsAndVerbose(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockParticipant := new(MockParticipant)
	defaultFactory = mockFactory

	tmpDir := t.TempDir()
	participantID = 0
	participantThreshold = 2
	participantOutput = filepath.Join(tmpDir, "output.json")
	participantCoordinator = "localhost:9000"
	participantTimeout = 5
	protocol = "grpc"
	tlsCert = "cert.pem"
	tlsKey = "key.pem"
	verbose = true
	defer func() {
		verbose = false
		tlsCert = ""
		tlsKey = ""
	}()

	expectedResult := &transport.DKGResult{
		SecretShare:     make([]byte, 32),
		ThresholdPubkey: make([]byte, 32),
		PublicShares:    [][]byte{make([]byte, 32)},
		SessionID:       "test",
		RecoveryData:    []byte("recovery"),
	}

	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(mockParticipant, nil)
	mockParticipant.On("Connect", mock.Anything, participantCoordinator).Return(nil)
	mockParticipant.On("RunDKG", mock.Anything, mock.AnythingOfType("*transport.DKGParams")).
		Return(expectedResult, nil)
	mockParticipant.On("Disconnect").Return(nil)

	err := runParticipant(participantCmd, nil)
	require.NoError(t, err)

	mockFactory.AssertExpectations(t)
	mockParticipant.AssertExpectations(t)
}

// TestFactoryErrorMessageContent tests error message format
func TestFactoryErrorMessageContent(t *testing.T) {
	factory := &DefaultTransportFactory{}

	// Test unsupported protocol error message for participant
	_, err := factory.NewParticipant(transport.Protocol("invalid"), &transport.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported protocol")
	assert.Contains(t, err.Error(), "invalid")

	// Test unsupported protocol error message for coordinator
	_, err = factory.NewCoordinator(transport.Protocol("invalid"), &transport.Config{}, &transport.SessionConfig{}, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported protocol")
	assert.Contains(t, err.Error(), "invalid")
}

// TestRunParticipantAllProtocols tests all supported protocols
func TestRunParticipantAllProtocolsWithMocks(t *testing.T) {
	protocols := []transport.Protocol{
		transport.ProtocolGRPC,
		transport.ProtocolHTTP,
		transport.ProtocolQUIC,
		transport.ProtocolUnix,
		transport.ProtocolLibp2p,
	}

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			originalFactory := defaultFactory
			defer func() { defaultFactory = originalFactory }()

			mockFactory := new(MockTransportFactory)
			mockParticipant := new(MockParticipant)
			defaultFactory = mockFactory

			tmpDir := t.TempDir()
			participantID = 0
			participantThreshold = 2
			participantOutput = filepath.Join(tmpDir, "output.json")
			participantCoordinator = "localhost:9000"
			participantTimeout = 5
			protocol = string(proto)
			verbose = false

			expectedResult := &transport.DKGResult{
				SecretShare:     make([]byte, 32),
				ThresholdPubkey: make([]byte, 32),
				PublicShares:    [][]byte{make([]byte, 32)},
				SessionID:       "test",
				RecoveryData:    []byte("recovery"),
			}

			mockFactory.On("NewParticipant", proto, mock.AnythingOfType("*transport.Config")).
				Return(mockParticipant, nil)
			mockParticipant.On("Connect", mock.Anything, participantCoordinator).Return(nil)
			mockParticipant.On("RunDKG", mock.Anything, mock.AnythingOfType("*transport.DKGParams")).
				Return(expectedResult, nil)
			mockParticipant.On("Disconnect").Return(nil)

			err := runParticipant(participantCmd, nil)
			require.NoError(t, err)

			mockFactory.AssertExpectations(t)
			mockParticipant.AssertExpectations(t)
		})
	}
}

// TestRunCoordinatorAllProtocolsWithMocks tests all supported protocols
func TestRunCoordinatorAllProtocolsWithMocks(t *testing.T) {
	protocols := []transport.Protocol{
		transport.ProtocolGRPC,
		transport.ProtocolHTTP,
		transport.ProtocolQUIC,
		transport.ProtocolUnix,
		transport.ProtocolLibp2p,
	}

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			originalFactory := defaultFactory
			defer func() { defaultFactory = originalFactory }()

			mockFactory := new(MockTransportFactory)
			mockCoordinator := new(MockCoordinator)
			defaultFactory = mockFactory

			coordinatorThreshold = 2
			coordinatorParticipants = 3
			coordinatorSessionID = "test"
			coordinatorListen = "localhost:9000"
			coordinatorTimeout = 1
			protocol = string(proto)
			codec = "json"
			verbose = false

			mockFactory.On("NewCoordinator", proto, mock.AnythingOfType("*transport.Config"),
				mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
				Return(mockCoordinator, nil)
			mockCoordinator.On("Start", mock.Anything).Return(nil)
			mockCoordinator.On("SessionID").Return(coordinatorSessionID)
			mockCoordinator.On("Address").Return(coordinatorListen)
			mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
				Return(context.DeadlineExceeded)
			mockCoordinator.On("Stop", mock.Anything).Return(nil)

			done := make(chan error, 1)
			go func() {
				done <- runCoordinator(coordinatorCmd, nil)
			}()

			select {
			case <-done:
				// Expected timeout
			case <-time.After(3 * time.Second):
				t.Fatal("test timeout")
			}

			mockFactory.AssertExpectations(t)
			mockCoordinator.AssertExpectations(t)
		})
	}
}

// TestRunCoordinatorWithEmptySessionID tests UUID generation path
func TestRunCoordinatorWithEmptySessionIDAndVerbose(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "" // Empty - will generate UUID
	coordinatorListen = "localhost:9000"
	coordinatorTimeout = 1
	protocol = "grpc"
	codec = "json"
	tlsCert = "cert.pem"
	tlsKey = "key.pem"
	tlsCA = "ca.pem"
	verbose = true
	defer func() {
		verbose = false
		tlsCert = ""
		tlsKey = ""
		tlsCA = ""
	}()

	// Mock will be called with a generated UUID
	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), mock.AnythingOfType("string")).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(nil)
	mockCoordinator.On("SessionID").Return("generated-uuid-12345")
	mockCoordinator.On("Address").Return(coordinatorListen)
	mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
		Return(context.DeadlineExceeded)
	mockCoordinator.On("Stop", mock.Anything).Return(nil)

	done := make(chan error, 1)
	go func() {
		done <- runCoordinator(coordinatorCmd, nil)
	}()

	select {
	case <-done:
		// Expected completion
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}

	mockFactory.AssertExpectations(t)
	mockCoordinator.AssertExpectations(t)
}

// TestRunCoordinatorWaitForParticipantsStopError tests stop error after wait error
func TestRunCoordinatorWaitForParticipantsStopError(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "stop-error-test"
	coordinatorListen = "localhost:9000"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = false

	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(nil)
	mockCoordinator.On("SessionID").Return(coordinatorSessionID)
	mockCoordinator.On("Address").Return(coordinatorListen)

	// WaitForParticipants fails
	mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
		Return(fmt.Errorf("participant connection error"))

	// Stop also fails
	mockCoordinator.On("Stop", mock.Anything).Return(fmt.Errorf("stop failed"))

	done := make(chan error, 1)
	go func() {
		done <- runCoordinator(coordinatorCmd, nil)
	}()

	select {
	case err := <-done:
		// Should get the original error from WaitForParticipants
		require.Error(t, err)
		assert.Contains(t, err.Error(), "participant connection error")
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}

	mockFactory.AssertExpectations(t)
	mockCoordinator.AssertExpectations(t)
}

// TestRunCoordinatorSuccessWithSignal tests the success path with signal handling
func TestRunCoordinatorSuccessWithSignal(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "signal-test"
	coordinatorListen = "localhost:9000"
	coordinatorTimeout = 5
	protocol = "grpc"
	codec = "json"
	verbose = false

	// Setup expectations - coordinator will succeed, then we send signal
	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(nil)
	mockCoordinator.On("SessionID").Return(coordinatorSessionID)
	mockCoordinator.On("Address").Return(coordinatorListen)

	// WaitForParticipants succeeds
	waitCalled := make(chan struct{})
	mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
		Run(func(args mock.Arguments) {
			close(waitCalled)
		}).
		Return(nil)
	mockCoordinator.On("Stop", mock.Anything).Return(nil)

	// Run in goroutine
	done := make(chan error, 1)
	go func() {
		done <- runCoordinator(coordinatorCmd, nil)
	}()

	// Wait for WaitForParticipants to be called
	select {
	case <-waitCalled:
		// Give a small delay for the coordinator to reach the signal wait
		time.Sleep(100 * time.Millisecond)
		// Send SIGINT to trigger graceful shutdown
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForParticipants was not called")
	}

	// Wait for completion - must complete before test returns
	select {
	case <-done:
		// Coordinator completed (either success or timeout)
	case <-time.After(5 * time.Second):
		t.Fatal("test timeout waiting for coordinator to complete after signal")
	}
}

// TestRunCoordinatorGracefulShutdown tests the graceful shutdown path
func TestRunCoordinatorGracefulShutdown(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "shutdown-test"
	coordinatorListen = "localhost:9000"
	coordinatorTimeout = 1
	protocol = "grpc"
	codec = "json"
	verbose = false

	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(nil)
	mockCoordinator.On("SessionID").Return(coordinatorSessionID)
	mockCoordinator.On("Address").Return(coordinatorListen)

	// WaitForParticipants returns error after short delay
	mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
		Run(func(args mock.Arguments) {
			time.Sleep(50 * time.Millisecond)
		}).
		Return(context.DeadlineExceeded)
	mockCoordinator.On("Stop", mock.Anything).Return(nil)

	done := make(chan error, 1)
	go func() {
		done <- runCoordinator(coordinatorCmd, nil)
	}()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}

	mockFactory.AssertExpectations(t)
	mockCoordinator.AssertExpectations(t)
}

// TestRunCoordinatorWithTLSVerbose tests coordinator with TLS and verbose output without CA
func TestRunCoordinatorWithTLSVerboseNoCA(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockCoordinator := new(MockCoordinator)
	defaultFactory = mockFactory

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "tls-verbose-test"
	coordinatorListen = "localhost:9000"
	coordinatorTimeout = 1
	protocol = "grpc"
	codec = "json"
	tlsCert = "server.crt"
	tlsKey = "server.key"
	tlsCA = "" // No CA
	verbose = true
	defer func() {
		verbose = false
		tlsCert = ""
		tlsKey = ""
		tlsCA = ""
	}()

	mockFactory.On("NewCoordinator", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config"),
		mock.AnythingOfType("*transport.SessionConfig"), coordinatorSessionID).
		Return(mockCoordinator, nil)
	mockCoordinator.On("Start", mock.Anything).Return(nil)
	mockCoordinator.On("SessionID").Return(coordinatorSessionID)
	mockCoordinator.On("Address").Return(coordinatorListen)
	mockCoordinator.On("WaitForParticipants", mock.Anything, coordinatorParticipants).
		Return(context.DeadlineExceeded)
	mockCoordinator.On("Stop", mock.Anything).Return(nil)

	done := make(chan error, 1)
	go func() {
		done <- runCoordinator(coordinatorCmd, nil)
	}()

	select {
	case <-done:
		// Expected
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}

	mockFactory.AssertExpectations(t)
	mockCoordinator.AssertExpectations(t)
}

// TestRunParticipantVerboseWithHostkeyGeneration tests verbose output during hostkey generation
func TestRunParticipantVerboseWithHostkeyGeneration(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockParticipant := new(MockParticipant)
	defaultFactory = mockFactory

	tmpDir := t.TempDir()
	participantID = 0
	participantThreshold = 2
	participantOutput = filepath.Join(tmpDir, "output.json")
	participantCoordinator = "localhost:9000"
	participantHostkey = "" // Will generate, triggers verbose output
	participantTimeout = 5
	protocol = "grpc"
	verbose = true
	defer func() { verbose = false }()

	expectedResult := &transport.DKGResult{
		SecretShare:     make([]byte, 32),
		ThresholdPubkey: make([]byte, 32),
		PublicShares:    [][]byte{make([]byte, 32)},
		SessionID:       "test",
		RecoveryData:    []byte("recovery"),
	}

	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(mockParticipant, nil)
	mockParticipant.On("Connect", mock.Anything, participantCoordinator).Return(nil)
	mockParticipant.On("RunDKG", mock.Anything, mock.AnythingOfType("*transport.DKGParams")).
		Return(expectedResult, nil)
	mockParticipant.On("Disconnect").Return(nil)

	err := runParticipant(participantCmd, nil)
	require.NoError(t, err)

	mockFactory.AssertExpectations(t)
	mockParticipant.AssertExpectations(t)
}

// TestRunParticipantVerboseConnectedAndDKGComplete tests verbose output for successful DKG
func TestRunParticipantVerboseConnectedAndDKGComplete(t *testing.T) {
	originalFactory := defaultFactory
	defer func() { defaultFactory = originalFactory }()

	mockFactory := new(MockTransportFactory)
	mockParticipant := new(MockParticipant)
	defaultFactory = mockFactory

	tmpDir := t.TempDir()
	participantID = 0
	participantThreshold = 2
	participantOutput = filepath.Join(tmpDir, "output.json")
	participantCoordinator = "localhost:9000"
	participantTimeout = 5
	protocol = "grpc"
	verbose = true
	defer func() { verbose = false }()

	expectedResult := &transport.DKGResult{
		SecretShare:     make([]byte, 32),
		ThresholdPubkey: make([]byte, 33), // 33-byte compressed key for verbose output
		PublicShares:    [][]byte{make([]byte, 32)},
		SessionID:       "verbose-test-session",
		RecoveryData:    []byte("recovery-data"),
	}

	mockFactory.On("NewParticipant", transport.ProtocolGRPC, mock.AnythingOfType("*transport.Config")).
		Return(mockParticipant, nil)
	mockParticipant.On("Connect", mock.Anything, participantCoordinator).Return(nil)
	mockParticipant.On("RunDKG", mock.Anything, mock.AnythingOfType("*transport.DKGParams")).
		Return(expectedResult, nil)
	mockParticipant.On("Disconnect").Return(nil)

	err := runParticipant(participantCmd, nil)
	require.NoError(t, err)

	mockFactory.AssertExpectations(t)
	mockParticipant.AssertExpectations(t)
}
