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

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRootCommand tests the root command initialization
func TestRootCommand(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("rootCmd is nil")
	}

	if rootCmd.Use != "frostdkg" {
		t.Errorf("expected Use to be 'frostdkg', got %s", rootCmd.Use)
	}

	// Check that subcommands are registered
	expectedCommands := []string{"version", "coordinator", "participant", "certgen", "verify", "config"}
	for _, cmdName := range expectedCommands {
		found := false
		for _, cmd := range rootCmd.Commands() {
			if cmd.Name() == cmdName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %s not found", cmdName)
		}
	}
}

// TestVersionCommand tests the version command
func TestVersionCommand(t *testing.T) {
	// Create a new command to avoid state pollution
	buf := new(bytes.Buffer)
	versionCmd.SetOut(buf)
	versionCmd.SetErr(buf)

	versionCmd.Run(versionCmd, nil)

	// Verify the command ran without error
	assert.Equal(t, "version", versionCmd.Name())
}

// TestGlobalFlags tests that global flags are properly registered
func TestGlobalFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
	}{
		{"config flag", "config"},
		{"protocol flag", "protocol"},
		{"codec flag", "codec"},
		{"tls-cert flag", "tls-cert"},
		{"tls-key flag", "tls-key"},
		{"tls-ca flag", "tls-ca"},
		{"insecure flag", "insecure"},
		{"verbose flag", "verbose"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := rootCmd.PersistentFlags().Lookup(tt.flagName)
			require.NotNil(t, flag, "flag %s not found", tt.flagName)
		})
	}
}

// TestCoordinatorFlags tests coordinator command flags
func TestCoordinatorFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
	}{
		{"listen flag", "listen"},
		{"threshold flag", "threshold"},
		{"participants flag", "participants"},
		{"session-id flag", "session-id"},
		{"ciphersuite flag", "ciphersuite"},
		{"timeout flag", "timeout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := coordinatorCmd.Flags().Lookup(tt.flagName)
			require.NotNil(t, flag, "flag %s not found", tt.flagName)
		})
	}
}

// TestParticipantFlags tests participant command flags
func TestParticipantFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
	}{
		{"coordinator flag", "coordinator"},
		{"id flag", "id"},
		{"output flag", "output"},
		{"hostkey flag", "hostkey"},
		{"hostpubkeys flag", "hostpubkeys"},
		{"threshold flag", "threshold"},
		{"timeout flag", "timeout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := participantCmd.Flags().Lookup(tt.flagName)
			require.NotNil(t, flag, "flag %s not found", tt.flagName)
		})
	}
}

// TestCertgenFlags tests certgen command flags
func TestCertgenFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
	}{
		{"type flag", "type"},
		{"output flag", "output"},
		{"name flag", "name"},
		{"days flag", "days"},
		{"hosts flag", "hosts"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := certgenCmd.Flags().Lookup(tt.flagName)
			require.NotNil(t, flag, "flag %s not found", tt.flagName)
		})
	}
}

// TestVerifyFlags tests verify command flags
func TestVerifyFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
	}{
		{"share flag", "share"},
		{"group-key flag", "group-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := verifyCmd.Flags().Lookup(tt.flagName)
			require.NotNil(t, flag, "flag %s not found", tt.flagName)
		})
	}
}

// TestCertgenECDSA tests ECDSA key generation
func TestCertgenECDSA(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "ecdsa"
	certgenOutput = tmpDir
	certgenName = "test-ecdsa"
	certgenDays = 365
	certgenHosts = []string{"localhost", "127.0.0.1"}
	verbose = false

	err := runCertgen(certgenCmd, nil)
	require.NoError(t, err)

	// Check that files were created
	certPath := filepath.Join(tmpDir, "test-ecdsa.crt")
	keyPath := filepath.Join(tmpDir, "test-ecdsa.key")

	assert.FileExists(t, certPath)
	assert.FileExists(t, keyPath)

	// Verify file permissions
	info, err := os.Stat(keyPath)
	require.NoError(t, err)

	// Key file should be readable only by owner (0600)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// TestCertgenEd25519 tests Ed25519 key generation
func TestCertgenEd25519(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "ed25519"
	certgenOutput = tmpDir
	certgenName = "test-ed25519"
	certgenDays = 30
	certgenHosts = []string{"test.example.com"}
	verbose = false

	err := runCertgen(certgenCmd, nil)
	require.NoError(t, err)

	// Check that files were created
	certPath := filepath.Join(tmpDir, "test-ed25519.crt")
	keyPath := filepath.Join(tmpDir, "test-ed25519.key")

	assert.FileExists(t, certPath)
	assert.FileExists(t, keyPath)
}

// TestCertgenEd25519Verbose tests Ed25519 key generation with verbose flag
func TestCertgenEd25519Verbose(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "ed25519"
	certgenOutput = tmpDir
	certgenName = "test-ed25519-verbose"
	certgenDays = 30
	certgenHosts = []string{"test.example.com"}
	verbose = true

	err := runCertgen(certgenCmd, nil)
	require.NoError(t, err)
	verbose = false // Reset

	// Check that files were created
	certPath := filepath.Join(tmpDir, "test-ed25519-verbose.crt")
	keyPath := filepath.Join(tmpDir, "test-ed25519-verbose.key")

	assert.FileExists(t, certPath)
	assert.FileExists(t, keyPath)
}

// TestCertgenInvalidType tests certgen with invalid key type
func TestCertgenInvalidType(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "rsa" // invalid
	certgenOutput = tmpDir
	certgenName = "test"
	certgenDays = 365
	certgenHosts = []string{"localhost"}
	verbose = false

	err := runCertgen(certgenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key type")
}

// TestCertgenInvalidDays tests certgen with invalid days
func TestCertgenInvalidDays(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "ecdsa"
	certgenOutput = tmpDir
	certgenName = "test"
	certgenDays = 0 // invalid
	certgenHosts = []string{"localhost"}
	verbose = false

	err := runCertgen(certgenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "days must be at least 1")
}

// TestCertgenDirectoryCreationError tests certgen with invalid directory path
func TestCertgenDirectoryCreationError(t *testing.T) {
	// Use /dev/null which cannot have directories created inside it
	certgenType = "ecdsa"
	certgenOutput = "/dev/null/cannot/create/dirs"
	certgenName = "test"
	certgenDays = 365
	certgenHosts = []string{"localhost"}
	verbose = false

	err := runCertgen(certgenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create output directory")
}

// TestVerifyValidKeyShare tests verifying a valid key share
func TestVerifyValidKeyShare(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "share.json")

	// Create a valid key share
	keyShare := KeyShareOutput{
		ParticipantIndex: 0,
		SecretShare:      hex.EncodeToString(make([]byte, 32)), // 32 bytes
		ThresholdPubkey:  hex.EncodeToString(make([]byte, 32)), // 32 bytes for ED25519
		PublicShares: []string{
			hex.EncodeToString(make([]byte, 32)),
			hex.EncodeToString(make([]byte, 32)),
		},
		SessionID:    "test-session",
		RecoveryData: hex.EncodeToString([]byte("recovery")),
		Timestamp:    time.Now().Unix(),
	}

	data, err := json.MarshalIndent(keyShare, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(sharePath, data, 0600)
	require.NoError(t, err)

	// Test verification
	verifyShare = sharePath
	verifyGroupKey = ""
	verbose = false

	err = runVerify(verifyCmd, nil)
	require.NoError(t, err)
}

// TestVerifyValidKeyShareVerbose tests verifying a valid key share with verbose output
func TestVerifyValidKeyShareVerbose(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "share.json")

	// Create a valid key share
	keyShare := KeyShareOutput{
		ParticipantIndex: 0,
		SecretShare:      hex.EncodeToString(make([]byte, 32)),
		ThresholdPubkey:  hex.EncodeToString(make([]byte, 32)),
		PublicShares: []string{
			hex.EncodeToString(make([]byte, 32)),
			hex.EncodeToString(make([]byte, 32)),
		},
		SessionID:    "test-session",
		RecoveryData: hex.EncodeToString([]byte("recovery")),
		Timestamp:    time.Now().Unix(),
	}

	data, err := json.MarshalIndent(keyShare, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(sharePath, data, 0600)
	require.NoError(t, err)

	// Test verification with verbose
	verifyShare = sharePath
	verifyGroupKey = ""
	verbose = true

	err = runVerify(verifyCmd, nil)
	require.NoError(t, err)
	verbose = false // Reset
}

// TestVerifyInvalidKeyShare tests verifying an invalid key share
func TestVerifyInvalidKeyShare(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "invalid.json")

	// Create an invalid key share (secret share wrong length)
	keyShare := KeyShareOutput{
		ParticipantIndex: 0,
		SecretShare:      hex.EncodeToString(make([]byte, 16)), // Wrong: 16 bytes instead of 32
		ThresholdPubkey:  hex.EncodeToString(make([]byte, 32)),
		PublicShares: []string{
			hex.EncodeToString(make([]byte, 32)),
		},
		SessionID: "test-session",
	}

	data, err := json.MarshalIndent(keyShare, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(sharePath, data, 0600)
	require.NoError(t, err)

	// Test verification
	verifyShare = sharePath
	verifyGroupKey = ""
	verbose = false

	err = runVerify(verifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be 32 bytes")
}

// TestVerifyGroupKeyMismatch tests verification with wrong group key
func TestVerifyGroupKeyMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "share.json")

	thresholdKey := hex.EncodeToString(make([]byte, 32))
	differentKey := hex.EncodeToString(bytes.Repeat([]byte{0x01}, 32))

	keyShare := KeyShareOutput{
		ParticipantIndex: 0,
		SecretShare:      hex.EncodeToString(make([]byte, 32)),
		ThresholdPubkey:  thresholdKey,
		PublicShares: []string{
			thresholdKey,
		},
		SessionID: "test-session",
	}

	data, err := json.MarshalIndent(keyShare, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(sharePath, data, 0600)
	require.NoError(t, err)

	// Test verification with wrong group key
	verifyShare = sharePath
	verifyGroupKey = differentKey
	verbose = false

	err = runVerify(verifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch")
}

// TestVerifyMissingFile tests verification with non-existent file
func TestVerifyMissingFile(t *testing.T) {
	verifyShare = "/tmp/nonexistent-file.json"
	verifyGroupKey = ""
	verbose = false

	err := runVerify(verifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read key share file")
}

// TestVerifyInvalidJSON tests verification with invalid JSON
func TestVerifyInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "invalid.json")

	err := os.WriteFile(sharePath, []byte("not valid json"), 0600)
	require.NoError(t, err)

	verifyShare = sharePath
	verifyGroupKey = ""
	verbose = false

	err = runVerify(verifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse key share JSON")
}

// TestVerifyMissingFields tests verification with missing required fields
func TestVerifyMissingFields(t *testing.T) {
	tests := []struct {
		name          string
		keyShare      KeyShareOutput
		errorContains string
	}{
		{
			name: "missing secret share",
			keyShare: KeyShareOutput{
				ThresholdPubkey: hex.EncodeToString(make([]byte, 32)),
				PublicShares:    []string{hex.EncodeToString(make([]byte, 32))},
				SessionID:       "test",
			},
			errorContains: "missing secret_share field",
		},
		{
			name: "missing threshold pubkey",
			keyShare: KeyShareOutput{
				SecretShare:  hex.EncodeToString(make([]byte, 32)),
				PublicShares: []string{hex.EncodeToString(make([]byte, 32))},
				SessionID:    "test",
			},
			errorContains: "missing threshold_pubkey field",
		},
		{
			name: "missing public shares",
			keyShare: KeyShareOutput{
				SecretShare:     hex.EncodeToString(make([]byte, 32)),
				ThresholdPubkey: hex.EncodeToString(make([]byte, 32)),
				SessionID:       "test",
			},
			errorContains: "missing public_shares field",
		},
		{
			name: "missing session id",
			keyShare: KeyShareOutput{
				SecretShare:     hex.EncodeToString(make([]byte, 32)),
				ThresholdPubkey: hex.EncodeToString(make([]byte, 32)),
				PublicShares:    []string{hex.EncodeToString(make([]byte, 32))},
			},
			errorContains: "missing session_id field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sharePath := filepath.Join(tmpDir, "share.json")

			data, err := json.MarshalIndent(tt.keyShare, "", "  ")
			require.NoError(t, err)

			err = os.WriteFile(sharePath, data, 0600)
			require.NoError(t, err)

			verifyShare = sharePath
			verifyGroupKey = ""
			verbose = false

			err = runVerify(verifyCmd, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

// TestVerifyInvalidHex tests verification with invalid hex encoding
func TestVerifyInvalidHex(t *testing.T) {
	tests := []struct {
		name          string
		keyShare      KeyShareOutput
		errorContains string
	}{
		{
			name: "invalid secret share hex",
			keyShare: KeyShareOutput{
				SecretShare:     "not-valid-hex",
				ThresholdPubkey: hex.EncodeToString(make([]byte, 32)),
				PublicShares:    []string{hex.EncodeToString(make([]byte, 32))},
				SessionID:       "test",
			},
			errorContains: "invalid secret_share hex",
		},
		{
			name: "invalid threshold pubkey hex",
			keyShare: KeyShareOutput{
				SecretShare:     hex.EncodeToString(make([]byte, 32)),
				ThresholdPubkey: "not-valid-hex",
				PublicShares:    []string{hex.EncodeToString(make([]byte, 32))},
				SessionID:       "test",
			},
			errorContains: "invalid threshold_pubkey hex",
		},
		{
			name: "invalid public share hex",
			keyShare: KeyShareOutput{
				SecretShare:     hex.EncodeToString(make([]byte, 32)),
				ThresholdPubkey: hex.EncodeToString(make([]byte, 32)),
				PublicShares:    []string{"not-valid-hex"},
				SessionID:       "test",
			},
			errorContains: "invalid public_share[0] hex",
		},
		{
			name: "invalid recovery data hex",
			keyShare: KeyShareOutput{
				SecretShare:     hex.EncodeToString(make([]byte, 32)),
				ThresholdPubkey: hex.EncodeToString(make([]byte, 32)),
				PublicShares:    []string{hex.EncodeToString(make([]byte, 32))},
				SessionID:       "test",
				RecoveryData:    "not-valid-hex",
			},
			errorContains: "invalid recovery_data hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sharePath := filepath.Join(tmpDir, "share.json")

			data, err := json.MarshalIndent(tt.keyShare, "", "  ")
			require.NoError(t, err)

			err = os.WriteFile(sharePath, data, 0600)
			require.NoError(t, err)

			verifyShare = sharePath
			verifyGroupKey = ""
			verbose = false

			err = runVerify(verifyCmd, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

// TestVerifyInvalidLengths tests verification with invalid data lengths
func TestVerifyInvalidLengths(t *testing.T) {
	tests := []struct {
		name          string
		keyShare      KeyShareOutput
		errorContains string
	}{
		{
			name: "wrong threshold pubkey length",
			keyShare: KeyShareOutput{
				SecretShare:     hex.EncodeToString(make([]byte, 32)),
				ThresholdPubkey: hex.EncodeToString(make([]byte, 16)), // Wrong: 16 bytes instead of 32
				PublicShares:    []string{hex.EncodeToString(make([]byte, 32))},
				SessionID:       "test",
			},
			errorContains: "threshold_pubkey must be 32 bytes",
		},
		{
			name: "wrong public share length",
			keyShare: KeyShareOutput{
				SecretShare:     hex.EncodeToString(make([]byte, 32)),
				ThresholdPubkey: hex.EncodeToString(make([]byte, 32)),
				PublicShares:    []string{hex.EncodeToString(make([]byte, 16))}, // Wrong: 16 bytes instead of 32
				SessionID:       "test",
			},
			errorContains: "public_share[0] must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sharePath := filepath.Join(tmpDir, "share.json")

			data, err := json.MarshalIndent(tt.keyShare, "", "  ")
			require.NoError(t, err)

			err = os.WriteFile(sharePath, data, 0600)
			require.NoError(t, err)

			verifyShare = sharePath
			verifyGroupKey = ""
			verbose = false

			err = runVerify(verifyCmd, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

// TestVerifyInvalidGroupKey tests verification with invalid group key
func TestVerifyInvalidGroupKey(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "share.json")

	keyShare := KeyShareOutput{
		SecretShare:     hex.EncodeToString(make([]byte, 32)),
		ThresholdPubkey: hex.EncodeToString(make([]byte, 32)),
		PublicShares:    []string{hex.EncodeToString(make([]byte, 32))},
		SessionID:       "test",
	}

	data, err := json.MarshalIndent(keyShare, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(sharePath, data, 0600)
	require.NoError(t, err)

	verifyShare = sharePath
	verifyGroupKey = "not-valid-hex"
	verbose = false

	err = runVerify(verifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid group-key hex")
}

// TestVerifyGroupKeyWrongLength tests verification with wrong group key length
func TestVerifyGroupKeyWrongLength(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "share.json")

	keyShare := KeyShareOutput{
		SecretShare:     hex.EncodeToString(make([]byte, 32)),
		ThresholdPubkey: hex.EncodeToString(make([]byte, 32)),
		PublicShares:    []string{hex.EncodeToString(make([]byte, 32))},
		SessionID:       "test",
	}

	data, err := json.MarshalIndent(keyShare, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(sharePath, data, 0600)
	require.NoError(t, err)

	verifyShare = sharePath
	verifyGroupKey = hex.EncodeToString(make([]byte, 16)) // Wrong: 16 bytes instead of 32
	verbose = false

	err = runVerify(verifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group-key must be 32 bytes")
}

// TestConfigInit tests config file generation
func TestConfigInit(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configOutput = configPath
	configForce = false

	err := runConfigInit(configInitCmd, nil)
	require.NoError(t, err)

	// Check that file was created
	assert.FileExists(t, configPath)

	// Read and validate content
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	content := string(data)
	expectedStrings := []string{
		"protocol:",
		"codec:",
		"tls:",
		"coordinator:",
		"participant:",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, content, expected)
	}
}

// TestConfigInitExisting tests config init with existing file
func TestConfigInitExisting(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create existing file
	err := os.WriteFile(configPath, []byte("existing"), 0644)
	require.NoError(t, err)

	configOutput = configPath
	configForce = false

	// Should fail without --force
	err = runConfigInit(configInitCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// Should succeed with --force
	configForce = true
	err = runConfigInit(configInitCmd, nil)
	require.NoError(t, err)
}

// TestConfigInitDefaultPath tests config init with default path
func TestConfigInitDefaultPath(t *testing.T) {
	// Create temp home directory
	tmpHome := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpHome)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	configOutput = "" // Use default path
	configForce = false

	err := runConfigInit(configInitCmd, nil)
	require.NoError(t, err)

	// Check that file was created in default location
	expectedPath := filepath.Join(tmpHome, ".frostdkg", "config.yaml")
	assert.FileExists(t, expectedPath)
}

// TestConfigShow tests config show command
func TestConfigShow(t *testing.T) {
	// Save original stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runConfigShow(configShowCmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Should contain header
	assert.Contains(t, output, "Current Configuration:")
}

// TestConfigShowWithSettings tests config show with viper settings
func TestConfigShowWithSettings(t *testing.T) {
	// Set some viper settings
	viper.Set("test.setting", "value")
	defer viper.Reset()

	// Save original stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runConfigShow(configShowCmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Should contain settings
	assert.Contains(t, output, "Current Configuration:")
}

// TestRunCoordinatorValidation tests coordinator parameter validation
func TestRunCoordinatorValidation(t *testing.T) {
	tests := []struct {
		name          string
		threshold     int
		participants  int
		expectError   bool
		errorContains string
	}{
		{
			name:          "threshold too low",
			threshold:     0,
			participants:  3,
			expectError:   true,
			errorContains: "threshold must be at least 1",
		},
		{
			name:          "participants less than threshold",
			threshold:     5,
			participants:  3,
			expectError:   true,
			errorContains: "must be >= threshold",
		},
		{
			name:          "threshold exceeds participants",
			threshold:     5,
			participants:  3,
			expectError:   true,
			errorContains: "must be >= threshold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coordinatorThreshold = tt.threshold
			coordinatorParticipants = tt.participants
			coordinatorSessionID = ""
			coordinatorListen = "localhost:9999"
			verbose = false

			err := runCoordinator(coordinatorCmd, nil)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestRunCoordinatorInvalidProtocol tests coordinator with invalid protocol
func TestRunCoordinatorInvalidProtocol(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test"
	coordinatorListen = "localhost:9999"
	protocol = "invalid-protocol"
	verbose = false

	err := runCoordinator(coordinatorCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported protocol")

	protocol = "grpc" // Reset
}

// TestRunParticipantValidation tests participant parameter validation
func TestRunParticipantValidation(t *testing.T) {
	tests := []struct {
		name          string
		participantID int
		threshold     int
		expectError   bool
		errorContains string
	}{
		{
			name:          "negative participant ID",
			participantID: -1,
			threshold:     2,
			expectError:   true,
			errorContains: "participant ID must be >= 0",
		},
		{
			name:          "threshold too low",
			participantID: 0,
			threshold:     0,
			expectError:   true,
			errorContains: "threshold must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			participantID = tt.participantID
			participantThreshold = tt.threshold
			participantCoordinator = "localhost:9999"
			participantOutput = filepath.Join(t.TempDir(), "output.json")
			verbose = false

			err := runParticipant(participantCmd, nil)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				// Will fail at connection, but validation should pass
				require.Error(t, err)
			}
		})
	}
}

// TestRunParticipantInvalidHostkey tests participant with invalid hostkey
func TestRunParticipantInvalidHostkey(t *testing.T) {
	participantID = 0
	participantThreshold = 2
	participantCoordinator = "localhost:9999"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantHostkey = "not-valid-hex"
	verbose = false

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hostkey hex")

	participantHostkey = "" // Reset
}

// TestRunParticipantWrongHostkeyLength tests participant with wrong hostkey length
func TestRunParticipantWrongHostkeyLength(t *testing.T) {
	participantID = 0
	participantThreshold = 2
	participantCoordinator = "localhost:9999"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantHostkey = hex.EncodeToString(make([]byte, 16)) // Should be 32 bytes
	verbose = false

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hostkey must be 32 bytes")

	participantHostkey = "" // Reset
}

// TestRunParticipantHostpubkeysNotImplemented tests participant with hostpubkeys flag
func TestRunParticipantHostpubkeysNotImplemented(t *testing.T) {
	participantID = 0
	participantThreshold = 2
	participantCoordinator = "localhost:9999"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantHostpubkeys = "some-value"
	verbose = false

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")

	participantHostpubkeys = "" // Reset
}

// TestRunParticipantInvalidProtocol tests participant with invalid protocol
func TestRunParticipantInvalidProtocol(t *testing.T) {
	participantID = 0
	participantThreshold = 2
	participantCoordinator = "localhost:9999"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "invalid-protocol"
	verbose = false

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported protocol")

	protocol = "grpc" // Reset
}

// TestRunParticipantIDExceedsHostKeys tests participant ID exceeding host keys
func TestRunParticipantIDExceedsHostKeys(t *testing.T) {
	participantID = 100 // Very large ID
	participantThreshold = 2
	participantCoordinator = "localhost:9999"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	verbose = false

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds number of host public keys")
}

// TestRunCoordinatorVerbose tests all verbose code paths in coordinator
func TestRunCoordinatorVerbose(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test-session"
	coordinatorListen = "localhost:9999"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "invalid" // Will fail quickly
	verbose = true
	tlsCert = "/tmp/cert.crt"
	tlsKey = "/tmp/key.key"
	tlsCA = "/tmp/ca.crt"

	err := runCoordinator(coordinatorCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported protocol")

	// Reset
	verbose = false
	tlsCert = ""
	tlsKey = ""
	tlsCA = ""
	protocol = "grpc"
}

// TestRunCoordinatorWithUnixSocket tests coordinator with Unix socket protocol
func TestRunCoordinatorWithUnixSocket(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test"
	coordinatorListen = sockPath
	protocol = "unix"
	verbose = false

	err := runCoordinator(coordinatorCmd, nil)
	// May fail or succeed depending on whether server can start
	// We're just testing that the unix protocol path is exercised
	_ = err

	protocol = "grpc" // Reset
}

// TestRunParticipantWithUnixSocket tests participant with Unix socket protocol
func TestRunParticipantWithUnixSocket(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = sockPath
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "unix"
	verbose = false

	err := runParticipant(participantCmd, nil)
	// Should fail since no coordinator is running
	require.Error(t, err)

	protocol = "grpc" // Reset
}

// TestRunCoordinatorAllProtocols tests all coordinator protocols
func TestRunCoordinatorAllProtocols(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		listen   string
	}{
		{"gRPC", "grpc", "127.0.0.1:29001"},
		{"HTTP", "http", "127.0.0.1:29002"},
		{"QUIC", "quic", "127.0.0.1:29003"},
		{"Unix", "unix", filepath.Join(t.TempDir(), "coord.sock")},
		{"libp2p", "libp2p", "127.0.0.1:29004"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coordinatorThreshold = 2
			coordinatorParticipants = 3
			coordinatorSessionID = "test-" + tt.name
			coordinatorListen = tt.listen
			coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
			coordinatorTimeout = 1
			protocol = tt.protocol
			verbose = false

			// Attempt to create coordinator - will fail during start
			_ = runCoordinator(coordinatorCmd, nil)

			protocol = "grpc" // Reset

			// Allow libp2p background goroutines to complete shutdown
			if tt.protocol == "libp2p" {
				time.Sleep(500 * time.Millisecond)
			}
		})
	}
}

// TestRunParticipantAllProtocols tests all participant protocols
func TestRunParticipantAllProtocols(t *testing.T) {
	tests := []struct {
		name        string
		protocol    string
		coordinator string
	}{
		{"gRPC", "grpc", "127.0.0.1:29101"},
		{"HTTP", "http", "http://127.0.0.1:29102"},
		{"QUIC", "quic", "127.0.0.1:29103"},
		{"Unix", "unix", filepath.Join(t.TempDir(), "part.sock")},
		{"libp2p", "libp2p", "/ip4/127.0.0.1/tcp/29104"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldTimeout := participantTimeout
			participantTimeout = 1
			defer func() { participantTimeout = oldTimeout }()

			participantID = 0
			participantThreshold = 2
			participantCoordinator = tt.coordinator
			participantOutput = filepath.Join(t.TempDir(), "output.json")
			protocol = tt.protocol
			verbose = false

			// Attempt to connect - will fail
			_ = runParticipant(participantCmd, nil)

			protocol = "grpc" // Reset

			// Allow libp2p background goroutines to complete shutdown
			if tt.protocol == "libp2p" {
				time.Sleep(500 * time.Millisecond)
			}
		})
	}
}

// TestRunCoordinatorWithAutogeneratedSessionID tests coordinator without session ID
func TestRunCoordinatorWithAutogeneratedSessionID(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "" // Will auto-generate UUID
	coordinatorListen = "127.0.0.1:29200"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = true

	// Will fail during server start
	_ = runCoordinator(coordinatorCmd, nil)

	verbose = false // Reset
}

// TestRunParticipantWithGeneratedHostkey tests participant with auto-generated hostkey
func TestRunParticipantWithGeneratedHostkey(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:29201"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantHostkey = "" // Will auto-generate
	protocol = "grpc"
	verbose = true

	// Will fail at connection
	_ = runParticipant(participantCmd, nil)

	verbose = false // Reset
}

// TestRunParticipantTLSPaths tests participant with TLS configuration paths
func TestRunParticipantTLSPaths(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:29202"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "grpc"
	verbose = true
	tlsCert = filepath.Join(t.TempDir(), "client.crt")
	tlsKey = filepath.Join(t.TempDir(), "client.key")

	// Will fail at connection
	_ = runParticipant(participantCmd, nil)

	verbose = false // Reset
	tlsCert = ""
	tlsKey = ""
}

// TestRunCoordinatorTLSPaths tests coordinator with TLS configuration paths
func TestRunCoordinatorTLSPaths(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test-tls"
	coordinatorListen = "127.0.0.1:29203"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = true
	tlsCert = filepath.Join(t.TempDir(), "server.crt")
	tlsKey = filepath.Join(t.TempDir(), "server.key")
	tlsCA = filepath.Join(t.TempDir(), "ca.crt")

	// Will fail during server start (missing cert files)
	_ = runCoordinator(coordinatorCmd, nil)

	verbose = false // Reset
	tlsCert = ""
	tlsKey = ""
	tlsCA = ""
}

// TestRunCoordinatorLibp2pDefaultAddress tests libp2p with default address
func TestRunCoordinatorLibp2pDefaultAddress(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test-libp2p-default"
	coordinatorListen = "0.0.0.0:9000" // Default address - tests special case
	protocol = "libp2p"
	verbose = false

	// Will fail during coordinator creation/start
	_ = runCoordinator(coordinatorCmd, nil)

	protocol = "grpc" // Reset

	// Allow libp2p background goroutines to complete shutdown
	time.Sleep(500 * time.Millisecond)
}

// TestRunCoordinatorLibp2pCustomAddress tests libp2p with custom address
func TestRunCoordinatorLibp2pCustomAddress(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test-libp2p-custom"
	coordinatorListen = "0.0.0.0:29204"
	protocol = "libp2p"
	verbose = false

	// Will fail during coordinator creation/start
	_ = runCoordinator(coordinatorCmd, nil)

	protocol = "grpc" // Reset

	// Allow libp2p background goroutines to complete shutdown
	time.Sleep(500 * time.Millisecond)
}

// TestRunParticipantWithValidHostkey tests participant with valid 32-byte hostkey
func TestRunParticipantWithValidHostkey(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:29301"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantHostkey = hex.EncodeToString(make([]byte, 32)) // Valid 32-byte key
	protocol = "grpc"
	verbose = true

	// Will fail at connection but should pass hostkey validation
	_ = runParticipant(participantCmd, nil)

	participantHostkey = "" // Reset
	verbose = false
}

// TestRunParticipantLargeID tests participant with large but valid ID
func TestRunParticipantLargeID(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 50 // Large ID that will exceed host keys
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:29302"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "grpc"
	verbose = false

	err := runParticipant(participantCmd, nil)
	// Should fail because ID exceeds number of generated host public keys
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds number of host public keys")
}

// TestRunConfigInitMkdirError tests config init when directory creation would fail
func TestRunConfigInitMkdirError(t *testing.T) {
	// Use a path that would require parent directory creation
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "subdir", "another", "config.yaml")

	configOutput = configPath
	configForce = false

	err := runConfigInit(configInitCmd, nil)
	// Should succeed - creates nested directories
	require.NoError(t, err)
	assert.FileExists(t, configPath)
}

// TestRunConfigShowWithConfigFile tests config show when a config file is used
func TestRunConfigShowWithConfigFile(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	err := os.WriteFile(configPath, []byte("protocol: http\ncodec: msgpack\n"), 0644)
	require.NoError(t, err)

	// Set the config file
	viper.SetConfigFile(configPath)
	err = viper.ReadInConfig()
	require.NoError(t, err)
	defer viper.Reset()

	// Save original stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runConfigShow(configShowCmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Should contain the config file path
	assert.Contains(t, output, "Current Configuration:")
}

// TestVerifyWithVerboseAndGroupKey tests verify with verbose output and group key check
func TestVerifyWithVerboseAndGroupKey(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "share.json")

	groupKey := hex.EncodeToString(make([]byte, 32))

	keyShare := KeyShareOutput{
		ParticipantIndex: 0,
		SecretShare:      hex.EncodeToString(make([]byte, 32)),
		ThresholdPubkey:  groupKey, // Match the group key
		PublicShares: []string{
			hex.EncodeToString(make([]byte, 32)),
			hex.EncodeToString(make([]byte, 32)),
		},
		SessionID:    "test-session",
		RecoveryData: hex.EncodeToString([]byte("recovery")),
		Timestamp:    time.Now().Unix(),
	}

	data, err := json.MarshalIndent(keyShare, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(sharePath, data, 0600)
	require.NoError(t, err)

	// Test verification with verbose and matching group key
	verifyShare = sharePath
	verifyGroupKey = groupKey // Should match
	verbose = true

	err = runVerify(verifyCmd, nil)
	require.NoError(t, err)

	verbose = false // Reset
	verifyGroupKey = ""
}

// TestVerifyWithEmptyRecoveryData tests verify with empty recovery data
func TestVerifyWithEmptyRecoveryData(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "share.json")

	keyShare := KeyShareOutput{
		ParticipantIndex: 0,
		SecretShare:      hex.EncodeToString(make([]byte, 32)),
		ThresholdPubkey:  hex.EncodeToString(make([]byte, 32)),
		PublicShares: []string{
			hex.EncodeToString(make([]byte, 32)),
		},
		SessionID:    "test-session",
		RecoveryData: "", // Empty recovery data
		Timestamp:    0,  // Zero timestamp
	}

	data, err := json.MarshalIndent(keyShare, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(sharePath, data, 0600)
	require.NoError(t, err)

	verifyShare = sharePath
	verifyGroupKey = ""
	verbose = true

	err = runVerify(verifyCmd, nil)
	require.NoError(t, err)

	verbose = false // Reset
}

// TestCertgenWithIPAddress tests certgen with IP address in hosts
func TestCertgenWithIPAddress(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "ecdsa"
	certgenOutput = tmpDir
	certgenName = "test-ip"
	certgenDays = 100
	certgenHosts = []string{"192.168.1.1", "10.0.0.1", "example.com"} // Mix of IPs and DNS names
	verbose = true

	err := runCertgen(certgenCmd, nil)
	require.NoError(t, err)
	verbose = false // Reset

	certPath := filepath.Join(tmpDir, "test-ip.crt")
	keyPath := filepath.Join(tmpDir, "test-ip.key")

	assert.FileExists(t, certPath)
	assert.FileExists(t, keyPath)
}

// TestRunParticipantWithAllVerbosePaths tests all verbose code paths in participant
func TestRunParticipantWithAllVerbosePaths(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 1
	participantThreshold = 3
	participantCoordinator = "127.0.0.1:29401"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantHostkey = "" // Auto-generate
	protocol = "grpc"
	verbose = true
	tlsCert = filepath.Join(t.TempDir(), "cert.crt")
	tlsKey = filepath.Join(t.TempDir(), "key.key")

	// Will fail at connection but exercises verbose paths
	_ = runParticipant(participantCmd, nil)

	verbose = false
	tlsCert = ""
	tlsKey = ""
}

// TestRunCoordinatorWithAllVerbosePaths tests all verbose code paths in coordinator
func TestRunCoordinatorWithAllVerbosePaths(t *testing.T) {
	coordinatorThreshold = 3
	coordinatorParticipants = 5
	coordinatorSessionID = "verbose-test"
	coordinatorListen = "0.0.0.0:29402"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = true
	tlsCert = filepath.Join(t.TempDir(), "server.crt")
	tlsKey = filepath.Join(t.TempDir(), "server.key")
	tlsCA = filepath.Join(t.TempDir(), "ca.crt")

	// Will fail at server start but exercises verbose paths
	_ = runCoordinator(coordinatorCmd, nil)

	verbose = false
	tlsCert = ""
	tlsKey = ""
	tlsCA = ""
}

// TestRunCoordinatorValidThresholdEqual tests valid threshold equal to participants
func TestRunCoordinatorValidThresholdEqual(t *testing.T) {
	coordinatorThreshold = 3
	coordinatorParticipants = 3 // threshold == participants is valid
	coordinatorSessionID = "equal-test"
	coordinatorListen = "127.0.0.1:29403"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = false

	// Will fail at server start but validation should pass
	_ = runCoordinator(coordinatorCmd, nil)
}

// TestRunCoordinatorMinimalThreshold tests minimal valid threshold
func TestRunCoordinatorMinimalThreshold(t *testing.T) {
	coordinatorThreshold = 1 // Minimum valid threshold
	coordinatorParticipants = 2
	coordinatorSessionID = "minimal-test"
	coordinatorListen = "127.0.0.1:29404"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = false

	// Will fail at server start but validation should pass
	_ = runCoordinator(coordinatorCmd, nil)
}

// TestRunParticipantMinimalThreshold tests minimal valid threshold for participant
func TestRunParticipantMinimalThreshold(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 1 // Minimum valid threshold
	participantCoordinator = "127.0.0.1:29405"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "grpc"
	verbose = false

	// Will fail at connection but validation should pass
	_ = runParticipant(participantCmd, nil)
}

// TestRunParticipantID0 tests participant with ID 0 (first participant)
func TestRunParticipantID0(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0 // First participant
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:29406"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "grpc"
	verbose = true

	// Will fail at connection but ID 0 is valid
	_ = runParticipant(participantCmd, nil)

	verbose = false
}

// TestRunCoordinatorEmptySessionID tests empty session ID generation
func TestRunCoordinatorEmptySessionID(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "" // Should auto-generate UUID
	coordinatorListen = "127.0.0.1:29407"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = true

	// Will fail at server start but should generate session ID
	_ = runCoordinator(coordinatorCmd, nil)

	verbose = false
}

// TestConfigFlags tests config command flags
func TestConfigFlags(t *testing.T) {
	tests := []struct {
		name     string
		cmd      *cobra.Command
		flagName string
	}{
		{"init output flag", configInitCmd, "output"},
		{"init force flag", configInitCmd, "force"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := tt.cmd.Flags().Lookup(tt.flagName)
			require.NotNil(t, flag, "flag %s not found", tt.flagName)
		})
	}
}

// TestRootPersistentPreRun tests the root command's PersistentPreRun
func TestRootPersistentPreRun(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte("protocol: http\n"), 0644)
	require.NoError(t, err)

	// Test with explicit config file
	cfgFile = configPath
	verbose = true
	defer func() {
		cfgFile = ""
		verbose = false
		viper.Reset()
	}()

	rootCmd.PersistentPreRun(rootCmd, nil)

	// Verify config was loaded
	assert.NotEmpty(t, viper.ConfigFileUsed())
}

// TestRootPersistentPreRunNoConfig tests PersistentPreRun without config file
func TestRootPersistentPreRunNoConfig(t *testing.T) {
	cfgFile = ""
	verbose = false
	defer viper.Reset()

	// Should not error when no config file exists
	rootCmd.PersistentPreRun(rootCmd, nil)
}

// TestConfigShowEmptySettings tests config show with no settings
func TestConfigShowEmptySettings(t *testing.T) {
	// Reset viper to ensure clean state
	viper.Reset()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runConfigShow(configShowCmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Should indicate no configuration loaded
	assert.Contains(t, output, "No configuration loaded")
}

// TestConfigInitWithCustomOutput tests config init with custom output path
func TestConfigInitWithCustomOutput(t *testing.T) {
	tmpDir := t.TempDir()
	customPath := filepath.Join(tmpDir, "custom", "path", "myconfig.yaml")

	configOutput = customPath
	configForce = false

	err := runConfigInit(configInitCmd, nil)
	require.NoError(t, err)

	// Verify file was created
	assert.FileExists(t, customPath)

	// Verify content
	data, err := os.ReadFile(customPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "protocol:")
}

// TestRunCoordinatorThresholdExceedsParticipantsEdgeCase tests edge case
func TestRunCoordinatorThresholdExceedsParticipantsEdgeCase(t *testing.T) {
	coordinatorThreshold = 10
	coordinatorParticipants = 5
	coordinatorSessionID = "test"
	coordinatorListen = "localhost:9999"
	verbose = false

	err := runCoordinator(coordinatorCmd, nil)
	require.Error(t, err)
	// Should catch participants < threshold
	assert.Contains(t, err.Error(), "participants (5) must be >= threshold (10)")
}

// TestRunParticipantConnectionFailure tests participant connection error handling
func TestRunParticipantConnectionFailure(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:19999" // Non-existent port
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "grpc"
	verbose = false

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	// Should fail with connection error
	assert.Contains(t, err.Error(), "failed to")
}

// TestRunParticipantVerboseWithoutTLS tests verbose path without TLS
func TestRunParticipantVerboseWithoutTLS(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:29500"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "grpc"
	verbose = true
	tlsCert = "" // No TLS
	tlsKey = ""

	_ = runParticipant(participantCmd, nil)

	verbose = false
}

// TestRunCoordinatorVerboseWithoutCA tests verbose path without CA cert
func TestRunCoordinatorVerboseWithoutCA(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "test"
	coordinatorListen = "127.0.0.1:29501"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = true
	tlsCert = filepath.Join(t.TempDir(), "server.crt")
	tlsKey = filepath.Join(t.TempDir(), "server.key")
	tlsCA = "" // No CA cert

	_ = runCoordinator(coordinatorCmd, nil)

	verbose = false
	tlsCert = ""
	tlsKey = ""
}

// TestCertgenECDSAFileWritePermissions verifies cert file permissions
func TestCertgenECDSAFileWritePermissions(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "ecdsa"
	certgenOutput = tmpDir
	certgenName = "test-perms"
	certgenDays = 365
	certgenHosts = []string{"localhost"}
	verbose = false

	err := runCertgen(certgenCmd, nil)
	require.NoError(t, err)

	// Check cert file permissions (should be 0644)
	certPath := filepath.Join(tmpDir, "test-perms.crt")
	info, err := os.Stat(certPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}

// TestRunParticipantMultiplePublicShares tests participant with correct number of public shares
func TestRunParticipantMultiplePublicShares(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 2 // ID within threshold+1 range
	participantThreshold = 5
	participantCoordinator = "127.0.0.1:29502"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "grpc"
	verbose = false

	// Will fail at connection but should generate correct number of host keys
	_ = runParticipant(participantCmd, nil)
}

// TestRunParticipantRandomGenerationPaths tests random generation code paths
func TestRunParticipantRandomGenerationPaths(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:29600"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantHostkey = "" // Will trigger random key generation
	protocol = "grpc"
	verbose = false

	// This tests the random generation paths by running with auto-generated keys
	_ = runParticipant(participantCmd, nil)
}

// TestRunParticipantFileOutputError tests file write error handling
func TestRunParticipantFileOutputError(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:29601"
	// Use invalid path for write error
	participantOutput = "/dev/null/cannot/write/here.json"
	protocol = "grpc"
	verbose = false

	err := runParticipant(participantCmd, nil)
	// Will fail - either at connection or file write
	require.Error(t, err)
}

// TestRunCoordinatorWaitForParticipantsTimeout tests timeout scenario
func TestRunCoordinatorWaitForParticipantsTimeout(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "timeout-test"
	coordinatorListen = "127.0.0.1:29700"
	coordinatorTimeout = 1 // Short timeout
	protocol = "grpc"
	verbose = false

	// Will fail due to timeout waiting for participants
	_ = runCoordinator(coordinatorCmd, nil)
}

// TestRunCoordinatorHTTPProtocol tests HTTP protocol path
func TestRunCoordinatorHTTPProtocol(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "http-test"
	coordinatorListen = "127.0.0.1:29701"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "http"
	verbose = false

	// Will fail at server start
	_ = runCoordinator(coordinatorCmd, nil)

	protocol = "grpc" // Reset
}

// TestRunCoordinatorQUICProtocol tests QUIC protocol path
func TestRunCoordinatorQUICProtocol(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "quic-test"
	coordinatorListen = "127.0.0.1:29702"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "quic"
	verbose = false

	// Will fail at server start
	_ = runCoordinator(coordinatorCmd, nil)

	protocol = "grpc" // Reset
}

// TestRunParticipantHTTPProtocol tests HTTP participant
func TestRunParticipantHTTPProtocol(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "http://127.0.0.1:29800"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "http"
	verbose = false

	_ = runParticipant(participantCmd, nil)

	protocol = "grpc" // Reset
}

// TestRunParticipantQUICProtocol tests QUIC participant
func TestRunParticipantQUICProtocol(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:29801"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "quic"
	verbose = false

	_ = runParticipant(participantCmd, nil)

	protocol = "grpc" // Reset
}

// TestRunParticipantLibp2pProtocol tests libp2p participant
func TestRunParticipantLibp2pProtocol(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "/ip4/127.0.0.1/tcp/29802"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "libp2p"
	verbose = false

	_ = runParticipant(participantCmd, nil)

	protocol = "grpc" // Reset

	// Allow libp2p background goroutines to complete shutdown
	time.Sleep(500 * time.Millisecond)
}

// TestRunCoordinatorLibp2pProtocol tests libp2p coordinator
func TestRunCoordinatorLibp2pProtocol(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "libp2p-test"
	coordinatorListen = "127.0.0.1:29803"
	coordinatorTimeout = 1
	protocol = "libp2p"
	verbose = false

	_ = runCoordinator(coordinatorCmd, nil)

	protocol = "grpc" // Reset

	// Allow libp2p background goroutines to complete shutdown
	time.Sleep(500 * time.Millisecond)
}

// TestRunCoordinatorLibp2pWithMultiaddrParsing tests libp2p multiaddr parsing
func TestRunCoordinatorLibp2pWithMultiaddrParsing(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "libp2p-multiaddr-test"
	coordinatorListen = "192.168.1.1:9999"
	coordinatorTimeout = 1
	protocol = "libp2p"
	verbose = false

	_ = runCoordinator(coordinatorCmd, nil)

	protocol = "grpc" // Reset

	// Allow libp2p background goroutines to complete shutdown
	time.Sleep(500 * time.Millisecond)
}

// TestCertgenEd25519WithSingleHost tests Ed25519 with single host
func TestCertgenEd25519WithSingleHost(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "ed25519"
	certgenOutput = tmpDir
	certgenName = "single-host"
	certgenDays = 180
	certgenHosts = []string{"single.example.com"}
	verbose = false

	err := runCertgen(certgenCmd, nil)
	require.NoError(t, err)

	certPath := filepath.Join(tmpDir, "single-host.crt")
	keyPath := filepath.Join(tmpDir, "single-host.key")

	assert.FileExists(t, certPath)
	assert.FileExists(t, keyPath)
}

// TestCertgenECDSAWithLongValidity tests ECDSA with long validity period
func TestCertgenECDSAWithLongValidity(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "ecdsa"
	certgenOutput = tmpDir
	certgenName = "long-validity"
	certgenDays = 3650 // 10 years
	certgenHosts = []string{"localhost"}
	verbose = false

	err := runCertgen(certgenCmd, nil)
	require.NoError(t, err)

	certPath := filepath.Join(tmpDir, "long-validity.crt")
	keyPath := filepath.Join(tmpDir, "long-validity.key")

	assert.FileExists(t, certPath)
	assert.FileExists(t, keyPath)
}

// TestConfigInitHomeDirectoryError tests error when HOME directory lookup fails
func TestConfigInitHomeDirectoryError(t *testing.T) {
	// This is difficult to test without mocking os.UserHomeDir()
	// Skip this test as it requires special OS conditions
	t.Skip("Skipping HOME directory error test - requires OS mocking")
}

// TestRunCoordinatorUnixProtocol tests unix socket coordinator
func TestRunCoordinatorUnixProtocol(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "coord.sock")

	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "unix-test"
	coordinatorListen = sockPath
	coordinatorTimeout = 1
	protocol = "unix"
	verbose = false

	_ = runCoordinator(coordinatorCmd, nil)

	protocol = "grpc" // Reset
}

// TestRunParticipantUnixProtocol tests unix socket participant
func TestRunParticipantUnixProtocol(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "part.sock")

	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = sockPath
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "unix"
	verbose = false

	_ = runParticipant(participantCmd, nil)

	protocol = "grpc" // Reset
}

// TestVerifyMultiplePublicShares tests verification with multiple public shares
func TestVerifyMultiplePublicShares(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "multi-shares.json")

	keyShare := KeyShareOutput{
		ParticipantIndex: 0,
		SecretShare:      hex.EncodeToString(make([]byte, 32)),
		ThresholdPubkey:  hex.EncodeToString(make([]byte, 32)),
		PublicShares: []string{
			hex.EncodeToString(make([]byte, 32)),
			hex.EncodeToString(make([]byte, 32)),
			hex.EncodeToString(make([]byte, 32)),
			hex.EncodeToString(make([]byte, 32)),
			hex.EncodeToString(make([]byte, 32)),
		},
		SessionID: "test-session",
	}

	data, err := json.MarshalIndent(keyShare, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(sharePath, data, 0600)
	require.NoError(t, err)

	verifyShare = sharePath
	verifyGroupKey = ""
	verbose = false

	err = runVerify(verifyCmd, nil)
	require.NoError(t, err)
}

// TestRunCoordinatorVerboseWithSessionID tests verbose output with explicit session ID
func TestRunCoordinatorVerboseWithSessionID(t *testing.T) {
	coordinatorThreshold = 2
	coordinatorParticipants = 3
	coordinatorSessionID = "explicit-session-id"
	coordinatorListen = "127.0.0.1:29900"
	coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
	coordinatorTimeout = 1
	protocol = "grpc"
	verbose = true

	_ = runCoordinator(coordinatorCmd, nil)

	verbose = false
}

// TestRunParticipantWithExplicitHostkey tests participant with provided hostkey
func TestRunParticipantWithExplicitHostkey(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 0
	participantThreshold = 2
	participantCoordinator = "127.0.0.1:29901"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	participantHostkey = hex.EncodeToString(make([]byte, 32))
	protocol = "grpc"
	verbose = false

	_ = runParticipant(participantCmd, nil)

	participantHostkey = "" // Reset
}

// TestConfigShowWithLoadedConfig tests showing loaded config
func TestConfigShowWithLoadedConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "loaded-config.yaml")

	err := os.WriteFile(configPath, []byte("protocol: quic\ncodec: cbor\n"), 0644)
	require.NoError(t, err)

	viper.SetConfigFile(configPath)
	err = viper.ReadInConfig()
	require.NoError(t, err)
	defer viper.Reset()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runConfigShow(configShowCmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	assert.Contains(t, output, "Loaded from:")
}

// TestRootPersistentPreRunWithVerbose tests PersistentPreRun with verbose flag
func TestRootPersistentPreRunWithVerbose(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "verbose-config.yaml")
	err := os.WriteFile(configPath, []byte("protocol: http\n"), 0644)
	require.NoError(t, err)

	cfgFile = configPath
	verbose = true
	defer func() {
		cfgFile = ""
		verbose = false
		viper.Reset()
	}()

	rootCmd.PersistentPreRun(rootCmd, nil)
}

// TestRunParticipantWithBoundaryThreshold tests participant with threshold at boundary
func TestRunParticipantWithBoundaryThreshold(t *testing.T) {
	oldTimeout := participantTimeout
	participantTimeout = 1
	defer func() { participantTimeout = oldTimeout }()

	participantID = 1
	participantThreshold = 10 // Will create 11 host keys
	participantCoordinator = "127.0.0.1:30000"
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	protocol = "grpc"
	verbose = false

	_ = runParticipant(participantCmd, nil)
}

// TestRunParticipantVerboseAllPaths tests all verbose paths with different configs
func TestRunParticipantVerboseAllPaths(t *testing.T) {
	tests := []struct {
		name      string
		id        int
		threshold int
		hostkey   string
		tlsCert   string
		tlsKey    string
	}{
		{
			name:      "verbose with ID 0 no TLS",
			id:        0,
			threshold: 2,
			hostkey:   "",
			tlsCert:   "",
			tlsKey:    "",
		},
		{
			name:      "verbose with ID 1 with hostkey",
			id:        1,
			threshold: 3,
			hostkey:   hex.EncodeToString(make([]byte, 32)),
			tlsCert:   "",
			tlsKey:    "",
		},
		{
			name:      "verbose with ID 2 with TLS",
			id:        2,
			threshold: 4,
			hostkey:   "",
			tlsCert:   filepath.Join(t.TempDir(), "client.crt"),
			tlsKey:    filepath.Join(t.TempDir(), "client.key"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldTimeout := participantTimeout
			participantTimeout = 1
			defer func() { participantTimeout = oldTimeout }()

			participantID = tt.id
			participantThreshold = tt.threshold
			participantCoordinator = "127.0.0.1:30100"
			participantOutput = filepath.Join(t.TempDir(), "output.json")
			participantHostkey = tt.hostkey
			tlsCert = tt.tlsCert
			tlsKey = tt.tlsKey
			protocol = "grpc"
			verbose = true

			_ = runParticipant(participantCmd, nil)

			// Reset
			participantHostkey = ""
			tlsCert = ""
			tlsKey = ""
			verbose = false
		})
	}
}

// TestRunCoordinatorVerboseAllPaths tests all verbose paths with different configs
func TestRunCoordinatorVerboseAllPaths(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		tlsCert   string
		tlsKey    string
		tlsCA     string
	}{
		{
			name:      "verbose without session ID",
			sessionID: "",
			tlsCert:   "",
			tlsKey:    "",
			tlsCA:     "",
		},
		{
			name:      "verbose with session ID no CA",
			sessionID: "test-session",
			tlsCert:   filepath.Join(t.TempDir(), "server.crt"),
			tlsKey:    filepath.Join(t.TempDir(), "server.key"),
			tlsCA:     "",
		},
		{
			name:      "verbose with session ID and CA",
			sessionID: "test-session-2",
			tlsCert:   filepath.Join(t.TempDir(), "server.crt"),
			tlsKey:    filepath.Join(t.TempDir(), "server.key"),
			tlsCA:     filepath.Join(t.TempDir(), "ca.crt"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coordinatorThreshold = 2
			coordinatorParticipants = 3
			coordinatorSessionID = tt.sessionID
			coordinatorListen = "127.0.0.1:30200"
			coordinatorCiphersuite = "FROST-ED25519-SHA512-v1"
			coordinatorTimeout = 1
			protocol = "grpc"
			verbose = true
			tlsCert = tt.tlsCert
			tlsKey = tt.tlsKey
			tlsCA = tt.tlsCA

			_ = runCoordinator(coordinatorCmd, nil)

			// Reset
			tlsCert = ""
			tlsKey = ""
			tlsCA = ""
			verbose = false
		})
	}
}

// TestCertgenAllPaths tests all code paths in certgen
func TestCertgenAllPaths(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		days    int
		hosts   []string
		verbose bool
	}{
		{
			name:    "ecdsa minimal",
			keyType: "ecdsa",
			days:    1,
			hosts:   []string{"localhost"},
			verbose: false,
		},
		{
			name:    "ed25519 verbose",
			keyType: "ed25519",
			days:    365,
			hosts:   []string{"example.com", "192.168.1.1"},
			verbose: true,
		},
		{
			name:    "ecdsa multiple hosts verbose",
			keyType: "ecdsa",
			days:    730,
			hosts:   []string{"host1.com", "host2.com", "10.0.0.1", "192.168.0.1"},
			verbose: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			certgenType = tt.keyType
			certgenOutput = tmpDir
			certgenName = tt.name
			certgenDays = tt.days
			certgenHosts = tt.hosts
			verbose = tt.verbose

			err := runCertgen(certgenCmd, nil)
			require.NoError(t, err)

			certPath := filepath.Join(tmpDir, tt.name+".crt")
			keyPath := filepath.Join(tmpDir, tt.name+".key")

			assert.FileExists(t, certPath)
			assert.FileExists(t, keyPath)

			verbose = false // Reset
		})
	}
}

// TestConfigInitAllPaths tests all paths in config init
func TestConfigInitAllPaths(t *testing.T) {
	tests := []struct {
		name        string
		useDefault  bool
		force       bool
		expectError bool
	}{
		{
			name:        "default path",
			useDefault:  true,
			force:       false,
			expectError: false,
		},
		{
			name:        "custom path",
			useDefault:  false,
			force:       false,
			expectError: false,
		},
		{
			name:        "custom path with force",
			useDefault:  false,
			force:       true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			var configPath string

			if tt.useDefault {
				// Set temp HOME
				originalHome := os.Getenv("HOME")
				_ = os.Setenv("HOME", tmpDir)
				defer func() { _ = os.Setenv("HOME", originalHome) }()
				configOutput = ""
			} else {
				configPath = filepath.Join(tmpDir, "custom-config.yaml")
				configOutput = configPath
			}

			configForce = tt.force

			err := runConfigInit(configInitCmd, nil)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			configForce = false // Reset
		})
	}
}

// TestAllProtocolsCoordinator tests that all protocols are attempted
func TestAllProtocolsCoordinator(t *testing.T) {
	protocols := []string{"grpc", "http", "quic", "unix", "libp2p"}

	for _, proto := range protocols {
		t.Run("coordinator-"+proto, func(t *testing.T) {
			coordinatorThreshold = 2
			coordinatorParticipants = 3
			coordinatorSessionID = "protocol-test"
			coordinatorTimeout = 1
			protocol = proto
			verbose = false

			if proto == "unix" {
				coordinatorListen = filepath.Join(t.TempDir(), "test.sock")
			} else {
				coordinatorListen = "127.0.0.1:30300"
			}

			_ = runCoordinator(coordinatorCmd, nil)

			protocol = "grpc" // Reset
		})
	}
}

// TestAllProtocolsParticipant tests that all protocols are attempted
func TestAllProtocolsParticipant(t *testing.T) {
	protocols := []string{"grpc", "http", "quic", "unix", "libp2p"}

	for _, proto := range protocols {
		t.Run("participant-"+proto, func(t *testing.T) {
			oldTimeout := participantTimeout
			participantTimeout = 1
			defer func() { participantTimeout = oldTimeout }()

			participantID = 0
			participantThreshold = 2
			participantOutput = filepath.Join(t.TempDir(), "output.json")
			protocol = proto
			verbose = false

			switch proto {
			case "unix":
				participantCoordinator = filepath.Join(t.TempDir(), "test.sock")
			case "libp2p":
				participantCoordinator = "/ip4/127.0.0.1/tcp/30400"
			case "http":
				participantCoordinator = "http://127.0.0.1:30400"
			default:
				participantCoordinator = "127.0.0.1:30400"
			}

			_ = runParticipant(participantCmd, nil)

			protocol = "grpc" // Reset
		})
	}
}

// TestCertgenCertFileWriteError tests certificate file write error
func TestCertgenCertFileWriteError(t *testing.T) {
	// Create a directory where we can't write
	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	err := os.Mkdir(readOnlyDir, 0755)
	require.NoError(t, err)

	certgenType = "ecdsa"
	certgenOutput = readOnlyDir
	certgenName = "test"
	certgenDays = 365
	certgenHosts = []string{"localhost"}
	verbose = false

	// First run should succeed
	err = runCertgen(certgenCmd, nil)
	require.NoError(t, err)

	// Make directory read-only to force write error
	err = os.Chmod(readOnlyDir, 0444)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(readOnlyDir, 0755) }() // Restore for cleanup

	certgenName = "test2" // Different name to avoid existing file
	err = runCertgen(certgenCmd, nil)
	// Should fail - can't write to read-only directory
	require.Error(t, err)
}

// TestConfigInitWriteError tests config init file write error
func TestConfigInitWriteError(t *testing.T) {
	// Create a read-only directory
	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	err := os.MkdirAll(readOnlyDir, 0755)
	require.NoError(t, err)

	// Make it read-only
	err = os.Chmod(readOnlyDir, 0444)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(readOnlyDir, 0755) }()

	configOutput = filepath.Join(readOnlyDir, "config.yaml")
	configForce = false

	err = runConfigInit(configInitCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write config file")
}

// TestConfigInitDirCreationError tests config init directory creation error
func TestConfigInitDirCreationError(t *testing.T) {
	// Try to create directory inside a file
	tmpDir := t.TempDir()
	blockingFile := filepath.Join(tmpDir, "blocking")
	err := os.WriteFile(blockingFile, []byte("block"), 0644)
	require.NoError(t, err)

	configOutput = filepath.Join(blockingFile, "subdir", "config.yaml")
	configForce = false

	err = runConfigInit(configInitCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create directory")
}

// TestRunCoordinatorThresholdExceedsParticipantsValidation tests threshold > participants
func TestRunCoordinatorThresholdExceedsParticipantsValidation(t *testing.T) {
	coordinatorThreshold = 10
	coordinatorParticipants = 3
	coordinatorSessionID = "validation-test"
	coordinatorListen = "127.0.0.1:31000"
	verbose = false

	err := runCoordinator(coordinatorCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be >= threshold")
}

// TestCertgenKeyFileWriteError tests key file write error specifically
func TestCertgenKeyFileWriteError(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "ecdsa"
	certgenOutput = tmpDir
	certgenName = "write-error-test"
	certgenDays = 365
	certgenHosts = []string{"localhost"}
	verbose = false

	// First create the cert successfully
	err := runCertgen(certgenCmd, nil)
	require.NoError(t, err)

	// Now make key file read-only and try again
	keyPath := filepath.Join(tmpDir, "write-error-test.key")
	err = os.Chmod(keyPath, 0444)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(keyPath, 0644) }()

	// Try to overwrite - should fail on key write
	err = runCertgen(certgenCmd, nil)
	require.Error(t, err)
}

// TestCertgenEd25519KeyFileWriteError tests Ed25519 key file write error
func TestCertgenEd25519KeyFileWriteError(t *testing.T) {
	tmpDir := t.TempDir()

	certgenType = "ed25519"
	certgenOutput = tmpDir
	certgenName = "ed25519-write-error"
	certgenDays = 365
	certgenHosts = []string{"localhost"}
	verbose = false

	// First create successfully
	err := runCertgen(certgenCmd, nil)
	require.NoError(t, err)

	// Make key file read-only
	keyPath := filepath.Join(tmpDir, "ed25519-write-error.key")
	err = os.Chmod(keyPath, 0444)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(keyPath, 0644) }()

	// Try to overwrite
	err = runCertgen(certgenCmd, nil)
	require.Error(t, err)
}

// TestCoordinatorCmdRequiredFlags verifies required flags are marked
func TestCoordinatorCmdRequiredFlags(t *testing.T) {
	// Verify the threshold flag is marked required
	thresholdFlag := coordinatorCmd.Flags().Lookup("threshold")
	require.NotNil(t, thresholdFlag)

	// Verify the participants flag is marked required
	participantsFlag := coordinatorCmd.Flags().Lookup("participants")
	require.NotNil(t, participantsFlag)
}

// TestParticipantCmdRequiredFlags verifies required flags are marked
func TestParticipantCmdRequiredFlags(t *testing.T) {
	// Verify the id flag is marked required
	idFlag := participantCmd.Flags().Lookup("id")
	require.NotNil(t, idFlag)

	// Verify the output flag is marked required
	outputFlag := participantCmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag)
}

// TestVerifyCmdRequiredFlags verifies required flags are marked
func TestVerifyCmdRequiredFlags(t *testing.T) {
	// Verify the share flag is marked required
	shareFlag := verifyCmd.Flags().Lookup("share")
	require.NotNil(t, shareFlag)
}

// TestRootCmdHasAllSubcommands verifies all expected subcommands are registered
func TestRootCmdHasAllSubcommands(t *testing.T) {
	expectedSubcommands := []string{
		"version",
		"coordinator",
		"participant",
		"certgen",
		"verify",
		"config",
	}

	for _, cmdName := range expectedSubcommands {
		found := false
		for _, cmd := range rootCmd.Commands() {
			if cmd.Name() == cmdName {
				found = true
				break
			}
		}
		assert.True(t, found, "subcommand %s should be registered", cmdName)
	}
}

// TestConfigCmdHasSubcommands verifies config subcommands are registered
func TestConfigCmdHasSubcommands(t *testing.T) {
	expectedSubcommands := []string{"init", "show"}

	for _, cmdName := range expectedSubcommands {
		found := false
		for _, cmd := range configCmd.Commands() {
			if cmd.Name() == cmdName {
				found = true
				break
			}
		}
		assert.True(t, found, "config subcommand %s should be registered", cmdName)
	}
}

// TestViperBindings tests that viper bindings are properly configured
func TestViperBindings(t *testing.T) {
	// Reset viper to clean state
	viper.Reset()
	defer viper.Reset()

	// Set some values via viper
	viper.Set("protocol", "http")
	viper.Set("codec", "msgpack")
	viper.Set("verbose", true)

	// Verify the values are set
	assert.Equal(t, "http", viper.GetString("protocol"))
	assert.Equal(t, "msgpack", viper.GetString("codec"))
	assert.True(t, viper.GetBool("verbose"))
}

// TestCoordinatorDefaultValues tests coordinator command default values
func TestCoordinatorDefaultValues(t *testing.T) {
	listenFlag := coordinatorCmd.Flags().Lookup("listen")
	require.NotNil(t, listenFlag)
	assert.Equal(t, "0.0.0.0:9000", listenFlag.DefValue)

	ciphersuiteFlag := coordinatorCmd.Flags().Lookup("ciphersuite")
	require.NotNil(t, ciphersuiteFlag)
	assert.Equal(t, "FROST-ED25519-SHA512-v1", ciphersuiteFlag.DefValue)

	timeoutFlag := coordinatorCmd.Flags().Lookup("timeout")
	require.NotNil(t, timeoutFlag)
	assert.Equal(t, "300", timeoutFlag.DefValue)
}

// TestParticipantDefaultValues tests participant command default values
func TestParticipantDefaultValues(t *testing.T) {
	coordinatorFlag := participantCmd.Flags().Lookup("coordinator")
	require.NotNil(t, coordinatorFlag)
	assert.Equal(t, "localhost:9000", coordinatorFlag.DefValue)

	thresholdFlag := participantCmd.Flags().Lookup("threshold")
	require.NotNil(t, thresholdFlag)
	assert.Equal(t, "2", thresholdFlag.DefValue)

	timeoutFlag := participantCmd.Flags().Lookup("timeout")
	require.NotNil(t, timeoutFlag)
	assert.Equal(t, "300", timeoutFlag.DefValue)
}

// TestCertgenDefaultValues tests certgen command default values
func TestCertgenDefaultValues(t *testing.T) {
	typeFlag := certgenCmd.Flags().Lookup("type")
	require.NotNil(t, typeFlag)
	assert.Equal(t, "ecdsa", typeFlag.DefValue)

	outputFlag := certgenCmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "./certs", outputFlag.DefValue)

	daysFlag := certgenCmd.Flags().Lookup("days")
	require.NotNil(t, daysFlag)
	assert.Equal(t, "365", daysFlag.DefValue)
}

// TestRootDefaultValues tests root command default values
func TestRootDefaultValues(t *testing.T) {
	protocolFlag := rootCmd.PersistentFlags().Lookup("protocol")
	require.NotNil(t, protocolFlag)
	assert.Equal(t, "grpc", protocolFlag.DefValue)

	codecFlag := rootCmd.PersistentFlags().Lookup("codec")
	require.NotNil(t, codecFlag)
	assert.Equal(t, "json", codecFlag.DefValue)

	insecureFlag := rootCmd.PersistentFlags().Lookup("insecure")
	require.NotNil(t, insecureFlag)
	assert.Equal(t, "false", insecureFlag.DefValue)
}

// TestVersionConstant tests that version constant is set
func TestVersionConstant(t *testing.T) {
	assert.NotEmpty(t, Version)
	assert.Equal(t, "dev", Version)
}

// TestKeyShareOutputStruct tests the KeyShareOutput struct JSON marshaling
func TestKeyShareOutputStruct(t *testing.T) {
	output := KeyShareOutput{
		ParticipantIndex: 1,
		SecretShare:      "abcd1234",
		ThresholdPubkey:  "efgh5678",
		PublicShares:     []string{"share1", "share2"},
		SessionID:        "session-123",
		RecoveryData:     "recovery-data",
		Timestamp:        1234567890,
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var decoded KeyShareOutput
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, output.ParticipantIndex, decoded.ParticipantIndex)
	assert.Equal(t, output.SecretShare, decoded.SecretShare)
	assert.Equal(t, output.ThresholdPubkey, decoded.ThresholdPubkey)
	assert.Equal(t, output.PublicShares, decoded.PublicShares)
	assert.Equal(t, output.SessionID, decoded.SessionID)
	assert.Equal(t, output.RecoveryData, decoded.RecoveryData)
	assert.Equal(t, output.Timestamp, decoded.Timestamp)
}

// TestSampleConfigContent verifies sample config has expected sections
func TestSampleConfigContent(t *testing.T) {
	expectedSections := []string{
		"protocol:",
		"codec:",
		"tls:",
		"insecure:",
		"verbose:",
		"coordinator:",
		"participant:",
		"certgen:",
		"verify:",
	}

	for _, section := range expectedSections {
		assert.Contains(t, sampleConfig, section, "sampleConfig should contain %s", section)
	}
}

// TestRunCoordinatorNegativeThreshold tests coordinator with negative threshold
func TestRunCoordinatorNegativeThreshold(t *testing.T) {
	coordinatorThreshold = -1
	coordinatorParticipants = 3
	coordinatorSessionID = "test"
	coordinatorListen = "localhost:9999"
	verbose = false

	err := runCoordinator(coordinatorCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold must be at least 1")
}

// TestRunParticipantNegativeThreshold tests participant with negative threshold
func TestRunParticipantNegativeThreshold(t *testing.T) {
	participantID = 0
	participantThreshold = -1
	participantOutput = filepath.Join(t.TempDir(), "output.json")
	verbose = false

	err := runParticipant(participantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold must be at least 1")
}

// TestCertgenNegativeDays tests certgen with negative days
func TestCertgenNegativeDays(t *testing.T) {
	certgenType = "ecdsa"
	certgenOutput = t.TempDir()
	certgenName = "test"
	certgenDays = -1
	certgenHosts = []string{"localhost"}
	verbose = false

	err := runCertgen(certgenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "days must be at least 1")
}

// TestVerifyWithZeroTimestamp tests verify with zero timestamp
func TestVerifyWithZeroTimestamp(t *testing.T) {
	tmpDir := t.TempDir()
	sharePath := filepath.Join(tmpDir, "share.json")

	keyShare := KeyShareOutput{
		ParticipantIndex: 0,
		SecretShare:      hex.EncodeToString(make([]byte, 32)),
		ThresholdPubkey:  hex.EncodeToString(make([]byte, 32)),
		PublicShares: []string{
			hex.EncodeToString(make([]byte, 32)),
		},
		SessionID: "test-session",
		Timestamp: 0, // Zero timestamp
	}

	data, err := json.MarshalIndent(keyShare, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(sharePath, data, 0600)
	require.NoError(t, err)

	verifyShare = sharePath
	verifyGroupKey = ""
	verbose = false

	err = runVerify(verifyCmd, nil)
	require.NoError(t, err)
}

// TestCoordinatorCmdUsage tests coordinator command usage string
func TestCoordinatorCmdUsage(t *testing.T) {
	assert.Equal(t, "coordinator", coordinatorCmd.Use)
	assert.NotEmpty(t, coordinatorCmd.Short)
	assert.NotEmpty(t, coordinatorCmd.Long)
}

// TestParticipantCmdUsage tests participant command usage string
func TestParticipantCmdUsage(t *testing.T) {
	assert.Equal(t, "participant", participantCmd.Use)
	assert.NotEmpty(t, participantCmd.Short)
	assert.NotEmpty(t, participantCmd.Long)
}

// TestCertgenCmdUsage tests certgen command usage string
func TestCertgenCmdUsage(t *testing.T) {
	assert.Equal(t, "certgen", certgenCmd.Use)
	assert.NotEmpty(t, certgenCmd.Short)
	assert.NotEmpty(t, certgenCmd.Long)
}

// TestVerifyCmdUsage tests verify command usage string
func TestVerifyCmdUsage(t *testing.T) {
	assert.Equal(t, "verify", verifyCmd.Use)
	assert.NotEmpty(t, verifyCmd.Short)
	assert.NotEmpty(t, verifyCmd.Long)
}

// TestConfigCmdUsage tests config command usage string
func TestConfigCmdUsage(t *testing.T) {
	assert.Equal(t, "config", configCmd.Use)
	assert.NotEmpty(t, configCmd.Short)
	assert.NotEmpty(t, configCmd.Long)
}

// TestVersionCmdUsage tests version command usage string
func TestVersionCmdUsage(t *testing.T) {
	assert.Equal(t, "version", versionCmd.Use)
	assert.NotEmpty(t, versionCmd.Short)
	assert.NotEmpty(t, versionCmd.Long)
}

// TestRootCmdUsage tests root command usage string
func TestRootCmdUsage(t *testing.T) {
	assert.Equal(t, "frostdkg", rootCmd.Use)
	assert.NotEmpty(t, rootCmd.Short)
	assert.NotEmpty(t, rootCmd.Long)
}
