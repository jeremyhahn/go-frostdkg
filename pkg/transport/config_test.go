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

package transport

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNewConfig tests the default config constructor.
func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	if cfg == nil {
		t.Fatal("NewConfig returned nil")
	}

	if cfg.Protocol != ProtocolGRPC {
		t.Errorf("Expected default protocol %s, got %s", ProtocolGRPC, cfg.Protocol)
	}

	if cfg.CodecType != DefaultCodec {
		t.Errorf("Expected default codec %s, got %s", DefaultCodec, cfg.CodecType)
	}

	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Expected default timeout %s, got %s", DefaultTimeout, cfg.Timeout)
	}

	if cfg.MaxMessageSize != DefaultMaxMessageSize {
		t.Errorf("Expected default max message size %d, got %d", DefaultMaxMessageSize, cfg.MaxMessageSize)
	}

	if !cfg.KeepAlive {
		t.Error("Expected KeepAlive to be true by default")
	}

	if cfg.KeepAliveInterval != DefaultKeepAliveInterval {
		t.Errorf("Expected default keepalive interval %s, got %s", DefaultKeepAliveInterval, cfg.KeepAliveInterval)
	}
}

// TestNewGRPCConfig tests gRPC config constructor.
func TestNewGRPCConfig(t *testing.T) {
	addr := "localhost:9000"
	cfg := NewGRPCConfig(addr)

	if cfg.Protocol != ProtocolGRPC {
		t.Errorf("Expected protocol %s, got %s", ProtocolGRPC, cfg.Protocol)
	}

	if cfg.Address != addr {
		t.Errorf("Expected address %s, got %s", addr, cfg.Address)
	}
}

// TestNewHTTPConfig tests HTTP config constructor.
func TestNewHTTPConfig(t *testing.T) {
	addr := "localhost:8080"
	cfg := NewHTTPConfig(addr)

	if cfg.Protocol != ProtocolHTTP {
		t.Errorf("Expected protocol %s, got %s", ProtocolHTTP, cfg.Protocol)
	}

	if cfg.Address != addr {
		t.Errorf("Expected address %s, got %s", addr, cfg.Address)
	}
}

// TestNewQUICConfig tests QUIC config constructor.
func TestNewQUICConfig(t *testing.T) {
	addr := "localhost:4433"
	cfg := NewQUICConfig(addr)

	if cfg.Protocol != ProtocolQUIC {
		t.Errorf("Expected protocol %s, got %s", ProtocolQUIC, cfg.Protocol)
	}

	if cfg.Address != addr {
		t.Errorf("Expected address %s, got %s", addr, cfg.Address)
	}
}

// TestNewUnixConfig tests Unix socket config constructor.
func TestNewUnixConfig(t *testing.T) {
	socketPath := "/tmp/frostdkg.sock"
	cfg := NewUnixConfig(socketPath)

	if cfg.Protocol != ProtocolUnix {
		t.Errorf("Expected protocol %s, got %s", ProtocolUnix, cfg.Protocol)
	}

	if cfg.Address != socketPath {
		t.Errorf("Expected address %s, got %s", socketPath, cfg.Address)
	}
}

// TestNewMemoryConfig tests memory config constructor.
func TestNewMemoryConfig(t *testing.T) {
	identifier := "test-session-123"
	cfg := NewMemoryConfig(identifier)

	if cfg.Protocol != ProtocolMemory {
		t.Errorf("Expected protocol %s, got %s", ProtocolMemory, cfg.Protocol)
	}

	if cfg.Address != identifier {
		t.Errorf("Expected address %s, got %s", identifier, cfg.Address)
	}
}

// TestNewTLSConfig tests TLS config constructor.
func TestNewTLSConfig(t *testing.T) {
	protocol := ProtocolGRPC
	addr := "localhost:9000"
	certFile := "/path/to/cert.pem"
	keyFile := "/path/to/key.pem"
	caFile := "/path/to/ca.pem"

	cfg := NewTLSConfig(protocol, addr, certFile, keyFile, caFile)

	if cfg.Protocol != protocol {
		t.Errorf("Expected protocol %s, got %s", protocol, cfg.Protocol)
	}

	if cfg.Address != addr {
		t.Errorf("Expected address %s, got %s", addr, cfg.Address)
	}

	if cfg.TLSCertFile != certFile {
		t.Errorf("Expected cert file %s, got %s", certFile, cfg.TLSCertFile)
	}

	if cfg.TLSKeyFile != keyFile {
		t.Errorf("Expected key file %s, got %s", keyFile, cfg.TLSKeyFile)
	}

	if cfg.TLSCAFile != caFile {
		t.Errorf("Expected CA file %s, got %s", caFile, cfg.TLSCAFile)
	}
}

// TestConfigValidate tests config validation with valid configs.
func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "valid gRPC config",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024 * 1024,
			},
		},
		{
			name: "valid HTTP config",
			config: &Config{
				Protocol:       ProtocolHTTP,
				Address:        "127.0.0.1:8080",
				CodecType:      "cbor",
				Timeout:        60 * time.Second,
				MaxMessageSize: 2048 * 1024,
			},
		},
		{
			name: "valid Unix config",
			config: &Config{
				Protocol:       ProtocolUnix,
				Address:        "/tmp/test.sock",
				CodecType:      "json",
				Timeout:        15 * time.Second,
				MaxMessageSize: 512 * 1024,
			},
		},
		{
			name: "valid memory config",
			config: &Config{
				Protocol:       ProtocolMemory,
				Address:        "test-123",
				CodecType:      "json",
				Timeout:        10 * time.Second,
				MaxMessageSize: 256 * 1024,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err != nil {
				t.Errorf("Expected valid config, got error: %v", err)
			}
		})
	}
}

// TestConfigValidateInvalid tests config validation with invalid configs.
func TestConfigValidateInvalid(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantError error
	}{
		{
			name:      "nil config",
			config:    nil,
			wantError: ErrInvalidConfig,
		},
		{
			name: "invalid protocol",
			config: &Config{
				Protocol:       Protocol("invalid"),
				Address:        "localhost:9000",
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrInvalidProtocol,
		},
		{
			name: "missing address for gRPC",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "",
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrInvalidAddress,
		},
		{
			name: "invalid TCP address format",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost",
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrInvalidAddress,
		},
		{
			name: "invalid Unix socket path",
			config: &Config{
				Protocol:       ProtocolUnix,
				Address:        "not-absolute",
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrInvalidAddress,
		},
		{
			name: "zero timeout",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				CodecType:      "json",
				Timeout:        0,
				MaxMessageSize: 1024,
			},
			wantError: ErrInvalidConfig,
		},
		{
			name: "negative timeout",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				CodecType:      "json",
				Timeout:        -1 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrInvalidConfig,
		},
		{
			name: "zero max message size",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 0,
			},
			wantError: ErrInvalidConfig,
		},
		{
			name: "empty codec",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				CodecType:      "",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrInvalidConfig,
		},
		{
			name: "unsupported codec",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				CodecType:      "xml",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrCodecNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err == nil {
				t.Fatal("Expected validation error, got nil")
			}

			if !errors.Is(err, tt.wantError) {
				t.Errorf("Expected error %v, got %v", tt.wantError, err)
			}
		})
	}
}

// TestConfigTLSMethods tests TLS-related config methods.
func TestConfigTLSMethods(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		hasTLS      bool
		isMutualTLS bool
		isServerTLS bool
	}{
		{
			name: "no TLS",
			config: &Config{
				TLSCertFile: "",
				TLSKeyFile:  "",
				TLSCAFile:   "",
			},
			hasTLS:      false,
			isMutualTLS: false,
			isServerTLS: false,
		},
		{
			name: "server TLS",
			config: &Config{
				TLSCertFile: "cert.pem",
				TLSKeyFile:  "key.pem",
				TLSCAFile:   "",
			},
			hasTLS:      true,
			isMutualTLS: false,
			isServerTLS: true,
		},
		{
			name: "mutual TLS",
			config: &Config{
				TLSCertFile: "cert.pem",
				TLSKeyFile:  "key.pem",
				TLSCAFile:   "ca.pem",
			},
			hasTLS:      true,
			isMutualTLS: true,
			isServerTLS: false,
		},
		{
			name: "only cert file",
			config: &Config{
				TLSCertFile: "cert.pem",
				TLSKeyFile:  "",
				TLSCAFile:   "",
			},
			hasTLS:      true,
			isMutualTLS: false,
			isServerTLS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.HasTLS(); got != tt.hasTLS {
				t.Errorf("HasTLS() = %v, want %v", got, tt.hasTLS)
			}

			if got := tt.config.IsMutualTLS(); got != tt.isMutualTLS {
				t.Errorf("IsMutualTLS() = %v, want %v", got, tt.isMutualTLS)
			}

			if got := tt.config.IsServerTLS(); got != tt.isServerTLS {
				t.Errorf("IsServerTLS() = %v, want %v", got, tt.isServerTLS)
			}
		})
	}
}

// TestConfigValidateTLS tests TLS validation with missing files.
func TestConfigValidateTLS(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()

	// Create test certificate files
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	caFile := filepath.Join(tmpDir, "ca.pem")

	// Create empty files
	for _, file := range []string{certFile, keyFile, caFile} {
		if err := os.WriteFile(file, []byte("test"), 0600); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	tests := []struct {
		name      string
		config    *Config
		wantError error
	}{
		{
			name: "valid TLS config",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				TLSCertFile:    certFile,
				TLSKeyFile:     keyFile,
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: nil,
		},
		{
			name: "valid mTLS config",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				TLSCertFile:    certFile,
				TLSKeyFile:     keyFile,
				TLSCAFile:      caFile,
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: nil,
		},
		{
			name: "missing key file",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				TLSCertFile:    certFile,
				TLSKeyFile:     "",
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrCertificateInvalid,
		},
		{
			name: "missing cert file",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				TLSCertFile:    "",
				TLSKeyFile:     keyFile,
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrCertificateInvalid,
		},
		{
			name: "nonexistent cert file",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				TLSCertFile:    "/nonexistent/cert.pem",
				TLSKeyFile:     keyFile,
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrCertificateNotFound,
		},
		{
			name: "nonexistent key file",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				TLSCertFile:    certFile,
				TLSKeyFile:     "/nonexistent/key.pem",
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrPrivateKeyNotFound,
		},
		{
			name: "nonexistent CA file",
			config: &Config{
				Protocol:       ProtocolGRPC,
				Address:        "localhost:9000",
				TLSCertFile:    certFile,
				TLSKeyFile:     keyFile,
				TLSCAFile:      "/nonexistent/ca.pem",
				CodecType:      "json",
				Timeout:        30 * time.Second,
				MaxMessageSize: 1024,
			},
			wantError: ErrCANotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError == nil {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if !errors.Is(err, tt.wantError) {
					t.Errorf("Expected error %v, got %v", tt.wantError, err)
				}
			}
		})
	}
}

// TestConfigClone tests config cloning.
func TestConfigClone(t *testing.T) {
	original := &Config{
		Protocol:          ProtocolGRPC,
		Address:           "localhost:9000",
		TLSCertFile:       "cert.pem",
		TLSKeyFile:        "key.pem",
		TLSCAFile:         "ca.pem",
		CodecType:         "json",
		Ciphersuite:       "FROST-ED25519-SHA512-v1",
		Timeout:           30 * time.Second,
		MaxMessageSize:    1024 * 1024,
		KeepAlive:         true,
		KeepAliveInterval: 30 * time.Second,
	}

	cloned := original.Clone()

	// Verify clone is not nil
	if cloned == nil {
		t.Fatal("Clone returned nil")
	}

	// Verify clone has same values
	if cloned.Protocol != original.Protocol {
		t.Error("Protocol mismatch")
	}
	if cloned.Address != original.Address {
		t.Error("Address mismatch")
	}
	if cloned.TLSCertFile != original.TLSCertFile {
		t.Error("TLSCertFile mismatch")
	}
	if cloned.CodecType != original.CodecType {
		t.Error("CodecType mismatch")
	}

	// Verify clone is independent
	cloned.Address = "different:8080"
	if original.Address == cloned.Address {
		t.Error("Clone is not independent")
	}

	// Test cloning nil config
	var nilCfg *Config
	nilClone := nilCfg.Clone()
	if nilClone != nil {
		t.Error("Cloning nil config should return nil")
	}
}

// TestConfigString tests config string representation.
func TestConfigString(t *testing.T) {
	tests := []struct {
		name         string
		config       *Config
		wantContains []string
	}{
		{
			name: "basic config",
			config: &Config{
				Protocol:  ProtocolGRPC,
				Address:   "localhost:9000",
				CodecType: "json",
				Timeout:   30 * time.Second,
			},
			wantContains: []string{"grpc", "localhost:9000", "json", "30s"},
		},
		{
			name: "config with TLS",
			config: &Config{
				Protocol:    ProtocolHTTP,
				Address:     "127.0.0.1:8080",
				TLSCertFile: "cert.pem",
				TLSKeyFile:  "key.pem",
				CodecType:   "cbor",
				Timeout:     60 * time.Second,
			},
			wantContains: []string{"http", "TLS", "cbor"},
		},
		{
			name: "config with mTLS",
			config: &Config{
				Protocol:    ProtocolGRPC,
				Address:     "localhost:9000",
				TLSCertFile: "cert.pem",
				TLSKeyFile:  "key.pem",
				TLSCAFile:   "ca.pem",
				CodecType:   "json",
				Timeout:     30 * time.Second,
			},
			wantContains: []string{"grpc", "mTLS", "json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.config.String()
			for _, want := range tt.wantContains {
				if !strings.Contains(str, want) {
					t.Errorf("String() should contain %q, got: %s", want, str)
				}
			}
		})
	}
}

// TestNewSessionConfig tests session config constructor.
func TestNewSessionConfig(t *testing.T) {
	threshold := 2
	numParticipants := 3
	ciphersuite := "FROST-ED25519-SHA512-v1"

	cfg := NewSessionConfig(threshold, numParticipants, ciphersuite)

	if cfg.Threshold != threshold {
		t.Errorf("Expected threshold %d, got %d", threshold, cfg.Threshold)
	}

	if cfg.NumParticipants != numParticipants {
		t.Errorf("Expected %d participants, got %d", numParticipants, cfg.NumParticipants)
	}

	if cfg.Ciphersuite != ciphersuite {
		t.Errorf("Expected ciphersuite %s, got %s", ciphersuite, cfg.Ciphersuite)
	}

	if cfg.Timeout != DefaultSessionTimeout {
		t.Errorf("Expected default timeout %s, got %s", DefaultSessionTimeout, cfg.Timeout)
	}

	if cfg.AllowPartialSessions {
		t.Error("Expected AllowPartialSessions to be false by default")
	}
}

// TestSessionConfigValidate tests session config validation.
func TestSessionConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *SessionConfig
		wantError error
	}{
		{
			name: "valid config",
			config: &SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "FROST-ED25519-SHA512-v1",
				Timeout:         5 * time.Minute,
			},
			wantError: nil,
		},
		{
			name:      "nil config",
			config:    nil,
			wantError: ErrInvalidConfig,
		},
		{
			name: "zero participants",
			config: &SessionConfig{
				Threshold:       1,
				NumParticipants: 0,
				Ciphersuite:     "test",
				Timeout:         5 * time.Minute,
			},
			wantError: ErrInvalidParticipantCount,
		},
		{
			name: "negative participants",
			config: &SessionConfig{
				Threshold:       1,
				NumParticipants: -1,
				Ciphersuite:     "test",
				Timeout:         5 * time.Minute,
			},
			wantError: ErrInvalidParticipantCount,
		},
		{
			name: "threshold too low",
			config: &SessionConfig{
				Threshold:       0,
				NumParticipants: 3,
				Ciphersuite:     "test",
				Timeout:         5 * time.Minute,
			},
			wantError: ErrInvalidThreshold,
		},
		{
			name: "threshold too high",
			config: &SessionConfig{
				Threshold:       4,
				NumParticipants: 3,
				Ciphersuite:     "test",
				Timeout:         5 * time.Minute,
			},
			wantError: ErrInvalidThreshold,
		},
		{
			name: "zero timeout",
			config: &SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "test",
				Timeout:         0,
			},
			wantError: ErrInvalidConfig,
		},
		{
			name: "empty ciphersuite",
			config: &SessionConfig{
				Threshold:       2,
				NumParticipants: 3,
				Ciphersuite:     "",
				Timeout:         5 * time.Minute,
			},
			wantError: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError == nil {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if !errors.Is(err, tt.wantError) {
					t.Errorf("Expected error %v, got %v", tt.wantError, err)
				}
			}
		})
	}
}

// TestSessionConfigString tests session config string representation.
func TestSessionConfigString(t *testing.T) {
	cfg := &SessionConfig{
		Threshold:       2,
		NumParticipants: 3,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
		Timeout:         5 * time.Minute,
	}

	str := cfg.String()

	wantContains := []string{"2", "3", "FROST-ED25519-SHA512-v1"}
	for _, want := range wantContains {
		if !strings.Contains(str, want) {
			t.Errorf("String() should contain %q, got: %s", want, str)
		}
	}
}
