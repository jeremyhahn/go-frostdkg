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
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// DefaultTimeout is the default connection timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxMessageSize is the default maximum message size (1MB).
	DefaultMaxMessageSize = 1024 * 1024

	// DefaultKeepAliveInterval is the default TCP keepalive interval.
	DefaultKeepAliveInterval = 30 * time.Second

	// DefaultCodec is the default message codec.
	DefaultCodec = "json"

	// DefaultSessionTimeout is the default session timeout.
	DefaultSessionTimeout = 5 * time.Minute

	// SecretKeySize is the size of a Ed25519 secret key in bytes.
	SecretKeySize = 32

	// PublicKeySize is the size of a Ed25519 public key in bytes.
	PublicKeySize = 32
)

// NewConfig creates a new Config with default values.
//
// The returned config has:
//   - Protocol: ProtocolGRPC
//   - CodecType: "json"
//   - Timeout: 30 seconds
//   - MaxMessageSize: 1MB
//   - KeepAlive: true
//   - KeepAliveInterval: 30 seconds
//
// Callers should set Address and other protocol-specific fields.
func NewConfig() *Config {
	return &Config{
		Protocol:          ProtocolGRPC,
		CodecType:         DefaultCodec,
		Timeout:           DefaultTimeout,
		MaxMessageSize:    DefaultMaxMessageSize,
		KeepAlive:         true,
		KeepAliveInterval: DefaultKeepAliveInterval,
	}
}

// NewGRPCConfig creates a Config for gRPC transport.
func NewGRPCConfig(address string) *Config {
	cfg := NewConfig()
	cfg.Protocol = ProtocolGRPC
	cfg.Address = address
	return cfg
}

// NewHTTPConfig creates a Config for HTTP transport.
func NewHTTPConfig(address string) *Config {
	cfg := NewConfig()
	cfg.Protocol = ProtocolHTTP
	cfg.Address = address
	return cfg
}

// NewQUICConfig creates a Config for QUIC transport.
func NewQUICConfig(address string) *Config {
	cfg := NewConfig()
	cfg.Protocol = ProtocolQUIC
	cfg.Address = address
	return cfg
}

// NewUnixConfig creates a Config for Unix socket transport.
func NewUnixConfig(socketPath string) *Config {
	cfg := NewConfig()
	cfg.Protocol = ProtocolUnix
	cfg.Address = socketPath
	return cfg
}

// NewMemoryConfig creates a Config for in-memory transport (testing).
func NewMemoryConfig(identifier string) *Config {
	cfg := NewConfig()
	cfg.Protocol = ProtocolMemory
	cfg.Address = identifier
	return cfg
}

// NewTLSConfig creates a Config with TLS enabled.
//
// For server-side TLS, provide certFile and keyFile.
// For mTLS (mutual TLS), also provide caFile.
func NewTLSConfig(protocol Protocol, address, certFile, keyFile, caFile string) *Config {
	cfg := NewConfig()
	cfg.Protocol = protocol
	cfg.Address = address
	cfg.TLSCertFile = certFile
	cfg.TLSKeyFile = keyFile
	cfg.TLSCAFile = caFile
	return cfg
}

// Validate checks if the configuration is valid.
//
// Returns an error if:
//   - Protocol is not supported
//   - Address is empty (except for memory protocol)
//   - TLS cert/key files don't exist (if TLS is configured)
//   - Timeout is zero or negative
//   - MaxMessageSize is zero or negative
//   - CodecType is empty
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	// Validate protocol
	if !c.isValidProtocol() {
		return fmt.Errorf("%w: %s", ErrInvalidProtocol, c.Protocol)
	}

	// Validate address (except for memory protocol which can be arbitrary)
	if c.Protocol != ProtocolMemory && c.Address == "" {
		return fmt.Errorf("%w: address is required", ErrInvalidAddress)
	}

	// Validate Unix socket path
	if c.Protocol == ProtocolUnix {
		if !strings.HasPrefix(c.Address, "/") && !strings.HasPrefix(c.Address, "./") {
			return fmt.Errorf("%w: Unix socket path must be absolute or relative", ErrInvalidAddress)
		}
	}

	// Validate TCP address format (for TCP-based protocols)
	if c.Protocol == ProtocolGRPC || c.Protocol == ProtocolHTTP || c.Protocol == ProtocolQUIC {
		if !strings.Contains(c.Address, ":") {
			return fmt.Errorf("%w: TCP address must be in format host:port", ErrInvalidAddress)
		}
	}

	// Validate TLS configuration
	if c.HasTLS() {
		if err := c.validateTLS(); err != nil {
			return err
		}
	}

	// Validate timeout
	if c.Timeout <= 0 {
		return fmt.Errorf("%w: timeout must be positive", ErrInvalidConfig)
	}

	// Validate max message size
	if c.MaxMessageSize <= 0 {
		return fmt.Errorf("%w: max message size must be positive", ErrInvalidConfig)
	}

	// Validate codec
	if c.CodecType == "" {
		return fmt.Errorf("%w: codec type is required", ErrInvalidConfig)
	}

	if !c.isValidCodec() {
		return fmt.Errorf("%w: unsupported codec %s", ErrCodecNotSupported, c.CodecType)
	}

	return nil
}

// HasTLS returns true if TLS is configured.
func (c *Config) HasTLS() bool {
	return c.TLSCertFile != "" || c.TLSKeyFile != "" || c.TLSCAFile != ""
}

// IsMutualTLS returns true if mutual TLS (mTLS) is configured.
func (c *Config) IsMutualTLS() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != "" && c.TLSCAFile != ""
}

// IsServerTLS returns true if server-side TLS is configured (but not mTLS).
func (c *Config) IsServerTLS() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != "" && c.TLSCAFile == ""
}

// validateTLS checks if TLS configuration is valid.
func (c *Config) validateTLS() error {
	// If cert file is specified, key file must also be specified
	if c.TLSCertFile != "" && c.TLSKeyFile == "" {
		return NewTLSError("TLS key file required when cert file is specified", ErrCertificateInvalid)
	}

	// If key file is specified, cert file must also be specified
	if c.TLSKeyFile != "" && c.TLSCertFile == "" {
		return NewTLSError("TLS cert file required when key file is specified", ErrCertificateInvalid)
	}

	// Check if cert file exists
	if c.TLSCertFile != "" {
		if _, err := os.Stat(c.TLSCertFile); os.IsNotExist(err) {
			return NewTLSError(fmt.Sprintf("cert file not found: %s", c.TLSCertFile), ErrCertificateNotFound)
		}
	}

	// Check if key file exists
	if c.TLSKeyFile != "" {
		if _, err := os.Stat(c.TLSKeyFile); os.IsNotExist(err) {
			return NewTLSError(fmt.Sprintf("key file not found: %s", c.TLSKeyFile), ErrPrivateKeyNotFound)
		}
	}

	// Check if CA file exists (for mTLS)
	if c.TLSCAFile != "" {
		if _, err := os.Stat(c.TLSCAFile); os.IsNotExist(err) {
			return NewTLSError(fmt.Sprintf("CA file not found: %s", c.TLSCAFile), ErrCANotFound)
		}
	}

	return nil
}

// isValidProtocol checks if the protocol is supported.
func (c *Config) isValidProtocol() bool {
	switch c.Protocol {
	case ProtocolGRPC, ProtocolHTTP, ProtocolQUIC, ProtocolLibp2p, ProtocolMCP, ProtocolUnix, ProtocolMemory:
		return true
	default:
		return false
	}
}

// isValidCodec checks if the codec is supported.
func (c *Config) isValidCodec() bool {
	codec := strings.ToLower(c.CodecType)
	switch codec {
	case "json", "cbor", "msgpack":
		return true
	default:
		return false
	}
}

// Clone creates a deep copy of the config.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	return &Config{
		Protocol:          c.Protocol,
		Address:           c.Address,
		TLSCertFile:       c.TLSCertFile,
		TLSKeyFile:        c.TLSKeyFile,
		TLSCAFile:         c.TLSCAFile,
		CodecType:         c.CodecType,
		Ciphersuite:       c.Ciphersuite,
		Timeout:           c.Timeout,
		MaxMessageSize:    c.MaxMessageSize,
		KeepAlive:         c.KeepAlive,
		KeepAliveInterval: c.KeepAliveInterval,
	}
}

// String returns a string representation of the config (with sensitive data redacted).
func (c *Config) String() string {
	tlsStatus := "disabled"
	if c.IsMutualTLS() {
		tlsStatus = "mTLS"
	} else if c.IsServerTLS() {
		tlsStatus = "TLS"
	}

	return fmt.Sprintf("Config{Protocol=%s, Address=%s, TLS=%s, Codec=%s, Timeout=%s}",
		c.Protocol, c.Address, tlsStatus, c.CodecType, c.Timeout)
}

// NewSessionConfig creates a new SessionConfig with default values.
func NewSessionConfig(threshold, numParticipants int, ciphersuite string) *SessionConfig {
	return &SessionConfig{
		Threshold:            threshold,
		NumParticipants:      numParticipants,
		Ciphersuite:          ciphersuite,
		Timeout:              DefaultSessionTimeout,
		AllowPartialSessions: false,
	}
}

// Validate checks if the session configuration is valid.
func (sc *SessionConfig) Validate() error {
	if sc == nil {
		return ErrInvalidConfig
	}

	// Validate participant count
	if sc.NumParticipants < 1 {
		return fmt.Errorf("%w: must have at least 1 participant", ErrInvalidParticipantCount)
	}

	// Validate threshold
	if sc.Threshold < 1 || sc.Threshold > sc.NumParticipants {
		return fmt.Errorf("%w: threshold must be between 1 and %d", ErrInvalidThreshold, sc.NumParticipants)
	}

	// Validate timeout
	if sc.Timeout <= 0 {
		return fmt.Errorf("%w: timeout must be positive", ErrInvalidConfig)
	}

	// Validate ciphersuite (must not be empty)
	if sc.Ciphersuite == "" {
		return fmt.Errorf("%w: ciphersuite is required", ErrInvalidConfig)
	}

	return nil
}

// String returns a string representation of the session config.
func (sc *SessionConfig) String() string {
	return fmt.Sprintf("SessionConfig{Threshold=%d, Participants=%d, Ciphersuite=%s, Timeout=%s}",
		sc.Threshold, sc.NumParticipants, sc.Ciphersuite, sc.Timeout)
}
