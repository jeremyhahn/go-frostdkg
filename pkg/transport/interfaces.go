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

// Package transport relays FROST DKG messages over gRPC, HTTP, QUIC, libp2p, MCP and Unix sockets; network transports' RunDKG returns ErrDKGNotImplemented, the memory transport is a test double.
package transport

import (
	"context"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// Logger interface for transport layer logging.
// Implementations can be provided by callers to capture transport events.
type Logger interface {
	// Info logs informational messages.
	Info(format string, args ...interface{})
	// Debug logs debug messages (verbose output).
	Debug(format string, args ...interface{})
	// Error logs error messages.
	Error(format string, args ...interface{})
}

// NopLogger is a no-op logger that discards all log messages.
type NopLogger struct{}

func (NopLogger) Info(format string, args ...interface{})  {}
func (NopLogger) Debug(format string, args ...interface{}) {}
func (NopLogger) Error(format string, args ...interface{}) {}

// StdoutLogger logs to stdout with a prefix.
type StdoutLogger struct {
	Prefix  string
	Verbose bool
}

func (l *StdoutLogger) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] %s\n", l.Prefix, msg)
}

func (l *StdoutLogger) Debug(format string, args ...interface{}) {
	if l.Verbose {
		msg := fmt.Sprintf(format, args...)
		fmt.Printf("[%s] DEBUG: %s\n", l.Prefix, msg)
	}
}

func (l *StdoutLogger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] ERROR: %s\n", l.Prefix, msg)
}

// Protocol represents supported transport protocols.
type Protocol string

const (
	// ProtocolGRPC uses gRPC over TCP with HTTP/2.
	ProtocolGRPC Protocol = "grpc"

	// ProtocolHTTP uses HTTP/1.1 or HTTP/2 over TCP.
	ProtocolHTTP Protocol = "http"

	// ProtocolQUIC uses QUIC protocol (UDP-based).
	ProtocolQUIC Protocol = "quic"

	// ProtocolLibp2p uses libp2p multi-transport stack.
	ProtocolLibp2p Protocol = "libp2p"

	// ProtocolMCP uses Model Context Protocol.
	ProtocolMCP Protocol = "mcp"

	// ProtocolUnix uses gRPC over Unix domain socket.
	ProtocolUnix Protocol = "unix"

	// ProtocolMemory uses in-process communication for testing.
	ProtocolMemory Protocol = "memory"
)

// Config holds connection and security settings; fields used vary by protocol.
type Config struct {
	// Protocol specifies the transport protocol to use.
	Protocol Protocol

	// Address is host:port for TCP protocols, a socket path for Unix, any identifier for memory.
	Address string

	// TLSCertFile is the path to TLS certificate file (PEM format).
	// Used for server-side TLS or client certificate in mTLS.
	TLSCertFile string

	// TLSKeyFile is the path to TLS private key file (PEM format).
	// Used for server-side TLS or client key in mTLS.
	TLSKeyFile string

	// TLSCAFile is the path to CA certificate file (PEM format).
	// Used for mTLS to verify peer certificates.
	TLSCAFile string

	// CodecType specifies message serialization format.
	// Supported: "json", "cbor", "msgpack"
	// Default: "json"
	CodecType string

	// Ciphersuite is the FROST ciphersuite identifier.
	// Example: "FROST-ED25519-SHA512-v1"
	Ciphersuite string

	// Timeout is the connection and operation timeout.
	// Default: 30 seconds
	Timeout time.Duration

	// MaxMessageSize is the maximum message size in bytes.
	// Default: 1MB
	MaxMessageSize int

	// KeepAlive enables TCP keepalive.
	// Default: true
	KeepAlive bool

	// KeepAliveInterval is the TCP keepalive interval.
	// Default: 30 seconds
	KeepAliveInterval time.Duration

	// Logger for transport layer events.
	// If nil, a NopLogger is used.
	Logger Logger
}

// Coordinator relays messages between participants with no cryptographic role: Start, WaitForParticipants, Stop.
type Coordinator interface {
	// Start begins listening for participant connections.
	// Returns error if the coordinator fails to start.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the coordinator.
	// Waits for active sessions to complete or context timeout.
	Stop(ctx context.Context) error

	// Address returns the network address the coordinator is listening on.
	// This may differ from the configured address (e.g., if port 0 was used).
	Address() string

	// SessionID returns the unique identifier for this DKG session.
	// The session ID is used to correlate messages and participants.
	SessionID() string

	// WaitForParticipants blocks until n participants have connected.
	// Returns error if context expires or connection errors occur.
	WaitForParticipants(ctx context.Context, n int) error
}

// Participant connects to a coordinator, runs the DKG session and returns its results.
type Participant interface {
	// Connect establishes a connection to the coordinator at the given address.
	// The address format depends on the transport protocol.
	Connect(ctx context.Context, addr string) error

	// Disconnect closes the connection to the coordinator.
	// Any in-progress DKG session is aborted.
	Disconnect() error

	// RunDKG executes the FROST DKG protocol using the provided parameters.
	// Blocks until the DKG completes or an error occurs.
	// Returns DKG results on success.
	RunDKG(ctx context.Context, params *DKGParams) (*DKGResult, error)
}

// DKGParams holds a participant's session inputs: host secret key, ordered host public keys, threshold, index and randomness.
type DKGParams struct {
	// HostSeckey is the 32-byte host secret key in an enclave (build with SealSecret); the params own it and Zeroize destroys it.
	HostSeckey *secmem.SecretBytes

	// HostPubkeys is the ordered list of all participants' host public keys.
	// Each key is 32 bytes (Ed25519 public key).
	// The order must be agreed upon by all participants.
	HostPubkeys [][]byte

	// Threshold is the signing threshold t (number of participants needed to sign).
	// Must satisfy: 1 <= Threshold <= len(HostPubkeys)
	Threshold int

	// ParticipantIdx is this participant's index in the HostPubkeys list.
	// Must satisfy: 0 <= ParticipantIdx < len(HostPubkeys)
	ParticipantIdx int

	// Random is 32 bytes of session randomness in an enclave; it is a secret, since with HostSeckey it derives the share.
	Random *secmem.SecretBytes
}

// DKGResult holds the secret share (confidential), threshold public key, public shares and session ID.
type DKGResult struct {
	// SecretShare is this participant's 32-byte share in an enclave; read it with secmem.WithSecret and Zeroize it once persisted.
	SecretShare *secmem.SecretBytes

	// ThresholdPubkey is the aggregate threshold public key (32 bytes, Ed25519).
	// This is the public key corresponding to the distributed secret key.
	ThresholdPubkey []byte

	// PublicShares contains the verification shares for all n participants.
	// Each share is 32 bytes (Ed25519 public key).
	// Index i corresponds to participant i's public share.
	PublicShares [][]byte

	// SessionID is the unique identifier for this DKG session.
	SessionID string

	// RecoveryData is the serialized data for DKG output recovery.
	// Can be shared publicly or obtained from other participants.
	RecoveryData []byte
}

// Zeroize securely clears sensitive data from the DKG parameters.
func (p *DKGParams) Zeroize() {
	if p == nil {
		return
	}
	if p.HostSeckey != nil {
		p.HostSeckey.Destroy()
	}
	p.HostSeckey = nil
	if p.Random != nil {
		p.Random.Destroy()
	}
	p.Random = nil
}

// Zeroize securely clears sensitive data from the DKG result.
func (r *DKGResult) Zeroize() {
	if r == nil {
		return
	}
	if r.SecretShare != nil {
		r.SecretShare.Destroy()
	}
	r.SecretShare = nil
}

// SealSecret seals a copy of secret in an enclave, leaving the caller's slice intact; nil for empty input.
func SealSecret(secret []byte) *secmem.SecretBytes {
	if len(secret) == 0 {
		return nil
	}
	c := make([]byte, len(secret))
	copy(c, secret)
	return secmem.NewSecretBytes(c)
}

// SessionConfig configures a coordinator's DKG session and participant validation.
type SessionConfig struct {
	// SessionID is the unique identifier for this session.
	// If empty, a timestamp-based ID will be generated.
	SessionID string

	// Threshold is the signing threshold t (1 <= t <= NumParticipants).
	Threshold int

	// NumParticipants is the total number of participants n.
	NumParticipants int

	// Ciphersuite is the FROST ciphersuite identifier.
	// Example: "FROST-ED25519-SHA512-v1"
	Ciphersuite string

	// Timeout is the maximum time to wait for session completion.
	// Default: 5 minutes
	Timeout time.Duration

	// AllowPartialSessions indicates if the session can proceed with fewer
	// than NumParticipants if some participants fail to connect.
	// Default: false (require all participants)
	AllowPartialSessions bool
}
