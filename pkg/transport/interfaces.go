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

// Package transport provides transport layer abstractions for FROST DKG protocol.
//
// The transport layer enables distributed key generation by providing:
//   - Multiple protocol support (gRPC, HTTP, QUIC, libp2p, MCP, Unix sockets)
//   - Coordinator for message relay between participants
//   - Participant interface for DKG session execution
//   - Pluggable codec support (JSON, CBOR, MessagePack)
//   - TLS/mTLS security
//
// The Coordinator is a relay server with no cryptographic role. It:
//   - Accepts connections from participants
//   - Relays messages between participants
//   - Manages session lifecycle
//   - Does not participate in DKG cryptography
//
// Participants connect to a Coordinator and execute the DKG protocol by:
//   - Establishing secure connections
//   - Sending/receiving protocol messages
//   - Running the FROST DKG session
//   - Receiving threshold keys and shares
package transport

import (
	"context"
	"fmt"
	"time"
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

// Config holds transport layer configuration.
//
// The Config specifies how to establish connections and secure communications
// for DKG sessions. Different protocols may use different config fields.
type Config struct {
	// Protocol specifies the transport protocol to use.
	Protocol Protocol

	// Address is the network address.
	// Format depends on protocol:
	//   - TCP protocols: "host:port" (e.g., "localhost:9000")
	//   - Unix socket: "/path/to/socket" (e.g., "/tmp/frostdkg.sock")
	//   - Memory: arbitrary identifier (e.g., "session-123")
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

// Coordinator interface manages a DKG session by relaying messages between participants.
//
// The coordinator has no cryptographic role and does not participate in the DKG.
// It acts purely as a message relay and session coordinator.
//
// Lifecycle:
//  1. Start() - Begin accepting participant connections
//  2. WaitForParticipants() - Wait for n participants to connect
//  3. (Message relay happens automatically)
//  4. Stop() - Shutdown and cleanup
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

// Participant interface represents a DKG participant that connects to a coordinator.
//
// Participants execute the FROST DKG protocol by:
//  1. Connecting to a coordinator
//  2. Running the DKG session with local parameters
//  3. Receiving DKG results (threshold key, secret share, public shares)
//  4. Disconnecting when complete
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

// DKGParams contains parameters for a DKG session execution.
//
// These parameters are provided by the participant and include:
//   - Host secret key (this participant's long-term identity key)
//   - Host public keys (all participants' identity keys, in order)
//   - Threshold (t-of-n threshold for signing)
//   - Participant index (this participant's position in the host public key list)
//   - Randomness (for DKG session, must be cryptographically secure)
type DKGParams struct {
	// HostSeckey is this participant's host secret key (32 bytes).
	// This is the long-term identity key for this participant.
	HostSeckey []byte

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

	// Random is cryptographically secure randomness for the DKG session (32 bytes).
	// Must be generated using a CSPRNG.
	Random []byte
}

// DKGResult contains the output of a successful DKG session.
//
// The result includes:
//   - Secret share (this participant's share of the threshold key)
//   - Threshold public key (the aggregate public key for t-of-n signing)
//   - Public shares (verification shares for all participants)
//   - Session ID (for correlating this session)
//
// The secret share must be kept confidential. All other data is public.
type DKGResult struct {
	// SecretShare is this participant's share of the threshold secret key (32 bytes).
	// MUST be kept confidential and securely stored.
	SecretShare []byte

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

// SessionConfig contains configuration for a coordinator DKG session.
//
// The coordinator uses this to validate incoming participants and
// manage session lifecycle.
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
