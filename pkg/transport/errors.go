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
	"fmt"
)

// Connection and network errors.
var (
	// ErrConnectionFailed indicates that establishing a connection failed.
	ErrConnectionFailed = errors.New("transport: connection failed")

	// ErrConnectionClosed indicates the connection was closed.
	ErrConnectionClosed = errors.New("transport: connection closed")

	// ErrConnectionTimeout indicates a connection attempt timed out.
	ErrConnectionTimeout = errors.New("transport: connection timeout")

	// ErrAlreadyConnected indicates the participant is already connected.
	ErrAlreadyConnected = errors.New("transport: already connected")

	// ErrNotConnected indicates the participant is not connected.
	ErrNotConnected = errors.New("transport: not connected")

	// ErrListenerFailed indicates the listener failed to start.
	ErrListenerFailed = errors.New("transport: listener failed to start")

	// ErrAddressInUse indicates the address is already in use.
	ErrAddressInUse = errors.New("transport: address already in use")
)

// Session and coordinator errors.
var (
	// ErrSessionNotFound indicates the requested session does not exist.
	ErrSessionNotFound = errors.New("transport: session not found")

	// ErrSessionExists indicates a session with this ID already exists.
	ErrSessionExists = errors.New("transport: session already exists")

	// ErrSessionClosed indicates the session has been closed.
	ErrSessionClosed = errors.New("transport: session closed")

	// ErrSessionTimeout indicates the session timed out.
	ErrSessionTimeout = errors.New("transport: session timeout")

	// ErrSessionFull indicates the session has reached maximum participants.
	ErrSessionFull = errors.New("transport: session full")

	// ErrDuplicateParticipant indicates a participant is already in the session.
	ErrDuplicateParticipant = errors.New("transport: duplicate participant")

	// ErrInsufficientParticipants indicates not enough participants for threshold.
	ErrInsufficientParticipants = errors.New("transport: insufficient participants")
)

// Message and protocol errors.
var (
	// ErrInvalidMessage indicates the message format is invalid.
	ErrInvalidMessage = errors.New("transport: invalid message")

	// ErrMessageTooLarge indicates the message exceeds maximum size.
	ErrMessageTooLarge = errors.New("transport: message too large")

	// ErrMessageTimeout indicates a message send/receive timed out.
	ErrMessageTimeout = errors.New("transport: message timeout")

	// ErrUnexpectedMessage indicates a message was received out of sequence.
	ErrUnexpectedMessage = errors.New("transport: unexpected message")

	// ErrProtocolMismatch indicates incompatible protocol versions.
	ErrProtocolMismatch = errors.New("transport: protocol version mismatch")

	// ErrCiphersuiteMismatch indicates incompatible ciphersuites.
	ErrCiphersuiteMismatch = errors.New("transport: ciphersuite mismatch")
)

// Configuration and validation errors.
var (
	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("transport: invalid configuration")

	// ErrInvalidProtocol indicates an unsupported or invalid protocol.
	ErrInvalidProtocol = errors.New("transport: invalid protocol")

	// ErrInvalidAddress indicates the address format is invalid.
	ErrInvalidAddress = errors.New("transport: invalid address")

	// ErrInvalidThreshold indicates invalid threshold parameters.
	ErrInvalidThreshold = errors.New("transport: invalid threshold (must have 1 <= t <= n)")

	// ErrInvalidParticipantCount indicates invalid number of participants.
	ErrInvalidParticipantCount = errors.New("transport: invalid participant count (must have n >= 1)")

	// ErrInvalidParticipantIndex indicates participant index out of range.
	ErrInvalidParticipantIndex = errors.New("transport: invalid participant index")

	// ErrInvalidHostKey indicates invalid host key format or length.
	ErrInvalidHostKey = errors.New("transport: invalid host key")

	// ErrInvalidRandomness indicates invalid randomness (wrong length or not random).
	ErrInvalidRandomness = errors.New("transport: invalid randomness (must be 32 bytes)")
)

// TLS and security errors.
var (
	// ErrTLSRequired indicates TLS is required but not configured.
	ErrTLSRequired = errors.New("transport: TLS required but not configured")

	// ErrCertificateInvalid indicates the TLS certificate is invalid.
	ErrCertificateInvalid = errors.New("transport: TLS certificate invalid")

	// ErrCertificateExpired indicates the TLS certificate has expired.
	ErrCertificateExpired = errors.New("transport: TLS certificate expired")

	// ErrCertificateNotFound indicates the certificate file was not found.
	ErrCertificateNotFound = errors.New("transport: certificate file not found")

	// ErrPrivateKeyNotFound indicates the private key file was not found.
	ErrPrivateKeyNotFound = errors.New("transport: private key file not found")

	// ErrCANotFound indicates the CA certificate file was not found.
	ErrCANotFound = errors.New("transport: CA certificate file not found")

	// ErrPeerVerificationFailed indicates peer certificate verification failed.
	ErrPeerVerificationFailed = errors.New("transport: peer certificate verification failed")

	// ErrHandshakeFailed indicates TLS handshake failed.
	ErrHandshakeFailed = errors.New("transport: TLS handshake failed")
)

// Codec errors.
var (
	// ErrCodecNotSupported indicates the codec is not supported.
	ErrCodecNotSupported = errors.New("transport: codec not supported")

	// ErrEncodingFailed indicates message encoding failed.
	ErrEncodingFailed = errors.New("transport: message encoding failed")

	// ErrDecodingFailed indicates message decoding failed.
	ErrDecodingFailed = errors.New("transport: message decoding failed")
)

// DKG execution errors.
var (
	// ErrDKGFailed indicates the DKG protocol execution failed.
	ErrDKGFailed = errors.New("transport: DKG execution failed")

	// ErrDKGAborted indicates the DKG was aborted by user or coordinator.
	ErrDKGAborted = errors.New("transport: DKG aborted")

	// ErrInvalidDKGParams indicates invalid DKG parameters.
	ErrInvalidDKGParams = errors.New("transport: invalid DKG parameters")

	// ErrInvalidDKGResult indicates invalid DKG result received.
	ErrInvalidDKGResult = errors.New("transport: invalid DKG result")
)

// ConnectionError wraps connection errors with additional context.
type ConnectionError struct {
	Address string
	Err     error
}

func (e *ConnectionError) Error() string {
	return fmt.Sprintf("connection error (address=%s): %v", e.Address, e.Err)
}

func (e *ConnectionError) Unwrap() error {
	return e.Err
}

// NewConnectionError creates a new ConnectionError.
func NewConnectionError(address string, err error) error {
	if err == nil {
		return nil
	}
	return &ConnectionError{
		Address: address,
		Err:     err,
	}
}

// SessionError wraps session errors with session context.
type SessionError struct {
	SessionID string
	Err       error
}

func (e *SessionError) Error() string {
	return fmt.Sprintf("session error (session=%s): %v", e.SessionID, e.Err)
}

func (e *SessionError) Unwrap() error {
	return e.Err
}

// NewSessionError creates a new SessionError.
func NewSessionError(sessionID string, err error) error {
	if err == nil {
		return nil
	}
	return &SessionError{
		SessionID: sessionID,
		Err:       err,
	}
}

// ProtocolError wraps protocol-level errors.
type ProtocolError struct {
	Protocol Protocol
	Err      error
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("protocol error (protocol=%s): %v", e.Protocol, e.Err)
}

func (e *ProtocolError) Unwrap() error {
	return e.Err
}

// NewProtocolError creates a new ProtocolError.
func NewProtocolError(protocol Protocol, err error) error {
	if err == nil {
		return nil
	}
	return &ProtocolError{
		Protocol: protocol,
		Err:      err,
	}
}

// TLSError wraps TLS-related errors.
type TLSError struct {
	Message string
	Err     error
}

func (e *TLSError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("TLS error: %s: %v", e.Message, e.Err)
	}
	return fmt.Sprintf("TLS error: %s", e.Message)
}

func (e *TLSError) Unwrap() error {
	return e.Err
}

// NewTLSError creates a new TLSError.
func NewTLSError(message string, err error) error {
	return &TLSError{
		Message: message,
		Err:     err,
	}
}

// ParticipantError wraps errors specific to a participant.
type ParticipantError struct {
	ParticipantID string
	Index         int
	Err           error
}

func (e *ParticipantError) Error() string {
	if e.ParticipantID != "" {
		return fmt.Sprintf("participant error (id=%s, index=%d): %v", e.ParticipantID, e.Index, e.Err)
	}
	return fmt.Sprintf("participant error (index=%d): %v", e.Index, e.Err)
}

func (e *ParticipantError) Unwrap() error {
	return e.Err
}

// NewParticipantError creates a new ParticipantError.
func NewParticipantError(participantID string, index int, err error) error {
	if err == nil {
		return nil
	}
	return &ParticipantError{
		ParticipantID: participantID,
		Index:         index,
		Err:           err,
	}
}
