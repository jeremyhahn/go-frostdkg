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
	"strings"
	"testing"
)

// TestErrorConstants verifies that error constants are properly defined.
func TestErrorConstants(t *testing.T) {
	errorTests := []struct {
		name string
		err  error
	}{
		// Connection errors
		{"ErrConnectionFailed", ErrConnectionFailed},
		{"ErrConnectionClosed", ErrConnectionClosed},
		{"ErrConnectionTimeout", ErrConnectionTimeout},
		{"ErrAlreadyConnected", ErrAlreadyConnected},
		{"ErrNotConnected", ErrNotConnected},
		{"ErrListenerFailed", ErrListenerFailed},
		{"ErrAddressInUse", ErrAddressInUse},

		// Session errors
		{"ErrSessionNotFound", ErrSessionNotFound},
		{"ErrSessionExists", ErrSessionExists},
		{"ErrSessionClosed", ErrSessionClosed},
		{"ErrSessionTimeout", ErrSessionTimeout},
		{"ErrSessionFull", ErrSessionFull},
		{"ErrDuplicateParticipant", ErrDuplicateParticipant},
		{"ErrInsufficientParticipants", ErrInsufficientParticipants},

		// Message errors
		{"ErrInvalidMessage", ErrInvalidMessage},
		{"ErrMessageTooLarge", ErrMessageTooLarge},
		{"ErrMessageTimeout", ErrMessageTimeout},
		{"ErrUnexpectedMessage", ErrUnexpectedMessage},
		{"ErrProtocolMismatch", ErrProtocolMismatch},
		{"ErrCiphersuiteMismatch", ErrCiphersuiteMismatch},

		// Config errors
		{"ErrInvalidConfig", ErrInvalidConfig},
		{"ErrInvalidProtocol", ErrInvalidProtocol},
		{"ErrInvalidAddress", ErrInvalidAddress},
		{"ErrInvalidThreshold", ErrInvalidThreshold},
		{"ErrInvalidParticipantCount", ErrInvalidParticipantCount},
		{"ErrInvalidParticipantIndex", ErrInvalidParticipantIndex},
		{"ErrInvalidHostKey", ErrInvalidHostKey},
		{"ErrInvalidRandomness", ErrInvalidRandomness},

		// TLS errors
		{"ErrTLSRequired", ErrTLSRequired},
		{"ErrCertificateInvalid", ErrCertificateInvalid},
		{"ErrCertificateExpired", ErrCertificateExpired},
		{"ErrCertificateNotFound", ErrCertificateNotFound},
		{"ErrPrivateKeyNotFound", ErrPrivateKeyNotFound},
		{"ErrCANotFound", ErrCANotFound},
		{"ErrPeerVerificationFailed", ErrPeerVerificationFailed},
		{"ErrHandshakeFailed", ErrHandshakeFailed},

		// Codec errors
		{"ErrCodecNotSupported", ErrCodecNotSupported},
		{"ErrEncodingFailed", ErrEncodingFailed},
		{"ErrDecodingFailed", ErrDecodingFailed},

		// DKG errors
		{"ErrDKGFailed", ErrDKGFailed},
		{"ErrDKGAborted", ErrDKGAborted},
		{"ErrInvalidDKGParams", ErrInvalidDKGParams},
		{"ErrInvalidDKGResult", ErrInvalidDKGResult},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
			if tt.err.Error() == "" {
				t.Errorf("%s has empty error message", tt.name)
			}
			if !strings.Contains(tt.err.Error(), "transport:") {
				t.Errorf("%s error message should contain 'transport:' prefix", tt.name)
			}
		})
	}
}

// TestConnectionErrorCreation tests NewConnectionError.
func TestConnectionErrorCreation(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		err     error
		wantNil bool
	}{
		{"with error", "localhost:9000", ErrConnectionFailed, false},
		{"nil error", "localhost:9000", nil, true},
		{"wrapped error", "127.0.0.1:8080", errors.New("network unreachable"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewConnectionError(tt.addr, tt.err)
			if tt.wantNil {
				if err != nil {
					t.Errorf("Expected nil error, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("Expected non-nil error")
			}

			connErr, ok := err.(*ConnectionError)
			if !ok {
				t.Fatalf("Expected *ConnectionError, got %T", err)
			}

			if connErr.Address != tt.addr {
				t.Errorf("Expected address %s, got %s", tt.addr, connErr.Address)
			}

			if !errors.Is(connErr.Err, tt.err) {
				t.Errorf("Expected wrapped error %v, got %v", tt.err, connErr.Err)
			}

			// Test error message contains address
			errMsg := err.Error()
			if !strings.Contains(errMsg, tt.addr) {
				t.Errorf("Error message should contain address %s: %s", tt.addr, errMsg)
			}
		})
	}
}

// TestConnectionErrorUnwrap tests ConnectionError unwrapping.
func TestConnectionErrorUnwrap(t *testing.T) {
	baseErr := ErrConnectionTimeout
	connErr := NewConnectionError("localhost:9000", baseErr)

	if !errors.Is(connErr, baseErr) {
		t.Error("errors.Is should find wrapped error")
	}

	unwrapped := errors.Unwrap(connErr)
	if unwrapped != baseErr {
		t.Errorf("Expected unwrapped error %v, got %v", baseErr, unwrapped)
	}
}

// TestSessionErrorCreation tests NewSessionError.
func TestSessionErrorCreation(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		err       error
		wantNil   bool
	}{
		{"with error", "session-123", ErrSessionNotFound, false},
		{"nil error", "session-456", nil, true},
		{"timeout error", "session-789", ErrSessionTimeout, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewSessionError(tt.sessionID, tt.err)
			if tt.wantNil {
				if err != nil {
					t.Errorf("Expected nil error, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("Expected non-nil error")
			}

			sessErr, ok := err.(*SessionError)
			if !ok {
				t.Fatalf("Expected *SessionError, got %T", err)
			}

			if sessErr.SessionID != tt.sessionID {
				t.Errorf("Expected session ID %s, got %s", tt.sessionID, sessErr.SessionID)
			}

			if !errors.Is(sessErr.Err, tt.err) {
				t.Errorf("Expected wrapped error %v, got %v", tt.err, sessErr.Err)
			}

			// Test error message contains session ID
			errMsg := err.Error()
			if !strings.Contains(errMsg, tt.sessionID) {
				t.Errorf("Error message should contain session ID %s: %s", tt.sessionID, errMsg)
			}
		})
	}
}

// TestProtocolErrorCreation tests NewProtocolError.
func TestProtocolErrorCreation(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		err      error
		wantNil  bool
	}{
		{"gRPC error", ProtocolGRPC, ErrProtocolMismatch, false},
		{"nil error", ProtocolHTTP, nil, true},
		{"QUIC error", ProtocolQUIC, errors.New("connection refused"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewProtocolError(tt.protocol, tt.err)
			if tt.wantNil {
				if err != nil {
					t.Errorf("Expected nil error, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("Expected non-nil error")
			}

			protoErr, ok := err.(*ProtocolError)
			if !ok {
				t.Fatalf("Expected *ProtocolError, got %T", err)
			}

			if protoErr.Protocol != tt.protocol {
				t.Errorf("Expected protocol %s, got %s", tt.protocol, protoErr.Protocol)
			}

			if !errors.Is(protoErr.Err, tt.err) {
				t.Errorf("Expected wrapped error %v, got %v", tt.err, protoErr.Err)
			}

			// Test error message contains protocol
			errMsg := err.Error()
			if !strings.Contains(errMsg, string(tt.protocol)) {
				t.Errorf("Error message should contain protocol %s: %s", tt.protocol, errMsg)
			}
		})
	}
}

// TestTLSErrorCreation tests NewTLSError.
func TestTLSErrorCreation(t *testing.T) {
	tests := []struct {
		name    string
		message string
		err     error
		wantErr bool
	}{
		{"with underlying error", "certificate validation failed", ErrCertificateInvalid, true},
		{"message only", "handshake timeout", nil, false},
		{"cert expired", "certificate has expired", ErrCertificateExpired, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewTLSError(tt.message, tt.err)
			if err == nil {
				t.Fatal("Expected non-nil error")
			}

			tlsErr, ok := err.(*TLSError)
			if !ok {
				t.Fatalf("Expected *TLSError, got %T", err)
			}

			if tlsErr.Message != tt.message {
				t.Errorf("Expected message %s, got %s", tt.message, tlsErr.Message)
			}

			errMsg := err.Error()
			if !strings.Contains(errMsg, "TLS error") {
				t.Error("Error message should contain 'TLS error'")
			}

			if !strings.Contains(errMsg, tt.message) {
				t.Errorf("Error message should contain message %s: %s", tt.message, errMsg)
			}

			if tt.wantErr {
				if tlsErr.Err == nil {
					t.Error("Expected underlying error to be set")
				}
				if !errors.Is(tlsErr.Err, tt.err) {
					t.Errorf("Expected underlying error %v, got %v", tt.err, tlsErr.Err)
				}
			} else {
				if tlsErr.Err != nil {
					t.Errorf("Expected no underlying error, got %v", tlsErr.Err)
				}
			}
		})
	}
}

// TestParticipantErrorCreation tests NewParticipantError.
func TestParticipantErrorCreation(t *testing.T) {
	tests := []struct {
		name          string
		participantID string
		index         int
		err           error
		wantNil       bool
	}{
		{"with ID", "participant-1", 0, ErrInvalidMessage, false},
		{"without ID", "", 2, ErrMessageTimeout, false},
		{"nil error", "participant-3", 1, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewParticipantError(tt.participantID, tt.index, tt.err)
			if tt.wantNil {
				if err != nil {
					t.Errorf("Expected nil error, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("Expected non-nil error")
			}

			partErr, ok := err.(*ParticipantError)
			if !ok {
				t.Fatalf("Expected *ParticipantError, got %T", err)
			}

			if partErr.ParticipantID != tt.participantID {
				t.Errorf("Expected participant ID %s, got %s", tt.participantID, partErr.ParticipantID)
			}

			if partErr.Index != tt.index {
				t.Errorf("Expected index %d, got %d", tt.index, partErr.Index)
			}

			if !errors.Is(partErr.Err, tt.err) {
				t.Errorf("Expected wrapped error %v, got %v", tt.err, partErr.Err)
			}

			errMsg := err.Error()
			if tt.participantID != "" && !strings.Contains(errMsg, tt.participantID) {
				t.Errorf("Error message should contain participant ID %s: %s", tt.participantID, errMsg)
			}
		})
	}
}

// TestErrorWrapping tests that all custom errors properly implement error wrapping.
func TestErrorWrapping(t *testing.T) {
	baseErr := errors.New("base error")

	tests := []struct {
		name string
		err  error
	}{
		{"ConnectionError", NewConnectionError("addr", baseErr)},
		{"SessionError", NewSessionError("session", baseErr)},
		{"ProtocolError", NewProtocolError(ProtocolGRPC, baseErr)},
		{"TLSError", NewTLSError("message", baseErr)},
		{"ParticipantError", NewParticipantError("id", 0, baseErr)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, baseErr) {
				t.Errorf("%s should wrap base error", tt.name)
			}

			unwrapped := errors.Unwrap(tt.err)
			if unwrapped != baseErr {
				t.Errorf("%s unwrap failed: expected %v, got %v", tt.name, baseErr, unwrapped)
			}
		})
	}
}
