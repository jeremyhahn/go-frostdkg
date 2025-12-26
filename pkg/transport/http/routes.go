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

// Package http provides HTTP/REST transport for FROST DKG protocol.
//
// This package implements a RESTful API for distributed key generation using
// standard library net/http with TLS 1.3 support. It provides:
//   - Coordinator server for message relay
//   - Client for participant connections
//   - Content negotiation (JSON, CBOR, MessagePack)
//   - Session management
//   - Graceful shutdown
//
// The HTTP transport uses a coordinator pattern where a central server relays
// messages between participants without participating in DKG cryptography.
package http

import (
	"fmt"
	"strings"
)

const (
	// API version prefix
	apiVersion = "v1"
)

// REST endpoint paths for DKG operations
const (
	// PathSessions - POST: Create new DKG session
	PathSessions = "/" + apiVersion + "/sessions"

	// PathSession - GET: Get session info by ID
	PathSession = "/" + apiVersion + "/sessions/%s"

	// PathJoinSession - POST: Join a session
	PathJoinSession = "/" + apiVersion + "/sessions/%s/join"

	// PathRound1 - POST: Submit Round1 message, GET: Get aggregated Round1
	PathRound1 = "/" + apiVersion + "/sessions/%s/round1"

	// PathRound2 - POST: Submit Round2 message, GET: Get aggregated Round2
	PathRound2 = "/" + apiVersion + "/sessions/%s/round2"

	// PathCertEq - POST: Submit CertEq signature
	PathCertEq = "/" + apiVersion + "/sessions/%s/certeq"

	// PathCertificate - GET: Get final certificate
	PathCertificate = "/" + apiVersion + "/sessions/%s/certificate"

	// PathHealth - GET: Health check endpoint
	PathHealth = "/" + apiVersion + "/health"
)

// HTTP headers
const (
	// HeaderContentType specifies the serialization format of the request/response
	HeaderContentType = "Content-Type"

	// HeaderAccept specifies the desired serialization format for the response
	HeaderAccept = "Accept"

	// HeaderRequestID is a unique identifier for request tracing
	HeaderRequestID = "X-Request-ID"

	// HeaderSessionID identifies the DKG session
	HeaderSessionID = "X-Session-ID"
)

// Content types for serialization formats
const (
	// ContentTypeJSON for JSON serialization
	ContentTypeJSON = "application/json"

	// ContentTypeCBOR for CBOR serialization
	ContentTypeCBOR = "application/cbor"

	// ContentTypeMsgPack for MessagePack serialization
	ContentTypeMsgPack = "application/msgpack"

	// ContentTypeText for plain text (health checks)
	ContentTypeText = "text/plain"
)

// RouteError represents routing-related errors
type RouteError struct {
	Path   string
	Method string
	Err    error
}

func (e *RouteError) Error() string {
	return fmt.Sprintf("route error [%s %s]: %v", e.Method, e.Path, e.Err)
}

func (e *RouteError) Unwrap() error {
	return e.Err
}

// SessionPath generates a session-specific path
func SessionPath(sessionID string) string {
	return fmt.Sprintf(PathSession, sessionID)
}

// JoinSessionPath generates a join session path
func JoinSessionPath(sessionID string) string {
	return fmt.Sprintf(PathJoinSession, sessionID)
}

// Round1Path generates a Round1 path
func Round1Path(sessionID string) string {
	return fmt.Sprintf(PathRound1, sessionID)
}

// Round2Path generates a Round2 path
func Round2Path(sessionID string) string {
	return fmt.Sprintf(PathRound2, sessionID)
}

// CertEqPath generates a CertEq path
func CertEqPath(sessionID string) string {
	return fmt.Sprintf(PathCertEq, sessionID)
}

// CertificatePath generates a certificate path
func CertificatePath(sessionID string) string {
	return fmt.Sprintf(PathCertificate, sessionID)
}

// ParseContentType extracts the codec type from Content-Type header
func ParseContentType(contentType string) string {
	// Handle charset and other parameters
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return ""
	}

	ct := strings.TrimSpace(parts[0])
	switch ct {
	case ContentTypeJSON:
		return "json"
	case ContentTypeCBOR:
		return "cbor"
	case ContentTypeMsgPack:
		return "msgpack"
	default:
		return ""
	}
}

// CodecToContentType converts codec type to Content-Type header value
func CodecToContentType(codecType string) string {
	switch codecType {
	case "json":
		return ContentTypeJSON
	case "cbor":
		return ContentTypeCBOR
	case "msgpack":
		return ContentTypeMsgPack
	default:
		return ContentTypeJSON
	}
}
