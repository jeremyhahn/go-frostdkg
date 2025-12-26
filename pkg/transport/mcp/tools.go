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

package mcp

import (
	"encoding/json"
)

// ToolName represents MCP tool identifiers for DKG operations.
type ToolName string

const (
	// ToolCreateSession creates a new DKG session.
	ToolCreateSession ToolName = "dkg_create_session"

	// ToolJoinSession joins an existing DKG session.
	ToolJoinSession ToolName = "dkg_join_session"

	// ToolGetSession retrieves session information.
	ToolGetSession ToolName = "dkg_get_session"

	// ToolSubmitRound1 submits a Round1 message.
	ToolSubmitRound1 ToolName = "dkg_submit_round1"

	// ToolSubmitRound2 submits a Round2 message.
	ToolSubmitRound2 ToolName = "dkg_submit_round2"

	// ToolSubmitCertEq submits a CertEq signature.
	ToolSubmitCertEq ToolName = "dkg_submit_certeq"

	// ToolGetResult retrieves DKG session result.
	ToolGetResult ToolName = "dkg_get_result"

	// ToolListSessions lists all active sessions.
	ToolListSessions ToolName = "dkg_list_sessions"
)

// Tool represents an MCP tool definition.
type Tool struct {
	Name        ToolName               `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// GetToolDefinitions returns all available MCP tools for DKG operations.
func GetToolDefinitions() []Tool {
	return []Tool{
		{
			Name:        ToolCreateSession,
			Description: "Create a new DKG session with specified parameters. Returns session ID and configuration.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Unique identifier for the DKG session",
					},
					"threshold": map[string]interface{}{
						"type":        "integer",
						"description": "Signing threshold t (1 <= t <= n)",
						"minimum":     1,
					},
					"num_participants": map[string]interface{}{
						"type":        "integer",
						"description": "Total number of participants n",
						"minimum":     1,
					},
					"ciphersuite": map[string]interface{}{
						"type":        "string",
						"description": "FROST ciphersuite identifier (e.g., FROST-ED25519-SHA512-v1)",
					},
					"timeout_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "Session timeout in seconds (default: 300)",
						"default":     300,
					},
				},
				"required": []string{"session_id", "threshold", "num_participants", "ciphersuite"},
			},
		},
		{
			Name:        ToolJoinSession,
			Description: "Join an existing DKG session as a participant. Returns participant index and session details.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Session identifier to join",
					},
					"host_pubkey": map[string]interface{}{
						"type":        "string",
						"description": "Participant's host public key (hex encoded, 33 bytes compressed)",
					},
				},
				"required": []string{"session_id", "host_pubkey"},
			},
		},
		{
			Name:        ToolGetSession,
			Description: "Retrieve information about a DKG session including participant list and status.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Session identifier",
					},
				},
				"required": []string{"session_id"},
			},
		},
		{
			Name:        ToolSubmitRound1,
			Description: "Submit Round1 message containing VSS commitments and proof of possession.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Session identifier",
					},
					"participant_idx": map[string]interface{}{
						"type":        "integer",
						"description": "Participant index in session",
					},
					"commitment": map[string]interface{}{
						"type":        "array",
						"description": "VSS commitment coefficients (array of hex-encoded points)",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
					"pop": map[string]interface{}{
						"type":        "string",
						"description": "Proof of possession (hex encoded)",
					},
					"pubnonce": map[string]interface{}{
						"type":        "string",
						"description": "Public nonce for CertEq (hex encoded)",
					},
				},
				"required": []string{"session_id", "participant_idx", "commitment", "pop", "pubnonce"},
			},
		},
		{
			Name:        ToolSubmitRound2,
			Description: "Submit Round2 message containing encrypted shares for other participants.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Session identifier",
					},
					"participant_idx": map[string]interface{}{
						"type":        "integer",
						"description": "Participant index in session",
					},
					"encrypted_shares": map[string]interface{}{
						"type":        "string",
						"description": "Encrypted shares for all participants (hex encoded)",
					},
				},
				"required": []string{"session_id", "participant_idx", "encrypted_shares"},
			},
		},
		{
			Name:        ToolSubmitCertEq,
			Description: "Submit CertEq signature to finalize the DKG session.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Session identifier",
					},
					"participant_idx": map[string]interface{}{
						"type":        "integer",
						"description": "Participant index in session",
					},
					"signature": map[string]interface{}{
						"type":        "string",
						"description": "CertEq signature (hex encoded)",
					},
				},
				"required": []string{"session_id", "participant_idx", "signature"},
			},
		},
		{
			Name:        ToolGetResult,
			Description: "Retrieve the DKG result including threshold public key and verification shares.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Session identifier",
					},
				},
				"required": []string{"session_id"},
			},
		},
		{
			Name:        ToolListSessions,
			Description: "List all active DKG sessions on the coordinator.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"include_completed": map[string]interface{}{
						"type":        "boolean",
						"description": "Include completed sessions in the list",
						"default":     false,
					},
				},
			},
		},
	}
}

// CreateSessionParams contains parameters for creating a DKG session.
type CreateSessionParams struct {
	SessionID       string `json:"session_id"`
	Threshold       int    `json:"threshold"`
	NumParticipants int    `json:"num_participants"`
	Ciphersuite     string `json:"ciphersuite"`
	TimeoutSeconds  int    `json:"timeout_seconds,omitempty"`
}

// CreateSessionResult contains the result of session creation.
type CreateSessionResult struct {
	SessionID       string `json:"session_id"`
	Threshold       int    `json:"threshold"`
	NumParticipants int    `json:"num_participants"`
	Ciphersuite     string `json:"ciphersuite"`
	Status          string `json:"status"`
}

// JoinSessionParams contains parameters for joining a session.
type JoinSessionParams struct {
	SessionID  string `json:"session_id"`
	HostPubkey string `json:"host_pubkey"`
}

// JoinSessionResult contains the result of joining a session.
type JoinSessionResult struct {
	SessionID       string   `json:"session_id"`
	ParticipantIdx  int      `json:"participant_idx"`
	Threshold       int      `json:"threshold"`
	NumParticipants int      `json:"num_participants"`
	HostPubkeys     []string `json:"host_pubkeys"`
	Ciphersuite     string   `json:"ciphersuite"`
}

// GetSessionParams contains parameters for retrieving session info.
type GetSessionParams struct {
	SessionID string `json:"session_id"`
}

// GetSessionResult contains session information.
type GetSessionResult struct {
	SessionID           string   `json:"session_id"`
	Threshold           int      `json:"threshold"`
	NumParticipants     int      `json:"num_participants"`
	CurrentParticipants int      `json:"current_participants"`
	Ciphersuite         string   `json:"ciphersuite"`
	Status              string   `json:"status"`
	HostPubkeys         []string `json:"host_pubkeys,omitempty"`
}

// SubmitRound1Params contains parameters for Round1 submission.
type SubmitRound1Params struct {
	SessionID      string   `json:"session_id"`
	ParticipantIdx int      `json:"participant_idx"`
	Commitment     []string `json:"commitment"`
	POP            string   `json:"pop"`
	Pubnonce       string   `json:"pubnonce"`
}

// SubmitRound1Result contains the result of Round1 submission.
type SubmitRound1Result struct {
	Status         string     `json:"status"`
	AllCommitments [][]string `json:"all_commitments,omitempty"`
	AllPOPs        []string   `json:"all_pops,omitempty"`
	AllPubnonces   []string   `json:"all_pubnonces,omitempty"`
	WaitingFor     int        `json:"waiting_for,omitempty"`
}

// SubmitRound2Params contains parameters for Round2 submission.
type SubmitRound2Params struct {
	SessionID       string `json:"session_id"`
	ParticipantIdx  int    `json:"participant_idx"`
	EncryptedShares string `json:"encrypted_shares"`
}

// SubmitRound2Result contains the result of Round2 submission.
type SubmitRound2Result struct {
	Status     string `json:"status"`
	WaitingFor int    `json:"waiting_for,omitempty"`
}

// SubmitCertEqParams contains parameters for CertEq signature submission.
type SubmitCertEqParams struct {
	SessionID      string `json:"session_id"`
	ParticipantIdx int    `json:"participant_idx"`
	Signature      string `json:"signature"`
}

// SubmitCertEqResult contains the result of CertEq submission.
type SubmitCertEqResult struct {
	Status      string `json:"status"`
	Certificate string `json:"certificate,omitempty"`
	WaitingFor  int    `json:"waiting_for,omitempty"`
}

// GetResultParams contains parameters for retrieving DKG result.
type GetResultParams struct {
	SessionID string `json:"session_id"`
}

// GetResultResult contains the DKG session result.
type GetResultResult struct {
	SessionID       string   `json:"session_id"`
	ThresholdPubkey string   `json:"threshold_pubkey"`
	PublicShares    []string `json:"public_shares"`
	RecoveryData    string   `json:"recovery_data,omitempty"`
	Status          string   `json:"status"`
}

// ListSessionsParams contains parameters for listing sessions.
type ListSessionsParams struct {
	IncludeCompleted bool `json:"include_completed,omitempty"`
}

// ListSessionsResult contains the list of sessions.
type ListSessionsResult struct {
	Sessions []SessionSummary `json:"sessions"`
}

// SessionSummary provides summary information about a session.
type SessionSummary struct {
	SessionID           string `json:"session_id"`
	Threshold           int    `json:"threshold"`
	NumParticipants     int    `json:"num_participants"`
	CurrentParticipants int    `json:"current_participants"`
	Status              string `json:"status"`
	Ciphersuite         string `json:"ciphersuite"`
}

// ToolError represents an error from a tool execution.
type ToolError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *ToolError) Error() string {
	return e.Message
}

// NewToolError creates a new tool error.
func NewToolError(code int, message string) *ToolError {
	return &ToolError{
		Code:    code,
		Message: message,
	}
}

// ToolErrorCode defines error codes for tool operations.
type ToolErrorCode int

const (
	// ErrorCodeInvalidParams indicates invalid tool parameters.
	ErrorCodeInvalidParams ToolErrorCode = 1000

	// ErrorCodeSessionNotFound indicates the session does not exist.
	ErrorCodeSessionNotFound ToolErrorCode = 1001

	// ErrorCodeSessionExists indicates the session already exists.
	ErrorCodeSessionExists ToolErrorCode = 1002

	// ErrorCodeSessionFull indicates the session has maximum participants.
	ErrorCodeSessionFull ToolErrorCode = 1003

	// ErrorCodeInvalidState indicates the operation is invalid in current state.
	ErrorCodeInvalidState ToolErrorCode = 1004

	// ErrorCodeTimeout indicates the operation timed out.
	ErrorCodeTimeout ToolErrorCode = 1005

	// ErrorCodeInternal indicates an internal server error.
	ErrorCodeInternal ToolErrorCode = 1006
)

// MarshalParams marshals tool parameters to JSON.
func MarshalParams(params interface{}) (json.RawMessage, error) {
	data, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

// UnmarshalParams unmarshals tool parameters from JSON.
func UnmarshalParams(data json.RawMessage, params interface{}) error {
	return json.Unmarshal(data, params)
}
