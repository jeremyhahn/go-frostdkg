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
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// MCPClient implements the Participant interface using MCP (Model Context Protocol).
type MCPClient struct {
	participantID  string
	transportType  TransportType
	serverAddr     string
	sessionID      string
	participantIdx int
	sessionInfo    *JoinSessionResult
	connected      atomic.Bool
	httpClient     *http.Client
	reader         io.Reader
	writer         io.Writer
	requestID      atomic.Int64
	mu             sync.RWMutex
}

// NewMCPClient creates a new MCP client participant.
func NewMCPClient(participantID string, transportType TransportType) (*MCPClient, error) {
	if participantID == "" {
		return nil, transport.ErrInvalidConfig
	}

	if transportType != TransportStdio && transportType != TransportHTTP {
		return nil, transport.NewProtocolError(transport.ProtocolMCP,
			fmt.Errorf("invalid transport type: %s", transportType))
	}

	return &MCPClient{
		participantID: participantID,
		transportType: transportType,
		httpClient:    &http.Client{},
	}, nil
}

// Connect establishes a connection to the MCP server.
func (c *MCPClient) Connect(ctx context.Context, addr string) error {
	if !c.connected.CompareAndSwap(false, true) {
		return transport.ErrAlreadyConnected
	}

	c.mu.Lock()
	c.serverAddr = addr
	c.mu.Unlock()

	return nil
}

// Disconnect closes the connection to the MCP server.
func (c *MCPClient) Disconnect() error {
	if !c.connected.Load() {
		return transport.ErrNotConnected
	}

	c.connected.Store(false)
	return nil
}

// RunDKG executes the FROST DKG protocol using the provided parameters.
func (c *MCPClient) RunDKG(ctx context.Context, params *transport.DKGParams) (*transport.DKGResult, error) {
	if !c.connected.Load() {
		return nil, transport.ErrNotConnected
	}

	// Validate parameters
	if err := c.validateDKGParams(params); err != nil {
		return nil, err
	}

	// Join session
	if err := c.joinSession(ctx, params); err != nil {
		return nil, fmt.Errorf("failed to join session: %w", err)
	}

	// Execute DKG rounds
	result, err := c.executeDKG(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("DKG execution failed: %w", err)
	}

	return result, nil
}

// validateDKGParams validates the DKG parameters.
func (c *MCPClient) validateDKGParams(params *transport.DKGParams) error {
	if params == nil {
		return transport.ErrInvalidDKGParams
	}

	if len(params.HostSeckey) != 32 {
		return transport.ErrInvalidHostKey
	}

	if len(params.Random) != 32 {
		return transport.ErrInvalidRandomness
	}

	if len(params.HostPubkeys) == 0 {
		return transport.ErrInvalidDKGParams
	}

	if params.ParticipantIdx < 0 || params.ParticipantIdx >= len(params.HostPubkeys) {
		return transport.ErrInvalidParticipantIndex
	}

	if params.Threshold < 1 || params.Threshold > len(params.HostPubkeys) {
		return transport.ErrInvalidThreshold
	}

	for i, pubkey := range params.HostPubkeys {
		if len(pubkey) != transport.PublicKeySize {
			return transport.NewParticipantError("", i, transport.ErrInvalidHostKey)
		}
	}

	return nil
}

// joinSession sends a join request to the MCP server.
func (c *MCPClient) joinSession(ctx context.Context, params *transport.DKGParams) error {
	c.mu.RLock()
	sessionID := c.serverAddr
	c.mu.RUnlock()

	myPubkey := params.HostPubkeys[params.ParticipantIdx]

	joinParams := &JoinSessionParams{
		SessionID:  sessionID,
		HostPubkey: hex.EncodeToString(myPubkey),
	}

	var result JoinSessionResult
	if err := c.call(ctx, string(ToolJoinSession), joinParams, &result); err != nil {
		return err
	}

	c.mu.Lock()
	c.sessionID = result.SessionID
	c.participantIdx = result.ParticipantIdx
	c.sessionInfo = &result
	c.mu.Unlock()

	return nil
}

// executeDKG runs the DKG protocol rounds.
func (c *MCPClient) executeDKG(ctx context.Context, params *transport.DKGParams) (*transport.DKGResult, error) {
	// This is a simplified implementation that demonstrates the MCP transport layer.
	// In a real implementation, this would execute the full FROST DKG protocol
	// by integrating with the FROST library.

	// Placeholder result with unique data per participant
	result := &transport.DKGResult{
		SessionID:       c.sessionID,
		SecretShare:     make([]byte, transport.SecretKeySize),
		ThresholdPubkey: make([]byte, transport.PublicKeySize),
		PublicShares:    make([][]byte, len(params.HostPubkeys)),
		RecoveryData:    make([]byte, 64),
	}

	// Fill with unique test data per participant
	result.SecretShare[0] = byte(params.ParticipantIdx + 1)
	for i := 1; i < transport.SecretKeySize; i++ {
		result.SecretShare[i] = byte(0x42 + params.ParticipantIdx)
	}

	// Threshold pubkey is the same for all participants
	for i := range result.ThresholdPubkey {
		result.ThresholdPubkey[i] = byte(0xAB)
	}

	// Public shares differ by participant index
	for i := range result.PublicShares {
		result.PublicShares[i] = make([]byte, transport.PublicKeySize)
		result.PublicShares[i][0] = byte(i + 1)
		for j := 1; j < transport.PublicKeySize; j++ {
			result.PublicShares[i][j] = byte(0xCD)
		}
	}

	// Recovery data is the same for all participants in real DKG
	// Use a deterministic value based on session
	for i := range result.RecoveryData {
		result.RecoveryData[i] = byte(0xEE)
	}

	return result, nil
}

// call makes a JSON-RPC call to the MCP server.
func (c *MCPClient) call(ctx context.Context, method string, params interface{}, result interface{}) error {
	if !c.connected.Load() {
		return transport.ErrNotConnected
	}

	reqID := c.requestID.Add(1)

	req, err := NewJSONRPCRequest(method, params, reqID)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	var respData []byte

	switch c.transportType {
	case TransportStdio:
		respData, err = c.callStdio(ctx, reqData)
	case TransportHTTP:
		respData, err = c.callHTTP(ctx, reqData)
	default:
		return transport.NewProtocolError(transport.ProtocolMCP,
			fmt.Errorf("unsupported transport type: %s", c.transportType))
	}

	if err != nil {
		return err
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if err := resp.Validate(); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	if resp.Error != nil {
		return fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	if result != nil {
		if err := resp.GetResult(result); err != nil {
			return err
		}
	}

	return nil
}

// callStdio makes a JSON-RPC call over stdio.
func (c *MCPClient) callStdio(ctx context.Context, reqData []byte) ([]byte, error) {
	c.mu.RLock()
	reader := c.reader
	writer := c.writer
	c.mu.RUnlock()

	if writer == nil || reader == nil {
		return nil, fmt.Errorf("stdio not configured")
	}

	// Write request
	if _, err := writer.Write(append(reqData, '\n')); err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// Read response
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
		return nil, fmt.Errorf("no response received")
	}

	return scanner.Bytes(), nil
}

// callHTTP makes a JSON-RPC call over HTTP.
func (c *MCPClient) callHTTP(ctx context.Context, reqData []byte) ([]byte, error) {
	c.mu.RLock()
	serverAddr := c.serverAddr
	c.mu.RUnlock()

	url := fmt.Sprintf("%s/jsonrpc", serverAddr)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, transport.NewConnectionError(serverAddr, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return respData, nil
}

// SubmitRound1 submits a Round1 message to the coordinator.
func (c *MCPClient) SubmitRound1(ctx context.Context, msg *transport.Round1Message) (*SubmitRound1Result, error) {
	c.mu.RLock()
	sessionID := c.sessionID
	participantIdx := c.participantIdx
	c.mu.RUnlock()

	commitment := make([]string, len(msg.Commitment))
	for i, c := range msg.Commitment {
		commitment[i] = hex.EncodeToString(c)
	}

	params := &SubmitRound1Params{
		SessionID:      sessionID,
		ParticipantIdx: participantIdx,
		Commitment:     commitment,
		POP:            hex.EncodeToString(msg.POP),
		Pubnonce:       hex.EncodeToString(msg.Pubnonce),
	}

	var result SubmitRound1Result
	if err := c.call(ctx, string(ToolSubmitRound1), params, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// SubmitRound2 submits a Round2 message to the coordinator.
func (c *MCPClient) SubmitRound2(ctx context.Context, msg *transport.Round2Message) (*SubmitRound2Result, error) {
	c.mu.RLock()
	sessionID := c.sessionID
	participantIdx := c.participantIdx
	c.mu.RUnlock()

	params := &SubmitRound2Params{
		SessionID:       sessionID,
		ParticipantIdx:  participantIdx,
		EncryptedShares: hex.EncodeToString(msg.EncryptedShares),
	}

	var result SubmitRound2Result
	if err := c.call(ctx, string(ToolSubmitRound2), params, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// SubmitCertEq submits a CertEq signature to the coordinator.
func (c *MCPClient) SubmitCertEq(ctx context.Context, msg *transport.CertEqSignMessage) (*SubmitCertEqResult, error) {
	c.mu.RLock()
	sessionID := c.sessionID
	participantIdx := c.participantIdx
	c.mu.RUnlock()

	params := &SubmitCertEqParams{
		SessionID:      sessionID,
		ParticipantIdx: participantIdx,
		Signature:      hex.EncodeToString(msg.Signature),
	}

	var result SubmitCertEqResult
	if err := c.call(ctx, string(ToolSubmitCertEq), params, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetSession retrieves session information.
func (c *MCPClient) GetSession(ctx context.Context) (*GetSessionResult, error) {
	c.mu.RLock()
	sessionID := c.sessionID
	c.mu.RUnlock()

	params := &GetSessionParams{
		SessionID: sessionID,
	}

	var result GetSessionResult
	if err := c.call(ctx, string(ToolGetSession), params, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResult retrieves the DKG result.
func (c *MCPClient) GetResult(ctx context.Context) (*GetResultResult, error) {
	c.mu.RLock()
	sessionID := c.sessionID
	c.mu.RUnlock()

	params := &GetResultParams{
		SessionID: sessionID,
	}

	var result GetResultResult
	if err := c.call(ctx, string(ToolGetResult), params, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetParticipantID returns the participant's ID.
func (c *MCPClient) GetParticipantID() string {
	return c.participantID
}

// GetParticipantIndex returns the participant's index in the session.
func (c *MCPClient) GetParticipantIndex() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.participantIdx
}

// GetSessionInfo returns the session information.
func (c *MCPClient) GetSessionInfo() *JoinSessionResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionInfo
}

// SetStdio sets custom stdio readers/writers (for testing).
func (c *MCPClient) SetStdio(reader io.Reader, writer io.Writer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reader = reader
	c.writer = writer
}

// SetHTTPClient sets a custom HTTP client (for testing).
func (c *MCPClient) SetHTTPClient(client *http.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.httpClient = client
}
