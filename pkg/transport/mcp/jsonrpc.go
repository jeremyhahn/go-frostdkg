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
	"fmt"
)

// JSONRPC version constant.
const JSONRPCVersion = "2.0"

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      interface{}     `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// JSONRPCNotification represents a JSON-RPC 2.0 notification (no ID).
type JSONRPCNotification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	JSONRPCParseError     = -32700
	JSONRPCInvalidRequest = -32600
	JSONRPCMethodNotFound = -32601
	JSONRPCInvalidParams  = -32602
	JSONRPCInternalError  = -32603
)

// NewJSONRPCRequest creates a new JSON-RPC request.
func NewJSONRPCRequest(method string, params interface{}, id interface{}) (*JSONRPCRequest, error) {
	var paramsData json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal params: %w", err)
		}
		paramsData = data
	}

	return &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  method,
		Params:  paramsData,
		ID:      id,
	}, nil
}

// NewJSONRPCResponse creates a successful JSON-RPC response.
func NewJSONRPCResponse(result interface{}, id interface{}) (*JSONRPCResponse, error) {
	var resultData json.RawMessage
	if result != nil {
		data, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal result: %w", err)
		}
		resultData = data
	}

	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		Result:  resultData,
		ID:      id,
	}, nil
}

// NewJSONRPCErrorResponse creates an error JSON-RPC response.
func NewJSONRPCErrorResponse(code int, message string, data interface{}, id interface{}) (*JSONRPCResponse, error) {
	var dataJSON json.RawMessage
	if data != nil {
		dataBytes, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal error data: %w", err)
		}
		dataJSON = dataBytes
	}

	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    dataJSON,
		},
		ID: id,
	}, nil
}

// NewJSONRPCNotification creates a JSON-RPC notification.
func NewJSONRPCNotification(method string, params interface{}) (*JSONRPCNotification, error) {
	var paramsData json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal params: %w", err)
		}
		paramsData = data
	}

	return &JSONRPCNotification{
		JSONRPC: JSONRPCVersion,
		Method:  method,
		Params:  paramsData,
	}, nil
}

// IsNotification returns true if the request has no ID (is a notification).
func (r *JSONRPCRequest) IsNotification() bool {
	return r.ID == nil
}

// Validate validates a JSON-RPC request.
func (r *JSONRPCRequest) Validate() error {
	if r.JSONRPC != JSONRPCVersion {
		return fmt.Errorf("invalid JSON-RPC version: %s", r.JSONRPC)
	}
	if r.Method == "" {
		return fmt.Errorf("method cannot be empty")
	}
	return nil
}

// Validate validates a JSON-RPC response.
func (r *JSONRPCResponse) Validate() error {
	if r.JSONRPC != JSONRPCVersion {
		return fmt.Errorf("invalid JSON-RPC version: %s", r.JSONRPC)
	}
	if r.Result != nil && r.Error != nil {
		return fmt.Errorf("response cannot have both result and error")
	}
	if r.Result == nil && r.Error == nil {
		return fmt.Errorf("response must have either result or error")
	}
	return nil
}

// GetResult unmarshals the result into the provided value.
func (r *JSONRPCResponse) GetResult(v interface{}) error {
	if r.Error != nil {
		return fmt.Errorf("response contains error: %s", r.Error.Message)
	}
	if r.Result == nil {
		return fmt.Errorf("response has no result")
	}
	return json.Unmarshal(r.Result, v)
}

// GetError returns the error from the response, or nil if no error.
func (r *JSONRPCResponse) GetError() error {
	if r.Error == nil {
		return nil
	}
	return fmt.Errorf("JSON-RPC error %d: %s", r.Error.Code, r.Error.Message)
}

// MarshalJSON implements json.Marshaler for JSONRPCRequest.
func (r *JSONRPCRequest) MarshalJSON() ([]byte, error) {
	type Alias JSONRPCRequest
	return json.Marshal((*Alias)(r))
}

// UnmarshalJSON implements json.Unmarshaler for JSONRPCRequest.
func (r *JSONRPCRequest) UnmarshalJSON(data []byte) error {
	type Alias JSONRPCRequest
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	return json.Unmarshal(data, aux)
}

// MarshalJSON implements json.Marshaler for JSONRPCResponse.
func (r *JSONRPCResponse) MarshalJSON() ([]byte, error) {
	type Alias JSONRPCResponse
	return json.Marshal((*Alias)(r))
}

// UnmarshalJSON implements json.Unmarshaler for JSONRPCResponse.
func (r *JSONRPCResponse) UnmarshalJSON(data []byte) error {
	type Alias JSONRPCResponse
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	return json.Unmarshal(data, aux)
}
