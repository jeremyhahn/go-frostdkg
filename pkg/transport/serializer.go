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
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/fxamacker/cbor/v2"
	"github.com/vmihailenco/msgpack/v5"
	"go.mongodb.org/mongo-driver/bson"
	"gopkg.in/yaml.v3"
)

// SerializerError represents serialization errors
type SerializerError struct {
	Operation string
	CodecType string
	Err       error
}

func (e *SerializerError) Error() string {
	return fmt.Sprintf("serializer: %s failed for codec %s: %v", e.Operation, e.CodecType, e.Err)
}

func (e *SerializerError) Unwrap() error {
	return e.Err
}

// Serializer provides message serialization using multiple codec types
type Serializer struct {
	codecType string
}

// NewSerializer creates a new serializer with the specified codec type.
// Supported types: json, msgpack, cbor, yaml, bson, toml
func NewSerializer(codecType string) (*Serializer, error) {
	switch codecType {
	case "json", "msgpack", "cbor", "yaml", "bson", "toml":
		return &Serializer{
			codecType: codecType,
		}, nil
	default:
		return nil, &SerializerError{
			Operation: "create",
			CodecType: codecType,
			Err:       fmt.Errorf("unsupported codec type: %s", codecType),
		}
	}
}

// Marshal serializes a message to bytes
func (s *Serializer) Marshal(msg any) ([]byte, error) {
	var data []byte
	var err error

	switch s.codecType {
	case "json":
		data, err = json.Marshal(msg)
	case "msgpack":
		data, err = msgpack.Marshal(msg)
	case "cbor":
		data, err = cbor.Marshal(msg)
	case "yaml":
		data, err = yaml.Marshal(msg)
	case "bson":
		data, err = bson.Marshal(msg)
	case "toml":
		buf := new(bytes.Buffer)
		err = toml.NewEncoder(buf).Encode(msg)
		data = buf.Bytes()
	default:
		return nil, &SerializerError{
			Operation: "marshal",
			CodecType: s.codecType,
			Err:       fmt.Errorf("unsupported codec type: %s", s.codecType),
		}
	}

	if err != nil {
		return nil, &SerializerError{
			Operation: "marshal",
			CodecType: s.codecType,
			Err:       err,
		}
	}
	return data, nil
}

// Unmarshal deserializes bytes into a message
func (s *Serializer) Unmarshal(data []byte, msg any) error {
	var err error

	switch s.codecType {
	case "json":
		err = json.Unmarshal(data, msg)
	case "msgpack":
		err = msgpack.Unmarshal(data, msg)
	case "cbor":
		err = cbor.Unmarshal(data, msg)
	case "yaml":
		err = yaml.Unmarshal(data, msg)
	case "bson":
		err = bson.Unmarshal(data, msg)
	case "toml":
		err = toml.Unmarshal(data, msg)
	default:
		return &SerializerError{
			Operation: "unmarshal",
			CodecType: s.codecType,
			Err:       fmt.Errorf("unsupported codec type: %s", s.codecType),
		}
	}

	if err != nil {
		return &SerializerError{
			Operation: "unmarshal",
			CodecType: s.codecType,
			Err:       err,
		}
	}
	return nil
}

// MarshalEnvelope serializes a message into an Envelope with metadata
func (s *Serializer) MarshalEnvelope(sessionID string, msgType MessageType, senderIdx int, msg any, timestamp int64) ([]byte, error) {
	// Marshal the inner message payload
	payload, err := s.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// Create envelope
	envelope := &Envelope{
		SessionID: sessionID,
		Type:      msgType,
		SenderIdx: senderIdx,
		Payload:   payload,
		Timestamp: timestamp,
	}

	// Marshal the envelope
	envelopeData, err := s.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	return envelopeData, nil
}

// UnmarshalEnvelope deserializes an Envelope and extracts the payload
func (s *Serializer) UnmarshalEnvelope(data []byte, envelope *Envelope) error {
	err := s.Unmarshal(data, envelope)
	if err != nil {
		return err
	}
	return nil
}

// UnmarshalPayload deserializes the payload from an envelope into the target message
func (s *Serializer) UnmarshalPayload(envelope *Envelope, msg any) error {
	return s.Unmarshal(envelope.Payload, msg)
}
