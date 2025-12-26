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
	"errors"
	"testing"
	"time"
)

func TestNewSerializer_ValidCodecs(t *testing.T) {
	codecs := []string{"json", "msgpack", "cbor", "yaml", "bson"}

	for _, codec := range codecs {
		t.Run(codec, func(t *testing.T) {
			s, err := NewSerializer(codec)
			if err != nil {
				t.Fatalf("expected no error for codec %s, got: %v", codec, err)
			}
			if s == nil {
				t.Fatalf("expected serializer, got nil")
			}
			if s.codecType != codec {
				t.Errorf("expected codecType %s, got %s", codec, s.codecType)
			}
		})
	}
}

func TestNewSerializer_InvalidCodec(t *testing.T) {
	s, err := NewSerializer("invalid")
	if err == nil {
		t.Fatal("expected error for invalid codec, got nil")
	}
	if s != nil {
		t.Errorf("expected nil serializer, got %v", s)
	}

	var serErr *SerializerError
	if !errors.As(err, &serErr) {
		t.Errorf("expected SerializerError, got %T", err)
	}
	if serErr.Operation != "create" {
		t.Errorf("expected operation 'create', got %s", serErr.Operation)
	}
	if serErr.CodecType != "invalid" {
		t.Errorf("expected codecType 'invalid', got %s", serErr.CodecType)
	}
}

func TestSerializer_MarshalUnmarshal_JoinMessage(t *testing.T) {
	codecs := []string{"json", "msgpack", "cbor"}

	original := &JoinMessage{
		HostPubkey: []byte("test-pubkey-data"),
	}

	for _, codec := range codecs {
		t.Run(codec, func(t *testing.T) {
			s, err := NewSerializer(codec)
			if err != nil {
				t.Fatalf("failed to create serializer: %v", err)
			}

			// Marshal
			data, err := s.Marshal(original)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("expected non-empty marshaled data")
			}

			// Unmarshal
			var decoded JoinMessage
			err = s.Unmarshal(data, &decoded)
			if err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			// Verify
			if !bytes.Equal(decoded.HostPubkey, original.HostPubkey) {
				t.Errorf("expected HostPubkey %v, got %v", original.HostPubkey, decoded.HostPubkey)
			}
		})
	}
}

func TestSerializer_MarshalUnmarshal_SessionInfoMessage(t *testing.T) {
	codecs := []string{"json", "msgpack", "cbor"}

	original := &SessionInfoMessage{
		SessionID:       "session-abc-123",
		Threshold:       3,
		NumParticipants: 5,
		ParticipantIdx:  2,
		HostPubkeys: [][]byte{
			[]byte("pubkey1"),
			[]byte("pubkey2"),
			[]byte("pubkey3"),
			[]byte("pubkey4"),
			[]byte("pubkey5"),
		},
		Ciphersuite: "FROST-ED25519-SHA512-v1",
	}

	for _, codec := range codecs {
		t.Run(codec, func(t *testing.T) {
			s, err := NewSerializer(codec)
			if err != nil {
				t.Fatalf("failed to create serializer: %v", err)
			}

			data, err := s.Marshal(original)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var decoded SessionInfoMessage
			err = s.Unmarshal(data, &decoded)
			if err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			if decoded.SessionID != original.SessionID {
				t.Errorf("expected SessionID %s, got %s", original.SessionID, decoded.SessionID)
			}
			if decoded.Threshold != original.Threshold {
				t.Errorf("expected Threshold %d, got %d", original.Threshold, decoded.Threshold)
			}
			if decoded.NumParticipants != original.NumParticipants {
				t.Errorf("expected NumParticipants %d, got %d", original.NumParticipants, decoded.NumParticipants)
			}
			if decoded.ParticipantIdx != original.ParticipantIdx {
				t.Errorf("expected ParticipantIdx %d, got %d", original.ParticipantIdx, decoded.ParticipantIdx)
			}
			if len(decoded.HostPubkeys) != len(original.HostPubkeys) {
				t.Errorf("expected %d HostPubkeys, got %d", len(original.HostPubkeys), len(decoded.HostPubkeys))
			}
			if decoded.Ciphersuite != original.Ciphersuite {
				t.Errorf("expected Ciphersuite %s, got %s", original.Ciphersuite, decoded.Ciphersuite)
			}
		})
	}
}

func TestSerializer_MarshalUnmarshal_Round1Message(t *testing.T) {
	codecs := []string{"json", "msgpack", "cbor"}

	original := &Round1Message{
		Commitment: [][]byte{
			[]byte("commitment-point-1"),
			[]byte("commitment-point-2"),
			[]byte("commitment-point-3"),
		},
		POP:      []byte("proof-of-possession-data"),
		Pubnonce: []byte("public-nonce-data"),
	}

	for _, codec := range codecs {
		t.Run(codec, func(t *testing.T) {
			s, err := NewSerializer(codec)
			if err != nil {
				t.Fatalf("failed to create serializer: %v", err)
			}

			data, err := s.Marshal(original)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var decoded Round1Message
			err = s.Unmarshal(data, &decoded)
			if err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			if len(decoded.Commitment) != len(original.Commitment) {
				t.Fatalf("expected %d commitments, got %d", len(original.Commitment), len(decoded.Commitment))
			}
			for i := range original.Commitment {
				if !bytes.Equal(decoded.Commitment[i], original.Commitment[i]) {
					t.Errorf("commitment[%d] mismatch", i)
				}
			}
			if !bytes.Equal(decoded.POP, original.POP) {
				t.Errorf("POP mismatch")
			}
			if !bytes.Equal(decoded.Pubnonce, original.Pubnonce) {
				t.Errorf("Pubnonce mismatch")
			}
		})
	}
}

func TestSerializer_MarshalUnmarshal_Round1AggMessage(t *testing.T) {
	codecs := []string{"json", "msgpack", "cbor"}

	original := &Round1AggMessage{
		AllCommitments: [][][]byte{
			{[]byte("p1c1"), []byte("p1c2")},
			{[]byte("p2c1"), []byte("p2c2")},
			{[]byte("p3c1"), []byte("p3c2")},
		},
		AllPOPs: [][]byte{
			[]byte("pop1"),
			[]byte("pop2"),
			[]byte("pop3"),
		},
		AllPubnonces: [][]byte{
			[]byte("nonce1"),
			[]byte("nonce2"),
			[]byte("nonce3"),
		},
	}

	for _, codec := range codecs {
		t.Run(codec, func(t *testing.T) {
			s, err := NewSerializer(codec)
			if err != nil {
				t.Fatalf("failed to create serializer: %v", err)
			}

			data, err := s.Marshal(original)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var decoded Round1AggMessage
			err = s.Unmarshal(data, &decoded)
			if err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			if len(decoded.AllCommitments) != len(original.AllCommitments) {
				t.Fatalf("expected %d AllCommitments, got %d", len(original.AllCommitments), len(decoded.AllCommitments))
			}
			if len(decoded.AllPOPs) != len(original.AllPOPs) {
				t.Fatalf("expected %d AllPOPs, got %d", len(original.AllPOPs), len(decoded.AllPOPs))
			}
			if len(decoded.AllPubnonces) != len(original.AllPubnonces) {
				t.Fatalf("expected %d AllPubnonces, got %d", len(original.AllPubnonces), len(decoded.AllPubnonces))
			}
		})
	}
}

func TestSerializer_MarshalUnmarshal_ErrorMessage(t *testing.T) {
	codecs := []string{"json", "msgpack", "cbor"}

	original := &ErrorMessage{
		Code:    500,
		Message: "Internal server error during DKG",
	}

	for _, codec := range codecs {
		t.Run(codec, func(t *testing.T) {
			s, err := NewSerializer(codec)
			if err != nil {
				t.Fatalf("failed to create serializer: %v", err)
			}

			data, err := s.Marshal(original)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var decoded ErrorMessage
			err = s.Unmarshal(data, &decoded)
			if err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			if decoded.Code != original.Code {
				t.Errorf("expected Code %d, got %d", original.Code, decoded.Code)
			}
			if decoded.Message != original.Message {
				t.Errorf("expected Message %s, got %s", original.Message, decoded.Message)
			}
		})
	}
}

func TestSerializer_MarshalUnmarshal_CompleteMessage(t *testing.T) {
	codecs := []string{"json", "msgpack", "cbor"}

	original := &CompleteMessage{
		ThresholdPubkey: []byte("threshold-public-key-data"),
		PublicShares: [][]byte{
			[]byte("public-share-1"),
			[]byte("public-share-2"),
			[]byte("public-share-3"),
		},
	}

	for _, codec := range codecs {
		t.Run(codec, func(t *testing.T) {
			s, err := NewSerializer(codec)
			if err != nil {
				t.Fatalf("failed to create serializer: %v", err)
			}

			data, err := s.Marshal(original)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var decoded CompleteMessage
			err = s.Unmarshal(data, &decoded)
			if err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			if !bytes.Equal(decoded.ThresholdPubkey, original.ThresholdPubkey) {
				t.Errorf("ThresholdPubkey mismatch")
			}
			if len(decoded.PublicShares) != len(original.PublicShares) {
				t.Fatalf("expected %d PublicShares, got %d", len(original.PublicShares), len(decoded.PublicShares))
			}
		})
	}
}

func TestSerializer_MarshalEnvelope(t *testing.T) {
	codecs := []string{"json", "msgpack", "cbor"}

	msg := &JoinMessage{
		HostPubkey: []byte("test-pubkey"),
	}

	timestamp := time.Now().Unix()

	for _, codec := range codecs {
		t.Run(codec, func(t *testing.T) {
			s, err := NewSerializer(codec)
			if err != nil {
				t.Fatalf("failed to create serializer: %v", err)
			}

			data, err := s.MarshalEnvelope("session-123", MsgTypeJoin, 1, msg, timestamp)
			if err != nil {
				t.Fatalf("MarshalEnvelope failed: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("expected non-empty envelope data")
			}

			// Unmarshal envelope
			var envelope Envelope
			err = s.UnmarshalEnvelope(data, &envelope)
			if err != nil {
				t.Fatalf("UnmarshalEnvelope failed: %v", err)
			}

			if envelope.SessionID != "session-123" {
				t.Errorf("expected SessionID 'session-123', got %s", envelope.SessionID)
			}
			if envelope.Type != MsgTypeJoin {
				t.Errorf("expected Type MsgTypeJoin, got %d", envelope.Type)
			}
			if envelope.SenderIdx != 1 {
				t.Errorf("expected SenderIdx 1, got %d", envelope.SenderIdx)
			}
			if envelope.Timestamp != timestamp {
				t.Errorf("expected Timestamp %d, got %d", timestamp, envelope.Timestamp)
			}

			// Unmarshal payload
			var decodedMsg JoinMessage
			err = s.UnmarshalPayload(&envelope, &decodedMsg)
			if err != nil {
				t.Fatalf("UnmarshalPayload failed: %v", err)
			}

			if !bytes.Equal(decodedMsg.HostPubkey, msg.HostPubkey) {
				t.Errorf("expected HostPubkey %v, got %v", msg.HostPubkey, decodedMsg.HostPubkey)
			}
		})
	}
}

func TestSerializer_UnmarshalEnvelope_AllMessageTypes(t *testing.T) {
	s, err := NewSerializer("json")
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	timestamp := time.Now().Unix()

	tests := []struct {
		name    string
		msgType MessageType
		msg     any
	}{
		{"JoinMessage", MsgTypeJoin, &JoinMessage{HostPubkey: []byte("pk")}},
		{"SessionInfoMessage", MsgTypeSessionInfo, &SessionInfoMessage{SessionID: "s1", Threshold: 2}},
		{"Round1Message", MsgTypeRound1, &Round1Message{Commitment: [][]byte{[]byte("c1")}}},
		{"Round1AggMessage", MsgTypeRound1Agg, &Round1AggMessage{AllPOPs: [][]byte{[]byte("pop")}}},
		{"Round2Message", MsgTypeRound2, &Round2Message{EncryptedShares: []byte("shares")}},
		{"CertEqSignMessage", MsgTypeCertEqSign, &CertEqSignMessage{Signature: []byte("sig")}},
		{"CertificateMessage", MsgTypeCertificate, &CertificateMessage{Certificate: []byte("cert")}},
		{"ErrorMessage", MsgTypeError, &ErrorMessage{Code: 500, Message: "error"}},
		{"CompleteMessage", MsgTypeComplete, &CompleteMessage{ThresholdPubkey: []byte("tpk")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := s.MarshalEnvelope("test-session", tt.msgType, 0, tt.msg, timestamp)
			if err != nil {
				t.Fatalf("MarshalEnvelope failed: %v", err)
			}

			var envelope Envelope
			err = s.UnmarshalEnvelope(data, &envelope)
			if err != nil {
				t.Fatalf("UnmarshalEnvelope failed: %v", err)
			}

			if envelope.Type != tt.msgType {
				t.Errorf("expected Type %d, got %d", tt.msgType, envelope.Type)
			}
		})
	}
}

func TestSerializer_Marshal_NilMessage(t *testing.T) {
	s, err := NewSerializer("json")
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	data, err := s.Marshal(nil)
	if err != nil {
		t.Fatalf("expected Marshal(nil) to succeed, got error: %v", err)
	}
	if data == nil {
		t.Error("expected non-nil data")
	}
}

func TestSerializer_Unmarshal_InvalidData(t *testing.T) {
	s, err := NewSerializer("json")
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	var msg JoinMessage
	err = s.Unmarshal([]byte("invalid json data"), &msg)
	if err == nil {
		t.Fatal("expected error for invalid data, got nil")
	}

	var serErr *SerializerError
	if !errors.As(err, &serErr) {
		t.Errorf("expected SerializerError, got %T", err)
	}
	if serErr.Operation != "unmarshal" {
		t.Errorf("expected operation 'unmarshal', got %s", serErr.Operation)
	}
}

func TestSerializerError_Error(t *testing.T) {
	err := &SerializerError{
		Operation: "test-op",
		CodecType: "test-codec",
		Err:       errors.New("underlying error"),
	}

	expected := "serializer: test-op failed for codec test-codec: underlying error"
	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestSerializerError_Unwrap(t *testing.T) {
	underlying := errors.New("root cause")
	err := &SerializerError{
		Operation: "test",
		CodecType: "test",
		Err:       underlying,
	}

	unwrapped := err.Unwrap()
	if unwrapped != underlying {
		t.Errorf("expected unwrapped error to be underlying error")
	}
}
