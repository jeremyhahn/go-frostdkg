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
	"testing"
)

func TestMessageType_Constants(t *testing.T) {
	tests := []struct {
		name     string
		msgType  MessageType
		expected uint8
	}{
		{"MsgTypeJoin", MsgTypeJoin, 1},
		{"MsgTypeSessionInfo", MsgTypeSessionInfo, 2},
		{"MsgTypeRound1", MsgTypeRound1, 3},
		{"MsgTypeRound1Agg", MsgTypeRound1Agg, 4},
		{"MsgTypeRound2", MsgTypeRound2, 5},
		{"MsgTypeRound2Agg", MsgTypeRound2Agg, 6},
		{"MsgTypeCertEqSign", MsgTypeCertEqSign, 7},
		{"MsgTypeCertificate", MsgTypeCertificate, 8},
		{"MsgTypeError", MsgTypeError, 9},
		{"MsgTypeComplete", MsgTypeComplete, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint8(tt.msgType) != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, uint8(tt.msgType))
			}
		})
	}
}

func TestEnvelope_Structure(t *testing.T) {
	envelope := Envelope{
		SessionID: "test-session",
		Type:      MsgTypeJoin,
		SenderIdx: 1,
		Payload:   []byte("test payload"),
		Timestamp: 1234567890,
	}

	if envelope.SessionID != "test-session" {
		t.Errorf("expected session_id 'test-session', got %s", envelope.SessionID)
	}
	if envelope.Type != MsgTypeJoin {
		t.Errorf("expected type MsgTypeJoin, got %d", envelope.Type)
	}
	if envelope.SenderIdx != 1 {
		t.Errorf("expected sender_idx 1, got %d", envelope.SenderIdx)
	}
	if string(envelope.Payload) != "test payload" {
		t.Errorf("expected payload 'test payload', got %s", string(envelope.Payload))
	}
	if envelope.Timestamp != 1234567890 {
		t.Errorf("expected timestamp 1234567890, got %d", envelope.Timestamp)
	}
}

func TestJoinMessage_Structure(t *testing.T) {
	msg := JoinMessage{
		HostPubkey: []byte("test-pubkey"),
	}

	if string(msg.HostPubkey) != "test-pubkey" {
		t.Errorf("expected host_pubkey 'test-pubkey', got %s", string(msg.HostPubkey))
	}
}

func TestSessionInfoMessage_Structure(t *testing.T) {
	msg := SessionInfoMessage{
		SessionID:       "session-123",
		Threshold:       2,
		NumParticipants: 3,
		ParticipantIdx:  1,
		HostPubkeys: [][]byte{
			[]byte("pubkey1"),
			[]byte("pubkey2"),
			[]byte("pubkey3"),
		},
		Ciphersuite: "FROST-ED25519-SHA512-v1",
	}

	if msg.SessionID != "session-123" {
		t.Errorf("expected session_id 'session-123', got %s", msg.SessionID)
	}
	if msg.Threshold != 2 {
		t.Errorf("expected threshold 2, got %d", msg.Threshold)
	}
	if msg.NumParticipants != 3 {
		t.Errorf("expected num_participants 3, got %d", msg.NumParticipants)
	}
	if msg.ParticipantIdx != 1 {
		t.Errorf("expected participant_idx 1, got %d", msg.ParticipantIdx)
	}
	if len(msg.HostPubkeys) != 3 {
		t.Errorf("expected 3 host_pubkeys, got %d", len(msg.HostPubkeys))
	}
	if msg.Ciphersuite != "FROST-ED25519-SHA512-v1" {
		t.Errorf("expected ciphersuite 'FROST-ED25519-SHA512-v1', got %s", msg.Ciphersuite)
	}
}

func TestRound1Message_Structure(t *testing.T) {
	msg := Round1Message{
		Commitment: [][]byte{
			[]byte("commitment1"),
			[]byte("commitment2"),
		},
		POP:      []byte("proof-of-possession"),
		Pubnonce: []byte("public-nonce"),
	}

	if len(msg.Commitment) != 2 {
		t.Errorf("expected 2 commitments, got %d", len(msg.Commitment))
	}
	if string(msg.POP) != "proof-of-possession" {
		t.Errorf("expected pop 'proof-of-possession', got %s", string(msg.POP))
	}
	if string(msg.Pubnonce) != "public-nonce" {
		t.Errorf("expected pubnonce 'public-nonce', got %s", string(msg.Pubnonce))
	}
}

func TestRound1AggMessage_Structure(t *testing.T) {
	msg := Round1AggMessage{
		AllCommitments: [][][]byte{
			{[]byte("p1c1"), []byte("p1c2")},
			{[]byte("p2c1"), []byte("p2c2")},
		},
		AllPOPs: [][]byte{
			[]byte("pop1"),
			[]byte("pop2"),
		},
		AllPubnonces: [][]byte{
			[]byte("nonce1"),
			[]byte("nonce2"),
		},
	}

	if len(msg.AllCommitments) != 2 {
		t.Errorf("expected 2 participant commitments, got %d", len(msg.AllCommitments))
	}
	if len(msg.AllPOPs) != 2 {
		t.Errorf("expected 2 POPs, got %d", len(msg.AllPOPs))
	}
	if len(msg.AllPubnonces) != 2 {
		t.Errorf("expected 2 pubnonces, got %d", len(msg.AllPubnonces))
	}
}

func TestRound2Message_Structure(t *testing.T) {
	msg := Round2Message{
		EncryptedShares: []byte("encrypted-share-data"),
	}

	if string(msg.EncryptedShares) != "encrypted-share-data" {
		t.Errorf("expected encrypted_shares 'encrypted-share-data', got %s", string(msg.EncryptedShares))
	}
}

func TestCertEqSignMessage_Structure(t *testing.T) {
	msg := CertEqSignMessage{
		Signature: []byte("signature-data"),
	}

	if string(msg.Signature) != "signature-data" {
		t.Errorf("expected signature 'signature-data', got %s", string(msg.Signature))
	}
}

func TestCertificateMessage_Structure(t *testing.T) {
	msg := CertificateMessage{
		Certificate: []byte("certificate-data"),
	}

	if string(msg.Certificate) != "certificate-data" {
		t.Errorf("expected certificate 'certificate-data', got %s", string(msg.Certificate))
	}
}

func TestErrorMessage_Structure(t *testing.T) {
	msg := ErrorMessage{
		Code:    500,
		Message: "Internal error",
	}

	if msg.Code != 500 {
		t.Errorf("expected code 500, got %d", msg.Code)
	}
	if msg.Message != "Internal error" {
		t.Errorf("expected message 'Internal error', got %s", msg.Message)
	}
}

func TestCompleteMessage_Structure(t *testing.T) {
	msg := CompleteMessage{
		ThresholdPubkey: []byte("threshold-pubkey"),
		PublicShares: [][]byte{
			[]byte("share1"),
			[]byte("share2"),
		},
	}

	if string(msg.ThresholdPubkey) != "threshold-pubkey" {
		t.Errorf("expected threshold_pubkey 'threshold-pubkey', got %s", string(msg.ThresholdPubkey))
	}
	if len(msg.PublicShares) != 2 {
		t.Errorf("expected 2 public_shares, got %d", len(msg.PublicShares))
	}
}

func TestEnvelope_EmptyFields(t *testing.T) {
	envelope := Envelope{}

	if envelope.SessionID != "" {
		t.Errorf("expected empty session_id, got %s", envelope.SessionID)
	}
	if envelope.Type != 0 {
		t.Errorf("expected type 0, got %d", envelope.Type)
	}
	if envelope.SenderIdx != 0 {
		t.Errorf("expected sender_idx 0, got %d", envelope.SenderIdx)
	}
	if envelope.Payload != nil {
		t.Errorf("expected nil payload, got %v", envelope.Payload)
	}
	if envelope.Timestamp != 0 {
		t.Errorf("expected timestamp 0, got %d", envelope.Timestamp)
	}
}

func TestSessionInfoMessage_EmptyHostPubkeys(t *testing.T) {
	msg := SessionInfoMessage{
		SessionID:       "session-123",
		Threshold:       2,
		NumParticipants: 0,
		ParticipantIdx:  0,
		HostPubkeys:     [][]byte{},
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	if len(msg.HostPubkeys) != 0 {
		t.Errorf("expected 0 host_pubkeys, got %d", len(msg.HostPubkeys))
	}
}
