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

// MessageType identifies DKG protocol messages
type MessageType uint8

const (
	MsgTypeJoin        MessageType = 1  // Participant joining session
	MsgTypeSessionInfo MessageType = 2  // Session info from coordinator
	MsgTypeRound1      MessageType = 3  // Round 1 broadcast
	MsgTypeRound1Agg   MessageType = 4  // Aggregated round 1 from coordinator
	MsgTypeRound2      MessageType = 5  // Round 2 shares
	MsgTypeRound2Agg   MessageType = 6  // Aggregated round 2 from coordinator
	MsgTypeCertEqSign  MessageType = 7  // CertEq signature
	MsgTypeCertificate MessageType = 8  // Final certificate
	MsgTypeError       MessageType = 9  // Error message
	MsgTypeComplete    MessageType = 10 // DKG complete
)

// Envelope wraps all messages for transport
type Envelope struct {
	SessionID string      `json:"session_id" msgpack:"session_id" cbor:"1,keyasint" yaml:"session_id" bson:"session_id"`
	Type      MessageType `json:"type" msgpack:"type" cbor:"2,keyasint" yaml:"type" bson:"type"`
	SenderIdx int         `json:"sender_idx" msgpack:"sender_idx" cbor:"3,keyasint" yaml:"sender_idx" bson:"sender_idx"`
	Payload   []byte      `json:"payload" msgpack:"payload" cbor:"4,keyasint" yaml:"payload" bson:"payload"`
	Timestamp int64       `json:"timestamp" msgpack:"timestamp" cbor:"5,keyasint" yaml:"timestamp" bson:"timestamp"`
}

// JoinMessage - participant requests to join
type JoinMessage struct {
	HostPubkey []byte `json:"host_pubkey" msgpack:"host_pubkey" cbor:"1,keyasint" yaml:"host_pubkey" bson:"host_pubkey"`
}

// SessionInfoMessage - coordinator sends session details
type SessionInfoMessage struct {
	SessionID       string   `json:"session_id" msgpack:"session_id" cbor:"1,keyasint" yaml:"session_id" bson:"session_id"`
	Threshold       int      `json:"threshold" msgpack:"threshold" cbor:"2,keyasint" yaml:"threshold" bson:"threshold"`
	NumParticipants int      `json:"num_participants" msgpack:"num_participants" cbor:"3,keyasint" yaml:"num_participants" bson:"num_participants"`
	ParticipantIdx  int      `json:"participant_idx" msgpack:"participant_idx" cbor:"4,keyasint" yaml:"participant_idx" bson:"participant_idx"`
	HostPubkeys     [][]byte `json:"host_pubkeys" msgpack:"host_pubkeys" cbor:"5,keyasint" yaml:"host_pubkeys" bson:"host_pubkeys"`
	Ciphersuite     string   `json:"ciphersuite" msgpack:"ciphersuite" cbor:"6,keyasint" yaml:"ciphersuite" bson:"ciphersuite"`
}

// Round1Message - VSS commitment and POP
type Round1Message struct {
	Commitment [][]byte `json:"commitment" msgpack:"commitment" cbor:"1,keyasint" yaml:"commitment" bson:"commitment"`
	POP        []byte   `json:"pop" msgpack:"pop" cbor:"2,keyasint" yaml:"pop" bson:"pop"`
	Pubnonce   []byte   `json:"pubnonce" msgpack:"pubnonce" cbor:"3,keyasint" yaml:"pubnonce" bson:"pubnonce"`
}

// Round1AggMessage - aggregated round 1 data from coordinator
type Round1AggMessage struct {
	AllCommitments [][][]byte `json:"all_commitments" msgpack:"all_commitments" cbor:"1,keyasint" yaml:"all_commitments" bson:"all_commitments"`
	AllPOPs        [][]byte   `json:"all_pops" msgpack:"all_pops" cbor:"2,keyasint" yaml:"all_pops" bson:"all_pops"`
	AllPubnonces   [][]byte   `json:"all_pubnonces" msgpack:"all_pubnonces" cbor:"3,keyasint" yaml:"all_pubnonces" bson:"all_pubnonces"`
}

// Round2Message - encrypted shares for a specific participant
type Round2Message struct {
	EncryptedShares []byte `json:"encrypted_shares" msgpack:"encrypted_shares" cbor:"1,keyasint" yaml:"encrypted_shares" bson:"encrypted_shares"`
}

// CertEqSignMessage - participant's CertEq signature
type CertEqSignMessage struct {
	Signature []byte `json:"signature" msgpack:"signature" cbor:"1,keyasint" yaml:"signature" bson:"signature"`
}

// CertificateMessage - final certificate from coordinator
type CertificateMessage struct {
	Certificate []byte `json:"certificate" msgpack:"certificate" cbor:"1,keyasint" yaml:"certificate" bson:"certificate"`
}

// ErrorMessage - error details
type ErrorMessage struct {
	Code    int    `json:"code" msgpack:"code" cbor:"1,keyasint" yaml:"code" bson:"code"`
	Message string `json:"message" msgpack:"message" cbor:"2,keyasint" yaml:"message" bson:"message"`
}

// CompleteMessage - DKG completion acknowledgment
type CompleteMessage struct {
	ThresholdPubkey []byte   `json:"threshold_pubkey" msgpack:"threshold_pubkey" cbor:"1,keyasint" yaml:"threshold_pubkey" bson:"threshold_pubkey"`
	PublicShares    [][]byte `json:"public_shares" msgpack:"public_shares" cbor:"2,keyasint" yaml:"public_shares" bson:"public_shares"`
}
