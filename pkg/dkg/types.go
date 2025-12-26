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

package dkg

import (
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// VSSCommitment represents a Verifiable Secret Sharing commitment.
// It is a vector of group elements representing commitments to polynomial coefficients.
type VSSCommitment struct {
	// Coefficients are the commitment coefficients [a_0*G, a_1*G, ..., a_{t-1}*G]
	Coefficients []group.Element
}

// DKGOutput holds the outputs of a DKG session.
// The output is compatible with FROST signing.
type DKGOutput struct {
	// SecretShare is the secret share of the participant (nil for coordinator).
	// This is a scalar value from the group.
	SecretShare group.Scalar

	// ThresholdPubkey is the generated threshold public key representing the group.
	// This is an element from the group.
	ThresholdPubkey group.Element

	// PublicShares contains the public shares of all participants.
	// Each entry is an element from the group.
	PublicShares []group.Element
}

// EncPedPop types for the EncPedPop protocol

// EncPedPopParticipantMsg is the participant message in EncPedPop.
type EncPedPopParticipantMsg struct {
	// SimplPMsg is the SimplPedPop participant message
	SimplPMsg *SimplPedPopParticipantMsg

	// PubNonce is the public encryption nonce (serialized group element)
	PubNonce []byte

	// EncShares are the encrypted shares for each participant
	EncShares []group.Scalar
}

// EncPedPopCoordinatorMsg is the coordinator message in EncPedPop.
type EncPedPopCoordinatorMsg struct {
	// SimplCMsg is the SimplPedPop coordinator message
	SimplCMsg *SimplPedPopCoordinatorMsg

	// PubNonces are the public nonces from all participants
	PubNonces [][]byte
}

// EncPedPopParticipantState is the participant state in EncPedPop.
type EncPedPopParticipantState struct {
	// SimplState is the SimplPedPop participant state
	SimplState *SimplPedPopParticipantState

	// PubNonce is this participant's public encryption nonce
	PubNonce []byte

	// EncKeys are all participants' encryption keys
	EncKeys [][]byte

	// Idx is this participant's index
	Idx int
}

// EncPedPopInvestigationMsg is the investigation message in EncPedPop.
type EncPedPopInvestigationMsg struct {
	// EncPartialSecshares are the encrypted partial secret shares
	EncPartialSecshares []group.Scalar

	// PartialPubshares are the partial public shares for verification
	PartialPubshares []group.Element
}

// ParticipantInvestigationData contains data needed for participant investigation.
type ParticipantInvestigationData struct {
	// SimplInvData is the SimplPedPop investigation data
	SimplInvData *SimplPedPopInvestigationData

	// EncSecshare is the encrypted secret share
	EncSecshare group.Scalar

	// Pads are the encryption pads
	Pads []group.Scalar
}

// SimplPedPop types for the SimplPedPop protocol

// SimplPedPopParticipantMsg is the participant message in SimplPedPop.
type SimplPedPopParticipantMsg struct {
	// Com is the VSS commitment
	Com *VSSCommitment

	// Pop is the proof of possession (64-byte Schnorr signature)
	Pop []byte
}

// SimplPedPopCoordinatorMsg is the coordinator message in SimplPedPop.
type SimplPedPopCoordinatorMsg struct {
	// ComsToSecrets are the commitments to secrets from all participants
	ComsToSecrets []group.Element

	// SumComsToNonconstTerms is the sum of commitments to non-constant polynomial terms
	SumComsToNonconstTerms []group.Element

	// Pops are the proofs of possession from all participants
	Pops [][]byte
}

// SimplPedPopParticipantState is the participant state in SimplPedPop.
type SimplPedPopParticipantState struct {
	// Threshold t
	Threshold int

	// NumParticipants n
	NumParticipants int

	// Idx is this participant's index
	Idx int

	// ComToSecret is the commitment to this participant's secret
	ComToSecret group.Element
}

// SimplPedPopInvestigationData is the investigation data in SimplPedPop.
type SimplPedPopInvestigationData struct {
	// NumParticipants is the number of participants
	NumParticipants int

	// Idx is this participant's index
	Idx int

	// Secshare is the secret share
	Secshare group.Scalar

	// Pubshare is the public share
	Pubshare group.Element
}
