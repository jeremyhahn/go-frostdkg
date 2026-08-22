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
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/stretchr/testify/require"
)

// The coordinator is untrusted. A coordinator message carrying fewer public
// nonces than there are participants must fail the round with a typed error,
// not panic the participant with an index-out-of-range.
func TestFROSTDKGEncParticipantRound2_ShortPubnoncesIsRejected(t *testing.T) {
	cs := ristretto255_sha512.New()
	grp := cs.Group()
	const n, threshold = 3, 2
	scalarLen := grp.ScalarLength()

	state := &FROSTDKGEncParticipantState{
		FROSTDKGParticipantState: &FROSTDKGParticipantState{
			NumParticipants: n,
			Threshold:       threshold,
			Index:           0,
		},
		HostSeckey:  sealCopy(make([]byte, scalarLen)),
		HostPubkeys: make([][]byte, n),
	}

	coordMsg := &FROSTDKGEncCoordinatorMsg{
		FROSTDKGCoordinatorMsg: &FROSTDKGCoordinatorMsg{
			AllCommitments: make([]*VSSCommitment, n),
			AllPOPs:        make([][]byte, n),
		},
		// One short — a faulty or malicious coordinator.
		AllPubnonces: make([][]byte, n-1),
	}

	_, _, err := FROSTDKGEncParticipantRound2(cs, state, coordMsg, make([]byte, n*scalarLen))
	require.Error(t, err)
	var faulty *FaultyCoordinatorError
	require.ErrorAs(t, err, &faulty)
}

func TestFROSTDKGEncParticipantRound2WithHostKey_ShortPubnoncesIsRejected(t *testing.T) {
	cs := ristretto255_sha512.New()
	grp := cs.Group()
	const n, threshold = 3, 2
	scalarLen := grp.ScalarLength()

	hostKey, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)

	state := &FROSTDKGEncParticipantStateHK{
		FROSTDKGParticipantState: &FROSTDKGParticipantState{
			NumParticipants: n,
			Threshold:       threshold,
			Index:           0,
		},
		HostKey:     hostKey,
		HostPubkeys: make([][]byte, n),
	}

	coordMsg := &FROSTDKGEncCoordinatorMsg{
		FROSTDKGCoordinatorMsg: &FROSTDKGCoordinatorMsg{
			AllCommitments: make([]*VSSCommitment, n),
			AllPOPs:        make([][]byte, n),
		},
		AllPubnonces: make([][]byte, n-1),
	}

	_, _, err = FROSTDKGEncParticipantRound2WithHostKey(cs, state, coordMsg, make([]byte, n*scalarLen))
	require.Error(t, err)
	var faulty *FaultyCoordinatorError
	require.ErrorAs(t, err, &faulty)
}
