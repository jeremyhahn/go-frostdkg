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
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// The HostKey a DKG state carries is BORROWED from the caller, never owned by
// the state. Zeroize drops the reference and must not destroy the key: a host
// key is a long-lived identity key that outlives any one session, and the same
// key drives both steps of a single ceremony. These tests pin that contract;
// restoring the sk.Zeroize() calls the states used to make fails every one.

func TestFROSTDKGEncParticipantStateHK_Zeroize_LeavesBorrowedHostKeyUsable(t *testing.T) {
	cs := testCiphersuite()
	hostKey, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)

	seed := make([]byte, 32)
	_, err = rand.Read(seed)
	require.NoError(t, err)

	state := &FROSTDKGEncParticipantStateHK{
		FROSTDKGParticipantState: &FROSTDKGParticipantState{Seed: sealCopy(seed)},
		HostKey:                  hostKey,
	}

	state.Zeroize()

	require.Nil(t, state.HostKey, "the state must drop its reference to the borrowed key")

	sig, err := hostKey.Sign([]byte("still the caller's key"))
	require.NoError(t, err, "the caller's host key must survive the borrower's teardown")
	require.NotEmpty(t, sig)
}

func TestFROSTDKGFullParticipantStateHK1_Zeroize_LeavesBorrowedHostKeyUsable(t *testing.T) {
	cs := testCiphersuite()
	hostKey, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)

	seed := make([]byte, 32)
	_, err = rand.Read(seed)
	require.NoError(t, err)

	state := &FROSTDKGFullParticipantStateHK1{
		EncState: &FROSTDKGEncParticipantStateHK{
			FROSTDKGParticipantState: &FROSTDKGParticipantState{Seed: sealCopy(seed)},
			HostKey:                  hostKey,
		},
		HostKey: hostKey,
	}

	state.Zeroize()

	require.Nil(t, state.HostKey, "the state must drop its reference to the borrowed key")

	sig, err := hostKey.Sign([]byte("still the caller's key"))
	require.NoError(t, err, "the caller's host key must survive the borrower's teardown")
	require.NotEmpty(t, sig)
}

func TestFROSTDKGFullParticipantStateHK2_Zeroize_LeavesBorrowedHostKeyUsable(t *testing.T) {
	cs := testCiphersuite()
	hostKey, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)

	grp := cs.Group()
	secretShare, err := grp.RandomScalar()
	require.NoError(t, err)

	state := &FROSTDKGFullParticipantStateHK2{
		Output:  &FROSTDKGOutput{SecretShare: secretShare},
		HostKey: hostKey,
	}

	state.Zeroize()

	require.Nil(t, state.HostKey, "the state must drop its reference to the borrowed key")

	sig, err := hostKey.Sign([]byte("still the caller's key"))
	require.NoError(t, err, "the caller's host key must survive the borrower's teardown")
	require.NotEmpty(t, sig)
}

// TestFROSTDKGFullParticipant_Step1ZeroizeThenStep2 is the concrete break the
// borrow rule prevents: step 1 and step 2 share one host key, so releasing the
// step-1 state — the obvious cleanup once step 2 holds the state it needs —
// used to destroy the key step 2 had just been handed.
func TestFROSTDKGFullParticipant_Step1ZeroizeThenStep2(t *testing.T) {
	cs := testCiphersuite()
	hostKey, err := GenerateSoftwareHostKey(cs)
	require.NoError(t, err)

	state1 := &FROSTDKGFullParticipantStateHK1{HostKey: hostKey}
	state2 := &FROSTDKGFullParticipantStateHK2{HostKey: state1.HostKey}

	state1.Zeroize()

	sig, err := state2.HostKey.Sign([]byte("certeq input"))
	require.NoError(t, err, "step 2 must still be able to sign after step 1 is released")
	require.NotEmpty(t, sig)
}
