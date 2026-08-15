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
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/stretchr/testify/require"
)

// guardTestServer returns a started two-participant server with both
// participants already joined, plus a context and a cleanup registration.
func guardTestServer(t *testing.T) (*MCPServer, context.Context) {
	t.Helper()

	config := &transport.SessionConfig{
		Threshold:       2,
		NumParticipants: 2,
		Ciphersuite:     "FROST-ED25519-SHA512-v1",
	}

	server, err := NewMCPServer("test-session", config, TransportStdio, "")
	require.NoError(t, err)

	ctx := context.Background()
	server.SetStdio(bytes.NewReader([]byte{}), &bytes.Buffer{})
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() { _ = server.Stop(ctx) })

	pubkey := make([]byte, transport.PublicKeySize)
	pubkey[0] = 0x02
	for i := 0; i < config.NumParticipants; i++ {
		joinParams := JoinSessionParams{
			SessionID:  "test-session",
			HostPubkey: hex.EncodeToString(pubkey),
		}
		paramsJSON, err := MarshalParams(joinParams)
		require.NoError(t, err)
		_, err = server.handleJoinSession(ctx, paramsJSON)
		require.NoError(t, err)
	}

	return server, ctx
}

// participant_idx arrives from the wire and is used to key the round maps,
// which are then walked to fill aggregation slices sized at NumParticipants.
// An index that was never registered used to be accepted, and the aggregation
// pass panicked with an index-out-of-range that killed the stdio process and
// corrupted the session under HTTP. Submissions must be refused before that.
func TestMCPServer_SubmitRound1_RejectsUnjoinedParticipantIndex(t *testing.T) {
	for _, idx := range []int{-1, 2, 7, 1 << 20} {
		server, ctx := guardTestServer(t)

		params := SubmitRound1Params{
			SessionID:      "test-session",
			ParticipantIdx: idx,
			Commitment:     []string{hex.EncodeToString(make([]byte, 33))},
			POP:            hex.EncodeToString(make([]byte, 64)),
			Pubnonce:       hex.EncodeToString(make([]byte, 66)),
		}
		paramsJSON, err := MarshalParams(params)
		require.NoError(t, err)

		_, err = server.handleSubmitRound1(ctx, paramsJSON)
		require.Errorf(t, err, "participant_idx %d must be rejected", idx)
	}
}

// The same guard must hold for the later rounds, which index the same slices.
func TestMCPServer_SubmitRound2_RejectsUnjoinedParticipantIndex(t *testing.T) {
	server, ctx := guardTestServer(t)

	params := SubmitRound2Params{
		SessionID:       "test-session",
		ParticipantIdx:  9,
		EncryptedShares: hex.EncodeToString(make([]byte, 64)),
	}
	paramsJSON, err := MarshalParams(params)
	require.NoError(t, err)

	_, err = server.handleSubmitRound2(ctx, paramsJSON)
	require.Error(t, err)
}

func TestMCPServer_SubmitCertEq_RejectsUnjoinedParticipantIndex(t *testing.T) {
	server, ctx := guardTestServer(t)

	params := SubmitCertEqParams{
		SessionID:      "test-session",
		ParticipantIdx: 9,
		Signature:      hex.EncodeToString(make([]byte, 64)),
	}
	paramsJSON, err := MarshalParams(params)
	require.NoError(t, err)

	_, err = server.handleSubmitCertEq(ctx, paramsJSON)
	require.Error(t, err)
}

// A registered index must still be accepted — the guard must not reject the
// legitimate path it was added to protect.
func TestMCPServer_SubmitRound1_AcceptsJoinedParticipantIndex(t *testing.T) {
	server, ctx := guardTestServer(t)

	params := SubmitRound1Params{
		SessionID:      "test-session",
		ParticipantIdx: 0,
		Commitment:     []string{hex.EncodeToString(make([]byte, 33))},
		POP:            hex.EncodeToString(make([]byte, 64)),
		Pubnonce:       hex.EncodeToString(make([]byte, 66)),
	}
	paramsJSON, err := MarshalParams(params)
	require.NoError(t, err)

	_, err = server.handleSubmitRound1(ctx, paramsJSON)
	require.NoError(t, err)
}

// Stop is reachable from more than one goroutine and previously closed
// stopChan after a plain Load check, so a concurrent pair panicked with
// "close of closed channel". Exactly one caller may succeed.
func TestMCPServer_Stop_ConcurrentCallsDoNotPanic(t *testing.T) {
	server, ctx := guardTestServer(t)

	const callers = 8
	errs := make(chan error, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		go func() {
			<-start
			errs <- server.Stop(ctx)
		}()
	}
	close(start)

	succeeded := 0
	for i := 0; i < callers; i++ {
		if err := <-errs; err == nil {
			succeeded++
		}
	}
	require.Equal(t, 1, succeeded, "exactly one Stop call should succeed")
}
