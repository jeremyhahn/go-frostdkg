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

package libp2p

import (
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

// recordingStream is a network.Stream that only records what is written to it.
// The embedded interface is nil: any method these tests do not exercise panics
// rather than quietly returning a zero value, which is the behaviour worth
// having in a fake.
type recordingStream struct {
	network.Stream

	mu     sync.Mutex
	writes int
}

func (s *recordingStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	return len(p), nil
}

func (s *recordingStream) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func TestAuthorizeSender_AcceptsTheBoundIndex(t *testing.T) {
	conn := &participantConn{peerID: testPeerID(t, "peer-1"), index: 1}
	envelope := &transport.Envelope{SenderIdx: 1, Type: transport.MsgTypeRound1}

	require.NoError(t, authorizeSender(conn, envelope))
}

func TestAuthorizeSender_RejectsAClaimedIndex(t *testing.T) {
	peerID := testPeerID(t, "peer-1")
	conn := &participantConn{peerID: peerID, index: 1}
	envelope := &transport.Envelope{SenderIdx: 0, Type: transport.MsgTypeRound1}

	err := authorizeSender(conn, envelope)

	require.ErrorIs(t, err, transport.ErrSenderIdentityMismatch)

	var identityErr *transport.SenderIdentityError
	require.ErrorAs(t, err, &identityErr)
	require.Equal(t, peerID.String(), identityErr.PeerID)
	require.Equal(t, 1, identityErr.BoundIndex)
	require.Equal(t, 0, identityErr.ClaimedIndex)
}

// TestAuthorizeSender_RejectsTheCoordinatorIndex covers the specific forgery
// worth naming: -1 is the index the coordinator itself sends under, so a
// participant claiming it would have its message relayed as coordinator
// traffic and skipped for no one.
func TestAuthorizeSender_RejectsTheCoordinatorIndex(t *testing.T) {
	conn := &participantConn{peerID: testPeerID(t, "peer-2"), index: 2}
	envelope := &transport.Envelope{SenderIdx: -1, Type: transport.MsgTypeRound1Agg}

	require.ErrorIs(t, authorizeSender(conn, envelope), transport.ErrSenderIdentityMismatch)
}

// newTestCoordinator builds a coordinator with no libp2p host. Only the
// participant tables, the serializer and the relay path are exercised here;
// nothing in these tests touches the network.
func newTestCoordinator(t *testing.T, numParticipants int) *P2PCoordinator {
	t.Helper()
	serializer, err := transport.NewSerializer("json")
	require.NoError(t, err)
	return &P2PCoordinator{
		sessionID:       "test-session",
		config:          &transport.SessionConfig{Threshold: 2, NumParticipants: numParticipants},
		serializer:      serializer,
		participants:    make(map[peer.ID]*participantConn),
		assignedIndexes: make(map[peer.ID]int),
	}
}

// join seats a peer the way handleStream does, and returns its connection.
func join(t *testing.T, pc *P2PCoordinator, name string) (*participantConn, *recordingStream) {
	t.Helper()
	peerID := testPeerID(t, name)
	index, err := pc.assignIndexLocked(peerID)
	require.NoError(t, err)
	stream := &recordingStream{}
	conn := &participantConn{peerID: peerID, index: index, stream: stream}
	pc.participants[peerID] = conn
	return conn, stream
}

// TestBroadcastMessage_RefusesAForgedSenderIndex is the end of the attack: a
// participant bound to index 1 sends an envelope declaring index 0. Nothing
// may be relayed, and the recording streams prove it rather than the test
// taking it on trust.
func TestBroadcastMessage_RefusesAForgedSenderIndex(t *testing.T) {
	pc := newTestCoordinator(t, 3)

	_, victimStream := join(t, pc, "victim")
	forger, forgerStream := join(t, pc, "forger")
	_, bystanderStream := join(t, pc, "bystander")

	err := pc.broadcastMessage(&incomingMessage{
		conn: forger,
		envelope: &transport.Envelope{
			SessionID: pc.sessionID,
			Type:      transport.MsgTypeRound1,
			SenderIdx: 0,
		},
	})

	require.ErrorIs(t, err, transport.ErrSenderIdentityMismatch)
	require.Zero(t, victimStream.count(), "the impersonated participant must receive nothing")
	require.Zero(t, bystanderStream.count(), "no participant may receive a forged message")
	require.Zero(t, forgerStream.count())

	var identityErr *transport.SenderIdentityError
	require.ErrorAs(t, err, &identityErr)
	require.Equal(t, 1, identityErr.BoundIndex)
	require.Equal(t, 0, identityErr.ClaimedIndex)
}

func TestBroadcastMessage_RelaysAMatchingIndexToEveryoneElse(t *testing.T) {
	pc := newTestCoordinator(t, 3)

	sender, senderStream := join(t, pc, "sender")
	_, peerStream := join(t, pc, "peer")
	_, otherStream := join(t, pc, "other")

	err := pc.broadcastMessage(&incomingMessage{
		conn:     sender,
		envelope: &transport.Envelope{Type: transport.MsgTypeRound1, SenderIdx: sender.index},
	})

	require.NoError(t, err)
	require.Zero(t, senderStream.count(), "the sender must not receive its own message")
	// Two writes per recipient: the length prefix and the payload.
	require.Equal(t, 2, peerStream.count())
	require.Equal(t, 2, otherStream.count())
}

// TestBroadcastMessage_RelaysAfterTheSenderDisconnects covers the race the
// authenticated binding travels with the message to avoid: the reader
// goroutine drops its participant from the live map as soon as the stream
// ends, so a sender that disconnects right after its final message would
// otherwise have that message discarded at fan-out.
func TestBroadcastMessage_RelaysAfterTheSenderDisconnects(t *testing.T) {
	pc := newTestCoordinator(t, 2)

	sender, _ := join(t, pc, "sender")
	_, peerStream := join(t, pc, "peer")

	msg := &incomingMessage{
		conn:     sender,
		envelope: &transport.Envelope{Type: transport.MsgTypeRound1, SenderIdx: sender.index},
	}

	// The sender disconnects between ingress and fan-out.
	delete(pc.participants, sender.peerID)

	require.NoError(t, pc.broadcastMessage(msg))
	require.Equal(t, 2, peerStream.count(), "the already-authenticated message must still be relayed")
}

// TestBroadcastMessage_RefusesAMessageWithNoBinding fails closed on a message
// that carries no authenticated connection at all.
func TestBroadcastMessage_RefusesAMessageWithNoBinding(t *testing.T) {
	pc := newTestCoordinator(t, 2)
	_, peerStream := join(t, pc, "peer")

	err := pc.broadcastMessage(&incomingMessage{
		envelope: &transport.Envelope{Type: transport.MsgTypeRound1, SenderIdx: 0},
	})

	require.ErrorIs(t, err, transport.ErrSenderIdentityMismatch)
	require.Zero(t, peerStream.count())

	require.ErrorIs(t, pc.broadcastMessage(nil), transport.ErrSenderIdentityMismatch)
}

// TestAssignIndex_NeverReusesAnIndexAfterADisconnect is the collision the
// index assignment must not have: deriving the index from the number of LIVE
// participants hands a newcomer an index somebody else already holds as soon
// as a middle participant leaves, and both then authorize as that index.
func TestAssignIndex_NeverReusesAnIndexAfterADisconnect(t *testing.T) {
	pc := newTestCoordinator(t, 3)

	first, _ := join(t, pc, "first")
	second, _ := join(t, pc, "second")
	third, _ := join(t, pc, "third")
	require.Equal(t, []int{0, 1, 2}, []int{first.index, second.index, third.index})

	// The middle participant disconnects; the reader goroutine removes it from
	// the live map but not from the session.
	delete(pc.participants, second.peerID)

	newcomer := testPeerID(t, "newcomer")
	_, err := pc.assignIndexLocked(newcomer)
	require.ErrorIs(t, err, transport.ErrSessionFull,
		"a fourth identity may not be seated in a 3-participant session")
	require.NotContains(t, pc.assignedIndexes, newcomer)
}

// TestAssignIndex_ReturnsTheSameIndexOnReconnect keeps the permanence rule
// from breaking reconnection: the peer that left gets its own index back.
func TestAssignIndex_ReturnsTheSameIndexOnReconnect(t *testing.T) {
	pc := newTestCoordinator(t, 3)

	_, _ = join(t, pc, "first")
	second, _ := join(t, pc, "second")
	require.Equal(t, 1, second.index)

	delete(pc.participants, second.peerID)

	index, err := pc.assignIndexLocked(second.peerID)
	require.NoError(t, err)
	require.Equal(t, 1, index)
}

func TestSenderIdentityError_UnwrapsToTheSentinel(t *testing.T) {
	err := transport.NewSenderIdentityError("12D3KooWTest", 2, 5)

	require.True(t, errors.Is(err, transport.ErrSenderIdentityMismatch))
	require.Contains(t, err.Error(), "bound=2")
	require.Contains(t, err.Error(), "claimed=5")
	require.Contains(t, err.Error(), "12D3KooWTest")
}
