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
	"net"
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/stretchr/testify/require"
)

// connStream adapts a net.Conn to the subset of network.Stream that
// ReadMessage and WriteMessage actually touch (Read and Write). The remaining
// methods are never called by those two functions.
type connStream struct {
	network.Stream
	conn net.Conn
}

func (p *connStream) Read(b []byte) (int, error)  { return p.conn.Read(b) }
func (p *connStream) Write(b []byte) (int, error) { return p.conn.Write(b) }

// tcpPair returns a connected pair over loopback TCP.
//
// The kernel socket buffer is what makes this test meaningful: it lets the
// writer get ahead of the reader so several frames sit in the buffer at once.
// net.Pipe is a synchronous, unbuffered handoff that delivers exactly one
// Write per Read, which hides the defect these tests cover.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	select {
	case server = <-accepted:
	case err := <-acceptErr:
		require.NoError(t, err)
	}
	t.Cleanup(func() { _ = server.Close() })

	return client, server
}

// Callers read in a loop from one long-lived stream. ReadMessage previously
// wrapped the stream in a per-call bufio.Reader, which pulled up to 4096 bytes
// off the socket and discarded everything past the first message when the
// reader went out of scope. Frames written back to back were lost and the
// framing desynchronised.
func TestReadMessage_ConsecutiveMessagesAreNotDropped(t *testing.T) {
	client, server := tcpPair(t)

	want := [][]byte{
		[]byte("MESSAGE-ONE"),
		[]byte("MESSAGE-TWO"),
		[]byte("MESSAGE-THREE"),
	}

	// Write every frame before reading any, so all three are in flight at
	// once. Waiting on the writer is what orders this, not a sleep.
	writeErr := make(chan error, 1)
	go func() {
		w := &connStream{conn: client}
		for _, msg := range want {
			if err := WriteMessage(w, msg); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()
	require.NoError(t, <-writeErr)

	r := &connStream{conn: server}
	for i, expected := range want {
		got, err := ReadMessage(r)
		require.NoErrorf(t, err, "read %d of %d", i+1, len(want))
		require.Equal(t, expected, got)
	}
}

// A zero-length message is a valid frame and must not disturb the ones after it.
func TestReadMessage_EmptyMessageBetweenTwoOthers(t *testing.T) {
	client, server := tcpPair(t)

	writeErr := make(chan error, 1)
	go func() {
		w := &connStream{conn: client}
		for _, msg := range [][]byte{[]byte("first"), {}, []byte("third")} {
			if err := WriteMessage(w, msg); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()
	require.NoError(t, <-writeErr)

	r := &connStream{conn: server}

	got, err := ReadMessage(r)
	require.NoError(t, err)
	require.Equal(t, []byte("first"), got)

	got, err = ReadMessage(r)
	require.NoError(t, err)
	require.Empty(t, got)

	got, err = ReadMessage(r)
	require.NoError(t, err)
	require.Equal(t, []byte("third"), got)
}
