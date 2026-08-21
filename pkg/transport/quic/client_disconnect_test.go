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

package quic

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/stretchr/testify/require"
)

// TestDisconnect_DoesNotHoldTheLockWhileWaiting pins the invariant whose
// absence deadlocked CI run 4495: Disconnect waits on the receive goroutine,
// and that goroutine takes connMu.RLock on every iteration, so Disconnect
// must not be holding connMu while it waits.
//
// The test asserts the invariant directly rather than trying to reproduce the
// race. Reproducing it needs the receive goroutine to reach its RLock in the
// window where Disconnect holds the write lock, which is a scheduling
// coincidence and not something a test should be built on. Blocking the
// waited-for goroutine on a channel the test controls puts Disconnect in
// exactly the state that matters — parked in wg.Wait — and then asks the one
// question that decides whether a real receive loop could make progress: is
// the lock free?
//
// It cannot hang either way: the goroutine is always released.
func TestDisconnect_DoesNotHoldTheLockWhileWaiting(t *testing.T) {
	c := &QUICClient{
		incomingChan: make(chan *transport.Envelope, 1),
		errorChan:    make(chan error, 1),
		shutdownChan: make(chan struct{}),
	}
	c.connected.Store(true)

	release := make(chan struct{})
	releaseOnce := func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}
	t.Cleanup(releaseOnce)

	// Stand in for receiveMessages: registered with the WaitGroup, and not
	// finishing until the test says so.
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		<-release
	}()

	disconnected := make(chan error, 1)
	go func() { disconnected <- c.Disconnect() }()

	// Wait until Disconnect is demonstrably inside its locked section: it
	// clears connected while holding the write lock. Polling before that would
	// find the lock free for the trivial reason that Disconnect had not
	// reached it yet, and pass against the deadlock it exists to catch.
	require.Eventually(t, func() bool {
		return !c.connected.Load()
	}, 2*time.Second, time.Millisecond, "Disconnect never started")

	// Disconnect cannot return until the goroutine above does, so it is now on
	// its way to wg.Wait or already parked there. Either way the lock has to
	// become free — a real receive loop is blocked on RLock until it does.
	require.Eventually(t, func() bool {
		if !c.connMu.TryLock() {
			return false
		}
		c.connMu.Unlock()
		return true
	}, 2*time.Second, 5*time.Millisecond,
		"Disconnect held connMu while waiting; the receive goroutine it waits for cannot take RLock, so neither ever finishes")

	releaseOnce()

	select {
	case err := <-disconnected:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Disconnect did not return after its goroutine finished")
	}
}

// TestDisconnect_WhenNotConnected is the error path, and proves Disconnect
// releases the lock on the way out of it.
func TestDisconnect_WhenNotConnected(t *testing.T) {
	c := &QUICClient{shutdownChan: make(chan struct{})}

	require.ErrorIs(t, c.Disconnect(), transport.ErrNotConnected)

	require.True(t, c.connMu.TryLock(), "the lock must be free after the not-connected path")
	c.connMu.Unlock()
}

// TestConnect_RefusedWhileAndAfterTeardown covers the window that releasing
// connMu early would otherwise open: with `connected` already false, a
// concurrent Connect could install a fresh conn and stream, and the Disconnect
// still winding down would close THAT connection instead of the one it was
// tearing down.
//
// Disconnect no longer re-reads c.conn after the wait, so it can only close
// what it took, and Connect refuses outright once a Disconnect has begun — the
// client's shutdownChan is created once and closed there, so a reconnected
// client's receive goroutine would exit immediately anyway (#21).
func TestConnect_RefusedWhileAndAfterTeardown(t *testing.T) {
	c := &QUICClient{
		config:       &transport.Config{Protocol: transport.ProtocolQUIC},
		incomingChan: make(chan *transport.Envelope, 1),
		errorChan:    make(chan error, 1),
		shutdownChan: make(chan struct{}),
	}
	c.connected.Store(true)

	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		<-release
	}()

	disconnected := make(chan error, 1)
	go func() { disconnected <- c.Disconnect() }()

	require.Eventually(t, func() bool {
		return !c.connected.Load()
	}, 2*time.Second, time.Millisecond, "Disconnect never started")

	// Teardown is in flight: Connect must not install anything.
	err := c.Connect(context.Background(), "127.0.0.1:1")
	require.ErrorIs(t, err, transport.ErrSessionClosed)
	require.Nil(t, c.conn, "Connect must not have installed a connection mid-teardown")
	require.Nil(t, c.stream)

	close(release)
	require.NoError(t, <-disconnected)

	// And still refused once teardown has finished.
	require.ErrorIs(t, c.Connect(context.Background(), "127.0.0.1:1"), transport.ErrSessionClosed)
}
