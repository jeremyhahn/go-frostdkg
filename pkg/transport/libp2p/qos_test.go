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
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/libp2p/go-libp2p/core/peer"
)

// Helper function to create a test peer ID.
func testPeerID(t *testing.T, id string) peer.ID {
	t.Helper()
	// Create a deterministic peer ID for testing
	return peer.ID(id)
}

func TestNewQoSManager(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		if qm == nil {
			t.Fatal("expected non-nil QoSManager")
		}
		if qm.config == nil {
			t.Fatal("expected non-nil config")
		}
	})

	t.Run("custom config", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn:       1024 * 1024,
			MaxBandwidthOut:      512 * 1024,
			MaxPeerBandwidth:     128 * 1024,
			BurstSize:            32 * 1024,
			EnablePrioritization: true,
			QueueSize:            500,
			BackpressureTimeout:  10 * time.Second,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		if qm.config.MaxBandwidthIn != config.MaxBandwidthIn {
			t.Errorf("expected MaxBandwidthIn %d, got %d", config.MaxBandwidthIn, qm.config.MaxBandwidthIn)
		}
		if qm.config.MaxBandwidthOut != config.MaxBandwidthOut {
			t.Errorf("expected MaxBandwidthOut %d, got %d", config.MaxBandwidthOut, qm.config.MaxBandwidthOut)
		}
	})

	t.Run("invalid config negative bandwidth", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn: -1,
		}

		_, err := NewQoSManager(config)
		if !errors.Is(err, ErrInvalidQoSConfig) {
			t.Errorf("expected ErrInvalidQoSConfig, got %v", err)
		}
	})

	t.Run("invalid config negative burst size", func(t *testing.T) {
		config := &QoSConfig{
			BurstSize: -1,
		}

		_, err := NewQoSManager(config)
		if !errors.Is(err, ErrInvalidQoSConfig) {
			t.Errorf("expected ErrInvalidQoSConfig, got %v", err)
		}
	})

	t.Run("invalid config negative queue size", func(t *testing.T) {
		config := &QoSConfig{
			QueueSize: -1,
		}

		_, err := NewQoSManager(config)
		if !errors.Is(err, ErrInvalidQoSConfig) {
			t.Errorf("expected ErrInvalidQoSConfig, got %v", err)
		}
	})
}

func TestQoSConfig_Validate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := DefaultQoSConfig()
		if err := config.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("negative MaxBandwidthIn", func(t *testing.T) {
		config := &QoSConfig{MaxBandwidthIn: -100}
		if err := config.Validate(); !errors.Is(err, ErrInvalidQoSConfig) {
			t.Errorf("expected ErrInvalidQoSConfig, got %v", err)
		}
	})

	t.Run("negative MaxBandwidthOut", func(t *testing.T) {
		config := &QoSConfig{MaxBandwidthOut: -100}
		if err := config.Validate(); !errors.Is(err, ErrInvalidQoSConfig) {
			t.Errorf("expected ErrInvalidQoSConfig, got %v", err)
		}
	})

	t.Run("negative MaxPeerBandwidth", func(t *testing.T) {
		config := &QoSConfig{MaxPeerBandwidth: -100}
		if err := config.Validate(); !errors.Is(err, ErrInvalidQoSConfig) {
			t.Errorf("expected ErrInvalidQoSConfig, got %v", err)
		}
	})
}

func TestDefaultQoSConfig(t *testing.T) {
	config := DefaultQoSConfig()

	if config.MaxBandwidthIn != 0 {
		t.Errorf("expected MaxBandwidthIn 0, got %d", config.MaxBandwidthIn)
	}
	if config.MaxBandwidthOut != 0 {
		t.Errorf("expected MaxBandwidthOut 0, got %d", config.MaxBandwidthOut)
	}
	if config.MaxPeerBandwidth != 0 {
		t.Errorf("expected MaxPeerBandwidth 0, got %d", config.MaxPeerBandwidth)
	}
	if config.BurstSize != 64*1024 {
		t.Errorf("expected BurstSize %d, got %d", 64*1024, config.BurstSize)
	}
	if !config.EnablePrioritization {
		t.Error("expected EnablePrioritization to be true")
	}
	if config.QueueSize != 1000 {
		t.Errorf("expected QueueSize 1000, got %d", config.QueueSize)
	}
	if config.BackpressureTimeout != 5*time.Second {
		t.Errorf("expected BackpressureTimeout 5s, got %v", config.BackpressureTimeout)
	}
}

func TestQoSManager_AllowIncoming(t *testing.T) {
	t.Run("unlimited bandwidth", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// Should always allow when unlimited
		for i := 0; i < 100; i++ {
			if err := qm.AllowIncoming(ctx, peerID, 1024); err != nil {
				t.Errorf("iteration %d: unexpected error: %v", i, err)
			}
		}
	})

	t.Run("rate limited exceeds", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn: 1000, // 1000 bytes/second
			BurstSize:      100,  // Small burst to trigger limit quickly
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// First request should succeed (uses burst)
		if err := qm.AllowIncoming(ctx, peerID, 50); err != nil {
			t.Fatalf("first request failed: %v", err)
		}

		// Second small request should succeed
		if err := qm.AllowIncoming(ctx, peerID, 50); err != nil {
			t.Fatalf("second request failed: %v", err)
		}

		// Large request exceeding remaining burst should fail
		err = qm.AllowIncoming(ctx, peerID, 200)
		if !errors.Is(err, ErrBandwidthExceeded) {
			t.Errorf("expected ErrBandwidthExceeded, got %v", err)
		}
	})

	t.Run("per-peer rate limited", func(t *testing.T) {
		config := &QoSConfig{
			MaxPeerBandwidth: 500, // 500 bytes/second per peer
			BurstSize:        100, // Small burst
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peer1 := testPeerID(t, "peer1")
		peer2 := testPeerID(t, "peer2")

		// peer1 uses up burst
		if err := qm.AllowIncoming(ctx, peer1, 100); err != nil {
			t.Fatalf("peer1 first request failed: %v", err)
		}

		// peer1 exceeds limit
		err = qm.AllowIncoming(ctx, peer1, 100)
		if !errors.Is(err, ErrPeerBandwidthExceeded) {
			t.Errorf("expected ErrPeerBandwidthExceeded, got %v", err)
		}

		// peer2 should still work (separate limit)
		if err := qm.AllowIncoming(ctx, peer2, 100); err != nil {
			t.Fatalf("peer2 request failed: %v", err)
		}
	})

	t.Run("closed manager", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := qm.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		err = qm.AllowIncoming(ctx, peerID, 100)
		if !errors.Is(err, ErrQoSManagerClosed) {
			t.Errorf("expected ErrQoSManagerClosed, got %v", err)
		}
	})
}

func TestQoSManager_AllowOutgoing(t *testing.T) {
	t.Run("unlimited bandwidth", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		for i := 0; i < 100; i++ {
			if err := qm.AllowOutgoing(ctx, peerID, 1024); err != nil {
				t.Errorf("iteration %d: unexpected error: %v", i, err)
			}
		}
	})

	t.Run("rate limited exceeds", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthOut: 1000,
			BurstSize:       100,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// Use up burst
		if err := qm.AllowOutgoing(ctx, peerID, 100); err != nil {
			t.Fatalf("first request failed: %v", err)
		}

		// Exceed limit
		err = qm.AllowOutgoing(ctx, peerID, 100)
		if !errors.Is(err, ErrBandwidthExceeded) {
			t.Errorf("expected ErrBandwidthExceeded, got %v", err)
		}
	})

	t.Run("closed manager", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := qm.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		err = qm.AllowOutgoing(ctx, peerID, 100)
		if !errors.Is(err, ErrQoSManagerClosed) {
			t.Errorf("expected ErrQoSManagerClosed, got %v", err)
		}
	})
}

func TestQoSManager_WaitIncoming(t *testing.T) {
	t.Run("immediate allow", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn: 10000,
			BurstSize:      1000,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		start := time.Now()
		if err := qm.WaitIncoming(ctx, peerID, 100); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		elapsed := time.Since(start)

		// Should complete almost immediately
		if elapsed > 100*time.Millisecond {
			t.Errorf("expected immediate completion, took %v", elapsed)
		}
	})

	t.Run("backpressure timeout", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn:      100, // Very low limit
			BurstSize:           10,  // Tiny burst
			BackpressureTimeout: 100 * time.Millisecond,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// Use up burst
		if err := qm.AllowIncoming(ctx, peerID, 10); err != nil {
			t.Fatalf("first request failed: %v", err)
		}

		// Request more than available should timeout
		err = qm.WaitIncoming(ctx, peerID, 1000)
		if !errors.Is(err, ErrBackpressureTimeout) {
			t.Errorf("expected ErrBackpressureTimeout, got %v", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn:      1, // Very low limit
			BurstSize:           1,
			BackpressureTimeout: 10 * time.Second,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		peerID := testPeerID(t, "peer1")

		// Use up burst
		if err := qm.AllowIncoming(ctx, peerID, 1); err != nil {
			t.Fatalf("first request failed: %v", err)
		}

		// Should timeout with context
		err = qm.WaitIncoming(ctx, peerID, 1000)
		if !errors.Is(err, ErrBackpressureTimeout) && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("expected timeout error, got %v", err)
		}
	})

	t.Run("closed manager", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := qm.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		err = qm.WaitIncoming(ctx, peerID, 100)
		if !errors.Is(err, ErrQoSManagerClosed) {
			t.Errorf("expected ErrQoSManagerClosed, got %v", err)
		}
	})
}

func TestQoSManager_WaitOutgoing(t *testing.T) {
	t.Run("immediate allow", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthOut: 10000,
			BurstSize:       1000,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		start := time.Now()
		if err := qm.WaitOutgoing(ctx, peerID, 100); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		elapsed := time.Since(start)

		if elapsed > 100*time.Millisecond {
			t.Errorf("expected immediate completion, took %v", elapsed)
		}
	})

	t.Run("backpressure timeout", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthOut:     100,
			BurstSize:           10,
			BackpressureTimeout: 100 * time.Millisecond,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// Use up burst
		if err := qm.AllowOutgoing(ctx, peerID, 10); err != nil {
			t.Fatalf("first request failed: %v", err)
		}

		err = qm.WaitOutgoing(ctx, peerID, 1000)
		if !errors.Is(err, ErrBackpressureTimeout) {
			t.Errorf("expected ErrBackpressureTimeout, got %v", err)
		}
	})

	t.Run("closed manager", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := qm.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		err = qm.WaitOutgoing(ctx, peerID, 100)
		if !errors.Is(err, ErrQoSManagerClosed) {
			t.Errorf("expected ErrQoSManagerClosed, got %v", err)
		}
	})
}

func TestQoSManager_BurstHandling(t *testing.T) {
	t.Run("burst allows temporary spike", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn: 100, // 100 bytes/second
			BurstSize:      500, // Allow 500 byte burst
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// Should be able to send burst amount immediately
		if err := qm.AllowIncoming(ctx, peerID, 500); err != nil {
			t.Fatalf("burst request failed: %v", err)
		}

		// Next request should fail (burst exhausted)
		err = qm.AllowIncoming(ctx, peerID, 100)
		if !errors.Is(err, ErrBandwidthExceeded) {
			t.Errorf("expected ErrBandwidthExceeded after burst, got %v", err)
		}
	})

	t.Run("burst replenishes over time", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn: 1000, // 1000 bytes/second
			BurstSize:      100,  // 100 byte burst
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// Use up burst
		if err := qm.AllowIncoming(ctx, peerID, 100); err != nil {
			t.Fatalf("first request failed: %v", err)
		}

		// Should fail immediately
		err = qm.AllowIncoming(ctx, peerID, 50)
		if !errors.Is(err, ErrBandwidthExceeded) {
			t.Errorf("expected ErrBandwidthExceeded, got %v", err)
		}

		// Wait for tokens to replenish (100ms should give us ~100 tokens at 1000/s)
		time.Sleep(150 * time.Millisecond)

		// Now should succeed
		if err := qm.AllowIncoming(ctx, peerID, 50); err != nil {
			t.Errorf("request after replenish failed: %v", err)
		}
	})
}

func TestQoSManager_PriorityQueue(t *testing.T) {
	t.Run("enqueue and dequeue", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		peerID := testPeerID(t, "peer1")

		// Enqueue messages
		if err := qm.EnqueueMessage([]byte("msg1"), peerID, transport.MsgTypeJoin); err != nil {
			t.Fatalf("enqueue failed: %v", err)
		}

		if qm.QueueLength() != 1 {
			t.Errorf("expected queue length 1, got %d", qm.QueueLength())
		}

		// Dequeue
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		msg, err := qm.DequeueMessage(ctx)
		if err != nil {
			t.Fatalf("dequeue failed: %v", err)
		}

		if string(msg.Data) != "msg1" {
			t.Errorf("expected 'msg1', got '%s'", string(msg.Data))
		}

		if qm.QueueLength() != 0 {
			t.Errorf("expected queue length 0, got %d", qm.QueueLength())
		}
	})

	t.Run("priority ordering", func(t *testing.T) {
		config := &QoSConfig{
			EnablePrioritization: true,
			QueueSize:            100,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		peerID := testPeerID(t, "peer1")

		// Enqueue in order: low, normal, high, critical
		if err := qm.EnqueueMessage([]byte("low"), peerID, transport.MessageType(99)); err != nil {
			t.Fatalf("enqueue low failed: %v", err)
		}
		if err := qm.EnqueueMessage([]byte("normal"), peerID, transport.MsgTypeJoin); err != nil {
			t.Fatalf("enqueue normal failed: %v", err)
		}
		if err := qm.EnqueueMessage([]byte("high"), peerID, transport.MsgTypeRound1); err != nil {
			t.Fatalf("enqueue high failed: %v", err)
		}
		if err := qm.EnqueueMessage([]byte("critical"), peerID, transport.MsgTypeError); err != nil {
			t.Fatalf("enqueue critical failed: %v", err)
		}

		// Dequeue should be: critical, high, normal, low
		expected := []string{"critical", "high", "normal", "low"}
		for _, exp := range expected {
			msg := qm.TryDequeueMessage()
			if msg == nil {
				t.Fatalf("expected message '%s', got nil", exp)
			}
			if string(msg.Data) != exp {
				t.Errorf("expected '%s', got '%s'", exp, string(msg.Data))
			}
		}
	})

	t.Run("FIFO within same priority", func(t *testing.T) {
		config := &QoSConfig{
			EnablePrioritization: true,
			QueueSize:            100,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		peerID := testPeerID(t, "peer1")

		// Enqueue multiple messages with same priority
		for i := 0; i < 5; i++ {
			time.Sleep(time.Millisecond) // Ensure distinct timestamps
			if err := qm.EnqueueMessage([]byte{byte(i)}, peerID, transport.MsgTypeRound1); err != nil {
				t.Fatalf("enqueue %d failed: %v", i, err)
			}
		}

		// Should dequeue in order
		for i := 0; i < 5; i++ {
			msg := qm.TryDequeueMessage()
			if msg == nil {
				t.Fatalf("expected message %d, got nil", i)
			}
			if msg.Data[0] != byte(i) {
				t.Errorf("expected order %d, got %d", i, msg.Data[0])
			}
		}
	})

	t.Run("queue full", func(t *testing.T) {
		config := &QoSConfig{
			QueueSize: 5,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		peerID := testPeerID(t, "peer1")

		// Fill queue
		for i := 0; i < 5; i++ {
			if err := qm.EnqueueMessage([]byte{byte(i)}, peerID, transport.MsgTypeJoin); err != nil {
				t.Fatalf("enqueue %d failed: %v", i, err)
			}
		}

		// Next enqueue should fail
		err = qm.EnqueueMessage([]byte{5}, peerID, transport.MsgTypeJoin)
		if !errors.Is(err, ErrQueueFull) {
			t.Errorf("expected ErrQueueFull, got %v", err)
		}

		// Check stats
		stats := qm.Stats()
		if stats.DroppedMessages != 1 {
			t.Errorf("expected 1 dropped message, got %d", stats.DroppedMessages)
		}
	})

	t.Run("try dequeue empty queue", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		msg := qm.TryDequeueMessage()
		if msg != nil {
			t.Errorf("expected nil from empty queue, got %v", msg)
		}
	})

	t.Run("dequeue context cancelled", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err = qm.DequeueMessage(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("expected context.DeadlineExceeded, got %v", err)
		}
	})

	t.Run("dequeue closed manager", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Start goroutine waiting on dequeue
		var wg sync.WaitGroup
		var dequeueErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			_, dequeueErr = qm.DequeueMessage(ctx)
		}()

		// Give goroutine time to start waiting
		time.Sleep(50 * time.Millisecond)

		// Close manager
		if err := qm.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}

		// Wait for goroutine
		wg.Wait()

		if !errors.Is(dequeueErr, ErrQoSManagerClosed) {
			t.Errorf("expected ErrQoSManagerClosed, got %v", dequeueErr)
		}
	})

	t.Run("enqueue closed manager", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := qm.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}

		peerID := testPeerID(t, "peer1")
		err = qm.EnqueueMessage([]byte("test"), peerID, transport.MsgTypeJoin)
		if !errors.Is(err, ErrQoSManagerClosed) {
			t.Errorf("expected ErrQoSManagerClosed, got %v", err)
		}
	})
}

func TestQoSManager_MessagePriority(t *testing.T) {
	config := &QoSConfig{
		EnablePrioritization: true,
	}

	qm, err := NewQoSManager(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() {
		if err := qm.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}
	}()

	tests := []struct {
		msgType  transport.MessageType
		expected MessagePriorityLevel
	}{
		{transport.MsgTypeSessionInfo, MsgPriorityCritical},
		{transport.MsgTypeError, MsgPriorityCritical},
		{transport.MsgTypeRound1, MsgPriorityHigh},
		{transport.MsgTypeRound1Agg, MsgPriorityHigh},
		{transport.MsgTypeRound2, MsgPriorityHigh},
		{transport.MsgTypeRound2Agg, MsgPriorityHigh},
		{transport.MsgTypeCertEqSign, MsgPriorityHigh},
		{transport.MsgTypeCertificate, MsgPriorityHigh},
		{transport.MsgTypeJoin, MsgPriorityNormal},
		{transport.MsgTypeComplete, MsgPriorityNormal},
		{transport.MessageType(99), MsgPriorityLow}, // Unknown type
	}

	for _, tc := range tests {
		priority := qm.getMessagePriority(tc.msgType)
		if priority != tc.expected {
			t.Errorf("msgType %d: expected priority %d, got %d", tc.msgType, tc.expected, priority)
		}
	}
}

func TestQoSManager_MessagePriority_Disabled(t *testing.T) {
	config := &QoSConfig{
		EnablePrioritization: false,
	}

	qm, err := NewQoSManager(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() {
		if err := qm.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}
	}()

	// All message types should return MsgPriorityNormal when prioritization is disabled
	msgTypes := []transport.MessageType{
		transport.MsgTypeSessionInfo,
		transport.MsgTypeError,
		transport.MsgTypeRound1,
		transport.MsgTypeJoin,
		transport.MessageType(99),
	}

	for _, msgType := range msgTypes {
		priority := qm.getMessagePriority(msgType)
		if priority != MsgPriorityNormal {
			t.Errorf("msgType %d: expected MsgPriorityNormal when disabled, got %d", msgType, priority)
		}
	}
}

func TestQoSManager_BackpressureHandling(t *testing.T) {
	t.Run("slow consumer scenario", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn:      500, // 500 bytes/second
			BurstSize:           100,
			BackpressureTimeout: 500 * time.Millisecond,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// Use up initial burst
		if err := qm.AllowIncoming(ctx, peerID, 100); err != nil {
			t.Fatalf("initial request failed: %v", err)
		}

		// Concurrent requests should apply backpressure
		var wg sync.WaitGroup
		var successCount atomic.Int32
		var timeoutCount atomic.Int32

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := qm.WaitIncoming(ctx, peerID, 50)
				if err == nil {
					successCount.Add(1)
				} else if errors.Is(err, ErrBackpressureTimeout) {
					timeoutCount.Add(1)
				}
			}()
		}

		wg.Wait()

		// Some should succeed, some should timeout due to rate limiting
		// At least some should timeout given the low rate and burst
		total := successCount.Load() + timeoutCount.Load()
		if total != 5 {
			t.Errorf("expected 5 total results, got %d", total)
		}
	})

	t.Run("gradual rate allows progress", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn:      1000, // 1000 bytes/second
			BurstSize:           1000,
			BackpressureTimeout: 2 * time.Second,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// Should be able to send burst immediately
		if err := qm.WaitIncoming(ctx, peerID, 500); err != nil {
			t.Fatalf("burst request failed: %v", err)
		}

		// Additional data within timeout should work
		if err := qm.WaitIncoming(ctx, peerID, 200); err != nil {
			t.Fatalf("second request failed: %v", err)
		}
	})
}

func TestQoSManager_Statistics(t *testing.T) {
	t.Run("stats tracking", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peer1 := testPeerID(t, "peer1")
		peer2 := testPeerID(t, "peer2")

		// Generate some traffic
		if err := qm.AllowIncoming(ctx, peer1, 100); err != nil {
			t.Fatalf("incoming failed: %v", err)
		}
		if err := qm.AllowOutgoing(ctx, peer1, 200); err != nil {
			t.Fatalf("outgoing failed: %v", err)
		}
		if err := qm.AllowIncoming(ctx, peer2, 50); err != nil {
			t.Fatalf("incoming peer2 failed: %v", err)
		}

		// Enqueue a message
		if err := qm.EnqueueMessage([]byte("test"), peer1, transport.MsgTypeJoin); err != nil {
			t.Fatalf("enqueue failed: %v", err)
		}

		stats := qm.Stats()
		if stats.TotalBytesIn != 150 {
			t.Errorf("expected TotalBytesIn 150, got %d", stats.TotalBytesIn)
		}
		if stats.TotalBytesOut != 200 {
			t.Errorf("expected TotalBytesOut 200, got %d", stats.TotalBytesOut)
		}
		if stats.QueueLength != 1 {
			t.Errorf("expected QueueLength 1, got %d", stats.QueueLength)
		}
	})

	t.Run("per-peer stats", func(t *testing.T) {
		config := &QoSConfig{
			MaxPeerBandwidth: 10000, // Enable per-peer tracking
			BurstSize:        10000,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peer1 := testPeerID(t, "peer1")
		peer2 := testPeerID(t, "peer2")

		if err := qm.AllowIncoming(ctx, peer1, 100); err != nil {
			t.Fatalf("incoming failed: %v", err)
		}
		if err := qm.AllowOutgoing(ctx, peer1, 200); err != nil {
			t.Fatalf("outgoing failed: %v", err)
		}
		if err := qm.AllowIncoming(ctx, peer2, 50); err != nil {
			t.Fatalf("incoming peer2 failed: %v", err)
		}

		stats1, ok := qm.PeerStats(peer1)
		if !ok {
			t.Fatal("expected peer1 stats to exist")
		}
		if stats1.BytesIn != 100 {
			t.Errorf("peer1 expected BytesIn 100, got %d", stats1.BytesIn)
		}
		if stats1.BytesOut != 200 {
			t.Errorf("peer1 expected BytesOut 200, got %d", stats1.BytesOut)
		}

		stats2, ok := qm.PeerStats(peer2)
		if !ok {
			t.Fatal("expected peer2 stats to exist")
		}
		if stats2.BytesIn != 50 {
			t.Errorf("peer2 expected BytesIn 50, got %d", stats2.BytesIn)
		}

		// Unknown peer
		_, ok = qm.PeerStats(testPeerID(t, "unknown"))
		if ok {
			t.Error("expected unknown peer to have no stats")
		}
	})

	t.Run("reset stats", func(t *testing.T) {
		config := &QoSConfig{
			MaxPeerBandwidth: 10000,
			BurstSize:        10000,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peer1 := testPeerID(t, "peer1")

		if err := qm.AllowIncoming(ctx, peer1, 100); err != nil {
			t.Fatalf("incoming failed: %v", err)
		}
		if err := qm.AllowOutgoing(ctx, peer1, 200); err != nil {
			t.Fatalf("outgoing failed: %v", err)
		}

		qm.ResetStats()

		stats := qm.Stats()
		if stats.TotalBytesIn != 0 {
			t.Errorf("expected TotalBytesIn 0 after reset, got %d", stats.TotalBytesIn)
		}
		if stats.TotalBytesOut != 0 {
			t.Errorf("expected TotalBytesOut 0 after reset, got %d", stats.TotalBytesOut)
		}

		peerStats, ok := qm.PeerStats(peer1)
		if !ok {
			t.Fatal("expected peer1 to still exist after reset")
		}
		if peerStats.BytesIn != 0 {
			t.Errorf("expected peer BytesIn 0 after reset, got %d", peerStats.BytesIn)
		}
	})
}

func TestQoSManager_PeerManagement(t *testing.T) {
	t.Run("remove peer", func(t *testing.T) {
		config := &QoSConfig{
			MaxPeerBandwidth: 10000,
			BurstSize:        10000,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peer1 := testPeerID(t, "peer1")

		if err := qm.AllowIncoming(ctx, peer1, 100); err != nil {
			t.Fatalf("incoming failed: %v", err)
		}

		_, ok := qm.PeerStats(peer1)
		if !ok {
			t.Fatal("expected peer1 stats to exist before removal")
		}

		qm.RemovePeer(peer1)

		_, ok = qm.PeerStats(peer1)
		if ok {
			t.Error("expected peer1 stats to be gone after removal")
		}

		stats := qm.Stats()
		if stats.PeerCount != 0 {
			t.Errorf("expected PeerCount 0, got %d", stats.PeerCount)
		}
	})
}

func TestQoSManager_DynamicLimits(t *testing.T) {
	t.Run("set global in limit", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// Initially unlimited
		if err := qm.AllowIncoming(ctx, peerID, 10000); err != nil {
			t.Fatalf("initial request failed: %v", err)
		}

		// Set limit
		qm.SetGlobalInLimit(100)

		// Now should be limited
		err = qm.AllowIncoming(ctx, peerID, 200)
		if !errors.Is(err, ErrBandwidthExceeded) {
			t.Errorf("expected ErrBandwidthExceeded after setting limit, got %v", err)
		}

		// Remove limit
		qm.SetGlobalInLimit(0)

		// Should be unlimited again
		if err := qm.AllowIncoming(ctx, peerID, 10000); err != nil {
			t.Fatalf("request after removing limit failed: %v", err)
		}
	})

	t.Run("set global out limit", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		peerID := testPeerID(t, "peer1")

		// Initially unlimited
		if err := qm.AllowOutgoing(ctx, peerID, 10000); err != nil {
			t.Fatalf("initial request failed: %v", err)
		}

		// Set limit
		qm.SetGlobalOutLimit(100)

		// Now should be limited
		err = qm.AllowOutgoing(ctx, peerID, 200)
		if !errors.Is(err, ErrBandwidthExceeded) {
			t.Errorf("expected ErrBandwidthExceeded after setting limit, got %v", err)
		}

		// Remove limit
		qm.SetGlobalOutLimit(0)

		// Should be unlimited again
		if err := qm.AllowOutgoing(ctx, peerID, 10000); err != nil {
			t.Fatalf("request after removing limit failed: %v", err)
		}
	})
}

func TestQoSManager_Close(t *testing.T) {
	t.Run("close idempotent", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// First close should succeed
		if err := qm.Close(); err != nil {
			t.Errorf("first close error: %v", err)
		}

		// Second close should return error
		err = qm.Close()
		if !errors.Is(err, ErrQoSManagerClosed) {
			t.Errorf("expected ErrQoSManagerClosed on second close, got %v", err)
		}
	})

	t.Run("is closed", func(t *testing.T) {
		qm, err := NewQoSManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if qm.IsClosed() {
			t.Error("expected not closed initially")
		}

		if err := qm.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}

		if !qm.IsClosed() {
			t.Error("expected closed after Close()")
		}
	})
}

func TestQoSManager_Concurrency(t *testing.T) {
	t.Run("concurrent rate limiting", func(t *testing.T) {
		config := &QoSConfig{
			MaxBandwidthIn:   10000,
			MaxBandwidthOut:  10000,
			MaxPeerBandwidth: 5000,
			BurstSize:        1000,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		ctx := context.Background()
		var wg sync.WaitGroup
		numGoroutines := 10
		numRequests := 100

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				peerID := testPeerID(t, "peer"+string(rune('0'+id)))
				for j := 0; j < numRequests; j++ {
					// Alternate between in and out
					if j%2 == 0 {
						_ = qm.AllowIncoming(ctx, peerID, 10)
					} else {
						_ = qm.AllowOutgoing(ctx, peerID, 10)
					}
				}
			}(i)
		}

		wg.Wait()

		stats := qm.Stats()
		// Some operations should have succeeded
		if stats.TotalBytesIn == 0 && stats.TotalBytesOut == 0 {
			t.Error("expected some traffic to be recorded")
		}
	})

	t.Run("concurrent queue operations", func(t *testing.T) {
		config := &QoSConfig{
			QueueSize: 1000,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		var wg sync.WaitGroup
		numProducers := 5
		numConsumers := 3
		messagesPerProducer := 50

		// Start consumers
		receivedCount := atomic.Int32{}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		for i := 0; i < numConsumers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					msg, err := qm.DequeueMessage(ctx)
					if err != nil {
						return
					}
					if msg != nil {
						receivedCount.Add(1)
					}
				}
			}()
		}

		// Start producers
		for i := 0; i < numProducers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				peerID := testPeerID(t, "peer"+string(rune('0'+id)))
				for j := 0; j < messagesPerProducer; j++ {
					if err := qm.EnqueueMessage([]byte{byte(id), byte(j)}, peerID, transport.MsgTypeRound1); err != nil {
						// Queue might be full, that's ok
						if !errors.Is(err, ErrQueueFull) {
							t.Errorf("unexpected enqueue error: %v", err)
						}
					}
				}
			}(i)
		}

		// Wait for producers to finish
		time.Sleep(100 * time.Millisecond)

		// Cancel context to stop consumers
		cancel()
		wg.Wait()

		// Should have received some messages
		if receivedCount.Load() == 0 {
			t.Error("expected some messages to be received")
		}
	})
}

func TestPriorityQueue_HeapOperations(t *testing.T) {
	t.Run("heap property maintained", func(t *testing.T) {
		config := &QoSConfig{
			EnablePrioritization: true,
			QueueSize:            100,
		}

		qm, err := NewQoSManager(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() {
			if err := qm.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		}()

		peerID := testPeerID(t, "peer1")

		// Add messages in random order
		messages := []struct {
			data    string
			msgType transport.MessageType
		}{
			{"normal1", transport.MsgTypeJoin},
			{"critical1", transport.MsgTypeError},
			{"high1", transport.MsgTypeRound1},
			{"low1", transport.MessageType(99)},
			{"high2", transport.MsgTypeRound2},
			{"critical2", transport.MsgTypeSessionInfo},
			{"normal2", transport.MsgTypeComplete},
		}

		for _, m := range messages {
			if err := qm.EnqueueMessage([]byte(m.data), peerID, m.msgType); err != nil {
				t.Fatalf("enqueue failed: %v", err)
			}
		}

		// Verify dequeue order respects priority
		var lastPriority = MsgPriorityCritical + 1
		for i := 0; i < len(messages); i++ {
			msg := qm.TryDequeueMessage()
			if msg == nil {
				t.Fatalf("expected message at position %d", i)
			}
			if msg.Priority > lastPriority {
				t.Errorf("priority order violated at position %d: got %d after %d", i, msg.Priority, lastPriority)
			}
			lastPriority = msg.Priority
		}
	})
}
