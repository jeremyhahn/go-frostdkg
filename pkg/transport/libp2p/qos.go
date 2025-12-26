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

// Package libp2p provides a libp2p-based transport for the FROST DKG protocol.
package libp2p

import (
	"container/heap"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/time/rate"
)

// QoS error types.
var (
	// ErrBandwidthExceeded indicates the bandwidth limit was exceeded.
	ErrBandwidthExceeded = errors.New("qos: bandwidth limit exceeded")

	// ErrPeerBandwidthExceeded indicates the per-peer bandwidth limit was exceeded.
	ErrPeerBandwidthExceeded = errors.New("qos: peer bandwidth limit exceeded")

	// ErrQueueFull indicates the message queue is full.
	ErrQueueFull = errors.New("qos: message queue full")

	// ErrBackpressureTimeout indicates backpressure handling timed out.
	ErrBackpressureTimeout = errors.New("qos: backpressure timeout")

	// ErrQoSManagerClosed indicates the QoS manager has been closed.
	ErrQoSManagerClosed = errors.New("qos: manager closed")

	// ErrInvalidQoSConfig indicates invalid QoS configuration.
	ErrInvalidQoSConfig = errors.New("qos: invalid configuration")
)

// QoSConfig contains configuration for QoS management.
type QoSConfig struct {
	// MaxBandwidthIn is the maximum incoming bandwidth in bytes per second.
	// Zero means unlimited.
	MaxBandwidthIn int64

	// MaxBandwidthOut is the maximum outgoing bandwidth in bytes per second.
	// Zero means unlimited.
	MaxBandwidthOut int64

	// MaxPeerBandwidth is the maximum bandwidth per peer in bytes per second.
	// Zero means unlimited.
	MaxPeerBandwidth int64

	// BurstSize is the maximum burst size in bytes for rate limiting.
	// This allows temporary bursts above the rate limit.
	BurstSize int

	// EnablePrioritization enables message priority queuing.
	// When enabled, DKG protocol messages are prioritized.
	EnablePrioritization bool

	// QueueSize is the maximum number of messages in the priority queue.
	// Default is 1000.
	QueueSize int

	// BackpressureTimeout is the maximum time to wait when applying backpressure.
	// Default is 5 seconds.
	BackpressureTimeout time.Duration
}

// DefaultQoSConfig returns a default QoS configuration.
func DefaultQoSConfig() *QoSConfig {
	return &QoSConfig{
		MaxBandwidthIn:       0, // Unlimited
		MaxBandwidthOut:      0, // Unlimited
		MaxPeerBandwidth:     0, // Unlimited
		BurstSize:            64 * 1024,
		EnablePrioritization: true,
		QueueSize:            1000,
		BackpressureTimeout:  5 * time.Second,
	}
}

// Validate validates the QoS configuration.
func (c *QoSConfig) Validate() error {
	if c.MaxBandwidthIn < 0 || c.MaxBandwidthOut < 0 || c.MaxPeerBandwidth < 0 {
		return ErrInvalidQoSConfig
	}
	if c.BurstSize < 0 {
		return ErrInvalidQoSConfig
	}
	if c.QueueSize < 0 {
		return ErrInvalidQoSConfig
	}
	return nil
}

// MessagePriorityLevel defines priority levels for DKG messages.
// This type is separate from SessionPriority to distinguish between
// connection-level and message-level prioritization.
type MessagePriorityLevel int

const (
	// MsgPriorityLow is for non-critical messages.
	MsgPriorityLow MessagePriorityLevel = iota
	// MsgPriorityNormal is the default priority.
	MsgPriorityNormal
	// MsgPriorityHigh is for DKG protocol messages.
	MsgPriorityHigh
	// MsgPriorityCritical is for session management and error messages.
	MsgPriorityCritical
)

// QueuedMessage represents a message in the priority queue.
type QueuedMessage struct {
	Data      []byte
	PeerID    peer.ID
	Priority  MessagePriorityLevel
	Timestamp time.Time
	index     int // heap index for priority queue
}

// priorityQueue implements heap.Interface for message prioritization.
type priorityQueue []*QueuedMessage

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	// Higher priority first, then earlier timestamp
	if pq[i].Priority != pq[j].Priority {
		return pq[i].Priority > pq[j].Priority
	}
	return pq[i].Timestamp.Before(pq[j].Timestamp)
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *priorityQueue) Push(x any) {
	n := len(*pq)
	item := x.(*QueuedMessage)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *priorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// peerLimiter tracks rate limiting state for a single peer.
type peerLimiter struct {
	inLimiter  *rate.Limiter
	outLimiter *rate.Limiter
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
}

// QoSManager manages bandwidth allocation and QoS for DKG sessions.
type QoSManager struct {
	config *QoSConfig

	// Global rate limiters
	globalInLimiter  *rate.Limiter
	globalOutLimiter *rate.Limiter

	// Per-peer rate limiters
	peerLimiters sync.Map // peer.ID -> *peerLimiter

	// Priority queue for outgoing messages
	outQueue   priorityQueue
	queueMu    sync.Mutex
	queueCond  *sync.Cond
	queueCount atomic.Int32

	// Statistics
	totalBytesIn    atomic.Int64
	totalBytesOut   atomic.Int64
	droppedMessages atomic.Int64

	// Lifecycle
	closed   atomic.Bool
	closeMu  sync.RWMutex
	doneChan chan struct{}
}

// NewQoSManager creates a new QoS manager with the given configuration.
func NewQoSManager(config *QoSConfig) (*QoSManager, error) {
	if config == nil {
		config = DefaultQoSConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	qm := &QoSManager{
		config:   config,
		outQueue: make(priorityQueue, 0, config.QueueSize),
		doneChan: make(chan struct{}),
	}
	qm.queueCond = sync.NewCond(&qm.queueMu)

	// Initialize global rate limiters
	if config.MaxBandwidthIn > 0 {
		burstSize := config.BurstSize
		if burstSize == 0 {
			burstSize = int(config.MaxBandwidthIn)
		}
		qm.globalInLimiter = rate.NewLimiter(rate.Limit(config.MaxBandwidthIn), burstSize)
	}

	if config.MaxBandwidthOut > 0 {
		burstSize := config.BurstSize
		if burstSize == 0 {
			burstSize = int(config.MaxBandwidthOut)
		}
		qm.globalOutLimiter = rate.NewLimiter(rate.Limit(config.MaxBandwidthOut), burstSize)
	}

	heap.Init(&qm.outQueue)

	return qm, nil
}

// Close shuts down the QoS manager.
func (qm *QoSManager) Close() error {
	if qm.closed.Swap(true) {
		return ErrQoSManagerClosed
	}

	close(qm.doneChan)

	// Wake up any waiting goroutines
	qm.queueCond.Broadcast()

	return nil
}

// AllowIncoming checks if incoming data of the given size is allowed.
// This implements the token bucket algorithm for smooth rate limiting.
func (qm *QoSManager) AllowIncoming(ctx context.Context, peerID peer.ID, size int) error {
	qm.closeMu.RLock()
	defer qm.closeMu.RUnlock()

	if qm.closed.Load() {
		return ErrQoSManagerClosed
	}

	// Check global limit
	if qm.globalInLimiter != nil {
		if !qm.globalInLimiter.AllowN(time.Now(), size) {
			return ErrBandwidthExceeded
		}
	}

	// Check per-peer limit
	if qm.config.MaxPeerBandwidth > 0 {
		limiter := qm.getOrCreatePeerLimiter(peerID)
		if !limiter.inLimiter.AllowN(time.Now(), size) {
			return ErrPeerBandwidthExceeded
		}
	}

	// Update statistics
	qm.totalBytesIn.Add(int64(size))
	if pl, ok := qm.peerLimiters.Load(peerID); ok {
		pl.(*peerLimiter).bytesIn.Add(int64(size))
	}

	return nil
}

// isExceedsBurstError checks if the error is due to request size exceeding burst limit.
func isExceedsBurstError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "exceeds limiter's burst")
}

// WaitIncoming waits until incoming data of the given size is allowed.
// This applies backpressure when the rate limit is exceeded.
func (qm *QoSManager) WaitIncoming(ctx context.Context, peerID peer.ID, size int) error {
	qm.closeMu.RLock()
	defer qm.closeMu.RUnlock()

	if qm.closed.Load() {
		return ErrQoSManagerClosed
	}

	timeout := qm.config.BackpressureTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Wait for global limit
	if qm.globalInLimiter != nil {
		if err := qm.globalInLimiter.WaitN(ctx, size); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isExceedsBurstError(err) {
				return ErrBackpressureTimeout
			}
			if errors.Is(err, context.Canceled) {
				return err
			}
			return ErrBackpressureTimeout
		}
	}

	// Wait for per-peer limit
	if qm.config.MaxPeerBandwidth > 0 {
		limiter := qm.getOrCreatePeerLimiter(peerID)
		if err := limiter.inLimiter.WaitN(ctx, size); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isExceedsBurstError(err) {
				return ErrBackpressureTimeout
			}
			if errors.Is(err, context.Canceled) {
				return err
			}
			return ErrBackpressureTimeout
		}
	}

	// Update statistics
	qm.totalBytesIn.Add(int64(size))
	if pl, ok := qm.peerLimiters.Load(peerID); ok {
		pl.(*peerLimiter).bytesIn.Add(int64(size))
	}

	return nil
}

// AllowOutgoing checks if outgoing data of the given size is allowed.
func (qm *QoSManager) AllowOutgoing(ctx context.Context, peerID peer.ID, size int) error {
	qm.closeMu.RLock()
	defer qm.closeMu.RUnlock()

	if qm.closed.Load() {
		return ErrQoSManagerClosed
	}

	// Check global limit
	if qm.globalOutLimiter != nil {
		if !qm.globalOutLimiter.AllowN(time.Now(), size) {
			return ErrBandwidthExceeded
		}
	}

	// Check per-peer limit
	if qm.config.MaxPeerBandwidth > 0 {
		limiter := qm.getOrCreatePeerLimiter(peerID)
		if !limiter.outLimiter.AllowN(time.Now(), size) {
			return ErrPeerBandwidthExceeded
		}
	}

	// Update statistics
	qm.totalBytesOut.Add(int64(size))
	if pl, ok := qm.peerLimiters.Load(peerID); ok {
		pl.(*peerLimiter).bytesOut.Add(int64(size))
	}

	return nil
}

// WaitOutgoing waits until outgoing data of the given size is allowed.
func (qm *QoSManager) WaitOutgoing(ctx context.Context, peerID peer.ID, size int) error {
	qm.closeMu.RLock()
	defer qm.closeMu.RUnlock()

	if qm.closed.Load() {
		return ErrQoSManagerClosed
	}

	timeout := qm.config.BackpressureTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Wait for global limit
	if qm.globalOutLimiter != nil {
		if err := qm.globalOutLimiter.WaitN(ctx, size); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isExceedsBurstError(err) {
				return ErrBackpressureTimeout
			}
			if errors.Is(err, context.Canceled) {
				return err
			}
			return ErrBackpressureTimeout
		}
	}

	// Wait for per-peer limit
	if qm.config.MaxPeerBandwidth > 0 {
		limiter := qm.getOrCreatePeerLimiter(peerID)
		if err := limiter.outLimiter.WaitN(ctx, size); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isExceedsBurstError(err) {
				return ErrBackpressureTimeout
			}
			if errors.Is(err, context.Canceled) {
				return err
			}
			return ErrBackpressureTimeout
		}
	}

	// Update statistics
	qm.totalBytesOut.Add(int64(size))
	if pl, ok := qm.peerLimiters.Load(peerID); ok {
		pl.(*peerLimiter).bytesOut.Add(int64(size))
	}

	return nil
}

// EnqueueMessage adds a message to the priority queue for sending.
// Returns ErrQueueFull if the queue is at capacity.
func (qm *QoSManager) EnqueueMessage(data []byte, peerID peer.ID, msgType transport.MessageType) error {
	if qm.closed.Load() {
		return ErrQoSManagerClosed
	}

	priority := qm.getMessagePriority(msgType)

	msg := &QueuedMessage{
		Data:      data,
		PeerID:    peerID,
		Priority:  priority,
		Timestamp: time.Now(),
	}

	qm.queueMu.Lock()
	defer qm.queueMu.Unlock()

	if len(qm.outQueue) >= qm.config.QueueSize {
		qm.droppedMessages.Add(1)
		return ErrQueueFull
	}

	heap.Push(&qm.outQueue, msg)
	qm.queueCount.Add(1)
	qm.queueCond.Signal()

	return nil
}

// DequeueMessage retrieves the highest priority message from the queue.
// Blocks until a message is available or the context is cancelled.
func (qm *QoSManager) DequeueMessage(ctx context.Context) (*QueuedMessage, error) {
	qm.queueMu.Lock()
	defer qm.queueMu.Unlock()

	for len(qm.outQueue) == 0 {
		if qm.closed.Load() {
			return nil, ErrQoSManagerClosed
		}

		// Wait with context awareness
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				qm.queueCond.Broadcast()
			case <-done:
			}
		}()

		qm.queueCond.Wait()
		close(done)

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	if qm.closed.Load() {
		return nil, ErrQoSManagerClosed
	}

	msg := heap.Pop(&qm.outQueue).(*QueuedMessage)
	qm.queueCount.Add(-1)

	return msg, nil
}

// TryDequeueMessage attempts to retrieve a message without blocking.
// Returns nil if the queue is empty.
func (qm *QoSManager) TryDequeueMessage() *QueuedMessage {
	qm.queueMu.Lock()
	defer qm.queueMu.Unlock()

	if len(qm.outQueue) == 0 {
		return nil
	}

	msg := heap.Pop(&qm.outQueue).(*QueuedMessage)
	qm.queueCount.Add(-1)

	return msg
}

// QueueLength returns the current number of messages in the queue.
func (qm *QoSManager) QueueLength() int {
	return int(qm.queueCount.Load())
}

// getMessagePriority determines the priority of a message based on its type.
func (qm *QoSManager) getMessagePriority(msgType transport.MessageType) MessagePriorityLevel {
	if !qm.config.EnablePrioritization {
		return MsgPriorityNormal
	}

	switch msgType {
	case transport.MsgTypeSessionInfo, transport.MsgTypeError:
		return MsgPriorityCritical
	case transport.MsgTypeRound1, transport.MsgTypeRound1Agg,
		transport.MsgTypeRound2, transport.MsgTypeRound2Agg,
		transport.MsgTypeCertEqSign, transport.MsgTypeCertificate:
		return MsgPriorityHigh
	case transport.MsgTypeJoin, transport.MsgTypeComplete:
		return MsgPriorityNormal
	default:
		return MsgPriorityLow
	}
}

// getOrCreatePeerLimiter returns the rate limiter for a peer, creating one if needed.
func (qm *QoSManager) getOrCreatePeerLimiter(peerID peer.ID) *peerLimiter {
	if existing, ok := qm.peerLimiters.Load(peerID); ok {
		return existing.(*peerLimiter)
	}

	burstSize := qm.config.BurstSize
	if burstSize == 0 {
		burstSize = int(qm.config.MaxPeerBandwidth)
	}

	limiter := &peerLimiter{
		inLimiter:  rate.NewLimiter(rate.Limit(qm.config.MaxPeerBandwidth), burstSize),
		outLimiter: rate.NewLimiter(rate.Limit(qm.config.MaxPeerBandwidth), burstSize),
	}

	actual, _ := qm.peerLimiters.LoadOrStore(peerID, limiter)
	return actual.(*peerLimiter)
}

// RemovePeer removes rate limiting state for a disconnected peer.
func (qm *QoSManager) RemovePeer(peerID peer.ID) {
	qm.peerLimiters.Delete(peerID)
}

// QoSStats holds current QoS statistics.
type QoSStats struct {
	TotalBytesIn    int64
	TotalBytesOut   int64
	DroppedMessages int64
	QueueLength     int
	PeerCount       int
}

// Stats returns current QoS statistics.
func (qm *QoSManager) Stats() QoSStats {
	peerCount := 0
	qm.peerLimiters.Range(func(_, _ any) bool {
		peerCount++
		return true
	})

	return QoSStats{
		TotalBytesIn:    qm.totalBytesIn.Load(),
		TotalBytesOut:   qm.totalBytesOut.Load(),
		DroppedMessages: qm.droppedMessages.Load(),
		QueueLength:     qm.QueueLength(),
		PeerCount:       peerCount,
	}
}

// PeerQoSStats holds statistics for a specific peer.
type PeerQoSStats struct {
	BytesIn  int64
	BytesOut int64
}

// PeerStats returns statistics for a specific peer.
func (qm *QoSManager) PeerStats(peerID peer.ID) (PeerQoSStats, bool) {
	if pl, ok := qm.peerLimiters.Load(peerID); ok {
		limiter := pl.(*peerLimiter)
		return PeerQoSStats{
			BytesIn:  limiter.bytesIn.Load(),
			BytesOut: limiter.bytesOut.Load(),
		}, true
	}
	return PeerQoSStats{}, false
}

// ResetStats resets all statistics counters.
func (qm *QoSManager) ResetStats() {
	qm.totalBytesIn.Store(0)
	qm.totalBytesOut.Store(0)
	qm.droppedMessages.Store(0)

	qm.peerLimiters.Range(func(key, value any) bool {
		limiter := value.(*peerLimiter)
		limiter.bytesIn.Store(0)
		limiter.bytesOut.Store(0)
		return true
	})
}

// SetGlobalInLimit updates the global incoming bandwidth limit.
func (qm *QoSManager) SetGlobalInLimit(bytesPerSecond int64) {
	qm.closeMu.Lock()
	defer qm.closeMu.Unlock()

	if bytesPerSecond <= 0 {
		qm.globalInLimiter = nil
		return
	}

	// Use the smaller of config burst size or the new rate limit for the burst.
	// This ensures rate limiting is effective when dynamically changing limits.
	burstSize := qm.config.BurstSize
	if burstSize == 0 || burstSize > int(bytesPerSecond) {
		burstSize = int(bytesPerSecond)
	}

	if qm.globalInLimiter != nil {
		qm.globalInLimiter.SetLimit(rate.Limit(bytesPerSecond))
		qm.globalInLimiter.SetBurst(burstSize)
	} else {
		qm.globalInLimiter = rate.NewLimiter(rate.Limit(bytesPerSecond), burstSize)
	}
}

// SetGlobalOutLimit updates the global outgoing bandwidth limit.
func (qm *QoSManager) SetGlobalOutLimit(bytesPerSecond int64) {
	qm.closeMu.Lock()
	defer qm.closeMu.Unlock()

	if bytesPerSecond <= 0 {
		qm.globalOutLimiter = nil
		return
	}

	// Use the smaller of config burst size or the new rate limit for the burst.
	// This ensures rate limiting is effective when dynamically changing limits.
	burstSize := qm.config.BurstSize
	if burstSize == 0 || burstSize > int(bytesPerSecond) {
		burstSize = int(bytesPerSecond)
	}

	if qm.globalOutLimiter != nil {
		qm.globalOutLimiter.SetLimit(rate.Limit(bytesPerSecond))
		qm.globalOutLimiter.SetBurst(burstSize)
	} else {
		qm.globalOutLimiter = rate.NewLimiter(rate.Limit(bytesPerSecond), burstSize)
	}
}

// IsClosed returns true if the QoS manager has been closed.
func (qm *QoSManager) IsClosed() bool {
	return qm.closed.Load()
}
