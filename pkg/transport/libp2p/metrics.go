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

// Package libp2p provides Prometheus metrics collection for the FROST DKG
// libp2p transport layer.
package libp2p

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics error types.
var (
	// ErrMetricsAlreadyStarted indicates the metrics server is already running.
	ErrMetricsAlreadyStarted = errors.New("libp2p: metrics server already started")

	// ErrMetricsNotStarted indicates the metrics server is not running.
	ErrMetricsNotStarted = errors.New("libp2p: metrics server not started")

	// ErrMetricsRegistrationFailed indicates metric registration failed.
	ErrMetricsRegistrationFailed = errors.New("libp2p: metric registration failed")

	// ErrMetricsInvalidConfig indicates invalid metrics configuration.
	ErrMetricsInvalidConfig = errors.New("libp2p: invalid metrics configuration")

	// ErrMetricsServerShutdown indicates the metrics server failed to shutdown.
	ErrMetricsServerShutdown = errors.New("libp2p: metrics server shutdown failed")
)

// MetricsConfig holds configuration for the metrics collector.
type MetricsConfig struct {
	// Enabled controls whether metrics collection is active.
	Enabled bool

	// Namespace is the Prometheus namespace for all metrics (default: "frost_dkg").
	Namespace string

	// Subsystem is the Prometheus subsystem for all metrics (default: "libp2p").
	Subsystem string

	// HTTPEnabled controls whether to start an HTTP metrics endpoint.
	HTTPEnabled bool

	// HTTPAddr is the address for the metrics HTTP endpoint (e.g., ":9090").
	HTTPAddr string

	// HTTPPath is the path for the metrics endpoint (default: "/metrics").
	HTTPPath string

	// HistogramBuckets defines custom histogram buckets for latency metrics.
	// If nil, default buckets are used.
	HistogramBuckets []float64

	// RoundDurationBuckets defines custom histogram buckets for round duration.
	// If nil, default buckets are used.
	RoundDurationBuckets []float64
}

// DefaultMetricsConfig returns a default metrics configuration.
func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		Enabled:   true,
		Namespace: "frost_dkg",
		Subsystem: "libp2p",
		HTTPPath:  "/metrics",
		HistogramBuckets: []float64{
			0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
		},
		RoundDurationBuckets: []float64{
			0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0,
		},
	}
}

// MetricsCollector collects Prometheus metrics for the FROST DKG libp2p transport.
type MetricsCollector struct {
	config   *MetricsConfig
	registry *prometheus.Registry

	// Counters
	messagesTotal    *prometheus.CounterVec
	connectionsTotal *prometheus.CounterVec
	bandwidthBytes   *prometheus.CounterVec
	errorsTotal      *prometheus.CounterVec

	// Gauges (using atomic values with GaugeFunc)
	activeSessions atomic.Int64
	connectedPeers atomic.Int64

	activeSessionsGauge prometheus.GaugeFunc
	connectedPeersGauge prometheus.GaugeFunc

	// Histograms
	messageLatency *prometheus.HistogramVec
	roundDuration  *prometheus.HistogramVec

	// HTTP server state
	httpServer  *http.Server
	httpStarted atomic.Bool
}

// NewMetricsCollector creates a new metrics collector with the given configuration.
// It creates a custom Prometheus registry to avoid polluting the global registry.
func NewMetricsCollector(config *MetricsConfig) (*MetricsCollector, error) {
	if config == nil {
		config = DefaultMetricsConfig()
	}

	if !config.Enabled {
		return &MetricsCollector{config: config}, nil
	}

	// Validate configuration
	if config.HTTPEnabled && config.HTTPAddr == "" {
		return nil, ErrMetricsInvalidConfig
	}

	// Use defaults if not specified
	namespace := config.Namespace
	if namespace == "" {
		namespace = "frost_dkg"
	}

	subsystem := config.Subsystem
	if subsystem == "" {
		subsystem = "libp2p"
	}

	histogramBuckets := config.HistogramBuckets
	if histogramBuckets == nil {
		histogramBuckets = DefaultMetricsConfig().HistogramBuckets
	}

	roundDurationBuckets := config.RoundDurationBuckets
	if roundDurationBuckets == nil {
		roundDurationBuckets = DefaultMetricsConfig().RoundDurationBuckets
	}

	mc := &MetricsCollector{
		config:   config,
		registry: prometheus.NewRegistry(),
	}

	// Create counters
	mc.messagesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "messages_total",
			Help:      "Total number of DKG messages sent and received.",
		},
		[]string{"type", "direction"},
	)

	mc.connectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "connections_total",
			Help:      "Total number of peer connections.",
		},
		[]string{"status"},
	)

	mc.bandwidthBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "bandwidth_bytes",
			Help:      "Total bandwidth usage in bytes.",
		},
		[]string{"direction"},
	)

	mc.errorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "errors_total",
			Help:      "Total number of errors by type.",
		},
		[]string{"type"},
	)

	// Create gauges using GaugeFunc for atomic values
	mc.activeSessionsGauge = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "active_sessions",
			Help:      "Number of currently active DKG sessions.",
		},
		func() float64 {
			return float64(mc.activeSessions.Load())
		},
	)

	mc.connectedPeersGauge = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "connected_peers",
			Help:      "Number of currently connected peers.",
		},
		func() float64 {
			return float64(mc.connectedPeers.Load())
		},
	)

	// Create histograms
	mc.messageLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "message_latency_seconds",
			Help:      "Message latency distribution in seconds.",
			Buckets:   histogramBuckets,
		},
		[]string{"type"},
	)

	mc.roundDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "round_duration_seconds",
			Help:      "DKG round duration distribution in seconds.",
			Buckets:   roundDurationBuckets,
		},
		[]string{"round"},
	)

	// Register all metrics
	collectors := []prometheus.Collector{
		mc.messagesTotal,
		mc.connectionsTotal,
		mc.bandwidthBytes,
		mc.errorsTotal,
		mc.activeSessionsGauge,
		mc.connectedPeersGauge,
		mc.messageLatency,
		mc.roundDuration,
	}

	for _, collector := range collectors {
		if err := mc.registry.Register(collector); err != nil {
			return nil, &MetricsError{
				Op:  "register",
				Err: err,
			}
		}
	}

	return mc, nil
}

// Registry returns the Prometheus registry used by this collector.
func (mc *MetricsCollector) Registry() *prometheus.Registry {
	return mc.registry
}

// Enabled returns true if metrics collection is enabled.
func (mc *MetricsCollector) Enabled() bool {
	return mc.config != nil && mc.config.Enabled
}

// StartHTTPServer starts the metrics HTTP endpoint.
// Returns ErrMetricsAlreadyStarted if the server is already running.
func (mc *MetricsCollector) StartHTTPServer(ctx context.Context) error {
	if !mc.Enabled() {
		return nil
	}

	if !mc.config.HTTPEnabled {
		return nil
	}

	if mc.httpStarted.Swap(true) {
		return ErrMetricsAlreadyStarted
	}

	path := mc.config.HTTPPath
	if path == "" {
		path = "/metrics"
	}

	mux := http.NewServeMux()
	mux.Handle(path, promhttp.HandlerFor(mc.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	mc.httpServer = &http.Server{
		Addr:              mc.config.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		if err := mc.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			mc.httpStarted.Store(false)
		}
	}()

	return nil
}

// StopHTTPServer gracefully stops the metrics HTTP endpoint.
func (mc *MetricsCollector) StopHTTPServer(ctx context.Context) error {
	if !mc.httpStarted.Load() {
		return nil
	}

	if mc.httpServer == nil {
		mc.httpStarted.Store(false)
		return nil
	}

	if err := mc.httpServer.Shutdown(ctx); err != nil {
		return &MetricsError{
			Op:  "shutdown",
			Err: err,
		}
	}

	mc.httpStarted.Store(false)
	return nil
}

// HTTPServerRunning returns true if the HTTP metrics server is running.
func (mc *MetricsCollector) HTTPServerRunning() bool {
	return mc.httpStarted.Load()
}

// RecordMessageSent records a message sent with the given type and size.
func (mc *MetricsCollector) RecordMessageSent(msgType string, sizeBytes int) {
	if !mc.Enabled() {
		return
	}
	mc.messagesTotal.WithLabelValues(msgType, "sent").Inc()
	mc.bandwidthBytes.WithLabelValues("out").Add(float64(sizeBytes))
}

// RecordMessageReceived records a message received with the given type and size.
func (mc *MetricsCollector) RecordMessageReceived(msgType string, sizeBytes int) {
	if !mc.Enabled() {
		return
	}
	mc.messagesTotal.WithLabelValues(msgType, "received").Inc()
	mc.bandwidthBytes.WithLabelValues("in").Add(float64(sizeBytes))
}

// RecordConnectionOpened records a successful connection establishment.
func (mc *MetricsCollector) RecordConnectionOpened() {
	if !mc.Enabled() {
		return
	}
	mc.connectionsTotal.WithLabelValues("opened").Inc()
	mc.connectedPeers.Add(1)
}

// RecordConnectionClosed records a connection closure.
func (mc *MetricsCollector) RecordConnectionClosed() {
	if !mc.Enabled() {
		return
	}
	mc.connectionsTotal.WithLabelValues("closed").Inc()
	current := mc.connectedPeers.Add(-1)
	if current < 0 {
		mc.connectedPeers.Store(0)
	}
}

// RecordConnectionFailed records a failed connection attempt.
func (mc *MetricsCollector) RecordConnectionFailed() {
	if !mc.Enabled() {
		return
	}
	mc.connectionsTotal.WithLabelValues("failed").Inc()
}

// RecordError records an error with the given type.
func (mc *MetricsCollector) RecordError(errorType string) {
	if !mc.Enabled() {
		return
	}
	mc.errorsTotal.WithLabelValues(errorType).Inc()
}

// RecordMessageLatency records the latency for a message with the given type.
func (mc *MetricsCollector) RecordMessageLatency(msgType string, latency time.Duration) {
	if !mc.Enabled() {
		return
	}
	mc.messageLatency.WithLabelValues(msgType).Observe(latency.Seconds())
}

// RecordRoundDuration records the duration of a DKG round.
func (mc *MetricsCollector) RecordRoundDuration(round string, duration time.Duration) {
	if !mc.Enabled() {
		return
	}
	mc.roundDuration.WithLabelValues(round).Observe(duration.Seconds())
}

// SessionStarted increments the active sessions counter.
func (mc *MetricsCollector) SessionStarted() {
	if !mc.Enabled() {
		return
	}
	mc.activeSessions.Add(1)
}

// SessionEnded decrements the active sessions counter.
func (mc *MetricsCollector) SessionEnded() {
	if !mc.Enabled() {
		return
	}
	current := mc.activeSessions.Add(-1)
	if current < 0 {
		mc.activeSessions.Store(0)
	}
}

// SetActiveSessions sets the active sessions gauge to a specific value.
func (mc *MetricsCollector) SetActiveSessions(count int64) {
	if !mc.Enabled() {
		return
	}
	mc.activeSessions.Store(count)
}

// SetConnectedPeers sets the connected peers gauge to a specific value.
func (mc *MetricsCollector) SetConnectedPeers(count int64) {
	if !mc.Enabled() {
		return
	}
	mc.connectedPeers.Store(count)
}

// GetActiveSessions returns the current number of active sessions.
func (mc *MetricsCollector) GetActiveSessions() int64 {
	return mc.activeSessions.Load()
}

// GetConnectedPeers returns the current number of connected peers.
func (mc *MetricsCollector) GetConnectedPeers() int64 {
	return mc.connectedPeers.Load()
}

// Reset resets all metrics to their initial values.
// This is useful for testing.
func (mc *MetricsCollector) Reset() {
	if !mc.Enabled() {
		return
	}
	mc.messagesTotal.Reset()
	mc.connectionsTotal.Reset()
	mc.bandwidthBytes.Reset()
	mc.errorsTotal.Reset()
	mc.messageLatency.Reset()
	mc.roundDuration.Reset()
	mc.activeSessions.Store(0)
	mc.connectedPeers.Store(0)
}

// MessageTimer provides a convenient way to measure message latency.
type MessageTimer struct {
	collector *MetricsCollector
	msgType   string
	startTime time.Time
}

// NewMessageTimer starts a new timer for measuring message latency.
func (mc *MetricsCollector) NewMessageTimer(msgType string) *MessageTimer {
	return &MessageTimer{
		collector: mc,
		msgType:   msgType,
		startTime: time.Now(),
	}
}

// Stop stops the timer and records the latency.
func (mt *MessageTimer) Stop() {
	if mt.collector != nil {
		mt.collector.RecordMessageLatency(mt.msgType, time.Since(mt.startTime))
	}
}

// RoundTimer provides a convenient way to measure DKG round duration.
type RoundTimer struct {
	collector *MetricsCollector
	round     string
	startTime time.Time
}

// NewRoundTimer starts a new timer for measuring round duration.
func (mc *MetricsCollector) NewRoundTimer(round string) *RoundTimer {
	return &RoundTimer{
		collector: mc,
		round:     round,
		startTime: time.Now(),
	}
}

// Stop stops the timer and records the round duration.
func (rt *RoundTimer) Stop() {
	if rt.collector != nil {
		rt.collector.RecordRoundDuration(rt.round, time.Since(rt.startTime))
	}
}

// MetricsError wraps metrics-related errors with operation context.
type MetricsError struct {
	Op  string
	Err error
}

// Error returns the error message.
func (e *MetricsError) Error() string {
	if e.Err != nil {
		return "libp2p metrics " + e.Op + " error: " + e.Err.Error()
	}
	return "libp2p metrics " + e.Op + " error"
}

// Unwrap returns the underlying error.
func (e *MetricsError) Unwrap() error {
	return e.Err
}
