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
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMetricsCollector_DefaultConfig verifies that a metrics collector
// can be created with default configuration.
func TestNewMetricsCollector_DefaultConfig(t *testing.T) {
	mc, err := NewMetricsCollector(nil)
	require.NoError(t, err)
	require.NotNil(t, mc)
	assert.True(t, mc.Enabled())
	assert.NotNil(t, mc.Registry())
}

// TestNewMetricsCollector_CustomConfig verifies that a metrics collector
// respects custom configuration.
func TestNewMetricsCollector_CustomConfig(t *testing.T) {
	cfg := &MetricsConfig{
		Enabled:     true,
		Namespace:   "custom_namespace",
		Subsystem:   "custom_subsystem",
		HTTPEnabled: true,
		HTTPAddr:    ":0",
		HTTPPath:    "/custom-metrics",
		HistogramBuckets: []float64{
			0.001, 0.01, 0.1, 1.0,
		},
		RoundDurationBuckets: []float64{
			1.0, 10.0, 60.0,
		},
	}

	mc, err := NewMetricsCollector(cfg)
	require.NoError(t, err)
	require.NotNil(t, mc)
	assert.True(t, mc.Enabled())
}

// TestNewMetricsCollector_Disabled verifies that metrics can be disabled.
func TestNewMetricsCollector_Disabled(t *testing.T) {
	cfg := &MetricsConfig{
		Enabled: false,
	}

	mc, err := NewMetricsCollector(cfg)
	require.NoError(t, err)
	require.NotNil(t, mc)
	assert.False(t, mc.Enabled())

	// Verify disabled collector doesn't panic on operations
	mc.RecordMessageSent("test", 100)
	mc.RecordMessageReceived("test", 100)
	mc.RecordConnectionOpened()
	mc.RecordConnectionClosed()
	mc.RecordConnectionFailed()
	mc.RecordError("test_error")
	mc.RecordMessageLatency("test", time.Millisecond)
	mc.RecordRoundDuration("1", time.Second)
	mc.SessionStarted()
	mc.SessionEnded()
	mc.SetActiveSessions(5)
	mc.SetConnectedPeers(10)
	mc.Reset()
}

// TestNewMetricsCollector_InvalidConfig verifies that invalid configuration
// is properly rejected.
func TestNewMetricsCollector_InvalidConfig(t *testing.T) {
	cfg := &MetricsConfig{
		Enabled:     true,
		HTTPEnabled: true,
		HTTPAddr:    "", // Invalid: HTTP enabled but no address
	}

	mc, err := NewMetricsCollector(cfg)
	require.Error(t, err)
	assert.Nil(t, mc)
	assert.True(t, errors.Is(err, ErrMetricsInvalidConfig))
}

// TestMetricsCollector_Registration verifies that all metrics are
// properly registered with the registry.
func TestMetricsCollector_Registration(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)
	require.NotNil(t, mc)

	// Trigger each metric at least once so they appear in Gather()
	// CounterVec and HistogramVec metrics only appear after observation
	mc.RecordMessageSent("test", 1)
	mc.RecordConnectionOpened()
	mc.RecordError("test")
	mc.RecordMessageLatency("test", time.Millisecond)
	mc.RecordRoundDuration("1", time.Millisecond)
	mc.SessionStarted()

	// Gather all registered metrics
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	// Expected metric names
	expectedMetrics := map[string]bool{
		"frost_dkg_libp2p_messages_total":          false,
		"frost_dkg_libp2p_connections_total":       false,
		"frost_dkg_libp2p_bandwidth_bytes":         false,
		"frost_dkg_libp2p_errors_total":            false,
		"frost_dkg_libp2p_active_sessions":         false,
		"frost_dkg_libp2p_connected_peers":         false,
		"frost_dkg_libp2p_message_latency_seconds": false,
		"frost_dkg_libp2p_round_duration_seconds":  false,
	}

	for _, family := range families {
		if _, ok := expectedMetrics[family.GetName()]; ok {
			expectedMetrics[family.GetName()] = true
		}
	}

	for name, found := range expectedMetrics {
		assert.True(t, found, "expected metric %s not found in registry", name)
	}
}

// TestMetricsCollector_MessagesCounter verifies message counters work correctly.
func TestMetricsCollector_MessagesCounter(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Record messages
	mc.RecordMessageSent("session_info", 256)
	mc.RecordMessageSent("commitment", 512)
	mc.RecordMessageSent("commitment", 512)
	mc.RecordMessageReceived("share", 1024)
	mc.RecordMessageReceived("share", 1024)
	mc.RecordMessageReceived("share", 1024)

	// Verify counters
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	var messagesFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_messages_total" {
			messagesFamily = family
			break
		}
	}
	require.NotNil(t, messagesFamily)

	// Check individual label combinations
	metrics := messagesFamily.GetMetric()
	found := make(map[string]float64)
	for _, m := range metrics {
		labels := m.GetLabel()
		key := ""
		for _, l := range labels {
			key += l.GetName() + "=" + l.GetValue() + ","
		}
		found[key] = m.GetCounter().GetValue()
	}

	assert.Equal(t, float64(1), found["direction=sent,type=session_info,"])
	assert.Equal(t, float64(2), found["direction=sent,type=commitment,"])
	assert.Equal(t, float64(3), found["direction=received,type=share,"])
}

// TestMetricsCollector_ConnectionsCounter verifies connection counters work correctly.
func TestMetricsCollector_ConnectionsCounter(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Simulate connection lifecycle
	mc.RecordConnectionOpened()
	mc.RecordConnectionOpened()
	mc.RecordConnectionOpened()
	mc.RecordConnectionFailed()
	mc.RecordConnectionFailed()
	mc.RecordConnectionClosed()

	// Verify counters
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	var connectionsFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_connections_total" {
			connectionsFamily = family
			break
		}
	}
	require.NotNil(t, connectionsFamily)

	// Check individual status values
	metrics := connectionsFamily.GetMetric()
	found := make(map[string]float64)
	for _, m := range metrics {
		for _, l := range m.GetLabel() {
			if l.GetName() == "status" {
				found[l.GetValue()] = m.GetCounter().GetValue()
			}
		}
	}

	assert.Equal(t, float64(3), found["opened"])
	assert.Equal(t, float64(2), found["failed"])
	assert.Equal(t, float64(1), found["closed"])
}

// TestMetricsCollector_BandwidthCounter verifies bandwidth tracking works correctly.
func TestMetricsCollector_BandwidthCounter(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Record bandwidth
	mc.RecordMessageSent("test", 1024)
	mc.RecordMessageSent("test", 2048)
	mc.RecordMessageReceived("test", 512)

	// Verify counters
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	var bandwidthFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_bandwidth_bytes" {
			bandwidthFamily = family
			break
		}
	}
	require.NotNil(t, bandwidthFamily)

	// Check bandwidth values
	metrics := bandwidthFamily.GetMetric()
	found := make(map[string]float64)
	for _, m := range metrics {
		for _, l := range m.GetLabel() {
			if l.GetName() == "direction" {
				found[l.GetValue()] = m.GetCounter().GetValue()
			}
		}
	}

	assert.Equal(t, float64(3072), found["out"]) // 1024 + 2048
	assert.Equal(t, float64(512), found["in"])
}

// TestMetricsCollector_ErrorsCounter verifies error tracking works correctly.
func TestMetricsCollector_ErrorsCounter(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Record errors
	mc.RecordError("connection_timeout")
	mc.RecordError("connection_timeout")
	mc.RecordError("protocol_error")
	mc.RecordError("invalid_message")
	mc.RecordError("invalid_message")
	mc.RecordError("invalid_message")

	// Verify counters
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	var errorsFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_errors_total" {
			errorsFamily = family
			break
		}
	}
	require.NotNil(t, errorsFamily)

	// Check error values
	metrics := errorsFamily.GetMetric()
	found := make(map[string]float64)
	for _, m := range metrics {
		for _, l := range m.GetLabel() {
			if l.GetName() == "type" {
				found[l.GetValue()] = m.GetCounter().GetValue()
			}
		}
	}

	assert.Equal(t, float64(2), found["connection_timeout"])
	assert.Equal(t, float64(1), found["protocol_error"])
	assert.Equal(t, float64(3), found["invalid_message"])
}

// TestMetricsCollector_ActiveSessionsGauge verifies session tracking works correctly.
func TestMetricsCollector_ActiveSessionsGauge(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Initial state
	assert.Equal(t, int64(0), mc.GetActiveSessions())

	// Start sessions
	mc.SessionStarted()
	mc.SessionStarted()
	mc.SessionStarted()
	assert.Equal(t, int64(3), mc.GetActiveSessions())

	// End sessions
	mc.SessionEnded()
	assert.Equal(t, int64(2), mc.GetActiveSessions())

	// Set directly
	mc.SetActiveSessions(10)
	assert.Equal(t, int64(10), mc.GetActiveSessions())

	// Verify in registry
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	var sessionsFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_active_sessions" {
			sessionsFamily = family
			break
		}
	}
	require.NotNil(t, sessionsFamily)
	assert.Equal(t, float64(10), sessionsFamily.GetMetric()[0].GetGauge().GetValue())
}

// TestMetricsCollector_ConnectedPeersGauge verifies peer tracking works correctly.
func TestMetricsCollector_ConnectedPeersGauge(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Initial state
	assert.Equal(t, int64(0), mc.GetConnectedPeers())

	// Open connections
	mc.RecordConnectionOpened()
	mc.RecordConnectionOpened()
	mc.RecordConnectionOpened()
	assert.Equal(t, int64(3), mc.GetConnectedPeers())

	// Close connections
	mc.RecordConnectionClosed()
	assert.Equal(t, int64(2), mc.GetConnectedPeers())

	// Set directly
	mc.SetConnectedPeers(5)
	assert.Equal(t, int64(5), mc.GetConnectedPeers())

	// Verify in registry
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	var peersFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_connected_peers" {
			peersFamily = family
			break
		}
	}
	require.NotNil(t, peersFamily)
	assert.Equal(t, float64(5), peersFamily.GetMetric()[0].GetGauge().GetValue())
}

// TestMetricsCollector_GaugeUnderflow verifies gauges don't go negative.
func TestMetricsCollector_GaugeUnderflow(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Try to decrement from zero
	mc.SessionEnded()
	assert.Equal(t, int64(0), mc.GetActiveSessions())

	mc.RecordConnectionClosed()
	assert.Equal(t, int64(0), mc.GetConnectedPeers())
}

// TestMetricsCollector_MessageLatencyHistogram verifies latency histogram works correctly.
func TestMetricsCollector_MessageLatencyHistogram(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Record latencies
	mc.RecordMessageLatency("session_info", 1*time.Millisecond)
	mc.RecordMessageLatency("session_info", 5*time.Millisecond)
	mc.RecordMessageLatency("session_info", 10*time.Millisecond)
	mc.RecordMessageLatency("commitment", 50*time.Millisecond)

	// Verify histogram
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	var latencyFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_message_latency_seconds" {
			latencyFamily = family
			break
		}
	}
	require.NotNil(t, latencyFamily)

	// Verify we have data for both message types
	found := make(map[string]uint64)
	for _, m := range latencyFamily.GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetName() == "type" {
				found[l.GetValue()] = m.GetHistogram().GetSampleCount()
			}
		}
	}

	assert.Equal(t, uint64(3), found["session_info"])
	assert.Equal(t, uint64(1), found["commitment"])
}

// TestMetricsCollector_RoundDurationHistogram verifies round duration histogram works correctly.
func TestMetricsCollector_RoundDurationHistogram(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Record round durations
	mc.RecordRoundDuration("1", 500*time.Millisecond)
	mc.RecordRoundDuration("1", 750*time.Millisecond)
	mc.RecordRoundDuration("2", 1*time.Second)
	mc.RecordRoundDuration("2", 2*time.Second)
	mc.RecordRoundDuration("3", 5*time.Second)

	// Verify histogram
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	var roundFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_round_duration_seconds" {
			roundFamily = family
			break
		}
	}
	require.NotNil(t, roundFamily)

	// Verify we have data for all rounds
	found := make(map[string]uint64)
	for _, m := range roundFamily.GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetName() == "round" {
				found[l.GetValue()] = m.GetHistogram().GetSampleCount()
			}
		}
	}

	assert.Equal(t, uint64(2), found["1"])
	assert.Equal(t, uint64(2), found["2"])
	assert.Equal(t, uint64(1), found["3"])
}

// TestMetricsCollector_MessageTimer verifies the message timer helper works correctly.
func TestMetricsCollector_MessageTimer(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Use timer
	timer := mc.NewMessageTimer("test_operation")
	time.Sleep(10 * time.Millisecond)
	timer.Stop()

	// Verify histogram recorded
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	var latencyFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_message_latency_seconds" {
			latencyFamily = family
			break
		}
	}
	require.NotNil(t, latencyFamily)

	var sampleCount uint64
	for _, m := range latencyFamily.GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetName() == "type" && l.GetValue() == "test_operation" {
				sampleCount = m.GetHistogram().GetSampleCount()
			}
		}
	}
	assert.Equal(t, uint64(1), sampleCount)
}

// TestMetricsCollector_RoundTimer verifies the round timer helper works correctly.
func TestMetricsCollector_RoundTimer(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Use timer
	timer := mc.NewRoundTimer("round_1")
	time.Sleep(10 * time.Millisecond)
	timer.Stop()

	// Verify histogram recorded
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	var roundFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_round_duration_seconds" {
			roundFamily = family
			break
		}
	}
	require.NotNil(t, roundFamily)

	var sampleCount uint64
	for _, m := range roundFamily.GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetName() == "round" && l.GetValue() == "round_1" {
				sampleCount = m.GetHistogram().GetSampleCount()
			}
		}
	}
	assert.Equal(t, uint64(1), sampleCount)
}

// TestMetricsCollector_Reset verifies that reset clears all metrics.
func TestMetricsCollector_Reset(t *testing.T) {
	mc, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Record some data
	mc.RecordMessageSent("test", 100)
	mc.RecordConnectionOpened()
	mc.RecordError("test")
	mc.SessionStarted()

	// Verify data exists
	assert.Equal(t, int64(1), mc.GetActiveSessions())
	assert.Equal(t, int64(1), mc.GetConnectedPeers())

	// Reset
	mc.Reset()

	// Verify gauges are reset
	assert.Equal(t, int64(0), mc.GetActiveSessions())
	assert.Equal(t, int64(0), mc.GetConnectedPeers())
}

// TestMetricsCollector_HTTPServer verifies the HTTP endpoint works correctly.
func TestMetricsCollector_HTTPServer(t *testing.T) {
	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	_ = listener.Close()

	cfg := &MetricsConfig{
		Enabled:     true,
		Namespace:   "frost_dkg",
		Subsystem:   "libp2p",
		HTTPEnabled: true,
		HTTPAddr:    addr,
		HTTPPath:    "/metrics",
	}

	mc, err := NewMetricsCollector(cfg)
	require.NoError(t, err)
	require.NotNil(t, mc)

	// Start HTTP server
	ctx := context.Background()
	err = mc.StartHTTPServer(ctx)
	require.NoError(t, err)
	assert.True(t, mc.HTTPServerRunning())

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Record some metrics
	mc.RecordMessageSent("test", 100)
	mc.SessionStarted()

	// Make HTTP request to metrics endpoint
	resp, err := http.Get("http://" + addr + "/metrics")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	bodyStr := string(body)

	// Verify metrics are present
	assert.True(t, strings.Contains(bodyStr, "frost_dkg_libp2p_messages_total"))
	assert.True(t, strings.Contains(bodyStr, "frost_dkg_libp2p_active_sessions"))

	// Stop HTTP server
	err = mc.StopHTTPServer(ctx)
	require.NoError(t, err)
	assert.False(t, mc.HTTPServerRunning())
}

// TestMetricsCollector_HTTPServer_AlreadyStarted verifies that starting
// the HTTP server twice returns an error.
func TestMetricsCollector_HTTPServer_AlreadyStarted(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	_ = listener.Close()

	cfg := &MetricsConfig{
		Enabled:     true,
		HTTPEnabled: true,
		HTTPAddr:    addr,
	}

	mc, err := NewMetricsCollector(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Start first time
	err = mc.StartHTTPServer(ctx)
	require.NoError(t, err)

	// Start second time
	err = mc.StartHTTPServer(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMetricsAlreadyStarted))

	// Cleanup
	err = mc.StopHTTPServer(ctx)
	require.NoError(t, err)
}

// TestMetricsCollector_HTTPServer_Disabled verifies that HTTP server
// operations are no-ops when disabled.
func TestMetricsCollector_HTTPServer_Disabled(t *testing.T) {
	cfg := &MetricsConfig{
		Enabled:     true,
		HTTPEnabled: false,
	}

	mc, err := NewMetricsCollector(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Start should be no-op
	err = mc.StartHTTPServer(ctx)
	require.NoError(t, err)
	assert.False(t, mc.HTTPServerRunning())

	// Stop should be no-op
	err = mc.StopHTTPServer(ctx)
	require.NoError(t, err)
}

// TestMetricsCollector_HTTPServer_StopUnstarted verifies that stopping
// an unstarted HTTP server is a no-op.
func TestMetricsCollector_HTTPServer_StopUnstarted(t *testing.T) {
	cfg := &MetricsConfig{
		Enabled:     true,
		HTTPEnabled: true,
		HTTPAddr:    ":0",
	}

	mc, err := NewMetricsCollector(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Stop without starting should be no-op
	err = mc.StopHTTPServer(ctx)
	require.NoError(t, err)
}

// TestMetricsError_Error verifies the MetricsError type works correctly.
func TestMetricsError_Error(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		underlyingErr := errors.New("underlying error")
		err := &MetricsError{
			Op:  "register",
			Err: underlyingErr,
		}

		assert.Equal(t, "libp2p metrics register error: underlying error", err.Error())
		assert.Equal(t, underlyingErr, err.Unwrap())
	})

	t.Run("without underlying error", func(t *testing.T) {
		err := &MetricsError{
			Op:  "shutdown",
			Err: nil,
		}

		assert.Equal(t, "libp2p metrics shutdown error", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

// TestMetricsCollector_CustomNamespace verifies that custom namespace and
// subsystem are properly applied.
func TestMetricsCollector_CustomNamespace(t *testing.T) {
	cfg := &MetricsConfig{
		Enabled:   true,
		Namespace: "my_app",
		Subsystem: "dkg",
	}

	mc, err := NewMetricsCollector(cfg)
	require.NoError(t, err)

	// Record a metric
	mc.RecordMessageSent("test", 100)

	// Verify custom namespace
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	found := false
	for _, family := range families {
		if family.GetName() == "my_app_dkg_messages_total" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected metric with custom namespace not found")
}

// TestMetricsCollector_EmptyNamespaceDefaults verifies that empty namespace
// and subsystem use defaults.
func TestMetricsCollector_EmptyNamespaceDefaults(t *testing.T) {
	cfg := &MetricsConfig{
		Enabled:   true,
		Namespace: "",
		Subsystem: "",
	}

	mc, err := NewMetricsCollector(cfg)
	require.NoError(t, err)

	// Record a metric
	mc.RecordMessageSent("test", 100)

	// Verify default namespace/subsystem is used
	families, err := mc.Registry().Gather()
	require.NoError(t, err)

	found := false
	for _, family := range families {
		if family.GetName() == "frost_dkg_libp2p_messages_total" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected metric with default namespace not found")
}

// TestDefaultMetricsConfig verifies default configuration values.
func TestDefaultMetricsConfig(t *testing.T) {
	cfg := DefaultMetricsConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "frost_dkg", cfg.Namespace)
	assert.Equal(t, "libp2p", cfg.Subsystem)
	assert.Equal(t, "/metrics", cfg.HTTPPath)
	assert.NotEmpty(t, cfg.HistogramBuckets)
	assert.NotEmpty(t, cfg.RoundDurationBuckets)
}

// TestMetricsCollector_RegistryIsolation verifies that each collector
// has its own isolated registry.
func TestMetricsCollector_RegistryIsolation(t *testing.T) {
	mc1, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	mc2, err := NewMetricsCollector(DefaultMetricsConfig())
	require.NoError(t, err)

	// Record different values
	mc1.RecordMessageSent("test", 100)
	mc1.RecordMessageSent("test", 100)

	mc2.RecordMessageSent("test", 100)

	// Verify isolation
	assert.NotSame(t, mc1.Registry(), mc2.Registry())
	assert.NotSame(t, mc1.Registry(), prometheus.DefaultRegisterer)
}

// TestMetricsCollector_NilTimers verifies timers handle nil collectors.
func TestMetricsCollector_NilTimers(t *testing.T) {
	// MessageTimer with nil collector
	mt := &MessageTimer{
		collector: nil,
		msgType:   "test",
		startTime: time.Now(),
	}
	// Should not panic
	mt.Stop()

	// RoundTimer with nil collector
	rt := &RoundTimer{
		collector: nil,
		round:     "1",
		startTime: time.Now(),
	}
	// Should not panic
	rt.Stop()
}
