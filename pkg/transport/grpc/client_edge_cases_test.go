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

package grpc

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/grpc/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Mock for gRPC stream
type MockDKGStream struct {
	mock.Mock
}

func (m *MockDKGStream) Send(msg *proto.DKGMessage) error {
	args := m.Called(msg)
	return args.Error(0)
}

func (m *MockDKGStream) Recv() (*proto.DKGMessage, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*proto.DKGMessage), args.Error(1)
}

func (m *MockDKGStream) CloseSend() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDKGStream) Header() (metadata.MD, error) {
	args := m.Called()
	return nil, args.Error(0)
}

func (m *MockDKGStream) Trailer() metadata.MD {
	return nil
}

func (m *MockDKGStream) Context() context.Context {
	return context.Background()
}

func (m *MockDKGStream) SendMsg(msg interface{}) error {
	return nil
}

func (m *MockDKGStream) RecvMsg(msg interface{}) error {
	return nil
}

// Test hasScheme function with various URL formats
func TestHasScheme(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "valid http scheme",
			addr:     "http://localhost:8080",
			expected: true,
		},
		{
			name:     "valid https scheme",
			addr:     "https://example.com",
			expected: true,
		},
		{
			name:     "valid dns scheme",
			addr:     "dns:///localhost:8080",
			expected: true,
		},
		{
			name:     "valid unix scheme",
			addr:     "unix:///tmp/socket",
			expected: true,
		},
		{
			name:     "no scheme - hostname only",
			addr:     "localhost",
			expected: false,
		},
		{
			name:     "no scheme - hostname with port",
			addr:     "localhost:8080",
			expected: false,
		},
		{
			name:     "no scheme - IP address",
			addr:     "127.0.0.1:8080",
			expected: false,
		},
		{
			name:     "invalid - colon without slashes",
			addr:     "localhost:8080/path",
			expected: false,
		},
		{
			name:     "invalid - single slash after colon",
			addr:     "http:/localhost",
			expected: false,
		},
		{
			name:     "empty string",
			addr:     "",
			expected: false,
		},
		{
			name:     "scheme with special characters",
			addr:     "grpc+tls://localhost:8080",
			expected: true,
		},
		{
			name:     "scheme starting with digit - accepted by implementation",
			addr:     "1http://localhost",
			expected: true,
		},
		{
			name:     "only colon",
			addr:     ":",
			expected: false,
		},
		{
			name:     "colon at start",
			addr:     ":8080",
			expected: false,
		},
		{
			name:     "scheme with dash",
			addr:     "my-scheme://localhost",
			expected: true,
		},
		{
			name:     "scheme with dot",
			addr:     "my.scheme://localhost",
			expected: true,
		},
		{
			name:     "scheme with plus",
			addr:     "grpc+unix://localhost",
			expected: true,
		},
		{
			name:     "invalid character in scheme",
			addr:     "my_scheme://localhost",
			expected: false,
		},
		{
			name:     "ipv6 address without scheme",
			addr:     "[::1]:8080",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasScheme(tt.addr)
			assert.Equal(t, tt.expected, result, "hasScheme(%q) = %v, want %v", tt.addr, result, tt.expected)
		})
	}
}

// Test waitForReady with timeout
func TestWaitForReady_Timeout(t *testing.T) {
	// Create a client connection to a non-existent server
	ctx := context.Background()
	conn, err := grpc.NewClient("localhost:99999", grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Create a very short timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()

	// Connection should not become ready within timeout
	result := waitForReady(timeoutCtx, conn)
	assert.False(t, result, "waitForReady should return false on timeout")
}

// Test waitForReady with shutdown state
func TestWaitForReady_Shutdown(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.NewClient("localhost:99999", grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.NoError(t, err)

	// Close the connection to force shutdown state
	_ = conn.Close()

	// Wait a bit for state to transition
	time.Sleep(50 * time.Millisecond)

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	result := waitForReady(timeoutCtx, conn)
	assert.False(t, result, "waitForReady should return false for shutdown state")
}

// Test Connect error paths
func TestGRPCClient_Connect_ErrorPaths(t *testing.T) {
	t.Run("already connected", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)
		client.connected.Store(true)

		ctx := context.Background()
		err = client.Connect(ctx, "localhost:8080")
		assert.ErrorIs(t, err, transport.ErrAlreadyConnected)
	})

	t.Run("connection timeout", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
			Timeout:  1 * time.Millisecond, // Very short timeout
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		ctx := context.Background()
		err = client.Connect(ctx, "localhost:99999")
		assert.Error(t, err)
	})

	t.Run("invalid TLS config", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol:    transport.ProtocolGRPC,
			TLSCertFile: "/nonexistent/cert.pem",
			TLSKeyFile:  "/nonexistent/key.pem",
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		ctx := context.Background()
		err = client.Connect(ctx, "localhost:8080")
		assert.Error(t, err)
	})
}

// Test Disconnect error paths
func TestGRPCClient_Disconnect_ErrorPaths(t *testing.T) {
	t.Run("not connected", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		err = client.Disconnect()
		assert.ErrorIs(t, err, transport.ErrNotConnected)
	})

	t.Run("stream close error - continues cleanup", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		// Set up client in connected state with mock stream
		client.connected.Store(true)
		mockStream := new(MockDKGStream)
		mockStream.On("CloseSend").Return(errors.New("stream close error")).Once()
		client.stream = mockStream
		client.shutdownChan = make(chan struct{})

		// Should complete without error despite stream close error
		err = client.Disconnect()
		assert.NoError(t, err)
		mockStream.AssertExpectations(t)
	})
}

// Test receiveMessages edge cases
func TestGRPCClient_ReceiveMessages_EdgeCases(t *testing.T) {
	t.Run("shutdown signal", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		mockStream := new(MockDKGStream)
		client.stream = mockStream
		client.shutdownChan = make(chan struct{})

		// Close shutdown channel to trigger return
		close(client.shutdownChan)

		client.wg.Add(1)
		client.receiveMessages()
		// Should return immediately without calling Recv
	})

	t.Run("recv error", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		mockStream := new(MockDKGStream)
		testErr := errors.New("recv error")
		mockStream.On("Recv").Return(nil, testErr).Once()
		client.stream = mockStream
		client.shutdownChan = make(chan struct{})

		client.wg.Add(1)
		go client.receiveMessages()

		// Wait for error to be sent
		select {
		case receivedErr := <-client.errorChan:
			assert.Equal(t, testErr, receivedErr)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for error")
		}

		client.wg.Wait()
		mockStream.AssertExpectations(t)
	})

	t.Run("shutdown during error send", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		mockStream := new(MockDKGStream)
		mockStream.On("Recv").Return(nil, io.EOF).Once()
		client.stream = mockStream
		client.shutdownChan = make(chan struct{})

		client.wg.Add(1)
		go client.receiveMessages()

		// Close shutdown immediately to trigger shutdown path during error send
		time.Sleep(10 * time.Millisecond)
		close(client.shutdownChan)

		client.wg.Wait()
		mockStream.AssertExpectations(t)
	})

	t.Run("successful message receive", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		mockStream := new(MockDKGStream)
		testMsg := &proto.DKGMessage{
			SessionId: "test",
			Type:      proto.MessageType_MSG_TYPE_SESSION_INFO,
		}
		mockStream.On("Recv").Return(testMsg, nil).Once()
		// Add a second call that blocks so goroutine doesn't panic on unexpected call
		mockStream.On("Recv").Return(nil, io.EOF).Once()
		client.stream = mockStream
		client.shutdownChan = make(chan struct{})

		client.wg.Add(1)
		go client.receiveMessages()

		// Read the message from the channel
		select {
		case msg := <-client.incomingChan:
			assert.Equal(t, testMsg, msg)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for message")
		}

		// Close shutdown to stop goroutine
		close(client.shutdownChan)
		client.wg.Wait()
		mockStream.AssertExpectations(t)
	})
}

// Test sendJoin error handling
func TestGRPCClient_SendJoin_ErrorHandling(t *testing.T) {
	t.Run("serialization error", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol:  transport.ProtocolGRPC,
			CodecType: "invalid_codec",
		}
		_, err := NewGRPCClient(cfg)
		// Should fail to create serializer
		assert.Error(t, err)
	})

	t.Run("stream send error", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol:  transport.ProtocolGRPC,
			CodecType: "json",
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		mockStream := new(MockDKGStream)
		sendErr := errors.New("send error")
		mockStream.On("Send", mock.Anything).Return(sendErr).Once()
		client.stream = mockStream

		params := generateTestParams(3, 2, 0)
		err = client.sendJoin(params)
		assert.Equal(t, sendErr, err)
		mockStream.AssertExpectations(t)
	})
}

// Test waitForSessionInfo edge cases
func TestGRPCClient_WaitForSessionInfo_EdgeCases(t *testing.T) {
	t.Run("context timeout", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err = client.waitForSessionInfo(ctx)
		assert.ErrorIs(t, err, transport.ErrSessionTimeout)
	})

	t.Run("error from channel", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		ctx := context.Background()
		testErr := errors.New("test error")

		go func() {
			client.errorChan <- testErr
		}()

		_, err = client.waitForSessionInfo(ctx)
		assert.Equal(t, testErr, err)
	})

	t.Run("wrong message type", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		ctx := context.Background()
		wrongMsg := &proto.DKGMessage{
			Type: proto.MessageType_MSG_TYPE_JOIN,
		}

		go func() {
			client.incomingChan <- wrongMsg
		}()

		_, err = client.waitForSessionInfo(ctx)
		assert.ErrorIs(t, err, transport.ErrUnexpectedMessage)
	})

	t.Run("invalid payload deserialization", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol:  transport.ProtocolGRPC,
			CodecType: "json",
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		ctx := context.Background()
		invalidMsg := &proto.DKGMessage{
			Type:    proto.MessageType_MSG_TYPE_SESSION_INFO,
			Payload: []byte("invalid json"),
		}

		go func() {
			client.incomingChan <- invalidMsg
		}()

		_, err = client.waitForSessionInfo(ctx)
		assert.Error(t, err)
	})
}

// Test RunDKG error paths
func TestGRPCClient_RunDKG_ErrorPaths(t *testing.T) {
	t.Run("not connected", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		params := generateTestParams(3, 2, 0)
		ctx := context.Background()

		_, err = client.RunDKG(ctx, params)
		assert.ErrorIs(t, err, transport.ErrNotConnected)
	})

	t.Run("invalid params", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)
		client.connected.Store(true)

		invalidParams := &transport.DKGParams{
			HostSeckey:     make([]byte, 10), // Invalid length
			ParticipantIdx: 0,
		}
		ctx := context.Background()

		_, err = client.RunDKG(ctx, invalidParams)
		assert.ErrorIs(t, err, transport.ErrInvalidHostKey)
	})
}

// Test timeout handling in Connect
func TestGRPCClient_Connect_TimeoutHandling(t *testing.T) {
	t.Run("custom timeout applied", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
			Timeout:  100 * time.Millisecond,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		timeout := client.getTimeout()
		assert.Equal(t, 100*time.Millisecond, timeout)
	})

	t.Run("default timeout used", func(t *testing.T) {
		cfg := &transport.Config{
			Protocol: transport.ProtocolGRPC,
		}
		client, err := NewGRPCClient(cfg)
		assert.NoError(t, err)

		timeout := client.getTimeout()
		assert.Equal(t, 30*time.Second, timeout)
	})
}

// Test Connect with different address formats
func TestGRPCClient_Connect_AddressFormats(t *testing.T) {
	tests := []struct {
		name     string
		protocol transport.Protocol
		addr     string
		hasError bool
	}{
		{
			name:     "unix socket address",
			protocol: transport.ProtocolUnix,
			addr:     "/tmp/test.sock",
			hasError: true, // Will fail to connect but tests address handling
		},
		{
			name:     "address with scheme",
			protocol: transport.ProtocolGRPC,
			addr:     "dns:///localhost:8080",
			hasError: true,
		},
		{
			name:     "address without scheme",
			protocol: transport.ProtocolGRPC,
			addr:     "localhost:8080",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &transport.Config{
				Protocol: tt.protocol,
				Timeout:  10 * time.Millisecond,
			}
			client, err := NewGRPCClient(cfg)
			assert.NoError(t, err)

			ctx := context.Background()
			err = client.Connect(ctx, tt.addr)
			if tt.hasError {
				assert.Error(t, err)
			}
		})
	}
}
