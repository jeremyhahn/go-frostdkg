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
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const (
	// ProtocolID is the DKG protocol identifier.
	ProtocolID = protocol.ID("/frost-dkg/1.0.0")

	// MaxMessageSize is the maximum message size (10MB).
	MaxMessageSize = 10 * 1024 * 1024
)

// safeUint32 safely converts a non-negative int to uint32.
// Returns 0 if the input is negative or exceeds MaxUint32.
func safeUint32(n int) uint32 {
	if n < 0 || n > int(^uint32(0)) {
		return 0
	}
	return uint32(n)
}

// safeInt32 safely converts a non-negative int to int32.
// Returns 0 if the input is negative or exceeds MaxInt32.
func safeInt32(n int) int32 {
	if n < 0 || n > int(^uint32(0)>>1) {
		return 0
	}
	return int32(n)
}

// StreamHandler handles incoming streams for a protocol.
type StreamHandler func(network.Stream)

// WriteMessage writes a length-prefixed message to a stream.
// Format: [4-byte length][message data]
func WriteMessage(stream network.Stream, data []byte) error {
	if len(data) > MaxMessageSize {
		return fmt.Errorf("message size %d exceeds maximum %d", len(data), MaxMessageSize)
	}

	// Write 4-byte length prefix
	// Length is bounded by MaxMessageSize check above, safe for uint32
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, safeUint32(len(data)))

	if _, err := stream.Write(lengthBuf); err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}

	// Write message data
	if _, err := stream.Write(data); err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}

	return nil
}

// ReadMessage reads a length-prefixed message from a stream.
// Format: [4-byte length][message data]
func ReadMessage(stream network.Stream) ([]byte, error) {
	reader := bufio.NewReader(stream)

	// Read 4-byte length prefix
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(reader, lengthBuf); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	if length > MaxMessageSize {
		return nil, fmt.Errorf("message size %d exceeds maximum %d", length, MaxMessageSize)
	}

	if length == 0 {
		return []byte{}, nil
	}

	// Read message data
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("failed to read message data: %w", err)
	}

	return data, nil
}

// OpenStream opens a new stream to a peer with the DKG protocol.
func OpenStream(ctx context.Context, host *DKGHost, peerIDStr string) (network.Stream, error) {
	peerID, err := peer.Decode(peerIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode peer ID %s: %w", peerIDStr, err)
	}

	stream, err := host.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream to peer %s: %w", peerIDStr, err)
	}
	return stream, nil
}
