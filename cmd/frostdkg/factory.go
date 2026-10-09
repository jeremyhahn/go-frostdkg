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

package main

import (
	"fmt"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/grpc"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/http"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/libp2p"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport/quic"
)

// TransportFactory creates transport layer components (coordinators and participants).
// This interface enables dependency injection for testing.
type TransportFactory interface {
	// NewParticipant creates a new participant for the given protocol.
	NewParticipant(protocol transport.Protocol, cfg *transport.Config) (transport.Participant, error)

	// NewCoordinator creates a new coordinator for the given protocol.
	NewCoordinator(protocol transport.Protocol, cfg *transport.Config, sessionCfg *transport.SessionConfig, sessionID string) (transport.Coordinator, error)
}

// DefaultTransportFactory implements TransportFactory using real transport implementations.
type DefaultTransportFactory struct{}

// NewParticipant creates a participant based on the protocol.
func (f *DefaultTransportFactory) NewParticipant(proto transport.Protocol, cfg *transport.Config) (transport.Participant, error) {
	switch proto {
	case transport.ProtocolGRPC, transport.ProtocolUnix:
		return grpc.NewGRPCClient(cfg)
	case transport.ProtocolHTTP:
		return http.NewHTTPClient(cfg)
	case transport.ProtocolQUIC:
		return quic.NewQUICClient(cfg)
	case transport.ProtocolLibp2p:
		return libp2p.NewP2PParticipantFromTransportConfig(cfg)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s (supported: grpc, http, quic, unix, libp2p)", proto)
	}
}

// NewCoordinator creates a coordinator based on the protocol.
func (f *DefaultTransportFactory) NewCoordinator(proto transport.Protocol, cfg *transport.Config, sessionCfg *transport.SessionConfig, sessionID string) (transport.Coordinator, error) {
	switch proto {
	case transport.ProtocolGRPC, transport.ProtocolUnix:
		return grpc.NewGRPCServer(cfg, sessionCfg)
	case transport.ProtocolHTTP:
		return http.NewHTTPServer(cfg, sessionCfg, sessionID)
	case transport.ProtocolQUIC:
		return quic.NewQUICServer(cfg, sessionCfg)
	case transport.ProtocolLibp2p:
		listenAddr, err := libp2p.ListenMultiaddr(cfg.Address)
		if err != nil {
			return nil, err
		}
		hostCfg := libp2p.DefaultHostConfig()
		hostCfg.ListenAddrs = []string{listenAddr}
		return libp2p.NewP2PCoordinator(sessionID, sessionCfg, hostCfg)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s (supported: grpc, http, quic, unix, libp2p)", proto)
	}
}

// Default factory instance used by the package.
// Can be overridden in tests for dependency injection.
var defaultFactory TransportFactory = &DefaultTransportFactory{}
