// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-frostdkg.
//
// go-frostdkg is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or <https://www.gnu.org/licenses/agpl-3.0.html>
//
// 2. Commercial License
//    Contact: licensing@automatethethings.com
//
// SPDX-License-Identifier: AGPL-3.0 OR Commercial

package libp2p

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	ma "github.com/multiformats/go-multiaddr"
)

func freeLoopbackTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release the port: %v", err)
	}
	return port
}

// TestParticipantListensOnTheConfiguredAddress fails if the hardcoded
// /ip4/0.0.0.0/tcp/0 literal comes back: a loopback address must yield a
// host bound to loopback only, on the requested port.
func TestParticipantListensOnTheConfiguredAddress(t *testing.T) {
	port := freeLoopbackTCPPort(t)

	for name, address := range map[string]string{
		"host:port":  fmt.Sprintf("127.0.0.1:%d", port),
		"multiaddr":  fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port),
		"ephemeral":  "127.0.0.1:0",
		"ephemeral2": "/ip4/127.0.0.1/tcp/0",
	} {
		t.Run(name, func(t *testing.T) {
			p, err := NewP2PParticipantFromTransportConfig(&transport.Config{Address: address})
			if err != nil {
				t.Fatalf("create participant: %v", err)
			}
			defer func() { _ = p.Disconnect() }()

			addrs := p.host.Addrs()
			if len(addrs) == 0 {
				t.Fatal("participant host has no listen addresses")
			}
			for _, a := range addrs {
				if strings.Contains(a.String(), "0.0.0.0") {
					t.Errorf("participant bound a wildcard address: %s", a)
				}
				if !strings.HasPrefix(a.String(), "/ip4/127.0.0.1/") {
					t.Errorf("participant bound outside the configured interface: %s", a)
				}
			}
			if strings.HasSuffix(name, "port") || name == "multiaddr" {
				want := fmt.Sprintf("/tcp/%d", port)
				if !strings.Contains(addrs[0].String(), want) {
					t.Errorf("participant bound %s, want port %s", addrs[0], want)
				}
			}
		})
	}
}

// An unset address keeps the defaults layer: an ephemeral port on every
// interface, so a participant never collides with a coordinator's port.
func TestParticipantWithoutAddressUsesTheDefault(t *testing.T) {
	p, err := NewP2PParticipantFromTransportConfig(&transport.Config{})
	if err != nil {
		t.Fatalf("create participant: %v", err)
	}
	defer func() { _ = p.Disconnect() }()

	for _, a := range p.host.Addrs() {
		if strings.Contains(a.String(), "/tcp/9000") {
			t.Errorf("participant bound the coordinator default port: %s", a)
		}
	}
}

// Port 0 is the participant's "pick one": it must not be rewritten to the
// coordinator default, so the bound port is neither 0 nor 9000.
func TestParticipantKeepsAnEphemeralPort(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1"} {
		p, err := NewP2PParticipantFromTransportConfig(&transport.Config{Address: address})
		if err != nil {
			t.Fatalf("create participant for %q: %v", address, err)
		}
		addrs := p.host.Addrs()
		if len(addrs) == 0 {
			_ = p.Disconnect()
			t.Fatalf("participant for %q has no listen addresses", address)
		}
		for _, a := range addrs {
			port, err := a.ValueForProtocol(ma.P_TCP)
			if err != nil {
				t.Errorf("address %s has no tcp port: %v", a, err)
				continue
			}
			if port == "0" || port == "9000" {
				t.Errorf("participant for %q bound port %s, want an ephemeral port", address, port)
			}
		}
		_ = p.Disconnect()
	}
}

func TestParticipantRejectsAnUnusableAddress(t *testing.T) {
	if _, err := NewP2PParticipantFromTransportConfig(&transport.Config{Address: "/not/a/multiaddr"}); err == nil {
		t.Fatal("expected an error for an invalid listen address")
	}
}
