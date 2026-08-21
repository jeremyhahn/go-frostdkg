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

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestListenMultiaddr(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
	}{
		{"empty address takes the whole default", "", "/ip4/0.0.0.0/tcp/9000"},
		{"host and port are both honoured", "127.0.0.1:7777", "/ip4/127.0.0.1/tcp/7777"},
		{"the default port is 9000", "10.0.0.4", "/ip4/10.0.0.4/tcp/9000"},
		{"an empty port falls back to 9000", "10.0.0.4:", "/ip4/10.0.0.4/tcp/9000"},
		{"an empty host binds every interface", ":7777", "/ip4/0.0.0.0/tcp/7777"},
		{"port 0 is not an ephemeral request", "0.0.0.0:0", "/ip4/0.0.0.0/tcp/9000"},
		{"IPv6 gets the ip6 component", "[::1]:7777", "/ip6/::1/tcp/7777"},
		{"an IPv4-resolvable DNS name gets dns4", "localhost:7777", "/dns4/localhost/tcp/7777"},
		{"a multiaddr passes through", "/ip4/192.168.1.5/tcp/4001", "/ip4/192.168.1.5/tcp/4001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ListenMultiaddr(tt.address)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)

			_, err = ma.NewMultiaddr(got)
			require.NoError(t, err, "the result must be a multiaddr libp2p can listen on")
		})
	}
}

func TestListenMultiaddr_RejectsUnusableAddresses(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{"a non-numeric port", "127.0.0.1:http"},
		{"a port above the range", "127.0.0.1:70000"},
		{"a malformed multiaddr", "/ip4/not-an-ip/tcp/9000"},
		{"an unknown multiaddr protocol", "/nope/127.0.0.1/tcp/9000"},
		{"a hostname that resolves to nothing", "no-such-host.invalid:9000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ListenMultiaddr(tt.address)
			require.ErrorIs(t, err, transport.ErrInvalidAddress)
		})
	}
}

// TestDNSProtocolFor is where the address-family choice is pinned. It takes
// resolved addresses rather than a hostname on purpose: an AAAA-only name is
// not something a test can conjure hermetically, and the decision being tested
// is the family one, not the lookup.
//
// The family matters because libp2p refuses the neutral /dns protocol for a
// listen address ("can only dial TCP over IPv4 or IPv6"), so the multiaddr has
// to commit to dns4 or dns6, and committing to dns4 for an AAAA-only host
// makes it unbindable.
func TestDNSProtocolFor(t *testing.T) {
	tests := []struct {
		name string
		ips  []net.IP
		want string
	}{
		{"IPv4 only", []net.IP{net.ParseIP("192.0.2.1")}, "dns4"},
		{"IPv6 only", []net.IP{net.ParseIP("2001:db8::1")}, "dns6"},
		{"dual stack prefers IPv4", []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1")}, "dns4"},
		{"IPv4-mapped IPv6 counts as IPv4", []net.IP{net.ParseIP("::ffff:192.0.2.1")}, "dns4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnsProtocolFor(tt.ips)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDNSProtocolFor_RejectsNoAddresses(t *testing.T) {
	_, err := dnsProtocolFor(nil)
	require.ErrorIs(t, err, transport.ErrInvalidAddress)
}

// TestListenMultiaddr_DefaultPortConstant pins the documented default so a
// change to it is a deliberate edit rather than a silent drift.
func TestListenMultiaddr_DefaultPortConstant(t *testing.T) {
	require.Equal(t, 9000, DefaultCoordinatorPort)
}
