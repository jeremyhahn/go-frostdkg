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
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	ma "github.com/multiformats/go-multiaddr"
)

// DefaultCoordinatorPort is the TCP port a libp2p coordinator listens on when
// the configured address names no port.
const DefaultCoordinatorPort = 9000

// defaultListenHost is the interface a coordinator binds when the configured
// address names no host.
const defaultListenHost = "0.0.0.0"

// ListenMultiaddr converts a transport address into the multiaddr form libp2p
// requires for a listen address.
//
// The rest of the transport layer speaks "host:port" (transport.Config.Address)
// while libp2p speaks multiaddrs, and every conversion site needs the same
// three defaults. Accepted forms:
//
//   - "" — the whole default, /ip4/0.0.0.0/tcp/9000
//   - "host:port" — an IPv4 or IPv6 literal, or a DNS name
//   - "host" — the host with DefaultCoordinatorPort
//   - a multiaddr already ("/ip4/…") — validated and returned unchanged, so a
//     configuration written in libp2p's own notation keeps working
//
// An empty host means 0.0.0.0; an empty or zero port means
// DefaultCoordinatorPort. Port 0 is not honoured as "pick one" here: a
// coordinator has to publish an address participants can dial, and the
// ephemeral-port case is the participant's, not the coordinator's.
//
// A DNS name is RESOLVED here rather than rendered from its spelling, so this
// function does name lookup for that one input shape — see listenProtocol. A
// name that resolves to nothing is rejected as an invalid address, which is
// where it would fail anyway, only later and less legibly.
func ListenMultiaddr(address string) (string, error) {
	return listenMultiaddr(address, DefaultCoordinatorPort)
}

// ParticipantListenMultiaddr is ListenMultiaddr for a participant: a missing
// or zero port stays 0, so the OS picks an ephemeral port and a participant
// never collides with a coordinator on the same host.
func ParticipantListenMultiaddr(address string) (string, error) {
	return listenMultiaddr(address, 0)
}

// listenMultiaddr implements ListenMultiaddr with defaultPort standing in for
// a missing or zero port.
func listenMultiaddr(address string, defaultPort int) (string, error) {
	if address == "" {
		address = defaultListenHost
	}

	// A multiaddr is already in the target form; validate rather than reparse.
	if strings.HasPrefix(address, "/") {
		if _, err := ma.NewMultiaddr(address); err != nil {
			return "", transport.NewConnectionError(address, transport.ErrInvalidAddress)
		}
		return address, nil
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		// No port at all: the whole string is the host.
		host, portStr = address, ""
	}

	port := defaultPort
	if portStr != "" {
		parsed, err := strconv.Atoi(portStr)
		if err != nil || parsed < 0 || parsed > 65535 {
			return "", transport.NewConnectionError(address, transport.ErrInvalidAddress)
		}
		if parsed != 0 {
			port = parsed
		}
	}

	if host == "" {
		host = defaultListenHost
	}

	proto, err := listenProtocol(host)
	if err != nil {
		return "", transport.NewConnectionError(address, err)
	}

	maddr := "/" + proto + "/" + host + "/tcp/" + strconv.Itoa(port)
	if _, err := ma.NewMultiaddr(maddr); err != nil {
		return "", transport.NewConnectionError(address, transport.ErrInvalidAddress)
	}
	return maddr, nil
}

// listenProtocol returns the multiaddr protocol component for a listen host.
//
// An IP literal answers itself. A hostname has to be resolved, because the
// choice between dns4 and dns6 is not a property of the name: libp2p refuses
// the family-neutral /dns protocol for a listen address outright ("can only
// dial TCP over IPv4 or IPv6"), dns4 resolves A records only, and dns6 AAAA
// only — so naming an AAAA-only host as dns4 makes it unbindable.
func listenProtocol(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return "ip4", nil
		}
		return "ip6", nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", transport.ErrInvalidAddress
	}
	return dnsProtocolFor(ips)
}

// dnsProtocolFor picks the dns multiaddr protocol matching the address
// families a hostname actually resolved to, preferring IPv4 where the name
// offers both — that is the family libp2p's TCP listener reaches first, and
// picking the other one for a dual-stack name would change what an existing
// deployment binds.
func dnsProtocolFor(ips []net.IP) (string, error) {
	hasIPv6 := false
	for _, ip := range ips {
		if ip.To4() != nil {
			return "dns4", nil
		}
		hasIPv6 = true
	}
	if hasIPv6 {
		return "dns6", nil
	}
	return "", transport.ErrInvalidAddress
}
