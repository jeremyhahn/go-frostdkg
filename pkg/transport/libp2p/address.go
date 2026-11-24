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

// ListenMultiaddr converts "", "host:port", "host" or a multiaddr to a libp2p listen multiaddr (default 0.0.0.0:DefaultCoordinatorPort); DNS names are resolved.
func ListenMultiaddr(address string) (string, error) {
	return listenMultiaddr(address, DefaultCoordinatorPort)
}

// ParticipantListenMultiaddr is ListenMultiaddr with a missing or zero port left 0, so the OS picks one.
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

// listenProtocol returns the multiaddr protocol for a listen host, resolving hostnames to choose dns4 or dns6.
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

// dnsProtocolFor picks dns4 or dns6 from the resolved families, preferring IPv4.
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
