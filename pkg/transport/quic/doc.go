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

// Package quic provides the QUIC transport for FROST DKG.
//
// EXPERIMENTAL — this transport does NOT run the DKG ceremony. It implements
// connection setup, session join and message relay only; Participant.RunDKG
// returns transport.ErrDKGNotImplemented and no key material.
//
// Until v0.3.0-alpha RunDKG returned a DKGResult built from a fixed pattern
// derived from the participant index, with a nil error — indistinguishable
// from a real ceremony and reconstructable by anyone. Failing closed replaces
// that. Wiring this transport to the real pkg/dkg driver is tracked as
// software task #61.
//
// See package transport for the full statement.
package quic
