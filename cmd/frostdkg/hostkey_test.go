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
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/stretchr/testify/require"
)

// These tests check the sealed secret is correct and failure paths return no secret.

func TestLoadHostSecretKey_SealsTheProvidedKey(t *testing.T) {
	key := make([]byte, transport.SecretKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}

	sealed, err := loadHostSecretKey(hex.EncodeToString(key), false)
	require.NoError(t, err)
	require.NotNil(t, sealed)
	t.Cleanup(sealed.Destroy)

	require.Equal(t, transport.SecretKeySize, sealed.Size())
	require.NoError(t, secmem.WithSecret(sealed, func(got []byte) error {
		require.True(t, bytes.Equal(key, got), "the sealed key must be the one supplied")
		return nil
	}))
}

func TestLoadHostSecretKey_GeneratesWhenNoneGiven(t *testing.T) {
	first, err := loadHostSecretKey("", false)
	require.NoError(t, err)
	require.NotNil(t, first)
	t.Cleanup(first.Destroy)
	require.Equal(t, transport.SecretKeySize, first.Size())

	second, err := loadHostSecretKey("", false)
	require.NoError(t, err)
	t.Cleanup(second.Destroy)

	// Two generated keys must differ; a constant would pass every other check.
	var a, b []byte
	require.NoError(t, secmem.WithSecret(first, func(k []byte) error {
		a = append([]byte(nil), k...)
		return nil
	}))
	require.NoError(t, secmem.WithSecret(second, func(k []byte) error {
		b = append([]byte(nil), k...)
		return nil
	}))
	require.False(t, bytes.Equal(a, b), "generated host keys must not repeat")
}

func TestLoadHostSecretKey_RejectsBadInputWithoutReturningASecret(t *testing.T) {
	tests := []struct {
		name   string
		hexKey string
	}{
		{"not hex", "zzzz"},
		{"too short", hex.EncodeToString(make([]byte, 16))},
		{"too long", hex.EncodeToString(make([]byte, 64))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sealed, err := loadHostSecretKey(tt.hexKey, false)
			require.Error(t, err)
			require.Nil(t, sealed, "a rejected key must not leave a sealed secret behind")
		})
	}
}

// TestRunParticipant_DoesNotWriteThroughTheHostkeyFlag checks the --hostkey string is left unchanged: writing through a string header is unsound.
func TestRunParticipant_DoesNotWriteThroughTheHostkeyFlag(t *testing.T) {
	original := participantHostkey
	originalProtocol := protocol
	t.Cleanup(func() {
		participantHostkey = original
		protocol = originalProtocol
	})

	key := make([]byte, transport.SecretKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	secretHex := hex.EncodeToString(key)
	// An independent copy, so an in-place scrub cannot wipe the expected value.
	expected := string(append([]byte(nil), secretHex...))
	participantHostkey = secretHex

	participantThreshold = 2
	participantID = 0
	participantTimeout = 1
	protocol = "grpc"

	// The DKG itself cannot run here; the flag must survive regardless.
	_ = runParticipant(participantCmd, nil)

	require.Equal(t, expected, participantHostkey,
		"runParticipant must not write through the flag's string header")
}

// TestRunParticipant_ToleratesALiteralHostkey is the crash this decision
// avoids: an invalid --hostkey is often a literal, and any write through it
// faults on read-only memory rather than returning an error.
func TestRunParticipant_ToleratesALiteralHostkey(t *testing.T) {
	original := participantHostkey
	originalProtocol := protocol
	t.Cleanup(func() {
		participantHostkey = original
		protocol = originalProtocol
	})

	participantHostkey = "not-valid-hex" // a literal: read-only backing array
	participantThreshold = 2
	participantID = 0
	participantTimeout = 1
	protocol = "grpc"

	err := runParticipant(participantCmd, nil)

	require.Error(t, err, "an invalid hostkey must be rejected, not fatal")
	require.Equal(t, "not-valid-hex", participantHostkey)
}

func TestGenerateSessionRandomness_SealsAndDiffers(t *testing.T) {
	first, err := generateSessionRandomness()
	require.NoError(t, err)
	require.NotNil(t, first)
	t.Cleanup(first.Destroy)
	require.Equal(t, transport.SecretKeySize, first.Size())

	second, err := generateSessionRandomness()
	require.NoError(t, err)
	t.Cleanup(second.Destroy)

	var a, b []byte
	require.NoError(t, secmem.WithSecret(first, func(r []byte) error {
		a = append([]byte(nil), r...)
		return nil
	}))
	require.NoError(t, secmem.WithSecret(second, func(r []byte) error {
		b = append([]byte(nil), r...)
		return nil
	}))
	require.False(t, bytes.Equal(a, b), "session randomness must not repeat")
	require.NotEqual(t, make([]byte, transport.SecretKeySize), a, "randomness must not be all zero")
}
