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

package dkg

import (
	"strings"
	"testing"
)

func TestFaultyParticipantError(t *testing.T) {
	t.Run("error_message_format", func(t *testing.T) {
		err := NewFaultyParticipantError(5, "invalid commitment")
		msg := err.Error()

		if !strings.Contains(msg, "participant 5") {
			t.Errorf("Error message should contain participant index, got: %s", msg)
		}
		if !strings.Contains(msg, "invalid commitment") {
			t.Errorf("Error message should contain reason, got: %s", msg)
		}
		if !strings.Contains(msg, "faulty") {
			t.Errorf("Error message should contain 'faulty', got: %s", msg)
		}
	})

	t.Run("different_indices", func(t *testing.T) {
		err0 := NewFaultyParticipantError(0, "reason")
		err1 := NewFaultyParticipantError(1, "reason")

		if err0.ParticipantIndex != 0 {
			t.Errorf("Expected index 0, got %d", err0.ParticipantIndex)
		}
		if err1.ParticipantIndex != 1 {
			t.Errorf("Expected index 1, got %d", err1.ParticipantIndex)
		}
	})
}

func TestFaultyCoordinatorError(t *testing.T) {
	t.Run("error_message_format", func(t *testing.T) {
		err := NewFaultyCoordinatorError("modified commitments")
		msg := err.Error()

		if !strings.Contains(msg, "coordinator") {
			t.Errorf("Error message should contain 'coordinator', got: %s", msg)
		}
		if !strings.Contains(msg, "modified commitments") {
			t.Errorf("Error message should contain reason, got: %s", msg)
		}
		if !strings.Contains(msg, "faulty") {
			t.Errorf("Error message should contain 'faulty', got: %s", msg)
		}
	})

	t.Run("stores_reason", func(t *testing.T) {
		err := NewFaultyCoordinatorError("test reason")
		if err.Reason != "test reason" {
			t.Errorf("Expected reason 'test reason', got '%s'", err.Reason)
		}
	})
}

func TestUnknownFaultyPartyError(t *testing.T) {
	t.Run("error_message_format", func(t *testing.T) {
		invData := &ParticipantInvestigationData{
			SimplInvData: &SimplPedPopInvestigationData{
				Idx: 3,
			},
		}
		err := NewUnknownFaultyPartyError(invData, "share verification failed")
		msg := err.Error()

		if !strings.Contains(msg, "unknown faulty party") {
			t.Errorf("Error message should contain 'unknown faulty party', got: %s", msg)
		}
		if !strings.Contains(msg, "share verification failed") {
			t.Errorf("Error message should contain reason, got: %s", msg)
		}
	})

	t.Run("stores_investigation_data", func(t *testing.T) {
		invData := &ParticipantInvestigationData{
			SimplInvData: &SimplPedPopInvestigationData{
				Idx: 7,
			},
		}
		err := NewUnknownFaultyPartyError(invData, "reason")

		if err.InvestigationData == nil {
			t.Error("InvestigationData should not be nil")
		}
		if err.InvestigationData.SimplInvData.Idx != 7 {
			t.Errorf("Expected participant index 7, got %d", err.InvestigationData.SimplInvData.Idx)
		}
	})

	t.Run("nil_investigation_data", func(t *testing.T) {
		err := NewUnknownFaultyPartyError(nil, "reason")
		if err.InvestigationData != nil {
			t.Error("InvestigationData should be nil")
		}
		// Should not panic when calling Error()
		_ = err.Error()
	})
}

func TestValidationConstants(t *testing.T) {
	t.Run("min_threshold", func(t *testing.T) {
		if MinThreshold != 2 {
			t.Errorf("MinThreshold should be 2, got %d", MinThreshold)
		}
	})

	t.Run("min_participants", func(t *testing.T) {
		if MinParticipants != 2 {
			t.Errorf("MinParticipants should be 2, got %d", MinParticipants)
		}
	})

	t.Run("max_participants", func(t *testing.T) {
		if MaxParticipants != 65535 {
			t.Errorf("MaxParticipants should be 65535, got %d", MaxParticipants)
		}
	})
}
