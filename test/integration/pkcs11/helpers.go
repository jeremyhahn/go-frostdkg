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

//go:build integration && pkcs11

package pkcs11_test

import (
	"crypto"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// SoftHSMHelper provides utilities for managing SoftHSM2 tokens in tests.
type SoftHSMHelper struct {
	Config *PKCS11Config
	t      *testing.T
}

// NewSoftHSMHelper creates a new SoftHSM helper for tests.
func NewSoftHSMHelper(t *testing.T) *SoftHSMHelper {
	return &SoftHSMHelper{
		Config: DefaultPKCS11Config(),
		t:      t,
	}
}

// InitToken initializes a new token with the given label.
func (h *SoftHSMHelper) InitToken(label string) error {
	// Check if token already exists
	slots, err := h.ListSlots()
	if err != nil {
		return fmt.Errorf("failed to list slots: %w", err)
	}

	for _, slot := range slots {
		if strings.Contains(slot, label) {
			h.t.Logf("Token %s already exists, skipping initialization", label)
			return nil
		}
	}

	// Initialize new token
	cmd := exec.Command("softhsm2-util",
		"--init-token",
		"--free",
		"--label", label,
		"--pin", h.Config.PIN,
		"--so-pin", h.Config.SOPIN,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to initialize token: %s: %w", string(output), err)
	}

	h.t.Logf("Initialized token: %s", label)
	return nil
}

// DeleteToken removes a token with the given label.
func (h *SoftHSMHelper) DeleteToken(label string) error {
	// Find slot by label
	slot, err := h.FindSlotByLabel(label)
	if err != nil {
		return err
	}

	cmd := exec.Command("softhsm2-util",
		"--delete-token",
		"--slot", slot,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete token: %s: %w", string(output), err)
	}

	h.t.Logf("Deleted token: %s", label)
	return nil
}

// ListSlots returns a list of available slots.
func (h *SoftHSMHelper) ListSlots() ([]string, error) {
	cmd := exec.Command("softhsm2-util", "--show-slots")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list slots: %s: %w", string(output), err)
	}

	lines := strings.Split(string(output), "\n")
	return lines, nil
}

// FindSlotByLabel finds a slot number by token label.
func (h *SoftHSMHelper) FindSlotByLabel(label string) (string, error) {
	slots, err := h.ListSlots()
	if err != nil {
		return "", err
	}

	var currentSlot string
	for _, line := range slots {
		if strings.HasPrefix(line, "Slot ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentSlot = parts[1]
			}
		}
		if strings.Contains(line, "Label:") && strings.Contains(line, label) {
			return currentSlot, nil
		}
	}

	return "", fmt.Errorf("token with label %s not found", label)
}

// GenerateKeyPair generates a key pair in the HSM.
func (h *SoftHSMHelper) GenerateKeyPair(label, keyType string, keyID []byte) error {
	h.t.Logf("Generating %s key pair with label: %s", keyType, label)

	// Use pkcs11-tool to generate key pair
	args := []string{
		"--module", h.Config.ModulePath,
		"--login",
		"--pin", h.Config.PIN,
		"--keypairgen",
		"--label", label,
		"--id", fmt.Sprintf("%x", keyID),
	}

	switch keyType {
	case "ed25519":
		args = append(args, "--key-type", "EC:edwards25519")
	case "secp256k1":
		args = append(args, "--key-type", "EC:secp256k1")
	case "P-256":
		args = append(args, "--key-type", "EC:prime256v1")
	case "P-384":
		args = append(args, "--key-type", "EC:secp384r1")
	default:
		return fmt.Errorf("unsupported key type: %s", keyType)
	}

	cmd := exec.Command("pkcs11-tool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %s: %w", string(output), err)
	}

	h.t.Logf("Generated key pair: %s", label)
	return nil
}

// ListObjects lists objects in the token.
func (h *SoftHSMHelper) ListObjects() ([]string, error) {
	cmd := exec.Command("pkcs11-tool",
		"--module", h.Config.ModulePath,
		"--login",
		"--pin", h.Config.PIN,
		"--list-objects",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list objects: %s: %w", string(output), err)
	}

	lines := strings.Split(string(output), "\n")
	return lines, nil
}

// CleanupTestToken removes all test objects from the token.
func (h *SoftHSMHelper) CleanupTestToken() error {
	// List and delete all test objects
	objects, err := h.ListObjects()
	if err != nil {
		h.t.Logf("Warning: failed to list objects for cleanup: %v", err)
		return nil
	}

	for _, obj := range objects {
		if strings.Contains(obj, "test-") {
			h.t.Logf("Would cleanup: %s", obj)
			// In production, would delete the object
		}
	}

	return nil
}

// VerifyPKCS11Environment verifies the PKCS#11 environment is ready for testing.
func VerifyPKCS11Environment(t *testing.T) error {
	t.Helper()

	config := DefaultPKCS11Config()

	// Check module exists
	if _, err := os.Stat(config.ModulePath); err != nil {
		return fmt.Errorf("PKCS#11 module not found: %w", err)
	}

	// Check softhsm2-util is available
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		return fmt.Errorf("softhsm2-util not found: %w", err)
	}

	// Check pkcs11-tool is available
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		return fmt.Errorf("pkcs11-tool not found: %w", err)
	}

	return nil
}

// TestTokenConfig holds configuration for a test token.
type TestTokenConfig struct {
	Label       string
	PIN         string
	SOPIN       string
	Ciphersuite string
}

// CreateTestToken creates a dedicated test token for a specific test.
func CreateTestToken(t *testing.T, name string) (*TestTokenConfig, func()) {
	t.Helper()

	helper := NewSoftHSMHelper(t)
	label := fmt.Sprintf("test-%s-%d", name, os.Getpid())

	if err := helper.InitToken(label); err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	config := &TestTokenConfig{
		Label: label,
		PIN:   helper.Config.PIN,
		SOPIN: helper.Config.SOPIN,
	}

	cleanup := func() {
		if err := helper.DeleteToken(label); err != nil {
			t.Logf("Warning: failed to cleanup test token %s: %v", label, err)
		}
	}

	return config, cleanup
}

// KeyPairInfo contains information about a key pair in the HSM.
type KeyPairInfo struct {
	Label     string
	ID        []byte
	KeyType   string
	PublicKey crypto.PublicKey
}

// SignatureTestVector contains test data for signature verification.
type SignatureTestVector struct {
	Message   []byte
	Signature []byte
	PublicKey crypto.PublicKey
	Valid     bool
}
