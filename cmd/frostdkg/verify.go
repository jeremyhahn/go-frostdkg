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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	verifyShare    string
	verifyGroupKey string
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify key shares",
	Long: `Verify that a key share file is valid and optionally check against a group public key.

This command validates:
  - JSON format is correct
  - All required fields are present
  - Cryptographic data has correct lengths based on ciphersuite
  - Secret share is 32 bytes
  - Public key shares match ciphersuite size (32 for Ed25519, 33 for P256/Secp256k1, 57 for Ed448)
  - Threshold public key matches expected value (if --group-key provided)

Examples:
  # Verify a key share file
  frostdkg verify --share participant1.json

  # Verify and check against expected group key
  frostdkg verify --share participant1.json \
    --group-key 02abc123...`,
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVarP(&verifyShare, "share", "s", "", "path to key share file")
	verifyCmd.Flags().StringVar(&verifyGroupKey, "group-key", "", "expected group public key (hex) to verify against")

	if err := verifyCmd.MarkFlagRequired("share"); err != nil {
		panic(fmt.Sprintf("failed to mark share flag as required: %v", err))
	}

	if err := viper.BindPFlag("verify.share", verifyCmd.Flags().Lookup("share")); err != nil {
		panic(fmt.Sprintf("failed to bind share flag: %v", err))
	}
	if err := viper.BindPFlag("verify.group_key", verifyCmd.Flags().Lookup("group-key")); err != nil {
		panic(fmt.Sprintf("failed to bind group_key flag: %v", err))
	}
}

func runVerify(cmd *cobra.Command, args []string) error {
	if verbose {
		fmt.Printf("Verifying key share: %s\n", verifyShare)
	}

	// Clean the file path to prevent directory traversal attacks
	cleanPath := filepath.Clean(verifyShare)

	// Read key share file
	data, err := os.ReadFile(cleanPath) //nolint:gosec // G304: Path is cleaned above
	if err != nil {
		return fmt.Errorf("failed to read key share file: %w", err)
	}

	// Parse JSON
	var keyShare KeyShareOutput
	if err := json.Unmarshal(data, &keyShare); err != nil {
		return fmt.Errorf("failed to parse key share JSON: %w", err)
	}

	if verbose {
		fmt.Println("Key share file format: OK")
	}

	// Determine expected key size from ciphersuite in the file, or use global flag
	cs := keyShare.Ciphersuite
	if cs == "" {
		// Fall back to the global --ciphersuite flag if not in file
		cs = ciphersuite
	}
	expectedKeySize := CiphersuiteKeySize(cs)

	if verbose {
		fmt.Printf("Ciphersuite: %s (key size: %d bytes)\n", cs, expectedKeySize)
	}

	// Verify required fields
	if keyShare.SecretShare == "" {
		return fmt.Errorf("missing secret_share field")
	}
	if keyShare.ThresholdPubkey == "" {
		return fmt.Errorf("missing threshold_pubkey field")
	}
	if len(keyShare.PublicShares) == 0 {
		return fmt.Errorf("missing public_shares field")
	}
	if keyShare.SessionID == "" {
		return fmt.Errorf("missing session_id field")
	}

	// Decode and validate secret share
	secretShare, err := hex.DecodeString(keyShare.SecretShare)
	if err != nil {
		return fmt.Errorf("invalid secret_share hex: %w", err)
	}
	if len(secretShare) != 32 {
		return fmt.Errorf("secret_share must be 32 bytes, got %d", len(secretShare))
	}
	if verbose {
		fmt.Println("Secret share length: OK (32 bytes)")
	}

	// Decode and validate threshold public key
	thresholdPubkey, err := hex.DecodeString(keyShare.ThresholdPubkey)
	if err != nil {
		return fmt.Errorf("invalid threshold_pubkey hex: %w", err)
	}
	if len(thresholdPubkey) != expectedKeySize {
		return fmt.Errorf("threshold_pubkey must be %d bytes for %s, got %d", expectedKeySize, cs, len(thresholdPubkey))
	}
	if verbose {
		fmt.Printf("Threshold public key length: OK (%d bytes)\n", expectedKeySize)
	}

	// Validate public shares
	for i, shareHex := range keyShare.PublicShares {
		share, err := hex.DecodeString(shareHex)
		if err != nil {
			return fmt.Errorf("invalid public_share[%d] hex: %w", i, err)
		}
		if len(share) != expectedKeySize {
			return fmt.Errorf("public_share[%d] must be %d bytes for %s, got %d", i, expectedKeySize, cs, len(share))
		}
	}
	if verbose {
		fmt.Printf("Public shares count: %d\n", len(keyShare.PublicShares))
		fmt.Printf("Public shares format: OK (all %d bytes)\n", expectedKeySize)
	}

	// Decode recovery data if present
	if keyShare.RecoveryData != "" {
		recoveryData, err := hex.DecodeString(keyShare.RecoveryData)
		if err != nil {
			return fmt.Errorf("invalid recovery_data hex: %w", err)
		}
		if verbose {
			fmt.Printf("Recovery data length: %d bytes\n", len(recoveryData))
		}
	}

	// Verify against expected group key if provided
	if verifyGroupKey != "" {
		expectedKey, err := hex.DecodeString(verifyGroupKey)
		if err != nil {
			return fmt.Errorf("invalid group-key hex: %w", err)
		}
		if len(expectedKey) != expectedKeySize {
			return fmt.Errorf("group-key must be %d bytes for %s, got %d", expectedKeySize, cs, len(expectedKey))
		}

		if hex.EncodeToString(thresholdPubkey) != hex.EncodeToString(expectedKey) {
			return fmt.Errorf("threshold public key mismatch:\n  got:      %s\n  expected: %s",
				keyShare.ThresholdPubkey, verifyGroupKey)
		}
		fmt.Println("Group key verification: OK")
	}

	// Print summary
	fmt.Println("\nVerification Summary:")
	fmt.Printf("  Participant Index: %d\n", keyShare.ParticipantIndex)
	fmt.Printf("  Ciphersuite: %s\n", cs)
	fmt.Printf("  Session ID: %s\n", keyShare.SessionID)
	fmt.Printf("  Threshold Public Key: %s\n", keyShare.ThresholdPubkey)
	fmt.Printf("  Number of Public Shares: %d\n", len(keyShare.PublicShares))
	if keyShare.Timestamp > 0 {
		fmt.Printf("  Timestamp: %d\n", keyShare.Timestamp)
	}

	fmt.Println("\nKey share is VALID")
	return nil
}
