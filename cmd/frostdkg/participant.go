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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	participantCoordinator string
	participantID          int
	participantOutput      string
	participantHostkey     string
	participantHostpubkeys string
	participantThreshold   int
	participantTimeout     int
)

// participantCmd represents the participant command
var participantCmd = &cobra.Command{
	Use:   "participant",
	Short: "Join a DKG session as a participant",
	Long: `Join a DKG session as a participant and execute the FROST-DKG protocol.

Participants connect to a coordinator, exchange cryptographic messages, and
receive their threshold key share. The key share must be kept secret.

Examples:
  # Join as participant 1 (0-indexed) with auto-generated host key
  frostdkg participant --coordinator localhost:9000 --id 0 \
    --threshold 2 --output participant1.json

  # Join with explicit host secret key (hex)
  frostdkg participant --coordinator localhost:9000 --id 1 \
    --hostkey abcd1234... --threshold 2 --output participant2.json

  # Join HTTP coordinator with TLS client cert
  frostdkg participant --protocol http --coordinator https://localhost:8443 \
    --tls-cert client.crt --tls-key client.key --tls-ca ca.crt \
    --id 0 --threshold 2 --output participant1.json`,
	RunE: runParticipant,
}

func init() {
	participantCmd.Flags().StringVar(&participantCoordinator, "coordinator", "localhost:9000", "coordinator address")
	participantCmd.Flags().IntVar(&participantID, "id", -1, "participant identifier (0-indexed)")
	participantCmd.Flags().StringVarP(&participantOutput, "output", "o", "", "output file path for key share")
	participantCmd.Flags().StringVar(&participantHostkey, "hostkey", "", "host secret key (hex, 32 bytes). Generated if not provided")
	participantCmd.Flags().StringVar(&participantHostpubkeys, "hostpubkeys", "", "comma-separated host public keys (hex, 32 bytes each)")
	participantCmd.Flags().IntVarP(&participantThreshold, "threshold", "t", 2, "signing threshold (must match coordinator)")
	participantCmd.Flags().IntVar(&participantTimeout, "timeout", 300, "operation timeout in seconds")

	if err := participantCmd.MarkFlagRequired("id"); err != nil {
		panic(fmt.Sprintf("failed to mark id flag as required: %v", err))
	}
	if err := participantCmd.MarkFlagRequired("output"); err != nil {
		panic(fmt.Sprintf("failed to mark output flag as required: %v", err))
	}

	if err := viper.BindPFlag("participant.coordinator", participantCmd.Flags().Lookup("coordinator")); err != nil {
		panic(fmt.Sprintf("failed to bind coordinator flag: %v", err))
	}
	if err := viper.BindPFlag("participant.id", participantCmd.Flags().Lookup("id")); err != nil {
		panic(fmt.Sprintf("failed to bind id flag: %v", err))
	}
	if err := viper.BindPFlag("participant.output", participantCmd.Flags().Lookup("output")); err != nil {
		panic(fmt.Sprintf("failed to bind output flag: %v", err))
	}
	if err := viper.BindPFlag("participant.hostkey", participantCmd.Flags().Lookup("hostkey")); err != nil {
		panic(fmt.Sprintf("failed to bind hostkey flag: %v", err))
	}
	if err := viper.BindPFlag("participant.hostpubkeys", participantCmd.Flags().Lookup("hostpubkeys")); err != nil {
		panic(fmt.Sprintf("failed to bind hostpubkeys flag: %v", err))
	}
	if err := viper.BindPFlag("participant.threshold", participantCmd.Flags().Lookup("threshold")); err != nil {
		panic(fmt.Sprintf("failed to bind threshold flag: %v", err))
	}
	if err := viper.BindPFlag("participant.timeout", participantCmd.Flags().Lookup("timeout")); err != nil {
		panic(fmt.Sprintf("failed to bind timeout flag: %v", err))
	}
}

// KeyShareOutput represents the JSON output format for key shares
type KeyShareOutput struct {
	ParticipantIndex int      `json:"participant_index"`
	Ciphersuite      string   `json:"ciphersuite"`
	SecretShare      string   `json:"secret_share"`     // hex-encoded
	ThresholdPubkey  string   `json:"threshold_pubkey"` // hex-encoded
	PublicShares     []string `json:"public_shares"`    // hex-encoded array
	SessionID        string   `json:"session_id"`
	RecoveryData     string   `json:"recovery_data"` // hex-encoded
	Timestamp        int64    `json:"timestamp"`
}

func runParticipant(cmd *cobra.Command, args []string) error {
	// Validate participant ID
	if participantID < 0 {
		return fmt.Errorf("participant ID must be >= 0")
	}

	// Validate threshold
	if participantThreshold < 1 {
		return fmt.Errorf("threshold must be at least 1")
	}

	// Get the public key size for the selected ciphersuite
	pubkeySize := CiphersuiteKeySize(ciphersuite)

	if verbose {
		fmt.Printf("Joining DKG session as participant %d...\n", participantID)
		fmt.Printf("  Coordinator: %s\n", participantCoordinator)
		fmt.Printf("  Protocol: %s\n", protocol)
		fmt.Printf("  Ciphersuite: %s\n", ciphersuite)
		fmt.Printf("  Public key size: %d bytes\n", pubkeySize)
		fmt.Printf("  Threshold: %d\n", participantThreshold)
		fmt.Printf("  Codec: %s\n", codec)
		if tlsCert != "" {
			fmt.Printf("  TLS Cert: %s\n", tlsCert)
			fmt.Printf("  TLS Key: %s\n", tlsKey)
		}
	}

	// Generate or load host secret key
	var hostSeckey []byte
	var err error

	if participantHostkey != "" {
		hostSeckey, err = hex.DecodeString(participantHostkey)
		if err != nil {
			return fmt.Errorf("invalid hostkey hex: %w", err)
		}
		if len(hostSeckey) != 32 {
			return fmt.Errorf("hostkey must be 32 bytes, got %d", len(hostSeckey))
		}
	} else {
		// Generate random host secret key
		hostSeckey = make([]byte, 32)
		if _, err := rand.Read(hostSeckey); err != nil {
			return fmt.Errorf("failed to generate host secret key: %w", err)
		}
		if verbose {
			fmt.Printf("Generated host secret key: %s\n", hex.EncodeToString(hostSeckey))
		}
	}

	// Generate random entropy for DKG
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("failed to generate randomness: %w", err)
	}

	// For now, we'll use placeholder host public keys
	// In a real scenario, these would be coordinated beforehand
	// This is a simplified example - typically you'd load these from config
	// or exchange them in a pre-session setup phase
	var hostPubkeys [][]byte

	// TODO: This is a placeholder. In production, host public keys should be
	// provided via config file or pre-shared. For now, we'll create dummy keys.
	// The actual implementation would derive the public key from the secret key
	// and coordinate with other participants.
	if participantHostpubkeys != "" {
		return fmt.Errorf("--hostpubkeys parsing not yet implemented; host keys should be coordinated via config")
	}

	// Placeholder: Create a minimal set of host pubkeys for the selected ciphersuite
	// In reality, these must be coordinated among all participants before DKG starts
	numParticipants := participantThreshold + 1 // Minimum for threshold
	hostPubkeys = make([][]byte, numParticipants)
	for i := 0; i < numParticipants; i++ {
		// Create public key with size based on ciphersuite
		hostPubkeys[i] = make([]byte, pubkeySize)
		if _, err := rand.Read(hostPubkeys[i]); err != nil {
			return fmt.Errorf("failed to generate host public key %d: %w", i, err)
		}
	}

	if participantID >= len(hostPubkeys) {
		return fmt.Errorf("participant ID %d exceeds number of host public keys %d", participantID, len(hostPubkeys))
	}

	// Create transport config
	cfg := &transport.Config{
		Protocol:          transport.Protocol(protocol),
		Address:           participantCoordinator,
		TLSCertFile:       tlsCert,
		TLSKeyFile:        tlsKey,
		TLSCAFile:         tlsCA,
		CodecType:         codec,
		Timeout:           time.Duration(participantTimeout) * time.Second,
		MaxMessageSize:    1024 * 1024, // 1MB
		KeepAlive:         true,
		KeepAliveInterval: 30 * time.Second,
	}

	// Create participant using factory
	participant, err := defaultFactory.NewParticipant(transport.Protocol(protocol), cfg)
	if err != nil {
		return fmt.Errorf("failed to create participant: %w", err)
	}

	// Connect to coordinator
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(participantTimeout)*time.Second)
	defer cancel()

	if verbose {
		fmt.Printf("Connecting to coordinator at %s...\n", participantCoordinator)
	}

	if err := participant.Connect(ctx, participantCoordinator); err != nil {
		return fmt.Errorf("failed to connect to coordinator: %w", err)
	}
	defer func() {
		if err := participant.Disconnect(); err != nil {
			fmt.Printf("Warning: failed to disconnect: %v\n", err)
		}
	}()

	if verbose {
		fmt.Println("Connected to coordinator")
		fmt.Println("Executing DKG protocol...")
	}

	// Prepare DKG parameters
	params := &transport.DKGParams{
		HostSeckey:     hostSeckey,
		HostPubkeys:    hostPubkeys,
		Threshold:      participantThreshold,
		ParticipantIdx: participantID,
		Random:         random,
	}

	// Execute DKG
	result, err := participant.RunDKG(ctx, params)
	if err != nil {
		return fmt.Errorf("DKG execution failed: %w", err)
	}

	if verbose {
		fmt.Println("DKG completed successfully!")
		fmt.Printf("Session ID: %s\n", result.SessionID)
		fmt.Printf("Threshold public key: %s\n", hex.EncodeToString(result.ThresholdPubkey))
	}

	// Prepare output
	publicSharesHex := make([]string, len(result.PublicShares))
	for i, share := range result.PublicShares {
		publicSharesHex[i] = hex.EncodeToString(share)
	}

	output := KeyShareOutput{
		ParticipantIndex: participantID,
		Ciphersuite:      ciphersuite,
		SecretShare:      hex.EncodeToString(result.SecretShare),
		ThresholdPubkey:  hex.EncodeToString(result.ThresholdPubkey),
		PublicShares:     publicSharesHex,
		SessionID:        result.SessionID,
		RecoveryData:     hex.EncodeToString(result.RecoveryData),
		Timestamp:        time.Now().Unix(),
	}

	// Write to file
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	if err := os.WriteFile(participantOutput, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Key share saved to: %s\n", participantOutput)
	fmt.Println("\nWARNING: Keep the secret_share confidential! Do not share it.")

	return nil
}
