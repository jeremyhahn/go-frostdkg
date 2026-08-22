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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
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

// generateSessionRandomness returns 32 bytes of CSPRNG output sealed in a
// memguard enclave, zeroing the buffer it generated into on every path.
//
// Same ownership rule as loadHostSecretKey: transport.SealSecret copies rather
// than consuming its input, so a caller that generated the buffer has to clear
// it. The raw randomness exists only inside this function.
func generateSessionRandomness() (*secmem.SecretBytes, error) {
	random := make([]byte, transport.SecretKeySize)
	defer secmem.ZeroBytes(random)

	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("failed to generate randomness: %w", err)
	}

	sealed := transport.SealSecret(random)
	if sealed == nil {
		return nil, fmt.Errorf("failed to seal the session randomness")
	}
	return sealed, nil
}

// loadHostSecretKey returns the participant's host secret key sealed in a
// memguard enclave, decoding the --hostkey flag when one was given and
// generating a fresh key otherwise.
//
// The raw key exists only inside this function, and the intermediate slice is
// zeroed on every path out. Sealing alone would not be enough:
// transport.SealSecret deliberately COPIES rather than consuming its input —
// the borrow rule, so that a caller holding several keys in one buffer does
// not have the rest wiped underneath it — which means a caller that seals and
// walks away leaves the plaintext on the ordinary heap for the life of the
// process. Before the enclave migration the params struct aliased this slice
// and DKGParams.Zeroize cleared it; now the params own a copy, so clearing the
// source is this function's job.
func loadHostSecretKey(hostkeyHex string, verbose bool) (*secmem.SecretBytes, error) {
	var hostSeckey []byte

	if hostkeyHex != "" {
		decoded, err := hex.DecodeString(hostkeyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid hostkey hex: %w", err)
		}
		hostSeckey = decoded
		defer secmem.ZeroBytes(hostSeckey)

		if len(hostSeckey) != transport.SecretKeySize {
			return nil, fmt.Errorf("hostkey must be %d bytes, got %d", transport.SecretKeySize, len(hostSeckey))
		}
	} else {
		hostSeckey = make([]byte, transport.SecretKeySize)
		defer secmem.ZeroBytes(hostSeckey)

		if _, err := rand.Read(hostSeckey); err != nil {
			return nil, fmt.Errorf("failed to generate host secret key: %w", err)
		}
		if verbose {
			fmt.Printf("Generated host secret key (fingerprint): %x\n", sha256.Sum256(hostSeckey))
		}
	}

	sealed := transport.SealSecret(hostSeckey)
	if sealed == nil {
		return nil, fmt.Errorf("failed to seal the host secret key")
	}
	return sealed, nil
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

	// Set up signal handling for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	// Generate or load host secret key. The raw bytes never reach this scope:
	// see loadHostSecretKey for why sealing alone would not be enough.
	//
	// The --hostkey flag's own string is deliberately NOT scrubbed. Writing
	// through a string header is unsound in both directions (go-frost#15,
	// measured by agent-go-frost): on a literal it SEGFAULTs, and on a heap
	// string it silently mutates every alias — and a flag value IS aliased,
	// pflag slices it out of os.Args. Scrubbing it would also buy nothing: a
	// key passed on the command line is already in /proc/PID/cmdline, ps
	// output and the shell history, so the Go copy is not the exposure. The
	// scrub that does mean something is on the decoded []byte, which
	// loadHostSecretKey owns and zeroes.
	hostSecret, err := loadHostSecretKey(participantHostkey, verbose)
	if err != nil {
		return err
	}
	// params.Zeroize below destroys this too; Destroy is idempotent, and this
	// defer covers the paths that return before params exists.
	defer hostSecret.Destroy()

	// Generate the DKG session randomness. It is sealed the same way the host
	// key is, and for the same reason: combined with the host key it derives
	// the participant seed, so it is a secret and not a nonce. The defer runs
	// before params exists, covering every error return between here and there.
	sessionRandom, err := generateSessionRandomness()
	if err != nil {
		return err
	}
	defer sessionRandom.Destroy()

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

	// Warn if running without TLS on network transports
	if tlsCert == "" && protocol != "memory" && !insecure {
		return fmt.Errorf("TLS is required for network transports (use --tls-cert/--tls-key, or --insecure for testing)")
	}
	if insecure && tlsCert == "" {
		fmt.Println("WARNING: Running without TLS. Do NOT use in production.")
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
	ctx, cancel := context.WithTimeout(ctx, time.Duration(participantTimeout)*time.Second)
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
		HostSeckey:     hostSecret,
		HostPubkeys:    hostPubkeys,
		Threshold:      participantThreshold,
		ParticipantIdx: participantID,
		Random:         sessionRandom,
	}
	defer params.Zeroize()

	// Execute DKG
	result, err := participant.RunDKG(ctx, params)
	if err != nil {
		return fmt.Errorf("DKG execution failed: %w", err)
	}
	defer result.Zeroize()

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

	// The share leaves the enclave only to be hex-encoded for the output file.
	// Every scrub below is a defer installed the moment the value exists, so
	// it covers the failure returns too -- an unwritable output directory used
	// to leave the plaintext share in memory, which is the one moment it most
	// obviously must not.
	var secretShareHex string
	if err := secmem.WithSecret(result.SecretShare, func(share []byte) error {
		secretShareHex = hex.EncodeToString(share)
		return nil
	}); err != nil {
		return fmt.Errorf("failed to read the secret share: %w", err)
	}
	defer secmem.ZeroString(&secretShareHex)

	output := KeyShareOutput{
		ParticipantIndex: participantID,
		Ciphersuite:      ciphersuite,
		SecretShare:      secretShareHex,
		ThresholdPubkey:  hex.EncodeToString(result.ThresholdPubkey),
		PublicShares:     publicSharesHex,
		SessionID:        result.SessionID,
		RecoveryData:     hex.EncodeToString(result.RecoveryData),
		Timestamp:        time.Now().Unix(),
	}
	// output.SecretShare aliases secretShareHex, so either scrub clears both;
	// both are deferred so neither depends on the other surviving a refactor.
	defer secmem.ZeroString(&output.SecretShare)
	defer secmem.ZeroString(&output.RecoveryData)

	// Write to file
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}
	defer secmem.ZeroBytes(jsonData)

	if err := os.WriteFile(participantOutput, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Key share saved to: %s\n", participantOutput)
	fmt.Println("\nWARNING: Keep the secret_share confidential! Do not share it.")

	return nil
}
