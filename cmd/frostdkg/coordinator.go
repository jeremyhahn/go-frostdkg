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
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	coordinatorListen       string
	coordinatorThreshold    int
	coordinatorParticipants int
	coordinatorSessionID    string
	coordinatorCiphersuite  string
	coordinatorTimeout      int
)

// coordinatorCmd represents the coordinator command
var coordinatorCmd = &cobra.Command{
	Use:   "coordinator",
	Short: "Start a DKG coordinator server",
	Long: `Start a DKG coordinator server that relays messages between participants.

The coordinator has no cryptographic role and does not participate in the DKG.
It acts purely as a message relay and session coordinator.

Examples:
  # Start gRPC coordinator for 3-of-5 threshold
  frostdkg coordinator --listen 0.0.0.0:9000 --threshold 3 --participants 5

  # Start HTTP coordinator with TLS
  frostdkg coordinator --protocol http --listen 0.0.0.0:8443 \
    --tls-cert server.crt --tls-key server.key \
    --threshold 2 --participants 3

  # Start QUIC coordinator with custom session ID
  frostdkg coordinator --protocol quic --listen 0.0.0.0:9001 \
    --threshold 2 --participants 3 --session-id my-session`,
	RunE: runCoordinator,
}

func init() {
	coordinatorCmd.Flags().StringVar(&coordinatorListen, "listen", "0.0.0.0:9000", "address to listen on")
	coordinatorCmd.Flags().IntVarP(&coordinatorThreshold, "threshold", "t", 2, "minimum signers required (t)")
	coordinatorCmd.Flags().IntVarP(&coordinatorParticipants, "participants", "n", 3, "total participants (n)")
	coordinatorCmd.Flags().StringVar(&coordinatorSessionID, "session-id", "", "session ID (generates UUID if not provided)")
	coordinatorCmd.Flags().StringVar(&coordinatorCiphersuite, "ciphersuite", "FROST-ED25519-SHA512-v1", "FROST ciphersuite identifier")
	coordinatorCmd.Flags().IntVar(&coordinatorTimeout, "timeout", 300, "session timeout in seconds")

	if err := coordinatorCmd.MarkFlagRequired("threshold"); err != nil {
		panic(fmt.Sprintf("failed to mark threshold flag as required: %v", err))
	}
	if err := coordinatorCmd.MarkFlagRequired("participants"); err != nil {
		panic(fmt.Sprintf("failed to mark participants flag as required: %v", err))
	}

	if err := viper.BindPFlag("coordinator.listen", coordinatorCmd.Flags().Lookup("listen")); err != nil {
		panic(fmt.Sprintf("failed to bind listen flag: %v", err))
	}
	if err := viper.BindPFlag("coordinator.threshold", coordinatorCmd.Flags().Lookup("threshold")); err != nil {
		panic(fmt.Sprintf("failed to bind threshold flag: %v", err))
	}
	if err := viper.BindPFlag("coordinator.participants", coordinatorCmd.Flags().Lookup("participants")); err != nil {
		panic(fmt.Sprintf("failed to bind participants flag: %v", err))
	}
	if err := viper.BindPFlag("coordinator.session_id", coordinatorCmd.Flags().Lookup("session-id")); err != nil {
		panic(fmt.Sprintf("failed to bind session_id flag: %v", err))
	}
	if err := viper.BindPFlag("coordinator.ciphersuite", coordinatorCmd.Flags().Lookup("ciphersuite")); err != nil {
		panic(fmt.Sprintf("failed to bind ciphersuite flag: %v", err))
	}
	if err := viper.BindPFlag("coordinator.timeout", coordinatorCmd.Flags().Lookup("timeout")); err != nil {
		panic(fmt.Sprintf("failed to bind timeout flag: %v", err))
	}
}

func runCoordinator(cmd *cobra.Command, args []string) error {
	// Validate parameters
	if coordinatorThreshold < 1 {
		return fmt.Errorf("threshold must be at least 1")
	}
	if coordinatorParticipants < coordinatorThreshold {
		return fmt.Errorf("participants (%d) must be >= threshold (%d)", coordinatorParticipants, coordinatorThreshold)
	}

	// Generate session ID if not provided
	sessionID := coordinatorSessionID
	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	if verbose {
		fmt.Printf("Starting %s coordinator server...\n", protocol)
		fmt.Printf("  Listen: %s\n", coordinatorListen)
		fmt.Printf("  Threshold: %d\n", coordinatorThreshold)
		fmt.Printf("  Participants: %d\n", coordinatorParticipants)
		fmt.Printf("  Session ID: %s\n", sessionID)
		fmt.Printf("  Ciphersuite: %s\n", coordinatorCiphersuite)
		fmt.Printf("  Codec: %s\n", codec)
		if tlsCert != "" {
			fmt.Printf("  TLS Cert: %s\n", tlsCert)
			fmt.Printf("  TLS Key: %s\n", tlsKey)
			if tlsCA != "" {
				fmt.Printf("  TLS CA: %s\n", tlsCA)
			}
		}
	}

	// Create transport config
	cfg := &transport.Config{
		Protocol:          transport.Protocol(protocol),
		Address:           coordinatorListen,
		TLSCertFile:       tlsCert,
		TLSKeyFile:        tlsKey,
		TLSCAFile:         tlsCA,
		CodecType:         codec,
		Ciphersuite:       coordinatorCiphersuite,
		Timeout:           time.Duration(coordinatorTimeout) * time.Second,
		MaxMessageSize:    1024 * 1024, // 1MB
		KeepAlive:         true,
		KeepAliveInterval: 30 * time.Second,
		Logger:            &transport.StdoutLogger{Prefix: "coordinator", Verbose: verbose},
	}

	// Create session config
	sessionCfg := &transport.SessionConfig{
		Threshold:            coordinatorThreshold,
		NumParticipants:      coordinatorParticipants,
		Ciphersuite:          coordinatorCiphersuite,
		Timeout:              time.Duration(coordinatorTimeout) * time.Second,
		AllowPartialSessions: false,
	}

	// Create coordinator using factory
	coordinator, err := defaultFactory.NewCoordinator(transport.Protocol(protocol), cfg, sessionCfg, sessionID)
	if err != nil {
		return fmt.Errorf("failed to create coordinator: %w", err)
	}

	// Start coordinator
	ctx := context.Background()
	if err := coordinator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start coordinator: %w", err)
	}

	fmt.Printf("Coordinator started successfully\n")
	fmt.Printf("Session ID: %s\n", coordinator.SessionID())
	fmt.Printf("Listening on: %s\n", coordinator.Address())
	fmt.Printf("Waiting for %d participants to connect...\n", coordinatorParticipants)

	// Wait for participants in a goroutine
	participantsDone := make(chan error, 1)
	go func() {
		waitCtx, cancel := context.WithTimeout(ctx, time.Duration(coordinatorTimeout)*time.Second)
		defer cancel()
		participantsDone <- coordinator.WaitForParticipants(waitCtx, coordinatorParticipants)
	}()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-participantsDone:
		if err != nil {
			fmt.Printf("Error waiting for participants: %v\n", err)
			// Try to stop gracefully
			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if stopErr := coordinator.Stop(stopCtx); stopErr != nil {
				fmt.Printf("Error stopping coordinator: %v\n", stopErr)
			}
			return err
		}
		fmt.Printf("All %d participants connected. DKG session in progress...\n", coordinatorParticipants)

		// Keep coordinator running until interrupted
		<-sigChan
		fmt.Println("\nShutting down coordinator...")

	case sig := <-sigChan:
		fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
	}

	// Graceful shutdown
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := coordinator.Stop(stopCtx); err != nil {
		return fmt.Errorf("error stopping coordinator: %w", err)
	}

	fmt.Println("Coordinator stopped")
	return nil
}
