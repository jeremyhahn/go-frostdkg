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
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	configOutput string
	configForce  bool
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration files",
	Long: `Generate and manage frostdkg configuration files.

Configuration files use YAML format and can specify default values for
all command-line flags. Command-line flags override config file values.

Environment variables can also be used with the FROSTDKG_ prefix.
For example: FROSTDKG_PROTOCOL=http

Examples:
  # Generate default config file
  frostdkg config init

  # Generate config file in custom location
  frostdkg config init --output /etc/frostdkg/config.yaml

  # Show current config
  frostdkg config show`,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a sample configuration file",
	Long:  `Generate a sample configuration file with default values and documentation.`,
	RunE:  runConfigInit,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  `Display the current configuration including values from config file, environment, and defaults.`,
	Run:   runConfigShow,
}

func init() {
	configInitCmd.Flags().StringVarP(&configOutput, "output", "o", "", "output path (default: $HOME/.frostdkg/config.yaml)")
	configInitCmd.Flags().BoolVarP(&configForce, "force", "f", false, "overwrite existing config file")

	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configShowCmd)
}

const sampleConfig = `# frostdkg configuration file
# Command-line flags override these values

# Default transport protocol
# Options: grpc, http, quic, libp2p, mcp, unix, memory
protocol: grpc

# Default serialization codec
# Options: json, msgpack, cbor
codec: json

# TLS configuration
tls:
  cert: ""      # Path to TLS certificate file
  key: ""       # Path to TLS private key file
  ca: ""        # Path to CA certificate (for mTLS)

# Disable TLS verification (WARNING: testing only)
insecure: false

# Verbose output
verbose: false

# Coordinator settings
coordinator:
  listen: "0.0.0.0:9000"
  threshold: 2
  participants: 3
  session_id: ""                        # Auto-generated if empty
  ciphersuite: "FROST-ED25519-SHA512-v1"
  timeout: 300                          # seconds

# Participant settings
participant:
  coordinator: "localhost:9000"
  id: 0
  output: "participant.json"
  hostkey: ""                           # Auto-generated if empty
  hostpubkeys: ""
  threshold: 2
  timeout: 300                          # seconds

# Certgen settings
certgen:
  type: "ecdsa"                         # ecdsa or ed25519
  output: "./certs"
  name: "localhost"
  days: 365
  hosts:
    - "localhost"
    - "127.0.0.1"

# Verify settings
verify:
  share: ""
  group_key: ""
`

func runConfigInit(cmd *cobra.Command, args []string) error {
	// Determine output path
	outputPath := configOutput
	if outputPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		outputPath = filepath.Join(homeDir, ".frostdkg", "config.yaml")
	}

	// Check if file exists
	if _, err := os.Stat(outputPath); err == nil && !configForce {
		return fmt.Errorf("config file already exists: %s (use --force to overwrite)", outputPath)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write config file with restricted permissions (config may contain sensitive settings)
	if err := os.WriteFile(outputPath, []byte(sampleConfig), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Configuration file created: %s\n", outputPath)
	fmt.Println("\nEdit the file to customize settings, or use command-line flags to override.")
	fmt.Printf("\nTo use this config file:\n")
	fmt.Printf("  export FROSTDKG_CONFIG=%s\n", outputPath)
	fmt.Printf("  OR\n")
	fmt.Printf("  frostdkg --config %s <command>\n", outputPath)

	return nil
}

func runConfigShow(cmd *cobra.Command, args []string) {
	fmt.Println("Current Configuration:")
	fmt.Println("======================")

	// Show all settings from viper
	settings := viper.AllSettings()

	if len(settings) == 0 {
		fmt.Println("No configuration loaded (using defaults)")
		return
	}

	// Display settings
	for key, value := range settings {
		fmt.Printf("%s: %v\n", key, value)
	}

	if viper.ConfigFileUsed() != "" {
		fmt.Printf("\nLoaded from: %s\n", viper.ConfigFileUsed())
	}

	fmt.Println("\nEnvironment variables with FROSTDKG_ prefix override these values.")
	fmt.Println("Command-line flags override both config file and environment variables.")
}
