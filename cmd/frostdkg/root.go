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
	"runtime"
	"strings"

	"github.com/jeremyhahn/go-frostdkg/pkg/dkg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Version information - set via ldflags at build time
var (
	// Version is the semantic version (from VERSION file)
	Version = "dev"
	// GitCommit is the git commit hash
	GitCommit = "unknown"
	// BuildTime is the build timestamp
	BuildTime = "unknown"
)

var (
	cfgFile string
	verbose bool
)

// Global flags
var (
	protocol    string
	codec       string
	ciphersuite string
	tlsCert     string
	tlsKey      string
	tlsCA       string
	insecure    bool
)

// Ciphersuite constants, aliased from the package that owns them.
//
// These were literals until the secp256k1 one drifted: the CLI spelled it
// FROST-SECP256K1-SHA256-v1 while RFC 9591 and dkg.CiphersuiteSecp256k1 spell
// it FROST-secp256k1-SHA256-v1, so selecting secp256k1 from the command line
// resolved to nothing. A second copy of a wire identifier cannot be kept
// correct by discipline; aliasing makes drift impossible.
const (
	CiphersuiteEd25519      = dkg.CiphersuiteEd25519
	CiphersuiteRistretto255 = dkg.CiphersuiteRistretto255
	CiphersuiteP256         = dkg.CiphersuiteP256
	CiphersuiteSecp256k1    = dkg.CiphersuiteSecp256k1
	CiphersuiteEd448        = dkg.CiphersuiteEd448
)

// CiphersuiteKeySize returns the public key size for a given ciphersuite
func CiphersuiteKeySize(cs string) int {
	switch cs {
	case CiphersuiteEd25519, CiphersuiteRistretto255:
		return 32
	case CiphersuiteP256, CiphersuiteSecp256k1:
		return 33
	case CiphersuiteEd448:
		return 57
	default:
		return 32 // Default to Ed25519
	}
}

// ValidCiphersuites returns the list of supported ciphersuites
func ValidCiphersuites() []string {
	return []string{
		CiphersuiteEd25519,
		CiphersuiteRistretto255,
		CiphersuiteP256,
		CiphersuiteSecp256k1,
		CiphersuiteEd448,
	}
}

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "frostdkg",
	Short: "FROST-DKG distributed key generation tool",
	Long: `frostdkg is a command-line tool for executing FROST Distributed Key Generation.

It supports multiple transport protocols (gRPC, HTTP, QUIC, Unix sockets, libp2p)
and serialization formats (JSON, MessagePack, CBOR) with TLS 1.3 security.

Use 'frostdkg coordinator' to start a DKG coordinator server.
Use 'frostdkg participant' to join a DKG session as a participant.
Use 'frostdkg certgen' to generate TLS certificates and keys.
Use 'frostdkg verify' to verify key shares.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize config
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
		} else {
			viper.AddConfigPath("$HOME/.frostdkg")
			viper.AddConfigPath(".")
			viper.SetConfigName("config")
			viper.SetConfigType("yaml")
		}

		// Read config file if it exists
		if err := viper.ReadInConfig(); err == nil && verbose {
			fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
		}

		// Environment variables
		viper.SetEnvPrefix("FROSTDKG")
		viper.AutomaticEnv()
	},
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version number and build information of frostdkg.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("frostdkg version %s\n", Version)
		fmt.Printf("Git commit: %s\n", GitCommit)
		fmt.Printf("Build date: %s\n", BuildTime)
		fmt.Printf("Go version: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.frostdkg/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&protocol, "protocol", "grpc", "transport protocol (grpc, http, quic, unix, libp2p)")
	rootCmd.PersistentFlags().StringVar(&codec, "codec", "json", "serialization format (json, msgpack, cbor)")
	// The help text lists the identifiers rather than repeating them: what a
	// user copies out of --help has to be a string the flag actually accepts.
	rootCmd.PersistentFlags().StringVar(&ciphersuite, "ciphersuite", CiphersuiteEd25519,
		fmt.Sprintf("FROST ciphersuite (%s)", strings.Join(ValidCiphersuites(), ", ")))
	rootCmd.PersistentFlags().StringVar(&tlsCert, "tls-cert", "", "TLS certificate file path")
	rootCmd.PersistentFlags().StringVar(&tlsKey, "tls-key", "", "TLS private key file path")
	rootCmd.PersistentFlags().StringVar(&tlsCA, "tls-ca", "", "CA certificate for mTLS (optional)")
	rootCmd.PersistentFlags().BoolVar(&insecure, "insecure", false, "disable TLS verification (WARNING: testing only)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Bind flags to viper
	if err := viper.BindPFlag("protocol", rootCmd.PersistentFlags().Lookup("protocol")); err != nil {
		panic(fmt.Sprintf("failed to bind protocol flag: %v", err))
	}
	if err := viper.BindPFlag("codec", rootCmd.PersistentFlags().Lookup("codec")); err != nil {
		panic(fmt.Sprintf("failed to bind codec flag: %v", err))
	}
	if err := viper.BindPFlag("tls.cert", rootCmd.PersistentFlags().Lookup("tls-cert")); err != nil {
		panic(fmt.Sprintf("failed to bind tls.cert flag: %v", err))
	}
	if err := viper.BindPFlag("tls.key", rootCmd.PersistentFlags().Lookup("tls-key")); err != nil {
		panic(fmt.Sprintf("failed to bind tls.key flag: %v", err))
	}
	if err := viper.BindPFlag("tls.ca", rootCmd.PersistentFlags().Lookup("tls-ca")); err != nil {
		panic(fmt.Sprintf("failed to bind tls.ca flag: %v", err))
	}
	if err := viper.BindPFlag("insecure", rootCmd.PersistentFlags().Lookup("insecure")); err != nil {
		panic(fmt.Sprintf("failed to bind insecure flag: %v", err))
	}
	if err := viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose")); err != nil {
		panic(fmt.Sprintf("failed to bind verbose flag: %v", err))
	}
	if err := viper.BindPFlag("ciphersuite", rootCmd.PersistentFlags().Lookup("ciphersuite")); err != nil {
		panic(fmt.Sprintf("failed to bind ciphersuite flag: %v", err))
	}

	// Add subcommands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(coordinatorCmd)
	rootCmd.AddCommand(participantCmd)
	rootCmd.AddCommand(certgenCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(configCmd)
}
