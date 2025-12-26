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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	keygenType   string
	keygenOutput string
	keygenName   string
	keygenDays   int
	keygenHosts  []string
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate TLS certificates and keys",
	Long: `Generate TLS certificates and private keys for secure communication.

Supports ECDSA (P-256) and Ed25519 key types. Generates self-signed certificates
suitable for testing and development. For production, use certificates from a
trusted Certificate Authority.

Examples:
  # Generate ECDSA certificate for localhost
  frostdkg keygen --type ecdsa --output ./certs --name localhost

  # Generate Ed25519 certificate with multiple hosts
  frostdkg keygen --type ed25519 --output ./certs --name server \
    --hosts localhost,127.0.0.1,server.example.com

  # Generate with custom validity period
  frostdkg keygen --type ecdsa --output ./certs --name test --days 30`,
	RunE: runKeygen,
}

func init() {
	keygenCmd.Flags().StringVar(&keygenType, "type", "ecdsa", "key type (ecdsa, ed25519)")
	keygenCmd.Flags().StringVarP(&keygenOutput, "output", "o", "./certs", "output directory")
	keygenCmd.Flags().StringVar(&keygenName, "name", "localhost", "common name for certificate")
	keygenCmd.Flags().IntVar(&keygenDays, "days", 365, "certificate validity period in days")
	keygenCmd.Flags().StringSliceVar(&keygenHosts, "hosts", []string{"localhost", "127.0.0.1"}, "DNS names and IP addresses")

	if err := viper.BindPFlag("keygen.type", keygenCmd.Flags().Lookup("type")); err != nil {
		panic(fmt.Sprintf("failed to bind keygen.type flag: %v", err))
	}
	if err := viper.BindPFlag("keygen.output", keygenCmd.Flags().Lookup("output")); err != nil {
		panic(fmt.Sprintf("failed to bind keygen.output flag: %v", err))
	}
	if err := viper.BindPFlag("keygen.name", keygenCmd.Flags().Lookup("name")); err != nil {
		panic(fmt.Sprintf("failed to bind keygen.name flag: %v", err))
	}
	if err := viper.BindPFlag("keygen.days", keygenCmd.Flags().Lookup("days")); err != nil {
		panic(fmt.Sprintf("failed to bind keygen.days flag: %v", err))
	}
	if err := viper.BindPFlag("keygen.hosts", keygenCmd.Flags().Lookup("hosts")); err != nil {
		panic(fmt.Sprintf("failed to bind keygen.hosts flag: %v", err))
	}
}

func runKeygen(cmd *cobra.Command, args []string) error {
	// Validate key type
	if keygenType != "ecdsa" && keygenType != "ed25519" {
		return fmt.Errorf("invalid key type: %s (must be ecdsa or ed25519)", keygenType)
	}

	// Validate days
	if keygenDays < 1 {
		return fmt.Errorf("days must be at least 1")
	}

	// Create output directory if it doesn't exist (restricted permissions for key material)
	if err := os.MkdirAll(keygenOutput, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if verbose {
		fmt.Printf("Generating %s certificate...\n", keygenType)
		fmt.Printf("  Name: %s\n", keygenName)
		fmt.Printf("  Validity: %d days\n", keygenDays)
		fmt.Printf("  Hosts: %v\n", keygenHosts)
		fmt.Printf("  Output: %s\n", keygenOutput)
	}

	// Generate key pair
	var privateKey interface{}
	var publicKey interface{}
	var keyType string
	var err error

	switch keygenType {
	case "ecdsa":
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		privateKey = ecdsaKey
		publicKey = &ecdsaKey.PublicKey
		keyType = "EC PRIVATE KEY"

	case "ed25519":
		ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}
		privateKey = ed25519Priv
		publicKey = ed25519Pub
		keyType = "PRIVATE KEY"
	}

	// Generate serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(keygenDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"go-frostdkg"},
			CommonName:   keygenName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Add hosts (DNS names and IP addresses)
	for _, h := range keygenHosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	var keyBytes []byte
	switch keygenType {
	case "ecdsa":
		keyBytes, err = x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
		if err != nil {
			return fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}
	case "ed25519":
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return fmt.Errorf("failed to marshal Ed25519 private key: %w", err)
		}
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})

	// Write certificate file (readable permissions - certificates are public)
	certPath := filepath.Join(keygenOutput, keygenName+".crt")
	// #nosec G306 -- certificates are public, readable permissions are intentional
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key file
	keyPath := filepath.Join(keygenOutput, keygenName+".key")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	fmt.Printf("Certificate generated successfully:\n")
	fmt.Printf("  Certificate: %s\n", certPath)
	fmt.Printf("  Private Key: %s\n", keyPath)
	fmt.Printf("\nUse with --tls-cert and --tls-key flags\n")

	return nil
}
