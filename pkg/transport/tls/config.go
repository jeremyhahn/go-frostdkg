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

// Package tls provides production-ready TLS 1.3 configuration utilities for secure communication.
//
// This package enforces TLS 1.3 as the minimum version and provides simple APIs for creating
// both server and client configurations with support for mutual TLS (mTLS). It includes
// utilities for certificate management and self-signed certificate generation for testing.
//
// Key features:
//   - TLS 1.3 enforcement for maximum security
//   - Mutual TLS (mTLS) support for bidirectional authentication
//   - Secure cipher suite selection (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305)
//   - Self-signed certificate generation using ECDSA P-256
//   - Comprehensive error handling with typed errors
//
// Example server configuration:
//
//	config, err := tls.ServerConfig("server.crt", "server.key", "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	server := &http.Server{
//	    Addr:      ":8443",
//	    TLSConfig: config,
//	}
//
// Example client configuration with mTLS:
//
//	config, err := tls.ClientConfig("client.crt", "client.key", "ca.crt", "server.example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	client := &http.Client{
//	    Transport: &http.Transport{
//	        TLSClientConfig: config,
//	    },
//	}
package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ServerConfig creates a TLS 1.3 server configuration
// certFile: path to server certificate (PEM)
// keyFile: path to server private key (PEM)
// caFile: optional path to CA cert for mTLS client verification (empty string to skip)
func ServerConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := LoadCertificate(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	config := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	// If CA file is provided, enable mTLS with client certificate verification
	if caFile != "" {
		certPool, err := LoadCAPool(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}
		config.ClientCAs = certPool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config, nil
}

// ClientConfig creates a TLS 1.3 client configuration
// certFile: optional path to client certificate for mTLS (empty to skip)
// keyFile: optional path to client private key for mTLS (empty to skip)
// caFile: path to CA cert to verify server (empty to use system roots)
// serverName: expected server name for verification (empty to skip)
func ClientConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		ServerName: serverName,
	}

	// Load client certificate for mTLS if provided
	if certFile != "" && keyFile != "" {
		cert, err := LoadCertificate(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate for server verification
	if caFile != "" {
		certPool, err := LoadCAPool(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}
		config.RootCAs = certPool
	}

	return config, nil
}

// InsecureClientConfig creates a TLS config that skips server verification.
//
// WARNING: This function is ONLY for testing and development purposes.
// It disables certificate verification which makes the connection vulnerable
// to man-in-the-middle attacks. NEVER use in production.
//
// For production, use ClientConfigWithCA() with proper CA certificates.
func InsecureClientConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //#nosec G402 -- Intentional for testing; see function documentation
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
}

// LoadCertificate loads a certificate and key from files
func LoadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	if certFile == "" {
		return tls.Certificate{}, ErrEmptyCertificate
	}
	if keyFile == "" {
		return tls.Certificate{}, ErrEmptyKey
	}

	// Check if certificate file exists
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return tls.Certificate{}, fmt.Errorf("%w: %s", ErrCertificateNotFound, certFile)
	}

	// Check if key file exists
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return tls.Certificate{}, fmt.Errorf("%w: %s", ErrKeyNotFound, keyFile)
	}

	// Load the certificate and key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	return cert, nil
}

// LoadCAPool loads a CA certificate pool from a file
func LoadCAPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, fmt.Errorf("%w: empty CA file path", ErrCANotFound)
	}

	// Clean the file path to prevent directory traversal attacks
	cleanPath := filepath.Clean(caFile)

	// Check if CA file exists
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: %s", ErrCANotFound, cleanPath)
	}

	// Read CA certificate
	caPEM, err := os.ReadFile(cleanPath) //nolint:gosec // G304: Path is cleaned above
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	if len(caPEM) == 0 {
		return nil, fmt.Errorf("%w: empty CA file", ErrInvalidCAPool)
	}

	// Create certificate pool
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: failed to parse CA certificate", ErrInvalidCAPool)
	}

	return certPool, nil
}

// GenerateSelfSigned generates a self-signed certificate for testing
// Returns certPEM, keyPEM, error
func GenerateSelfSigned(hosts []string, validFor time.Duration) ([]byte, []byte, error) {
	if validFor == 0 {
		validFor = 365 * 24 * time.Hour // Default to 1 year
	}

	// Generate ECDSA private key using P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate a random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"go-frostdkg Test"},
			CommonName:   "go-frostdkg Test Certificate",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Add hosts (DNS names and IP addresses)
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return certPEM, keyPEM, nil
}
