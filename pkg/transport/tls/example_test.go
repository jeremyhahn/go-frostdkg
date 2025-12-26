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

package tls_test

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// ExampleServerConfig demonstrates creating a TLS 1.3 server configuration
func ExampleServerConfig() {
	// For this example, generate self-signed certificates
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// Write certificates to temporary files
	tmpDir := os.TempDir()
	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.Remove(certFile) }()

	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.Remove(keyFile) }()

	// Create server TLS configuration without mTLS
	config, err := tlsconfig.ServerConfig(certFile, keyFile, "")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("TLS Version: 1.%d\n", config.MinVersion-tls.VersionTLS10)
	fmt.Printf("Client Auth: %v\n", config.ClientAuth)
	// Output:
	// TLS Version: 1.3
	// Client Auth: NoClientCert
}

// ExampleServerConfig_mTLS demonstrates creating a TLS 1.3 server configuration with mutual TLS
func ExampleServerConfig_mTLS() {
	// Generate server certificates
	serverCert, serverKey, err := tlsconfig.GenerateSelfSigned([]string{"localhost"}, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// Generate CA certificate for client verification
	caCert, _, err := tlsconfig.GenerateSelfSigned([]string{"ca"}, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// Write to temporary files
	tmpDir := os.TempDir()
	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")
	caFile := filepath.Join(tmpDir, "ca.crt")

	if err := os.WriteFile(certFile, serverCert, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyFile, serverKey, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(caFile, caCert, 0600); err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = os.Remove(certFile)
		_ = os.Remove(keyFile)
		_ = os.Remove(caFile)
	}()

	// Create server TLS configuration with mTLS
	config, err := tlsconfig.ServerConfig(certFile, keyFile, caFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("TLS Version: 1.%d\n", config.MinVersion-tls.VersionTLS10)
	fmt.Printf("Client Auth: %v\n", config.ClientAuth)
	fmt.Printf("Requires Client Cert: %v\n", config.ClientAuth == tls.RequireAndVerifyClientCert)
	// Output:
	// TLS Version: 1.3
	// Client Auth: RequireAndVerifyClientCert
	// Requires Client Cert: true
}

// ExampleClientConfig demonstrates creating a TLS 1.3 client configuration
func ExampleClientConfig() {
	// Generate CA certificate for server verification
	caCert, _, err := tlsconfig.GenerateSelfSigned([]string{"ca"}, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// Write to temporary file
	tmpDir := os.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")

	if err := os.WriteFile(caFile, caCert, 0600); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.Remove(caFile) }()

	// Create client TLS configuration
	config, err := tlsconfig.ClientConfig("", "", caFile, "localhost")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("TLS Version: 1.%d\n", config.MinVersion-tls.VersionTLS10)
	fmt.Printf("Server Name: %s\n", config.ServerName)
	fmt.Printf("Has Client Cert: %v\n", len(config.Certificates) > 0)
	// Output:
	// TLS Version: 1.3
	// Server Name: localhost
	// Has Client Cert: false
}

// ExampleClientConfig_mTLS demonstrates creating a TLS 1.3 client configuration with mutual TLS
func ExampleClientConfig_mTLS() {
	// Generate client certificates
	clientCert, clientKey, err := tlsconfig.GenerateSelfSigned([]string{"client"}, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// Generate CA certificate for server verification
	caCert, _, err := tlsconfig.GenerateSelfSigned([]string{"ca"}, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// Write to temporary files
	tmpDir := os.TempDir()
	certFile := filepath.Join(tmpDir, "client.crt")
	keyFile := filepath.Join(tmpDir, "client.key")
	caFile := filepath.Join(tmpDir, "ca.crt")

	if err := os.WriteFile(certFile, clientCert, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyFile, clientKey, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(caFile, caCert, 0600); err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = os.Remove(certFile)
		_ = os.Remove(keyFile)
		_ = os.Remove(caFile)
	}()

	// Create client TLS configuration with mTLS
	config, err := tlsconfig.ClientConfig(certFile, keyFile, caFile, "localhost")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("TLS Version: 1.%d\n", config.MinVersion-tls.VersionTLS10)
	fmt.Printf("Server Name: %s\n", config.ServerName)
	fmt.Printf("Has Client Cert: %v\n", len(config.Certificates) > 0)
	// Output:
	// TLS Version: 1.3
	// Server Name: localhost
	// Has Client Cert: true
}

// ExampleInsecureClientConfig demonstrates creating an insecure client configuration for testing
func ExampleInsecureClientConfig() {
	config := tlsconfig.InsecureClientConfig()

	fmt.Printf("TLS Version: 1.%d\n", config.MinVersion-tls.VersionTLS10)
	fmt.Printf("Skip Verify: %v\n", config.InsecureSkipVerify)
	// Output:
	// TLS Version: 1.3
	// Skip Verify: true
}

// ExampleGenerateSelfSigned demonstrates generating a self-signed certificate
func ExampleGenerateSelfSigned() {
	// Generate a self-signed certificate valid for 1 year
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
		[]string{"localhost", "127.0.0.1", "::1"},
		365*24*time.Hour,
	)
	if err != nil {
		log.Fatal(err)
	}

	// The certificate and key can be written to files or used directly
	fmt.Printf("Certificate generated: %v\n", len(certPEM) > 0)
	fmt.Printf("Key generated: %v\n", len(keyPEM) > 0)
	fmt.Printf("Generated: success\n")
	// Output:
	// Certificate generated: true
	// Key generated: true
	// Generated: success
}

// ExampleLoadCertificate demonstrates loading a certificate from files
func ExampleLoadCertificate() {
	// Generate test certificates
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned([]string{"localhost"}, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// Write to temporary files
	tmpDir := os.TempDir()
	certFile := filepath.Join(tmpDir, "test.crt")
	keyFile := filepath.Join(tmpDir, "test.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = os.Remove(certFile)
		_ = os.Remove(keyFile)
	}()

	// Load the certificate
	cert, err := tlsconfig.LoadCertificate(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Certificate loaded: %v\n", cert.Certificate != nil)
	// Output:
	// Certificate loaded: true
}

// ExampleLoadCAPool demonstrates loading a CA certificate pool
func ExampleLoadCAPool() {
	// Generate CA certificate
	caPEM, _, err := tlsconfig.GenerateSelfSigned([]string{"ca"}, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// Write to temporary file
	tmpDir := os.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")

	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.Remove(caFile) }()

	// Load CA pool
	pool, err := tlsconfig.LoadCAPool(caFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("CA Pool loaded: %v\n", pool != nil)
	// Output:
	// CA Pool loaded: true
}
