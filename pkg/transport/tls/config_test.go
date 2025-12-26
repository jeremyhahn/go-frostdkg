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

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestServerConfig tests server TLS configuration creation
func TestServerConfig(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) (certFile, keyFile, caFile string, cleanup func())
		wantErr     error
		validateCfg func(t *testing.T, cfg *tls.Config)
	}{
		{
			name: "valid server config without mTLS",
			setup: func(t *testing.T) (string, string, string, func()) {
				dir := t.TempDir()
				certFile := filepath.Join(dir, "server.crt")
				keyFile := filepath.Join(dir, "server.key")

				certPEM, keyPEM, err := GenerateSelfSigned([]string{"localhost"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate certificate: %v", err)
				}

				if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
					t.Fatalf("failed to write cert file: %v", err)
				}
				if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
					t.Fatalf("failed to write key file: %v", err)
				}

				return certFile, keyFile, "", func() {}
			},
			wantErr: nil,
			validateCfg: func(t *testing.T, cfg *tls.Config) {
				if cfg.MinVersion != tls.VersionTLS13 {
					t.Errorf("expected MinVersion TLS 1.3, got %d", cfg.MinVersion)
				}
				if cfg.MaxVersion != tls.VersionTLS13 {
					t.Errorf("expected MaxVersion TLS 1.3, got %d", cfg.MaxVersion)
				}
				if len(cfg.Certificates) != 1 {
					t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
				}
				if cfg.ClientAuth != tls.NoClientCert {
					t.Errorf("expected no client cert requirement, got %v", cfg.ClientAuth)
				}
			},
		},
		{
			name: "valid server config with mTLS",
			setup: func(t *testing.T) (string, string, string, func()) {
				dir := t.TempDir()
				certFile := filepath.Join(dir, "server.crt")
				keyFile := filepath.Join(dir, "server.key")
				caFile := filepath.Join(dir, "ca.crt")

				certPEM, keyPEM, err := GenerateSelfSigned([]string{"localhost"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate certificate: %v", err)
				}

				caPEM, _, err := GenerateSelfSigned([]string{"ca"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate CA certificate: %v", err)
				}

				if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
					t.Fatalf("failed to write cert file: %v", err)
				}
				if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
					t.Fatalf("failed to write key file: %v", err)
				}
				if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
					t.Fatalf("failed to write CA file: %v", err)
				}

				return certFile, keyFile, caFile, func() {}
			},
			wantErr: nil,
			validateCfg: func(t *testing.T, cfg *tls.Config) {
				if cfg.MinVersion != tls.VersionTLS13 {
					t.Errorf("expected MinVersion TLS 1.3, got %d", cfg.MinVersion)
				}
				if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
					t.Errorf("expected RequireAndVerifyClientCert, got %v", cfg.ClientAuth)
				}
				if cfg.ClientCAs == nil {
					t.Error("expected ClientCAs to be set")
				}
			},
		},
		{
			name: "certificate file not found",
			setup: func(t *testing.T) (string, string, string, func()) {
				dir := t.TempDir()
				return filepath.Join(dir, "nonexistent.crt"),
					filepath.Join(dir, "server.key"),
					"",
					func() {}
			},
			wantErr: ErrCertificateNotFound,
		},
		{
			name: "key file not found",
			setup: func(t *testing.T) (string, string, string, func()) {
				dir := t.TempDir()
				certFile := filepath.Join(dir, "server.crt")

				certPEM, _, err := GenerateSelfSigned([]string{"localhost"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate certificate: %v", err)
				}

				if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
					t.Fatalf("failed to write cert file: %v", err)
				}

				return certFile, filepath.Join(dir, "nonexistent.key"), "", func() {}
			},
			wantErr: ErrKeyNotFound,
		},
		{
			name: "invalid CA file",
			setup: func(t *testing.T) (string, string, string, func()) {
				dir := t.TempDir()
				certFile := filepath.Join(dir, "server.crt")
				keyFile := filepath.Join(dir, "server.key")
				caFile := filepath.Join(dir, "ca.crt")

				certPEM, keyPEM, err := GenerateSelfSigned([]string{"localhost"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate certificate: %v", err)
				}

				if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
					t.Fatalf("failed to write cert file: %v", err)
				}
				if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
					t.Fatalf("failed to write key file: %v", err)
				}
				if err := os.WriteFile(caFile, []byte("invalid CA data"), 0600); err != nil {
					t.Fatalf("failed to write CA file: %v", err)
				}

				return certFile, keyFile, caFile, func() {}
			},
			wantErr: ErrInvalidCAPool,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certFile, keyFile, caFile, cleanup := tt.setup(t)
			defer cleanup()

			cfg, err := ServerConfig(certFile, keyFile, caFile)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validateCfg != nil {
				tt.validateCfg(t, cfg)
			}
		})
	}
}

// TestClientConfig tests client TLS configuration creation
func TestClientConfig(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) (certFile, keyFile, caFile, serverName string, cleanup func())
		wantErr     error
		validateCfg func(t *testing.T, cfg *tls.Config)
	}{
		{
			name: "valid client config without mTLS",
			setup: func(t *testing.T) (string, string, string, string, func()) {
				dir := t.TempDir()
				caFile := filepath.Join(dir, "ca.crt")

				caPEM, _, err := GenerateSelfSigned([]string{"ca"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate CA certificate: %v", err)
				}

				if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
					t.Fatalf("failed to write CA file: %v", err)
				}

				return "", "", caFile, "localhost", func() {}
			},
			wantErr: nil,
			validateCfg: func(t *testing.T, cfg *tls.Config) {
				if cfg.MinVersion != tls.VersionTLS13 {
					t.Errorf("expected MinVersion TLS 1.3, got %d", cfg.MinVersion)
				}
				if cfg.MaxVersion != tls.VersionTLS13 {
					t.Errorf("expected MaxVersion TLS 1.3, got %d", cfg.MaxVersion)
				}
				if len(cfg.Certificates) != 0 {
					t.Errorf("expected 0 certificates, got %d", len(cfg.Certificates))
				}
				if cfg.ServerName != "localhost" {
					t.Errorf("expected ServerName localhost, got %s", cfg.ServerName)
				}
				if cfg.RootCAs == nil {
					t.Error("expected RootCAs to be set")
				}
			},
		},
		{
			name: "valid client config with mTLS",
			setup: func(t *testing.T) (string, string, string, string, func()) {
				dir := t.TempDir()
				certFile := filepath.Join(dir, "client.crt")
				keyFile := filepath.Join(dir, "client.key")
				caFile := filepath.Join(dir, "ca.crt")

				certPEM, keyPEM, err := GenerateSelfSigned([]string{"client"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate certificate: %v", err)
				}

				caPEM, _, err := GenerateSelfSigned([]string{"ca"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate CA certificate: %v", err)
				}

				if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
					t.Fatalf("failed to write cert file: %v", err)
				}
				if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
					t.Fatalf("failed to write key file: %v", err)
				}
				if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
					t.Fatalf("failed to write CA file: %v", err)
				}

				return certFile, keyFile, caFile, "localhost", func() {}
			},
			wantErr: nil,
			validateCfg: func(t *testing.T, cfg *tls.Config) {
				if cfg.MinVersion != tls.VersionTLS13 {
					t.Errorf("expected MinVersion TLS 1.3, got %d", cfg.MinVersion)
				}
				if len(cfg.Certificates) != 1 {
					t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
				}
				if cfg.RootCAs == nil {
					t.Error("expected RootCAs to be set")
				}
			},
		},
		{
			name: "client config without CA uses system roots",
			setup: func(t *testing.T) (string, string, string, string, func()) {
				return "", "", "", "localhost", func() {}
			},
			wantErr: nil,
			validateCfg: func(t *testing.T, cfg *tls.Config) {
				if cfg.MinVersion != tls.VersionTLS13 {
					t.Errorf("expected MinVersion TLS 1.3, got %d", cfg.MinVersion)
				}
				if cfg.RootCAs != nil {
					t.Error("expected RootCAs to be nil (system roots)")
				}
			},
		},
		{
			name: "invalid client certificate",
			setup: func(t *testing.T) (string, string, string, string, func()) {
				dir := t.TempDir()
				certFile := filepath.Join(dir, "client.crt")
				keyFile := filepath.Join(dir, "client.key")

				if err := os.WriteFile(certFile, []byte("invalid cert"), 0600); err != nil {
					t.Fatalf("failed to write cert file: %v", err)
				}
				if err := os.WriteFile(keyFile, []byte("invalid key"), 0600); err != nil {
					t.Fatalf("failed to write key file: %v", err)
				}

				return certFile, keyFile, "", "localhost", func() {}
			},
			wantErr: ErrInvalidCertificate,
		},
		{
			name: "CA file not found",
			setup: func(t *testing.T) (string, string, string, string, func()) {
				dir := t.TempDir()
				return "", "", filepath.Join(dir, "nonexistent.crt"), "localhost", func() {}
			},
			wantErr: ErrCANotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certFile, keyFile, caFile, serverName, cleanup := tt.setup(t)
			defer cleanup()

			cfg, err := ClientConfig(certFile, keyFile, caFile, serverName)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validateCfg != nil {
				tt.validateCfg(t, cfg)
			}
		})
	}
}

// TestInsecureClientConfig tests insecure client configuration
func TestInsecureClientConfig(t *testing.T) {
	cfg := InsecureClientConfig()

	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion TLS 1.3, got %d", cfg.MinVersion)
	}

	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("expected MaxVersion TLS 1.3, got %d", cfg.MaxVersion)
	}

	if !cfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}

// TestLoadCertificate tests certificate loading
func TestLoadCertificate(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (certFile, keyFile string, cleanup func())
		wantErr error
	}{
		{
			name: "valid certificate and key",
			setup: func(t *testing.T) (string, string, func()) {
				dir := t.TempDir()
				certFile := filepath.Join(dir, "cert.crt")
				keyFile := filepath.Join(dir, "cert.key")

				certPEM, keyPEM, err := GenerateSelfSigned([]string{"localhost"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate certificate: %v", err)
				}

				if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
					t.Fatalf("failed to write cert file: %v", err)
				}
				if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
					t.Fatalf("failed to write key file: %v", err)
				}

				return certFile, keyFile, func() {}
			},
			wantErr: nil,
		},
		{
			name: "empty certificate path",
			setup: func(t *testing.T) (string, string, func()) {
				return "", "key.pem", func() {}
			},
			wantErr: ErrEmptyCertificate,
		},
		{
			name: "empty key path",
			setup: func(t *testing.T) (string, string, func()) {
				return "cert.pem", "", func() {}
			},
			wantErr: ErrEmptyKey,
		},
		{
			name: "certificate file not found",
			setup: func(t *testing.T) (string, string, func()) {
				dir := t.TempDir()
				return filepath.Join(dir, "nonexistent.crt"),
					filepath.Join(dir, "key.key"),
					func() {}
			},
			wantErr: ErrCertificateNotFound,
		},
		{
			name: "key file not found",
			setup: func(t *testing.T) (string, string, func()) {
				dir := t.TempDir()
				certFile := filepath.Join(dir, "cert.crt")

				certPEM, _, err := GenerateSelfSigned([]string{"localhost"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate certificate: %v", err)
				}

				if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
					t.Fatalf("failed to write cert file: %v", err)
				}

				return certFile, filepath.Join(dir, "nonexistent.key"), func() {}
			},
			wantErr: ErrKeyNotFound,
		},
		{
			name: "invalid certificate format",
			setup: func(t *testing.T) (string, string, func()) {
				dir := t.TempDir()
				certFile := filepath.Join(dir, "cert.crt")
				keyFile := filepath.Join(dir, "cert.key")

				if err := os.WriteFile(certFile, []byte("invalid certificate data"), 0600); err != nil {
					t.Fatalf("failed to write cert file: %v", err)
				}
				if err := os.WriteFile(keyFile, []byte("invalid key data"), 0600); err != nil {
					t.Fatalf("failed to write key file: %v", err)
				}

				return certFile, keyFile, func() {}
			},
			wantErr: ErrInvalidCertificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certFile, keyFile, cleanup := tt.setup(t)
			defer cleanup()

			cert, err := LoadCertificate(certFile, keyFile)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cert.Certificate == nil {
				t.Error("expected non-nil certificate")
			}
		})
	}
}

// TestLoadCAPool tests CA certificate pool loading
func TestLoadCAPool(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (caFile string, cleanup func())
		wantErr error
	}{
		{
			name: "valid CA certificate",
			setup: func(t *testing.T) (string, func()) {
				dir := t.TempDir()
				caFile := filepath.Join(dir, "ca.crt")

				caPEM, _, err := GenerateSelfSigned([]string{"ca"}, time.Hour)
				if err != nil {
					t.Fatalf("failed to generate CA certificate: %v", err)
				}

				if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
					t.Fatalf("failed to write CA file: %v", err)
				}

				return caFile, func() {}
			},
			wantErr: nil,
		},
		{
			name: "empty CA file path",
			setup: func(t *testing.T) (string, func()) {
				return "", func() {}
			},
			wantErr: ErrCANotFound,
		},
		{
			name: "CA file not found",
			setup: func(t *testing.T) (string, func()) {
				dir := t.TempDir()
				return filepath.Join(dir, "nonexistent.crt"), func() {}
			},
			wantErr: ErrCANotFound,
		},
		{
			name: "empty CA file",
			setup: func(t *testing.T) (string, func()) {
				dir := t.TempDir()
				caFile := filepath.Join(dir, "ca.crt")

				if err := os.WriteFile(caFile, []byte{}, 0600); err != nil {
					t.Fatalf("failed to write CA file: %v", err)
				}

				return caFile, func() {}
			},
			wantErr: ErrInvalidCAPool,
		},
		{
			name: "invalid CA certificate format",
			setup: func(t *testing.T) (string, func()) {
				dir := t.TempDir()
				caFile := filepath.Join(dir, "ca.crt")

				if err := os.WriteFile(caFile, []byte("invalid CA data"), 0600); err != nil {
					t.Fatalf("failed to write CA file: %v", err)
				}

				return caFile, func() {}
			},
			wantErr: ErrInvalidCAPool,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caFile, cleanup := tt.setup(t)
			defer cleanup()

			pool, err := LoadCAPool(caFile)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if pool == nil {
				t.Error("expected non-nil certificate pool")
			}
		})
	}
}

// TestGenerateSelfSigned tests self-signed certificate generation
func TestGenerateSelfSigned(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []string
		validFor time.Duration
		wantErr  bool
	}{
		{
			name:     "generate with DNS name",
			hosts:    []string{"localhost"},
			validFor: time.Hour,
			wantErr:  false,
		},
		{
			name:     "generate with IP address",
			hosts:    []string{"127.0.0.1"},
			validFor: time.Hour,
			wantErr:  false,
		},
		{
			name:     "generate with multiple hosts",
			hosts:    []string{"localhost", "127.0.0.1", "::1"},
			validFor: time.Hour,
			wantErr:  false,
		},
		{
			name:     "generate with no hosts",
			hosts:    []string{},
			validFor: time.Hour,
			wantErr:  false,
		},
		{
			name:     "generate with zero duration (uses default)",
			hosts:    []string{"localhost"},
			validFor: 0,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPEM, keyPEM, err := GenerateSelfSigned(tt.hosts, tt.validFor)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(certPEM) == 0 {
				t.Error("expected non-empty certificate PEM")
			}

			if len(keyPEM) == 0 {
				t.Error("expected non-empty key PEM")
			}

			// Verify the certificate can be parsed
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				t.Fatalf("failed to parse generated certificate: %v", err)
			}

			if len(cert.Certificate) == 0 {
				t.Error("expected at least one certificate in chain")
			}

			// Parse and verify the certificate structure
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("failed to parse X.509 certificate: %v", err)
			}

			// Verify hosts
			totalHosts := len(x509Cert.DNSNames) + len(x509Cert.IPAddresses)
			if totalHosts != len(tt.hosts) {
				t.Errorf("expected %d hosts, got %d", len(tt.hosts), totalHosts)
			}

			// Verify it's a CA certificate
			if !x509Cert.IsCA {
				t.Error("expected certificate to be a CA")
			}

			// Verify key usage
			if x509Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
				t.Error("expected KeyUsageDigitalSignature")
			}

			if x509Cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
				t.Error("expected KeyUsageKeyEncipherment")
			}
		})
	}
}

// TestGenerateSelfSignedAndUse tests that generated certificates can be used
func TestGenerateSelfSignedAndUse(t *testing.T) {
	// Generate a self-signed certificate
	certPEM, keyPEM, err := GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	// Write to temporary files
	dir := t.TempDir()
	certFile := filepath.Join(dir, "test.crt")
	keyFile := filepath.Join(dir, "test.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Test server config
	serverCfg, err := ServerConfig(certFile, keyFile, "")
	if err != nil {
		t.Fatalf("failed to create server config: %v", err)
	}

	if serverCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %d", serverCfg.MinVersion)
	}

	// Test client config
	clientCfg, err := ClientConfig("", "", certFile, "localhost")
	if err != nil {
		t.Fatalf("failed to create client config: %v", err)
	}

	if clientCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %d", clientCfg.MinVersion)
	}
}

// TestCipherSuites verifies that only TLS 1.3 cipher suites are configured
func TestCipherSuites(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.crt")
	keyFile := filepath.Join(dir, "cert.key")

	certPEM, keyPEM, err := GenerateSelfSigned([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	serverCfg, err := ServerConfig(certFile, keyFile, "")
	if err != nil {
		t.Fatalf("failed to create server config: %v", err)
	}

	expectedCiphers := []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}

	if len(serverCfg.CipherSuites) != len(expectedCiphers) {
		t.Errorf("expected %d cipher suites, got %d", len(expectedCiphers), len(serverCfg.CipherSuites))
	}

	for i, expected := range expectedCiphers {
		if i >= len(serverCfg.CipherSuites) {
			break
		}
		if serverCfg.CipherSuites[i] != expected {
			t.Errorf("cipher suite %d: expected 0x%x, got 0x%x", i, expected, serverCfg.CipherSuites[i])
		}
	}
}
