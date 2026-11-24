// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integration

package quic

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
	tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"
)

// One ephemeral self-signed P-256 pair per test binary, shared by server and client so verification stays on.

var (
	testPKIOnce sync.Once
	testPKIDir  string
	testPKICert string
	testPKIKey  string
	testPKIErr  error
)

// testPKIFiles returns paths to the suite's shared certificate and key,
// generating them on first use.
func testPKIFiles(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	testPKIOnce.Do(generateTestPKI)
	if testPKIErr != nil {
		t.Fatalf("Failed to generate test PKI: %v", testPKIErr)
	}
	return testPKICert, testPKIKey
}

func generateTestPKI() {
	hosts := []string{"127.0.0.1", "localhost"}
	certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(hosts, 24*time.Hour)
	if err != nil {
		testPKIErr = err
		return
	}

	// Not t.TempDir(): the material outlives any single test, so it is owned by
	// the binary and removed by TestMain.
	dir, err := os.MkdirTemp("", "frostdkg-quic-testpki-")
	if err != nil {
		testPKIErr = err
		return
	}
	testPKIDir = dir

	cert := filepath.Join(dir, "test.crt")
	key := filepath.Join(dir, "test.key")
	if err := os.WriteFile(cert, certPEM, 0600); err != nil {
		testPKIErr = err
		return
	}
	if err := os.WriteFile(key, keyPEM, 0600); err != nil {
		testPKIErr = err
		return
	}

	testPKICert, testPKIKey = cert, key
}

// testClientConfig returns a client transport config that trusts the suite's
// certificate. TLSCAFile is what satisfies Connect's TLS requirement and, more
// importantly, is what makes the client actually verify the server rather than
// skip verification.
func testClientConfig(t *testing.T, timeout time.Duration) *transport.Config {
	t.Helper()

	certFile, _ := testPKIFiles(t)
	return &transport.Config{
		Protocol:  transport.ProtocolQUIC,
		CodecType: "json",
		Timeout:   timeout,
		TLSCAFile: certFile,
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if testPKIDir != "" {
		_ = os.RemoveAll(testPKIDir)
	}
	os.Exit(code)
}
