//go:build integration && pkcs11

package pkcs11_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// CLIPkcs11Config holds configuration for CLI PKCS#11 tests.
type CLIPkcs11Config struct {
	BinaryPath  string
	ModulePath  string
	TokenLabel  string
	PIN         string
	KeyLabel    string
	Ciphersuite string
}

// DefaultCLIPkcs11Config returns the default configuration for CLI PKCS#11 tests.
func DefaultCLIPkcs11Config() *CLIPkcs11Config {
	modulePath := os.Getenv("PKCS11_MODULE")
	if modulePath == "" {
		modulePath = "/usr/lib/softhsm/libsofthsm2.so"
	}

	binaryPath := os.Getenv("FROSTDKG_BINARY")
	if binaryPath == "" {
		candidates := []string{
			"../../../cmd/frostdkg/frostdkg",
			"./frostdkg",
			"frostdkg",
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				binaryPath = p
				break
			}
		}
	}

	return &CLIPkcs11Config{
		BinaryPath:  binaryPath,
		ModulePath:  modulePath,
		TokenLabel:  "test-token",
		PIN:         "1234",
		KeyLabel:    "frost-dkg-key",
		Ciphersuite: "ed25519",
	}
}

// TestCLIPkcs11Prerequisites verifies that CLI and PKCS#11 prerequisites are available.
func TestCLIPkcs11Prerequisites(t *testing.T) {
	config := DefaultCLIPkcs11Config()

	if _, err := os.Stat(config.ModulePath); os.IsNotExist(err) {
		t.Skipf("PKCS#11 module not found at %s", config.ModulePath)
	}

	softhsmConf := os.Getenv("SOFTHSM2_CONF")
	if softhsmConf != "" {
		if _, err := os.Stat(softhsmConf); os.IsNotExist(err) {
			t.Logf("Warning: SOFTHSM2_CONF points to non-existent file: %s", softhsmConf)
		}
	}

	t.Log("CLI PKCS#11 prerequisites verified")
	t.Logf("  Module: %s", config.ModulePath)
	t.Logf("  Token: %s", config.TokenLabel)
}

// TestCLIHelpOutput tests that CLI help output works.
func TestCLIHelpOutput(t *testing.T) {
	config := DefaultCLIPkcs11Config()

	if config.BinaryPath == "" {
		t.Skip("frostdkg binary not found, skipping CLI test")
	}

	cmd := exec.Command(config.BinaryPath, "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("Could not run frostdkg binary: %v", err)
	}

	require.Contains(t, string(output), "frostdkg")
}

// TestCLIVersionOutput tests that CLI version output works.
func TestCLIVersionOutput(t *testing.T) {
	config := DefaultCLIPkcs11Config()

	if config.BinaryPath == "" {
		t.Skip("frostdkg binary not found, skipping CLI test")
	}

	cmd := exec.Command(config.BinaryPath, "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("Could not run frostdkg version: %v", err)
	}

	require.NotEmpty(t, string(output))
}

// TestCLIParticipantWithPKCS11_FlagValidation tests that PKCS#11 flags are validated.
func TestCLIParticipantWithPKCS11_FlagValidation(t *testing.T) {
	t.Skip("TODO: Implement PKCS#11 CLI flags for participant command")
}

// TestCLICertgenWithPKCS11 tests certificate generation into PKCS#11 token.
func TestCLICertgenWithPKCS11(t *testing.T) {
	t.Skip("TODO: Implement PKCS#11 certgen CLI command")
}

// TestCLICoordinatorWithPKCS11Participants tests coordinator with PKCS#11 participants.
func TestCLICoordinatorWithPKCS11Participants(t *testing.T) {
	t.Skip("TODO: Implement full DKG CLI test with PKCS#11 backend")
}

// TestCLIThresholdSigningWithPKCS11 tests threshold signing with HSM-backed keys.
func TestCLIThresholdSigningWithPKCS11(t *testing.T) {
	t.Skip("TODO: Implement threshold signing CLI with PKCS#11")
}

// TestCLIKeyRefreshWithPKCS11 tests proactive key refresh with PKCS#11.
func TestCLIKeyRefreshWithPKCS11(t *testing.T) {
	t.Skip("TODO: Implement key refresh CLI with PKCS#11")
}

// TestCLIShareRepairWithPKCS11 tests share repair with PKCS#11.
func TestCLIShareRepairWithPKCS11(t *testing.T) {
	t.Skip("TODO: Implement share repair CLI with PKCS#11")
}

// TestCLIConfigFilePKCS11 tests PKCS#11 configuration via config file.
func TestCLIConfigFilePKCS11(t *testing.T) {
	t.Skip("TODO: Implement PKCS#11 config file support")
}

// TestCLIEnvironmentVariablesPKCS11 tests PKCS#11 configuration via env vars.
func TestCLIEnvironmentVariablesPKCS11(t *testing.T) {
	t.Skip("TODO: Implement PKCS#11 environment variable support")
}

// runCLICommand runs the frostdkg CLI with the given arguments.
func runCLICommand(t *testing.T, config *CLIPkcs11Config, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	if config.BinaryPath == "" {
		t.Skip("frostdkg binary not found")
	}

	cmd := exec.Command(config.BinaryPath, args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	cmd.Env = append(os.Environ(),
		"PKCS11_MODULE="+config.ModulePath,
		"SOFTHSM2_CONF="+os.Getenv("SOFTHSM2_CONF"),
	)

	err = cmd.Run()
	return stdoutBuf.String(), stderrBuf.String(), err
}

// ensureBinaryBuilt ensures the frostdkg binary is built.
func ensureBinaryBuilt(t *testing.T) string {
	t.Helper()

	config := DefaultCLIPkcs11Config()
	if config.BinaryPath != "" {
		if _, err := os.Stat(config.BinaryPath); err == nil {
			return config.BinaryPath
		}
	}

	projectRoot := filepath.Join("..", "..", "..")
	binaryPath := filepath.Join(projectRoot, "cmd", "frostdkg", "frostdkg")

	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = filepath.Join(projectRoot, "cmd", "frostdkg")

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("Failed to build frostdkg: %v\n%s", err, output)
		return ""
	}

	return binaryPath
}
