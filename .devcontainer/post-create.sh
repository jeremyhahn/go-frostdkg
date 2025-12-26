#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2025 Jeremy Hahn
#
# Post-create script for devcontainer setup

set -e

echo "Setting up go-frostdkg development environment..."

# Ensure SoftHSM token directory is writable
sudo chown -R vscode:vscode /var/lib/softhsm || true

# Initialize a test token if it doesn't exist
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "test-token"; then
    echo "Initializing SoftHSM2 test token..."
    softhsm2-util --init-token --slot 0 --label "test-token" --pin 1234 --so-pin 12345678
fi

# Create additional test tokens for different ciphersuites
echo "Creating ciphersuite-specific test tokens..."

# Token for Ed25519 tests
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "ed25519-token"; then
    softhsm2-util --init-token --free --label "ed25519-token" --pin 1234 --so-pin 12345678
fi

# Token for secp256k1 tests
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "secp256k1-token"; then
    softhsm2-util --init-token --free --label "secp256k1-token" --pin 1234 --so-pin 12345678
fi

# Token for P-256 tests
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "p256-token"; then
    softhsm2-util --init-token --free --label "p256-token" --pin 1234 --so-pin 12345678
fi

# Install Go dependencies
echo "Installing Go dependencies..."
go mod download

# Install development tools
echo "Installing development tools..."
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest || true

# Verify SoftHSM2 is working
echo "Verifying SoftHSM2 installation..."
softhsm2-util --show-slots

echo ""
echo "Development environment setup complete!"
echo ""
echo "SoftHSM2 Configuration:"
echo "  Config file: ${SOFTHSM2_CONF}"
echo "  PKCS#11 module: ${PKCS11_MODULE}"
echo "  Test token PIN: 1234"
echo "  Test token SO-PIN: 12345678"
echo ""
echo "Available tokens:"
softhsm2-util --show-slots | grep -E "(Slot|Label)" || true
echo ""
echo "To run PKCS#11 integration tests:"
echo "  make integration-test-pkcs11"
