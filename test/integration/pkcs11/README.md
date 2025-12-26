# PKCS#11 Integration Tests

This directory contains integration tests for hardware-backed key operations using PKCS#11.

## Prerequisites

### SoftHSM2 Installation

The tests use SoftHSM2 as a software-based PKCS#11 implementation for testing. The devcontainer includes SoftHSM2 pre-installed.

For local development:

```bash
# Ubuntu/Debian
sudo apt-get install softhsm2 opensc

# macOS
brew install softhsm

# Configure SoftHSM2
sudo mkdir -p /var/lib/softhsm/tokens
sudo chmod 755 /var/lib/softhsm/tokens
```

### Environment Variables

- `SOFTHSM2_CONF`: Path to SoftHSM2 configuration file (default: `/etc/softhsm/softhsm2.conf`)
- `PKCS11_MODULE`: Path to PKCS#11 module library (default: `/usr/lib/softhsm/libsofthsm2.so`)

## Running Tests

### Using Make

```bash
# Run all PKCS#11 integration tests
make integration-test-pkcs11

# Run specific ciphersuite tests
make integration-test-pkcs11-ed25519
make integration-test-pkcs11-secp256k1
```

### Using Go directly

```bash
# Run all PKCS#11 tests
go test -v -tags="integration pkcs11" ./test/integration/pkcs11/...

# Run specific test
go test -v -tags="integration pkcs11" -run TestDKGWithPKCS11_AllCiphersuites ./test/integration/pkcs11/...
```

## Test Coverage

### Ciphersuites Tested

- FROST-ED25519-SHA512-v1
- FROST-ED448-SHAKE256-v1
- FROST-secp256k1-SHA256-v1
- FROST-P256-SHA256-v1
- FROST-P384-SHA384-v1
- FROST-ristretto255-SHA512-v1

### Test Scenarios

1. **Key Generation**: Generate key pairs in HSM and verify they work
2. **DKG Protocol**: Run full DKG with HSM-backed host keys
3. **Secret Share Storage**: Store and retrieve shares from HSM
4. **Threshold Signing**: Perform threshold signatures with HSM keys
5. **Key Refresh**: Proactive security through key refresh
6. **Share Repair**: Recover lost shares using remaining participants
7. **Cross-Backend Compatibility**: Mixed software/HSM participants

## Token Configuration

Default test token settings:
- Label: `test-token`
- PIN: `1234`
- SO-PIN: `12345678`

Additional ciphersuite-specific tokens:
- `ed25519-token`: For Ed25519 curve tests
- `secp256k1-token`: For secp256k1 curve tests
- `p256-token`: For P-256 curve tests

## Assertions

Tests include comprehensive assertions to verify:

- Signature validity
- Public key correctness
- Share consistency
- Cross-participant compatibility
- Proper error handling for invalid operations

## Troubleshooting

### Common Issues

1. **Token not initialized**
   ```bash
   softhsm2-util --init-token --slot 0 --label "test-token" --pin 1234 --so-pin 12345678
   ```

2. **Permission denied**
   ```bash
   sudo chown -R $(whoami) /var/lib/softhsm/tokens
   ```

3. **Module not found**
   Check the `PKCS11_MODULE` environment variable points to the correct library.

### Debug Mode

Enable verbose logging:
```bash
SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf go test -v -tags="integration pkcs11" ./test/integration/pkcs11/...
```
