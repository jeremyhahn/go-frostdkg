# frostdkg CLI Reference

Command-line tool for executing FROST Distributed Key Generation (DKG) with support for multiple transport protocols and serialization formats.

## Overview

`frostdkg` provides a complete implementation of the FROST-DKG protocol with:

- Multiple transport protocols: gRPC, HTTP, QUIC, libp2p, MCP, Unix sockets, in-memory
- Multiple serialization formats: JSON, MessagePack, CBOR
- TLS 1.3 security with optional mutual TLS (mTLS)
- Built-in certificate generation for testing
- Key share verification utilities

## Installation

### From Source

```bash
make install
```

This installs the `frostdkg` binary to your `$GOPATH/bin`.

### Build Only

```bash
make build-cli
```

The binary will be at `./bin/frostdkg`.

## Global Flags

These flags apply to all commands and configure transport, security, and output:

| Flag | Description | Default |
|------|-------------|---------|
| `--config` | Config file path | `$HOME/.frostdkg/config.yaml` |
| `--protocol` | Transport protocol (`grpc`, `http`, `quic`, `unix`, `libp2p`, `mcp`, `memory`) | `grpc` |
| `--codec` | Serialization format (`json`, `msgpack`, `cbor`) | `json` |
| `--tls-cert` | TLS certificate file path | |
| `--tls-key` | TLS private key file path | |
| `--tls-ca` | CA certificate for mTLS (optional) | |
| `--insecure` | Disable TLS verification (WARNING: testing only) | `false` |
| `-v, --verbose` | Enable verbose output | `false` |

## Commands

### coordinator

Start a DKG coordinator server that relays messages between participants.

**Role:** The coordinator has no cryptographic role and does not participate in the DKG. It acts purely as a message relay and session coordinator.

#### Usage

```bash
frostdkg coordinator [flags]
```

#### Flags

| Flag | Shorthand | Description | Default | Required |
|------|-----------|-------------|---------|----------|
| `--listen` | | Address to listen on | `0.0.0.0:9000` | No |
| `--threshold` | `-t` | Minimum signers required | `2` | Yes |
| `--participants` | `-n` | Total participants | `3` | Yes |
| `--session-id` | | Session identifier (generates UUID if not provided) | | No |
| `--ciphersuite` | | FROST ciphersuite identifier | `FROST-ED25519-SHA512-v1` | No |
| `--timeout` | | Session timeout in seconds | `300` | No |

#### Examples

Start gRPC coordinator for 3-of-5 threshold scheme:
```bash
frostdkg coordinator --listen 0.0.0.0:9000 --threshold 3 --participants 5
```

Start HTTP coordinator with TLS:
```bash
frostdkg coordinator --protocol http --listen 0.0.0.0:8443 \
  --tls-cert server.crt --tls-key server.key \
  --threshold 2 --participants 3
```

Start QUIC coordinator with custom session ID:
```bash
frostdkg coordinator --protocol quic --listen 0.0.0.0:9001 \
  --threshold 2 --participants 3 --session-id my-session
```

Start coordinator with verbose output:
```bash
frostdkg coordinator --threshold 2 --participants 3 --verbose
```

### participant

Join a DKG session as a participant and execute the FROST-DKG protocol.

**Role:** Participants connect to a coordinator, exchange cryptographic messages, and receive their threshold key share. The key share must be kept secret.

#### Usage

```bash
frostdkg participant [flags]
```

#### Flags

| Flag | Shorthand | Description | Default | Required |
|------|-----------|-------------|---------|----------|
| `--coordinator` | | Coordinator address | `localhost:9000` | No |
| `--id` | | Participant identifier (0-indexed) | `-1` | Yes |
| `--output` | `-o` | Output file path for key share | | Yes |
| `--hostkey` | | Host secret key (hex, 32 bytes). Generated if not provided | | No |
| `--hostpubkeys` | | Comma-separated host public keys (hex, 33 bytes each) | | No |
| `--threshold` | `-t` | Signing threshold (must match coordinator) | `2` | No |
| `--timeout` | | Operation timeout in seconds | `300` | No |

#### Examples

Join as participant 0 with auto-generated host key:
```bash
frostdkg participant --coordinator localhost:9000 --id 0 \
  --threshold 2 --output participant0.json
```

Join with explicit host secret key:
```bash
frostdkg participant --coordinator localhost:9000 --id 1 \
  --hostkey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --threshold 2 --output participant1.json
```

Join HTTP coordinator with TLS client certificate:
```bash
frostdkg participant --protocol http --coordinator https://localhost:8443 \
  --tls-cert client.crt --tls-key client.key --tls-ca ca.crt \
  --id 0 --threshold 2 --output participant0.json
```

Join QUIC coordinator:
```bash
frostdkg participant --protocol quic --coordinator localhost:9001 \
  --tls-ca ca.crt --id 2 --threshold 2 --output participant2.json
```

Join with verbose output:
```bash
frostdkg participant --coordinator localhost:9000 --id 0 \
  --threshold 2 --output participant0.json --verbose
```

### keygen

Generate TLS certificates and private keys for secure communication.

**Note:** Generates self-signed certificates suitable for testing and development. For production, use certificates from a trusted Certificate Authority.

#### Usage

```bash
frostdkg keygen [flags]
```

#### Flags

| Flag | Shorthand | Description | Default | Required |
|------|-----------|-------------|---------|----------|
| `--type` | | Key type (`ecdsa`, `ed25519`) | `ecdsa` | No |
| `--output` | `-o` | Output directory | `./certs` | No |
| `--name` | | Common name for certificate | `localhost` | No |
| `--days` | | Certificate validity period in days | `365` | No |
| `--hosts` | | DNS names and IP addresses | `[localhost,127.0.0.1]` | No |

#### Examples

Generate ECDSA certificate for localhost:
```bash
frostdkg keygen --type ecdsa --output ./certs --name localhost
```

Generate Ed25519 certificate with multiple hosts:
```bash
frostdkg keygen --type ed25519 --output ./certs --name server \
  --hosts localhost,127.0.0.1,server.example.com
```

Generate with custom validity period:
```bash
frostdkg keygen --type ecdsa --output ./certs --name test --days 30
```

Generate server and client certificates:
```bash
# Server certificate
frostdkg keygen --type ecdsa --output ./certs --name server \
  --hosts server.example.com,192.168.1.100

# Client certificate
frostdkg keygen --type ecdsa --output ./certs --name client0
```

### verify

Verify that a key share file is valid and optionally check against an expected group public key.

**Validation checks:**
- JSON format is correct
- All required fields are present
- Cryptographic data has correct lengths
- Secret share is 32 bytes
- Public key shares are 33 bytes each (compressed)
- Threshold public key matches expected value (if `--group-key` provided)

#### Usage

```bash
frostdkg verify [flags]
```

#### Flags

| Flag | Shorthand | Description | Default | Required |
|------|-----------|-------------|---------|----------|
| `--share` | `-s` | Path to key share file | | Yes |
| `--group-key` | | Expected group public key (hex, 33 bytes) to verify against | | No |

#### Examples

Verify a key share file:
```bash
frostdkg verify --share participant0.json
```

Verify and check against expected group key:
```bash
frostdkg verify --share participant0.json \
  --group-key 02abc123def456789abc123def456789abc123def456789abc123def456789abc12
```

Verify all participants have the same group key:
```bash
# Extract group key from first participant
GROUP_KEY=$(jq -r .threshold_pubkey participant0.json)

# Verify all participants
frostdkg verify --share participant0.json --group-key $GROUP_KEY
frostdkg verify --share participant1.json --group-key $GROUP_KEY
frostdkg verify --share participant2.json --group-key $GROUP_KEY
```

Verify with verbose output:
```bash
frostdkg verify --share participant0.json --verbose
```

### config

Manage configuration files for frostdkg.

Configuration files use YAML format and can specify default values for all command-line flags. Command-line flags override config file values.

Environment variables can also be used with the `FROSTDKG_` prefix (e.g., `FROSTDKG_PROTOCOL=http`).

#### Subcommands

- `init` - Generate a sample configuration file
- `show` - Display current configuration

#### config init

Generate a sample configuration file with default values and documentation.

##### Usage

```bash
frostdkg config init [flags]
```

##### Flags

| Flag | Shorthand | Description | Default | Required |
|------|-----------|-------------|---------|----------|
| `--output` | `-o` | Output path | `$HOME/.frostdkg/config.yaml` | No |
| `--force` | `-f` | Overwrite existing config file | `false` | No |

##### Examples

Generate default config file:
```bash
frostdkg config init
```

Generate config file in custom location:
```bash
frostdkg config init --output /etc/frostdkg/config.yaml
```

Overwrite existing config file:
```bash
frostdkg config init --force
```

#### config show

Display the current configuration including values from config file, environment, and defaults.

##### Usage

```bash
frostdkg config show
```

##### Examples

Show current configuration:
```bash
frostdkg config show
```

Show configuration with custom config file:
```bash
frostdkg --config /etc/frostdkg/config.yaml config show
```

### version

Print version information.

#### Usage

```bash
frostdkg version
```

#### Example

```bash
frostdkg version
# Output: frostdkg version 0.1.0
```

## Configuration File

Configuration files use YAML format and support all CLI flags. The default location is `$HOME/.frostdkg/config.yaml`.

### Sample Configuration

```yaml
# frostdkg configuration file
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

# Keygen settings
keygen:
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
```

### Using Configuration Files

Specify config file via flag:
```bash
frostdkg --config /path/to/config.yaml coordinator
```

Or via environment variable:
```bash
export FROSTDKG_CONFIG=/path/to/config.yaml
frostdkg coordinator
```

## Environment Variables

All configuration values can be set via environment variables with the `FROSTDKG_` prefix:

```bash
export FROSTDKG_PROTOCOL=http
export FROSTDKG_CODEC=msgpack
export FROSTDKG_TLS_CERT=/path/to/cert.crt
export FROSTDKG_TLS_KEY=/path/to/key.key
export FROSTDKG_VERBOSE=true
```

### Priority Order

Configuration values are resolved in the following order (highest priority first):

1. Command-line flags
2. Environment variables
3. Configuration file
4. Default values

## Key Share Format

Generated key shares are saved in JSON format with file permissions set to `0600` (read/write for owner only).

### Structure

```json
{
  "participant_index": 0,
  "secret_share": "hex-encoded 32 bytes",
  "threshold_pubkey": "hex-encoded 33 bytes compressed",
  "public_shares": [
    "hex-encoded 33 bytes compressed",
    "hex-encoded 33 bytes compressed",
    "hex-encoded 33 bytes compressed"
  ],
  "session_id": "unique-session-identifier",
  "recovery_data": "hex-encoded recovery information",
  "timestamp": 1766439797
}
```

### Fields

- **participant_index**: Zero-indexed participant identifier
- **secret_share**: The participant's secret key share (32 bytes hex). KEEP CONFIDENTIAL!
- **threshold_pubkey**: The group's threshold public key (33 bytes compressed)
- **public_shares**: Array of all participants' public key shares
- **session_id**: Unique session identifier for this DKG round
- **recovery_data**: Additional recovery information for session verification
- **timestamp**: Unix timestamp when the key share was generated

**CRITICAL:** The `secret_share` field contains sensitive cryptographic material and must be kept confidential. Store it securely and never transmit it over insecure channels.

## Transport Protocols

### gRPC

Default protocol using gRPC over TCP with HTTP/2.

```bash
frostdkg --protocol grpc coordinator --listen 0.0.0.0:9000
frostdkg --protocol grpc participant --coordinator localhost:9000 --id 0 -o share.json
```

**Features:**
- Bidirectional streaming
- HTTP/2 multiplexing
- Efficient binary protocol
- Built-in load balancing

### HTTP

RESTful HTTP protocol with TLS 1.3 support.

```bash
frostdkg --protocol http coordinator --listen 0.0.0.0:8443 \
  --tls-cert server.crt --tls-key server.key

frostdkg --protocol http participant --coordinator https://localhost:8443 \
  --tls-ca ca.crt --id 0 -o share.json
```

**Features:**
- Standard HTTP/HTTPS
- Wide compatibility
- Easy debugging with standard tools
- RESTful API design

### QUIC

QUIC protocol (UDP-based) with built-in TLS 1.3 encryption.

```bash
frostdkg --protocol quic coordinator --listen 0.0.0.0:9001 \
  --tls-cert server.crt --tls-key server.key

frostdkg --protocol quic participant --coordinator localhost:9001 \
  --tls-ca ca.crt --id 0 -o share.json
```

**Features:**
- Low latency
- Connection migration
- Improved congestion control
- Built-in encryption

### libp2p

Peer-to-peer networking with libp2p multi-transport stack and Noise protocol encryption.

```bash
frostdkg --protocol libp2p coordinator

frostdkg --protocol libp2p participant --coordinator /ip4/127.0.0.1/tcp/9000 \
  --id 0 -o share.json
```

**Features:**
- Decentralized architecture
- NAT traversal
- Multiple transport support
- Secure by default (Noise protocol)

### Unix Sockets

gRPC over Unix domain sockets (no TLS required).

```bash
frostdkg --protocol unix coordinator --listen /tmp/frostdkg.sock

frostdkg --protocol unix participant --coordinator /tmp/frostdkg.sock \
  --id 0 -o share.json
```

**Features:**
- Local machine only
- No network overhead
- Automatic file-based permissions
- Fast IPC

### Memory

In-memory transport for testing (no network).

```bash
frostdkg --protocol memory coordinator

frostdkg --protocol memory participant --id 0 -o share.json
```

**Features:**
- Zero network overhead
- Ideal for testing
- Deterministic behavior
- Fast execution

## Complete Workflow Example

This example demonstrates a complete 2-of-3 threshold DKG session using gRPC with TLS.

### Step 1: Generate Certificates

Generate server certificate for coordinator:
```bash
frostdkg keygen --type ecdsa --output ./certs --name server
```

Generate client certificates for participants:
```bash
frostdkg keygen --type ecdsa --output ./certs --name client0
frostdkg keygen --type ecdsa --output ./certs --name client1
frostdkg keygen --type ecdsa --output ./certs --name client2
```

### Step 2: Start Coordinator

```bash
frostdkg coordinator --protocol grpc --listen 0.0.0.0:9000 \
  --threshold 2 --participants 3 \
  --tls-cert ./certs/server.crt --tls-key ./certs/server.key \
  --verbose
```

Output:
```
Starting grpc coordinator server...
  Listen: 0.0.0.0:9000
  Threshold: 2
  Participants: 3
  Session ID: 550e8400-e29b-41d4-a716-446655440000
  Ciphersuite: FROST-ED25519-SHA512-v1
  Codec: json
  TLS Cert: ./certs/server.crt
  TLS Key: ./certs/server.key
Coordinator started successfully
Session ID: 550e8400-e29b-41d4-a716-446655440000
Listening on: 0.0.0.0:9000
Waiting for 3 participants to connect...
```

### Step 3: Join as Participants

Open three separate terminals and run:

**Terminal 1 (Participant 0):**
```bash
frostdkg participant --coordinator localhost:9000 --id 0 \
  --threshold 2 --output participant0.json \
  --tls-ca ./certs/server.crt --verbose
```

**Terminal 2 (Participant 1):**
```bash
frostdkg participant --coordinator localhost:9000 --id 1 \
  --threshold 2 --output participant1.json \
  --tls-ca ./certs/server.crt --verbose
```

**Terminal 3 (Participant 2):**
```bash
frostdkg participant --coordinator localhost:9000 --id 2 \
  --threshold 2 --output participant2.json \
  --tls-ca ./certs/server.crt --verbose
```

Each participant output:
```
Joining DKG session as participant 0...
  Coordinator: localhost:9000
  Protocol: grpc
  Threshold: 2
  Codec: json
  TLS Cert: ./certs/server.crt
Generated host secret key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
Connecting to coordinator at localhost:9000...
Connected to coordinator
Executing DKG protocol...
DKG completed successfully!
Session ID: 550e8400-e29b-41d4-a716-446655440000
Threshold public key: 02abc123def456789abc123def456789abc123def456789abc123def456789abc12
Key share saved to: participant0.json

WARNING: Keep the secret_share confidential! Do not share it.
```

### Step 4: Verify Key Shares

Extract the group public key from any participant:
```bash
GROUP_KEY=$(jq -r .threshold_pubkey participant0.json)
echo "Group Public Key: $GROUP_KEY"
```

Verify all participants have the same group key:
```bash
frostdkg verify --share participant0.json --group-key $GROUP_KEY
frostdkg verify --share participant1.json --group-key $GROUP_KEY
frostdkg verify --share participant2.json --group-key $GROUP_KEY
```

Expected output for each verification:
```
Key share file format: OK
Secret share length: OK (32 bytes)
Threshold public key length: OK (33 bytes)
Public shares count: 3
Public shares format: OK (all 33 bytes)
Recovery data length: 256 bytes
Group key verification: OK

Verification Summary:
  Participant Index: 0
  Session ID: 550e8400-e29b-41d4-a716-446655440000
  Threshold Public Key: 02abc123def456789abc123def456789abc123def456789abc123def456789abc12
  Number of Public Shares: 3
  Timestamp: 1766439797

Key share is VALID
```

## Security Considerations

### TLS Requirements

- **Production:** Always use TLS certificates from a trusted Certificate Authority
- **Testing:** Self-signed certificates from `frostdkg keygen` are acceptable
- **Network Protocols:** gRPC, HTTP, and QUIC require TLS in production environments
- **Local Protocols:** Unix sockets and memory transport do not require TLS

### Key Material Protection

- **Secret Shares:** The `secret_share` field in key share files contains sensitive cryptographic material
- **File Permissions:** Key share files are automatically created with `0600` permissions (owner read/write only)
- **Storage:** Store key shares in secure locations (encrypted filesystems, hardware security modules, etc.)
- **Transmission:** Never transmit secret shares over insecure channels
- **Backup:** Implement secure backup procedures for key shares

### Certificate Management

- **Self-Signed:** Only use self-signed certificates for testing and development
- **CA Certificates:** Use certificates from trusted CAs in production
- **mTLS:** Consider mutual TLS for enhanced security
- **Rotation:** Implement certificate rotation policies
- **Validation:** Always validate certificates unless using `--insecure` (testing only)

### Insecure Mode Warning

The `--insecure` flag disables TLS certificate verification:

**NEVER use in production!** This flag is only for testing and development.

```bash
# Testing only - DO NOT use in production
frostdkg --insecure participant --coordinator localhost:9000 --id 0 -o share.json
```

### Network Security

- **Firewall:** Configure firewalls to restrict coordinator access
- **Authentication:** Implement authentication mechanisms for production deployments
- **Monitoring:** Monitor for suspicious activity and failed DKG attempts
- **Rate Limiting:** Implement rate limiting to prevent DoS attacks

## Troubleshooting

### Common Issues

#### Connection Refused

**Problem:** `failed to connect to coordinator: connection refused`

**Solutions:**
- Verify coordinator is running and listening on the correct address
- Check firewall rules allow connections
- Ensure correct protocol is specified

#### TLS Certificate Errors

**Problem:** `x509: certificate signed by unknown authority`

**Solutions:**
- Provide CA certificate with `--tls-ca` flag
- Use `--insecure` for testing only
- Verify certificate paths are correct

#### Timeout Errors

**Problem:** `context deadline exceeded`

**Solutions:**
- Increase timeout with `--timeout` flag
- Check network connectivity
- Verify all participants are online

#### Invalid Key Share

**Problem:** `failed to parse key share JSON`

**Solutions:**
- Verify file is valid JSON
- Check file hasn't been corrupted
- Ensure file was generated by frostdkg

### Debug Mode

Enable verbose output for detailed logging:

```bash
frostdkg --verbose coordinator --threshold 2 --participants 3
```

### Getting Help

Display help for any command:

```bash
frostdkg --help
frostdkg coordinator --help
frostdkg participant --help
frostdkg keygen --help
frostdkg verify --help
frostdkg config --help
```

## Performance Tuning

### Timeout Configuration

Adjust timeouts based on network conditions:

```bash
# Increase timeout for slow networks
frostdkg coordinator --timeout 600  # 10 minutes

# Decrease timeout for fast local networks
frostdkg coordinator --timeout 60   # 1 minute
```

### Codec Selection

Choose codec based on performance requirements:

- **JSON:** Human-readable, debuggable (default)
- **MessagePack:** Compact binary format, faster than JSON
- **CBOR:** Concise binary format, good balance

```bash
# Use MessagePack for better performance
frostdkg --codec msgpack coordinator --threshold 2 --participants 3
frostdkg --codec msgpack participant --id 0 -o share.json
```

### Protocol Selection

Choose protocol based on requirements:

- **gRPC:** Best for RPC-style communication, efficient
- **HTTP:** Best for compatibility, easy debugging
- **QUIC:** Best for low latency, unreliable networks
- **libp2p:** Best for decentralized deployments
- **Unix:** Best for local IPC
- **Memory:** Best for testing

## Testing

### Unit Tests

Run CLI unit tests:

```bash
make test-cli
```

### Integration Tests

Run full integration tests:

```bash
make integration-test-cli
```

### Code Coverage

Generate coverage report:

```bash
make coverage-cli
```

## Building

### Build Binary

```bash
make build-cli
```

Output: `./bin/frostdkg`

### Install to GOPATH

```bash
make install
```

Installs to: `$GOPATH/bin/frostdkg`

### Clean Build Artifacts

```bash
make clean
```

## License

Apache 2.0 - See [LICENSE.md](../LICENSE.md) for details
