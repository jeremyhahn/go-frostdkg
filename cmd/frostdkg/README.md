# frostdkg CLI

Command-line tool for executing FROST Distributed Key Generation (DKG).

## Features

- **Multi-Protocol Support**: gRPC, HTTP, QUIC, libp2p, MCP, Unix sockets, and in-memory
- **Multiple Codecs**: JSON, MessagePack, CBOR serialization
- **TLS 1.3 Security**: Built-in support for secure communications with mTLS
- **Certificate Generation**: Generate ECDSA and Ed25519 certificates for testing
- **Key Share Verification**: Validate generated key shares
- **Configuration Management**: YAML config files and environment variables

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

## Commands

### Coordinator

Start a DKG coordinator server that relays messages between participants.

```bash
# Start gRPC coordinator for 3-of-5 threshold
frostdkg coordinator --listen 0.0.0.0:9000 --threshold 3 --participants 5

# Start HTTP coordinator with TLS
frostdkg coordinator --protocol http --listen 0.0.0.0:8443 \
  --tls-cert server.crt --tls-key server.key \
  --threshold 2 --participants 3

# Start QUIC coordinator with custom session ID
frostdkg coordinator --protocol quic --listen 0.0.0.0:9001 \
  --threshold 2 --participants 3 --session-id my-session
```

**Flags:**
- `--listen`: Address to listen on (default: `0.0.0.0:9000`)
- `-t, --threshold`: Minimum signers required (t)
- `-n, --participants`: Total participants (n)
- `--session-id`: Session identifier (generates UUID if not provided)
- `--ciphersuite`: FROST ciphersuite (default: `FROST-ED25519-SHA512-v1`)
- `--timeout`: Session timeout in seconds (default: 300)

### Participant

Join a DKG session as a participant and receive a key share.

```bash
# Join as participant 0 (0-indexed)
frostdkg participant --coordinator localhost:9000 --id 0 \
  --threshold 2 --output participant0.json

# Join HTTP coordinator with TLS client cert
frostdkg participant --protocol http --coordinator https://localhost:8443 \
  --tls-cert client.crt --tls-key client.key --tls-ca ca.crt \
  --id 1 --threshold 2 --output participant1.json

# Join with explicit host secret key (hex)
frostdkg participant --coordinator localhost:9000 --id 2 \
  --hostkey abcd1234... --threshold 2 --output participant2.json
```

**Flags:**
- `--coordinator`: Coordinator address (required)
- `--id`: Participant identifier, 0-indexed (required)
- `-o, --output`: Output file path for key share (required)
- `--hostkey`: Host secret key in hex (32 bytes). Auto-generated if not provided
- `--hostpubkeys`: Comma-separated host public keys (hex, 33 bytes each)
- `-t, --threshold`: Signing threshold (must match coordinator)
- `--timeout`: Operation timeout in seconds (default: 300)

### Certificate Generation

Generate TLS certificates and keys for secure communication.

```bash
# Generate ECDSA certificate for localhost
frostdkg certgen --type ecdsa --output ./certs --name localhost

# Generate Ed25519 certificate with multiple hosts
frostdkg certgen --type ed25519 --output ./certs --name server \
  --hosts localhost,127.0.0.1,server.example.com

# Generate with custom validity period
frostdkg certgen --type ecdsa --output ./certs --name test --days 30
```

**Flags:**
- `--type`: Key type (`ecdsa` or `ed25519`, default: `ecdsa`)
- `-o, --output`: Output directory (default: `./certs`)
- `--name`: Common name for certificate (default: `localhost`)
- `--days`: Certificate validity period in days (default: 365)
- `--hosts`: DNS names and IP addresses (default: `localhost,127.0.0.1`)

### Verification

Verify key share files and optionally check against expected group key.

```bash
# Verify a key share file
frostdkg verify --share participant0.json

# Verify and check against expected group key
frostdkg verify --share participant0.json \
  --group-key 02abc123...
```

**Flags:**
- `-s, --share`: Path to key share file (required)
- `--group-key`: Expected group public key in hex to verify against (optional)

### Configuration

Generate and manage configuration files.

```bash
# Generate default config file
frostdkg config init

# Generate config file in custom location
frostdkg config init --output /etc/frostdkg/config.yaml

# Show current configuration
frostdkg config show
```

**Flags:**
- `-o, --output`: Output path (default: `$HOME/.frostdkg/config.yaml`)
- `-f, --force`: Overwrite existing config file

## Global Flags

These flags apply to all commands:

- `--config`: Config file path (default: `$HOME/.frostdkg/config.yaml`)
- `--protocol`: Transport protocol (`grpc`, `http`, `quic`, `libp2p`, `mcp`, `unix`, `memory`)
- `--codec`: Serialization format (`json`, `msgpack`, `cbor`)
- `--tls-cert`: TLS certificate file path
- `--tls-key`: TLS private key file path
- `--tls-ca`: CA certificate for mTLS
- `--insecure`: Disable TLS verification (WARNING: testing only)
- `-v, --verbose`: Verbose output

## Configuration File

Configuration files use YAML format:

```yaml
# Default transport protocol
protocol: grpc

# Default serialization codec
codec: json

# TLS configuration
tls:
  cert: ""
  key: ""
  ca: ""

# Coordinator settings
coordinator:
  listen: "0.0.0.0:9000"
  threshold: 2
  participants: 3
  ciphersuite: "FROST-ED25519-SHA512-v1"
  timeout: 300

# Participant settings
participant:
  coordinator: "localhost:9000"
  id: 0
  output: "participant.json"
  threshold: 2
  timeout: 300
```

Command-line flags override config file values.

## Environment Variables

All config values can be set via environment variables with the `FROSTDKG_` prefix:

```bash
export FROSTDKG_PROTOCOL=http
export FROSTDKG_CODEC=msgpack
export FROSTDKG_TLS_CERT=/path/to/cert.crt
export FROSTDKG_TLS_KEY=/path/to/key.key
```

## Example: Complete DKG Session

### 1. Generate Certificates (Optional)

```bash
# Generate server certificate for coordinator
frostdkg certgen --type ecdsa --output ./certs --name server

# Generate client certificates for participants
frostdkg certgen --type ecdsa --output ./certs --name client0
frostdkg certgen --type ecdsa --output ./certs --name client1
```

### 2. Start Coordinator

```bash
frostdkg coordinator --protocol grpc --listen 0.0.0.0:9000 \
  --threshold 2 --participants 3 --verbose
```

### 3. Join as Participants (in separate terminals)

Terminal 1:
```bash
frostdkg participant --coordinator localhost:9000 --id 0 \
  --threshold 2 --output participant0.json --verbose
```

Terminal 2:
```bash
frostdkg participant --coordinator localhost:9000 --id 1 \
  --threshold 2 --output participant1.json --verbose
```

Terminal 3:
```bash
frostdkg participant --coordinator localhost:9000 --id 2 \
  --threshold 2 --output participant2.json --verbose
```

### 4. Verify Key Shares

```bash
# Get the group public key from any participant's output
GROUP_KEY=$(jq -r .threshold_pubkey participant0.json)

# Verify all shares have the same group key
frostdkg verify --share participant0.json --group-key $GROUP_KEY
frostdkg verify --share participant1.json --group-key $GROUP_KEY
frostdkg verify --share participant2.json --group-key $GROUP_KEY
```

## Key Share Format

Generated key shares are saved in JSON format:

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

**IMPORTANT**: The `secret_share` field contains sensitive cryptographic material and must be kept confidential!

## Protocols

### gRPC
Default protocol using gRPC over TCP with HTTP/2.

```bash
--protocol grpc --listen 0.0.0.0:9000
```

### HTTP
HTTP/REST protocol with TLS 1.3.

```bash
--protocol http --listen 0.0.0.0:8443 --tls-cert server.crt --tls-key server.key
```

### QUIC
QUIC protocol (UDP-based) with built-in TLS 1.3.

```bash
--protocol quic --listen 0.0.0.0:9001 --tls-cert server.crt --tls-key server.key
```

### libp2p
libp2p multi-transport stack with Noise encryption.

```bash
--protocol libp2p
```

### MCP
Model Context Protocol for AI tool integration.

```bash
--protocol mcp
```

### Unix Sockets
gRPC over Unix domain sockets (no TLS required).

```bash
--protocol unix --listen /tmp/frostdkg.sock
```

### Memory
In-memory transport for testing (no network).

```bash
--protocol memory
```

## Security Considerations

1. **TLS Required**: Network protocols (gRPC, HTTP, QUIC) require TLS certificates in production
2. **Secret Shares**: Never share or transmit secret shares over insecure channels
3. **Certificate Management**: Use certificates from a trusted CA in production
4. **File Permissions**: Key share files are created with 0600 permissions
5. **Insecure Mode**: Only use `--insecure` flag in testing environments

## Testing

Run CLI tests:

```bash
make test-cli
```

Generate coverage report:

```bash
make coverage-cli
```

## Building

Build the CLI binary:

```bash
make build-cli
```

Install to GOPATH:

```bash
make install
```

Clean build artifacts:

```bash
make clean
```

## Version

```bash
frostdkg version
```

## Help

Get help for any command:

```bash
frostdkg --help
frostdkg coordinator --help
frostdkg participant --help
frostdkg certgen --help
frostdkg verify --help
frostdkg config --help
```

## License

Apache 2.0
