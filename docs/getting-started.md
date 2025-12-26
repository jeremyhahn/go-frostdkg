# Getting Started with FROST DKG

Quick start guide for running distributed key generation with the `frostdkg` CLI tool.

## Installation

```bash
go install github.com/jeremyhahn/go-frostdkg/cmd/frostdkg@latest
```

Verify installation:
```bash
frostdkg version
```

## Quick Start: 2-of-3 Threshold Setup

This example creates a 2-of-3 threshold scheme where any 2 participants can sign, but at least 3 total shares are distributed.

### Step 1: Generate TLS Certificates

Create self-signed certificates for secure communication:

```bash
frostdkg keygen --type ecdsa --output ./certs --name localhost
```

This generates:
- `./certs/localhost.crt` - Certificate file
- `./certs/localhost.key` - Private key file

### Step 2: Start Coordinator

In terminal 1:
```bash
frostdkg coordinator \
  --listen 0.0.0.0:9000 \
  --threshold 2 \
  --participants 3 \
  --tls-cert ./certs/localhost.crt \
  --tls-key ./certs/localhost.key \
  --verbose
```

The coordinator relays messages between participants but has no cryptographic role.

### Step 3: Connect Participants

Open three separate terminals and run each participant:

**Terminal 2 - Participant 0:**
```bash
frostdkg participant \
  --coordinator localhost:9000 \
  --id 0 \
  --threshold 2 \
  --output share0.json \
  --tls-cert ./certs/localhost.crt \
  --tls-key ./certs/localhost.key \
  --verbose
```

**Terminal 3 - Participant 1:**
```bash
frostdkg participant \
  --coordinator localhost:9000 \
  --id 1 \
  --threshold 2 \
  --output share1.json \
  --tls-cert ./certs/localhost.crt \
  --tls-key ./certs/localhost.key \
  --verbose
```

**Terminal 4 - Participant 2:**
```bash
frostdkg participant \
  --coordinator localhost:9000 \
  --id 2 \
  --threshold 2 \
  --output share2.json \
  --tls-cert ./certs/localhost.crt \
  --tls-key ./certs/localhost.key \
  --verbose
```

### Step 4: Verify Key Shares

After DKG completes, verify each share:

```bash
frostdkg verify --share share0.json
frostdkg verify --share share1.json
frostdkg verify --share share2.json
```

All shares should show the same threshold public key, confirming successful key generation.

## Using Different Protocols

### HTTP Transport
```bash
# Coordinator
frostdkg coordinator --protocol http --listen 0.0.0.0:8443 \
  --threshold 2 --participants 3 \
  --tls-cert ./certs/localhost.crt --tls-key ./certs/localhost.key

# Participant
frostdkg participant --protocol http --coordinator https://localhost:8443 \
  --id 0 --threshold 2 --output share0.json \
  --tls-cert ./certs/localhost.crt --tls-key ./certs/localhost.key
```

### QUIC Transport
```bash
# Coordinator
frostdkg coordinator --protocol quic --listen 0.0.0.0:9001 \
  --threshold 2 --participants 3 \
  --tls-cert ./certs/localhost.crt --tls-key ./certs/localhost.key

# Participant
frostdkg participant --protocol quic --coordinator localhost:9001 \
  --id 0 --threshold 2 --output share0.json \
  --tls-cert ./certs/localhost.crt --tls-key ./certs/localhost.key
```

### libp2p Transport
```bash
# Coordinator
frostdkg coordinator --protocol libp2p --listen 0.0.0.0:9002 \
  --threshold 2 --participants 3 --session-id my-session

# Participant
frostdkg participant --protocol libp2p --coordinator localhost:9002 \
  --id 0 --threshold 2 --output share0.json
```

## Using Configuration Files

Generate a configuration template:
```bash
frostdkg config init --output ~/.frostdkg/config.yaml
```

Edit the configuration file to set defaults:
```yaml
protocol: grpc
codec: json
tls:
  cert: "./certs/localhost.crt"
  key: "./certs/localhost.key"
coordinator:
  threshold: 2
  participants: 3
  listen: "0.0.0.0:9000"
```

Run with config file:
```bash
frostdkg --config ~/.frostdkg/config.yaml coordinator
frostdkg --config ~/.frostdkg/config.yaml participant --id 0 --output share0.json
```

## Next Steps

- [Architecture](architecture.md): Learn about the FROST DKG protocol and system design
- [Transport Layer](transport.md): Understand different transport options and when to use them
- [CLI Reference](cli.md): Explore all available commands and flags
- [Security Policy](security.md): Known vulnerabilities and security practices

## Important Security Notes

- **Keep shares secure**: Never share the `secret_share` field from output files
- **Use trusted CAs**: For production, use certificates from a trusted Certificate Authority
- **Secure communication**: Always use TLS in production environments
- **Backup shares**: Store key shares in secure, redundant locations

For known vulnerabilities and security updates, see the [Security Policy](security.md).
