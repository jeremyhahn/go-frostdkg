# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-12-26

Initial release of go-frostdkg, a FROST-compliant distributed key generation library for threshold signatures.

### Features

- **FROST DKG**: Threshold key generation supporting Ed25519, ristretto255, Ed448, P-256, and secp256k1
- **Transports**: gRPC, REST, QUIC, libp2p, and Unix socket protocols with TLS/mTLS
- **libp2p**: DHT discovery, pubsub messaging, circuit relay, connection pooling, and Prometheus metrics
- **CLI**: Coordinator and participant commands for running DKG sessions
- **Cross-platform**: Support for Linux, macOS (Darwin), and Windows
- **Security**: gosec scanning, govulncheck, TLS 1.3 enforcement, secure file permissions
