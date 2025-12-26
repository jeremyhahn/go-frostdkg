# TLS 1.3 Configuration Package

Production-ready TLS 1.3 configuration module for secure communication in go-frostdkg.

## Features

- **TLS 1.3 Only**: Enforces minimum TLS version 1.3 for maximum security
- **Mutual TLS (mTLS)**: Full support for bidirectional certificate authentication
- **Secure Cipher Suites**: Pre-configured with strongest TLS 1.3 cipher suites
- **Self-Signed Certificates**: Built-in certificate generation for testing
- **Simple API**: Easy-to-use functions for both server and client configurations
- **Comprehensive Error Handling**: Descriptive typed errors for all failure cases

## Installation

```bash
go get github.com/jeremyhahn/go-frostdkg/pkg/transport/tls
```

## Usage

### Server Configuration

Create a TLS 1.3 server configuration:

```go
import tlsconfig "github.com/jeremyhahn/go-frostdkg/pkg/transport/tls"

// Basic server configuration
config, err := tlsconfig.ServerConfig("server.crt", "server.key", "")
if err != nil {
    log.Fatal(err)
}

// Use with net/http
server := &http.Server{
    Addr:      ":8443",
    TLSConfig: config,
}
server.ListenAndServeTLS("", "") // Certificates already in config
```

### Server with Mutual TLS

Require and verify client certificates:

```go
// Server configuration with client certificate verification
config, err := tlsconfig.ServerConfig("server.crt", "server.key", "ca.crt")
if err != nil {
    log.Fatal(err)
}
// config.ClientAuth is now set to RequireAndVerifyClientCert
```

### Client Configuration

Create a TLS 1.3 client configuration:

```go
// Basic client configuration
config, err := tlsconfig.ClientConfig("", "", "ca.crt", "server.example.com")
if err != nil {
    log.Fatal(err)
}

// Use with net/http
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: config,
    },
}
```

### Client with Mutual TLS

Authenticate client with certificate:

```go
// Client configuration with client certificate for mTLS
config, err := tlsconfig.ClientConfig("client.crt", "client.key", "ca.crt", "server.example.com")
if err != nil {
    log.Fatal(err)
}
```

### Generate Self-Signed Certificates

For testing and development:

```go
// Generate a self-signed certificate valid for 24 hours
certPEM, keyPEM, err := tlsconfig.GenerateSelfSigned(
    []string{"localhost", "127.0.0.1"},
    24 * time.Hour,
)
if err != nil {
    log.Fatal(err)
}

// Write to files
os.WriteFile("test.crt", certPEM, 0600)
os.WriteFile("test.key", keyPEM, 0600)
```

### Insecure Client (Testing Only)

Skip server verification for testing:

```go
// WARNING: Only use for testing!
config := tlsconfig.InsecureClientConfig()
```

## API Reference

### ServerConfig

```go
func ServerConfig(certFile, keyFile, caFile string) (*tls.Config, error)
```

Creates a TLS 1.3 server configuration.

- `certFile`: Path to server certificate (PEM format)
- `keyFile`: Path to server private key (PEM format)
- `caFile`: Optional path to CA cert for mTLS client verification (empty string to skip)

### ClientConfig

```go
func ClientConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error)
```

Creates a TLS 1.3 client configuration.

- `certFile`: Optional path to client certificate for mTLS (empty to skip)
- `keyFile`: Optional path to client private key for mTLS (empty to skip)
- `caFile`: Path to CA cert to verify server (empty to use system roots)
- `serverName`: Expected server name for verification (empty to skip)

### InsecureClientConfig

```go
func InsecureClientConfig() *tls.Config
```

Creates a TLS config that skips server verification. **WARNING: Only use for testing!**

### LoadCertificate

```go
func LoadCertificate(certFile, keyFile string) (tls.Certificate, error)
```

Loads a certificate and key from files.

### LoadCAPool

```go
func LoadCAPool(caFile string) (*x509.CertPool, error)
```

Loads a CA certificate pool from a file.

### GenerateSelfSigned

```go
func GenerateSelfSigned(hosts []string, validFor time.Duration) ([]byte, []byte, error)
```

Generates a self-signed certificate for testing.

- Returns `certPEM`, `keyPEM`, `error`
- Uses ECDSA with P-256 curve
- Supports both DNS names and IP addresses

## Security Features

### TLS Version Enforcement

All configurations enforce TLS 1.3:

```go
MinVersion: tls.VersionTLS13
MaxVersion: tls.VersionTLS13
```

### Cipher Suites

Pre-configured with secure TLS 1.3 cipher suites in order of preference:

1. `TLS_AES_256_GCM_SHA384`
2. `TLS_AES_128_GCM_SHA256`
3. `TLS_CHACHA20_POLY1305_SHA256`

### Certificate Verification

- Server certificates are always verified by clients (unless using `InsecureClientConfig`)
- mTLS requires `RequireAndVerifyClientCert` on the server side
- Custom CA certificates are supported for self-signed deployments

## Error Handling

The package defines typed errors for all failure cases:

- `ErrCertificateNotFound`: Certificate file not found
- `ErrKeyNotFound`: Private key file not found
- `ErrCANotFound`: CA certificate file not found
- `ErrInvalidCertificate`: Invalid or unparseable certificate
- `ErrInvalidKey`: Invalid or unparseable private key
- `ErrCertKeyMismatch`: Certificate and key do not match
- `ErrInvalidCAPool`: Invalid CA certificate pool
- `ErrEmptyCertificate`: Empty certificate data provided
- `ErrEmptyKey`: Empty key data provided

## Testing

The package includes comprehensive tests with 93.2% code coverage:

```bash
# Run tests
make test-tls

# Generate coverage report
make coverage-tls

# Run with race detector
go test -race ./pkg/transport/tls/...
```

## Examples

See `example_test.go` for complete working examples:

- `ExampleServerConfig`: Basic server configuration
- `ExampleServerConfig_mTLS`: Server with mutual TLS
- `ExampleClientConfig`: Basic client configuration
- `ExampleClientConfig_mTLS`: Client with mutual TLS
- `ExampleGenerateSelfSigned`: Certificate generation
- `ExampleLoadCertificate`: Loading certificates
- `ExampleLoadCAPool`: Loading CA pools

## Best Practices

1. **Never use `InsecureClientConfig` in production**
2. **Always use mTLS for internal service communication**
3. **Rotate certificates regularly**
4. **Store private keys with restrictive permissions (0600)**
5. **Use proper certificate management for production deployments**
6. **Consider using a certificate management service (HashiCorp Vault, cert-manager, etc.)**

## License

See LICENSE.md in the repository root.
