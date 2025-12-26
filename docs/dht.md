# DHT Discovery for FROST-DKG

This document describes the Distributed Hash Table (DHT) based peer discovery system used in the libp2p transport for FROST-DKG.

## Overview

The DHT discovery system enables decentralized peer discovery without requiring a central server. Peers can find each other by advertising and querying **rendezvous points** - well-known identifiers in the DHT that act as meeting places for peers interested in the same DKG session, ciphersuite, or coordinator.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DHT DISCOVERY ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│    ┌──────────────────┐                    ┌──────────────────┐             │
│    │   DKGHost with   │                    │   DKGHost with   │             │
│    │    Discovery     │                    │    Discovery     │             │
│    └────────┬─────────┘                    └────────┬─────────┘             │
│             │                                       │                       │
│             ▼                                       ▼                       │
│    ┌──────────────────┐                    ┌──────────────────┐             │
│    │DiscoveryService  │◄──── DHT Network ──►│DiscoveryService │             │
│    │                  │                    │                  │             │
│    │ - Kademlia DHT   │                    │ - Kademlia DHT   │             │
│    │ - Routing Disc.  │                    │ - Routing Disc.  │             │
│    │ - Peer Cache     │                    │ - Peer Cache     │             │
│    └──────────────────┘                    └──────────────────┘             │
│             │                                       │                       │
│             ▼                                       ▼                       │
│    ┌──────────────────────────────────────────────────────────┐             │
│    │                    Kademlia DHT Network                  │             │
│    │                                                          │             │
│    │   Rendezvous Points:                                     │             │
│    │   /frost-dkg/v1/session/<sessionID>                      │             │
│    │   /frost-dkg/v1/coordinator/<sessionID>                  │             │
│    │   /frost-dkg/v1/ciphersuite/<name>                       │             │
│    │                                                          │             │
│    └──────────────────────────────────────────────────────────┘             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

### DiscoveryService

The main component that wraps the Kademlia DHT and provides DKG-specific discovery operations.

**Location**: `pkg/transport/libp2p/discovery.go`

```go
type DiscoveryService struct {
    host            host.Host              // libp2p host
    dht             *dht.IpfsDHT           // Kademlia DHT instance
    discovery       *drouting.RoutingDiscovery  // Routing-based discovery
    config          *DiscoveryConfig       // Configuration
    advertisements  map[string]context.CancelFunc  // Active advertisements
    discoveredPeers map[string][]peer.AddrInfo     // Peer cache
}
```

### DiscoveryConfig

Configuration options for the discovery service.

```go
type DiscoveryConfig struct {
    Mode              DHTMode        // Auto, Server, or Client
    BootstrapPeers    []peer.AddrInfo // Initial peers to connect to
    AdvertiseTTL      time.Duration  // TTL for advertisements (default: 10m)
    RefreshInterval   time.Duration  // Routing table refresh (default: 30s)
    FindPeersTimeout  time.Duration  // Peer discovery timeout (default: 30s)
    EnableAutoRefresh bool           // Enable automatic refresh (default: true)
    MaxPeers          int            // Max peers per query (default: 100)
}
```

### DKGHostWithDiscovery

A convenience wrapper that combines a DKGHost with DHT discovery capabilities.

```go
type DKGHostWithDiscovery struct {
    *DKGHost
    discovery *DiscoveryService
}
```

## DHT Modes

| Mode | Constant | Description | Use Case |
|------|----------|-------------|----------|
| Auto | `DHTModeAuto` | Libp2p determines mode based on network | Default, most flexible |
| Server | `DHTModeServer` | Full DHT participant, stores records | Stable nodes with public IPs |
| Client | `DHTModeClient` | Query-only, doesn't store records | NAT'd peers, mobile devices |

## Rendezvous Points

Rendezvous points are well-known identifiers where peers advertise and discover each other.

### Session Discovery
```
/frost-dkg/v1/session/<sessionID>
```
Used by participants to find other peers in the same DKG session.

### Coordinator Discovery
```
/frost-dkg/v1/coordinator/<sessionID>
```
Used by participants to find the coordinator for a specific session.

### Ciphersuite Discovery
```
/frost-dkg/v1/ciphersuite/<ciphersuite>
```
Used to find peers supporting a specific ciphersuite (e.g., `FROST-ED25519-SHA512-v1`).

## Process Flows

### Bootstrap Flow

```
┌─────────┐                    ┌─────────────────┐
│  Peer   │                    │ Bootstrap Peers │
└────┬────┘                    └────────┬────────┘
     │                                  │
     │  1. Connect to bootstrap peers   │
     │─────────────────────────────────►│
     │                                  │
     │  2. Exchange routing tables      │
     │◄────────────────────────────────►│
     │                                  │
     │  3. Learn about other peers      │
     │◄─────────────────────────────────│
     │                                  │
     ▼                                  │
┌─────────┐                             │
│ DHT     │  4. Integrated into network │
│ Ready   │◄────────────────────────────┘
└─────────┘
```

### Advertise Flow

```
┌─────────┐                    ┌─────────────┐
│  Peer   │                    │ DHT Network │
└────┬────┘                    └──────┬──────┘
     │                                │
     │  1. AdvertiseSession("abc")    │
     │───────────────────────────────►│
     │                                │
     │  2. Store provider record      │
     │     at /frost-dkg/v1/session/abc
     │                                │
     │  3. Re-advertise periodically  │
     │     (based on AdvertiseTTL)    │
     │───────────────────────────────►│
     │                                │
```

### Discovery Flow

```
┌─────────┐                    ┌─────────────┐                    ┌─────────┐
│ Peer A  │                    │ DHT Network │                    │ Peer B  │
└────┬────┘                    └──────┬──────┘                    └────┬────┘
     │                                │                                │
     │                                │  1. Peer B advertises session  │
     │                                │◄───────────────────────────────│
     │                                │                                │
     │  2. FindSessionPeers("abc")    │                                │
     │───────────────────────────────►│                                │
     │                                │                                │
     │  3. Query DHT for providers    │                                │
     │◄───────────────────────────────│                                │
     │                                │                                │
     │  4. Receive Peer B's info      │                                │
     │◄───────────────────────────────│                                │
     │                                │                                │
     │  5. Connect directly to Peer B │                                │
     │─────────────────────────────────────────────────────────────────►│
     │                                │                                │
```

### Complete Session Setup Flow

```
┌────────────┐    ┌────────────┐    ┌────────────┐    ┌─────────────┐
│Coordinator │    │Participant1│    │Participant2│    │ DHT Network │
└─────┬──────┘    └─────┬──────┘    └─────┬──────┘    └──────┬──────┘
      │                 │                 │                  │
      │  1. Start DHT & advertise as coordinator             │
      │──────────────────────────────────────────────────────►│
      │                 │                 │                  │
      │                 │  2. FindCoordinator("session-123") │
      │                 │────────────────────────────────────►│
      │                 │                 │                  │
      │                 │  3. Receive coordinator info       │
      │                 │◄────────────────────────────────────│
      │                 │                 │                  │
      │  4. Connect     │                 │                  │
      │◄────────────────│                 │                  │
      │                 │                 │                  │
      │                 │                 │  5. FindCoordinator
      │                 │                 │──────────────────►│
      │                 │                 │                  │
      │                 │                 │  6. Coordinator info
      │                 │                 │◄──────────────────│
      │                 │                 │                  │
      │  7. Connect     │                 │                  │
      │◄──────────────────────────────────│                  │
      │                 │                 │                  │
      │  8. All participants connected, begin DKG            │
      │─────────────────┼─────────────────┼──────────────────│
```

## API Reference

### Creating a Discovery Service

```go
// With default configuration
cfg := DefaultDiscoveryConfig()
ds, err := NewDiscoveryService(host.Host(), cfg)
if err != nil {
    return err
}

// Start the service
if err := ds.Start(ctx); err != nil {
    return err
}
defer ds.Stop(ctx)
```

### Advertising

```go
// Advertise participation in a session
err := ds.AdvertiseSession(ctx, "session-123")

// Advertise as coordinator
err := ds.AdvertiseCoordinator(ctx, "session-123")

// Advertise ciphersuite support
err := ds.AdvertiseCiphersuite(ctx, "FROST-ED25519-SHA512-v1")

// Stop advertising
err := ds.StopAdvertisingSession("session-123")
err := ds.StopAdvertisingCoordinator("session-123")
```

### Finding Peers

```go
// Find session participants
peers, err := ds.FindSessionPeers(ctx, "session-123")

// Find coordinator
coordinators, err := ds.FindCoordinator(ctx, "session-123")

// Find peers supporting a ciphersuite
peers, err := ds.FindCiphersuitePeers(ctx, "FROST-ED25519-SHA512-v1")

// Connect to a discovered peer
err := ds.ConnectToPeer(ctx, peerInfo)
```

### Peer Caching

```go
// Get cached peers (from previous discoveries)
peers := ds.GetCachedPeers("/frost-dkg/v1/session/session-123")

// Clear the cache
ds.ClearCache()
```

### Using DKGHostWithDiscovery

```go
// Create host with DHT enabled
cfg := DefaultDiscoveryHostConfig()
cfg.EnableDHT = true
cfg.DHTMode = DHTModeServer
cfg.BootstrapPeers = []string{
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
}

host, err := NewHostWithDiscovery(ctx, cfg)
if err != nil {
    return err
}
defer host.Close()

// Access discovery service
ds := host.Discovery()
if ds != nil {
    err := ds.AdvertiseSession(ctx, "my-session")
}
```

## Configuration Examples

### Production Configuration (Server Mode)

```go
cfg := &DiscoveryConfig{
    Mode: DHTModeServer,
    BootstrapPeers: []peer.AddrInfo{
        // IPFS bootstrap nodes or your own infrastructure
        mustParseAddrInfo("/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"),
    },
    AdvertiseTTL:      10 * time.Minute,
    RefreshInterval:   30 * time.Second,
    FindPeersTimeout:  30 * time.Second,
    EnableAutoRefresh: true,
    MaxPeers:          100,
}
```

### Development Configuration (Client Mode)

```go
cfg := &DiscoveryConfig{
    Mode:              DHTModeClient,
    BootstrapPeers:    []peer.AddrInfo{}, // No bootstrap for local testing
    AdvertiseTTL:      1 * time.Minute,
    RefreshInterval:   10 * time.Second,
    FindPeersTimeout:  5 * time.Second,
    EnableAutoRefresh: false, // Disable for faster tests
    MaxPeers:          10,
}
```

## Error Handling

The discovery service defines specific error types for common failure scenarios:

| Error | Description |
|-------|-------------|
| `ErrDHTNotStarted` | Operation attempted before calling Start() |
| `ErrDHTAlreadyStarted` | Start() called multiple times |
| `ErrDHTBootstrapFailed` | Failed to bootstrap the DHT |
| `ErrDHTClosed` | Operation attempted after Stop() |
| `ErrNoBootstrapPeers` | Bootstrap required but no peers provided |
| `ErrInvalidRendezvous` | Empty or invalid rendezvous string |
| `ErrAdvertiseFailed` | Failed to advertise to DHT |
| `ErrFindPeersFailed` | Failed to find peers in DHT |
| `ErrInvalidSessionID` | Empty session ID provided |
| `ErrInvalidCiphersuite` | Empty ciphersuite provided |

## Best Practices

### 1. Use Bootstrap Peers in Production

```go
cfg.BootstrapPeers = []peer.AddrInfo{
    // Use multiple bootstrap peers for redundancy
    parseAddrInfo("/dnsaddr/bootstrap.libp2p.io/..."),
    parseAddrInfo("/ip4/your-bootstrap-server/tcp/4001/p2p/..."),
}
```

### 2. Choose the Right DHT Mode

- **Server mode**: Use for stable, publicly accessible nodes
- **Client mode**: Use for NAT'd nodes or when you only need to query
- **Auto mode**: Let libp2p decide based on network conditions

### 3. Handle Discovery Errors Gracefully

```go
peers, err := ds.FindSessionPeers(ctx, sessionID)
if err != nil {
    if errors.Is(err, ErrDHTClosed) {
        // Service was stopped, handle gracefully
        return
    }
    // Log error but continue - discovery may succeed later
    log.Printf("discovery failed: %v", err)
}
```

### 4. Use Caching for Repeated Lookups

```go
// Check cache first
if cached := ds.GetCachedPeers(rendezvous); len(cached) > 0 {
    return cached, nil
}

// Fall back to DHT query
return ds.FindSessionPeers(ctx, sessionID)
```

### 5. Set Appropriate Timeouts

```go
// Use context with timeout for discovery operations
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

peers, err := ds.FindSessionPeers(ctx, sessionID)
```

## Metrics & Monitoring

The discovery service integrates with the Prometheus metrics collector:

```go
// Track discovery operations
metrics.RecordMessageSent("dht_advertise", 0)
metrics.RecordMessageReceived("dht_find_peers", len(peers))
```

Key metrics to monitor:
- Number of active advertisements
- Peer discovery success/failure rates
- DHT routing table size
- Bootstrap peer connectivity

## Security Considerations

1. **Peer Verification**: Always verify peer identities after discovery before trusting them
2. **Rate Limiting**: Implement rate limiting on discovery operations to prevent abuse
3. **Bootstrap Trust**: Only use trusted bootstrap peers in production
4. **Session Isolation**: Use unique session IDs to prevent cross-session interference

## References

- [libp2p Kademlia DHT Specification](https://github.com/libp2p/specs/tree/master/kad-dht)
- [libp2p Routing Discovery](https://github.com/libp2p/go-libp2p/tree/master/p2p/discovery/routing)
- [Kademlia Paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)
