# go-frostdkg roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-08
> Changes are proposed by docs-only PR.

## Mission

FROST threshold distributed key generation, built on the go-frost primitives.
Ceremonies run over libp2p, QUIC, gRPC and Unix transports, idempotent and resumable.
Layer 6 project owned by agent-go-frostdkg, exempt from L4 tier placement.

## Current milestone

None. Target kind RC.
No projected date.

## Now

- [#38](http://git.example.internal/jeremyhahn/go-frostdkg/issues/38) main CI green with no HIGH CVEs in the Trivy and Docker gates — open
- [#7](http://git.example.internal/jeremyhahn/go-frostdkg/issues/7) security wave: fail-closed transport keys and participant-identity binding — open
- [#43](http://git.example.internal/jeremyhahn/go-frostdkg/issues/43) workflows no longer mount the host Docker socket — open
- [#13](http://git.example.internal/jeremyhahn/go-frostdkg/issues/13) quic, grpc and unix transports bind the sender index to the joined identity — blocked: reason in issue
- [#21](http://git.example.internal/jeremyhahn/go-frostdkg/issues/21) QUICClient reconnects after Disconnect — blocked: reason in issue
- [#23](http://git.example.internal/jeremyhahn/go-frostdkg/issues/23) SoftwareHostKey plaintext export settled — blocked: owner ruling
- [#25](http://git.example.internal/jeremyhahn/go-frostdkg/issues/25) unused plaintext secret types removed from pkg/dkg — blocked: reason in issue

## Next

- [#30](http://git.example.internal/jeremyhahn/go-frostdkg/issues/30) idle participant streams shut down gracefully — blocked: reason in issue
- [#6](http://git.example.internal/jeremyhahn/go-frostdkg/issues/6) builds on Go 1.27.0 — open
- [#22](http://git.example.internal/jeremyhahn/go-frostdkg/issues/22) ciphersuite resolution delegated to go-frost suites — blocked: reason in issue
- [#32](http://git.example.internal/jeremyhahn/go-frostdkg/issues/32) release-alpha recipe produces correct signed tags — open
- [#33](http://git.example.internal/jeremyhahn/go-frostdkg/issues/33) libp2p participant honours the configured address — open
- [#34](http://git.example.internal/jeremyhahn/go-frostdkg/issues/34) CI uses the analysis tools baked into the runner image — open
- [#35](http://git.example.internal/jeremyhahn/go-frostdkg/issues/35) CI keeps the baked golangci-lint version — open

## Later

- [#44](http://git.example.internal/jeremyhahn/go-frostdkg/issues/44) signed release artifacts — open
- [#45](http://git.example.internal/jeremyhahn/go-frostdkg/issues/45) docs carry status banners and stamps — open
- [#36](http://git.example.internal/jeremyhahn/go-frostdkg/issues/36) superseded CI runs cancelled — open

## Dependencies

- Up: go-frost v0.3.0-alpha
- Down: none; no in-house module consumes go-frostdkg

## Non-goals

- Cryptographic primitives and ciphersuites; go-frost owns them.
- Placement in the core platform stack; see [docs/00](../handbook/software/docs/00-ownership-and-sdk-boundary.md).
