# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `make lint` and the CI Lint job run actionlint over `.github/workflows/`
  (pinned v1.7.13), and the shellcheck findings it reported in `ci.yml` and
  `release.yml` are fixed by quoting, not silenced (#47).

## [0.3.0-alpha] - 2026-08-15

MINOR, not PATCH. The owner's ruling offered PATCH on the grounds that this is
a behaviour correction with no new API; implementing it well needed a new
exported sentinel (`transport.ErrDKGNotImplemented`), so callers can match with
`errors.Is` instead of parsing a string. Added exported API is MINOR pre-1.0
per conventions/release-versioning.md §1, and the behaviour change is breaking
for anything that compiled against the old success return — which lands in
MINOR too. Both routes give the same answer.

### Changed — BREAKING: the network transports no longer return key material

`Participant.RunDKG` on the **quic, grpc, grpc/unix, http, libp2p and mcp**
transports now returns `transport.ErrDKGNotImplemented` and a nil result.

They never ran the DKG. Each built a `DKGResult` whose `SecretShare` was
`byte(0x42 + participantIdx)` repeated, whose `ThresholdPubkey` was 32 bytes of
`0xAB`, and returned it with a **nil error** — a value indistinguishable from a
real ceremony and reconstructable by anyone who knew the participant index. Any
caller wiring a network transport to a signer received that as a threshold key.

Connection setup, session join, session-info exchange and message relay are
real, are unchanged, and still run; only the ceremony is absent. The FROST DKG
itself in `pkg/dkg` is complete and is what the library API exercises. Wiring
the transports to it is tracked as software task #61.

The **in-memory transport is exempt** and still returns a deterministic result:
it is a test double, and that is the point.

### Added

- `transport.ErrDKGNotImplemented`.

### Fixed

- `ConcurrentDKGRunner.RunParticipants` aggregated participant errors with
  `fmt.Errorf("...: %v", errs)`, flattening them into a string so `errors.Is`
  and `errors.As` could not see through the aggregate. It now uses
  `errors.Join`.

### Documentation

- The `transport` package doc, and `doc.go` for each network transport, carry
  an EXPERIMENTAL banner stating plainly that the transport does not run the
  ceremony. `quic`, `grpc` and `mcp` had no package comment at all and now have
  one.
- The four HTTP per-round helpers (`executeRound1`, `executeRound2`,
  `submitCertEqSignature`, `retrieveCertificate`) are **kept**. They are not
  dead scaffolding: `http_test.go` exercises all four end to end against a live
  server, and #61's wiring needs exactly them. Their `//nolint:unused` comments
  claimed they were "used by integration tests with build tag", which was
  wrong; they now say what is actually true.

### Testing

Every suite that asserted the fabricated result now asserts the error. Worth
recording what those suites had been proving: `TestProtocolParity_2of3` and
`_3of5` compared transports against each other and found them "functionally
equivalent" — they agreed because all of them fabricated the *same* constants.
The per-transport tests asserted only the *lengths* of `SecretShare` and
`ThresholdPubkey`, which the fill satisfied. Fifteen tests across nine files
were updated; the setup, connect, join and relay coverage they provide is
retained.

## [0.2.0-alpha] - 2026-08-15

MINOR rather than PATCH because it adds an exported identifier
(`dkg.ErrEvalAtZero`) and changes which error values several `pkg/dkg` paths
return; pre-1.0, both land in MINOR.

### Fixed

- **`computeProofOfKnowledge` returned an all-zero proof.** The function ended
  with `defer z.Zeroize()`, and because `group.Scalar.Add` returns a fresh
  scalar rather than mutating its receiver, `z` was the same scalar stored in
  `Signature.Z`. Every caller received a proof whose `Z` was the zero scalar,
  including `RefreshDKGPart1`, which publishes it in its `Round1Package`.
- **Index-out-of-range on a short coordinator message.** The encrypted round-2
  entry points indexed `coordMsg.AllPubnonces` per participant without
  validating its length; the coordinator is untrusted, so a short message
  panicked the participant instead of failing the round. Both entry points now
  validate first and return `FaultyCoordinatorError`.
- **Message loss on libp2p streams.** `ReadMessage` created a `bufio.Reader`
  per call on a long-lived stream, buffering up to 4096 bytes and discarding
  everything past the current frame. Frames written back to back were lost and
  the framing desynchronised, hanging the DKG. Reads now come straight off the
  stream.
- **Unauthenticated remote panic in the MCP coordinator.** `participant_idx`
  arrived from the wire and keyed the round maps, which are walked to fill
  slices sized at `NumParticipants`; an unregistered index reached that walk
  and panicked. All three submit handlers now require a joined participant.
- **`Stop()` panicked on concurrent calls** in the QUIC, gRPC, Unix and MCP
  servers — a check-then-act on the running flag let two callers close the same
  channel. `MCPServer` additionally never recreated `stopChan`, so
  Start/Stop/Start/Stop was a deterministic panic.
- **MCP stdio defaulted to nil streams.** The "default to stdin/stdout" branch
  assigned `io.Reader(nil)`/`io.Writer(nil)` — nil interfaces, not empty
  streams — so the documented default panicked on first read.
- **Unix socket transport hardening.** `unix.go` was missed when the gRPC and
  QUIC servers were hardened: it derived its session ID from the wall clock and
  registered participants with no bounds check. Its socket is also now created
  `0600` (it has no peer authentication, so the mode is its only access
  control), and teardown uses a non-recursive remove.

### Added

- `dkg.ErrEvalAtZero`, replacing the ad-hoc error `Polynomial.Eval` returned
  when asked to evaluate at zero.

### Changed

- The host-public-key checks on the encrypted DKG path now report through
  `FaultyParticipantError` instead of `fmt.Errorf`, so a caller can identify
  the offending participant programmatically rather than by parsing a string.
- `RefreshDKGPart2`'s constant-term identity check was removed. The receiver
  constructed the element it then asserted on, so the check could never fire;
  what actually binds a sender's constant term is `VerifySecshare` in
  `RefreshDKGShares`. A control that cannot fail reads as coverage it does not
  provide.

- The libp2p host is released when `Stop` is called before `Start`.
- Integration tests wait for tcp/9000 rather than sleeping, give the QUIC
  clients a CA they can actually verify, and inject CLI write failures through
  filesystem shape rather than permission bits — CI job containers run as root,
  which bypasses mode checks and made those negative tests vacuous.

### Security

- Adopted the `go 1.26.6` toolchain (stdlib fixes for GO-2026-6218 and
  GO-2026-6090) and `x/net v0.57.0` for CVE-2026-46600.
- Adopted `ci-template v1` and completed the mandatory security-analysis suite
  (golangci-lint, gosec, govulncheck, trivy fs, trivy image), and restored the
  Integration Tests and Docker Build & Scan jobs, which had been dark.
- Dropped the workflow-level `GOSUMDB=off` override, which had disabled
  checksum verification for every third-party dependency, not just the
  first-party modules it was meant to exempt.
- `make trivy`, `make trivy-image` and `make vulncheck` now fail closed. The
  first two printed "skipping" and returned 0 when the scanner was absent, so
  `make security` reported success having scanned nothing; `vulncheck` ran
  under `|| true`, which swallowed compile errors and database failures alike.
- The CI coverage gate no longer depends on `bc` and asserts that the coverage
  value parsed before comparing it — an unparseable value previously skipped
  the threshold silently.
- `.env`, key and certificate patterns are now gitignored (they were not, while
  the documented Gitea-token workflow writes `.devcontainer/.env`), and the
  matching `.dockerignore` entries are recursive rather than root-anchored.

## [0.1.1-alpha] - 2026-08-13

Cut during the dependency-resolution cutover; this entry is written
retrospectively, as the release went out without one. Its contents are the
commits reachable from the `v0.1.1-alpha` tag only — everything else from that
week's work landed afterwards and appears under 0.2.0-alpha above.

### Changed

- Cross-repo dependencies resolve as tagged modules fetched from Gitea rather
  than through a shared `go.work`; `go-frost` is pinned at `v0.1.7-alpha`.

### Fixed

- `Polynomial.Eval` returns an error instead of panicking when asked to
  evaluate at zero — **BREAKING**: its signature gained an `error` return.

## [0.1.0-alpha] - 2025-12-27

Initial release of go-frostdkg, a FROST-compliant distributed key generation library for threshold signatures.

### Features

- **FROST DKG**: Threshold key generation supporting Ed25519, ristretto255, Ed448, P-256, and secp256k1
- **Transports**: gRPC, REST, QUIC, libp2p, and Unix socket protocols with TLS/mTLS
- **libp2p**: DHT discovery, pubsub messaging, circuit relay, connection pooling, and Prometheus metrics
- **CLI**: Coordinator and participant commands for running DKG sessions
- **Cross-platform**: Support for Linux, macOS (Darwin), and Windows
- **Security**: gosec scanning, govulncheck, TLS 1.3 enforcement, secure file permissions
