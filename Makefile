# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet
GOINSTALL=$(GOCMD) install

# Version info
BUILD_VERSION=$(shell cat VERSION 2>/dev/null || echo "dev")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-X main.Version=$(BUILD_VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Docker parameters
DOCKER_IMAGE=go-frostdkg
DOCKER_TAG=latest

# Directories
COVERAGE_DIR=./coverage
BIN_DIR=./bin

# =============================================================================
# Build Targets
# =============================================================================

.PHONY: all
all: fmt lint test build-cli

.PHONY: build
build: build-cli

.PHONY: build-cli
build-cli:
	@echo "Building frostdkg CLI $(BUILD_VERSION)..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/frostdkg ./cmd/frostdkg
	@echo "Binary created: $(BIN_DIR)/frostdkg"

.PHONY: check
check:
	@echo "Checking compilation..."
	$(GOBUILD) ./...
	@echo "Compilation check passed"

.PHONY: install
install: build-cli
	@echo "Installing frostdkg CLI $(BUILD_VERSION)..."
	$(GOINSTALL) $(LDFLAGS) ./cmd/frostdkg

# =============================================================================
# Unit Test Targets
# =============================================================================

.PHONY: test
test: test-unit

.PHONY: test-unit
test-unit:
	@echo "Running unit tests..."
	@$(GOCMD) list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./... | \
		grep -v '/test/integration' | \
		xargs -r $(GOTEST) -v -race -timeout 60s

.PHONY: test-schnorr
test-schnorr:
	@echo "Running tests for schnorr package..."
	$(GOTEST) -v -race -timeout 30s ./pkg/schnorr

.PHONY: test-dkg
test-dkg:
	@echo "Running tests for dkg package..."
	$(GOTEST) -v -race -timeout 30s ./pkg/dkg

.PHONY: test-cli
test-cli:
	@echo "Running tests for CLI..."
	$(GOTEST) -v -race -timeout 60s ./cmd/frostdkg

.PHONY: test-tls
test-tls:
	@echo "Running tests for TLS package..."
	$(GOTEST) -v -race -timeout 30s ./pkg/transport/tls

.PHONY: test-libp2p
test-libp2p:
	@echo "Running unit tests for libp2p package..."
	$(GOTEST) -v -race -timeout 30s ./pkg/transport/libp2p

.PHONY: test-libp2p-integration
test-libp2p-integration:
	@echo "Running integration tests for libp2p package..."
	$(GOTEST) -v -race -timeout 120s -tags=integration ./pkg/transport/libp2p

# =============================================================================
# Integration Test Targets
# =============================================================================

.PHONY: integration-test-local
integration-test-local:
	@echo "Running all integration tests locally..."
	$(GOTEST) -v -race -timeout 300s -tags=integration ./...

.PHONY: integration-test
integration-test:
	@echo "Building integration test Docker image..."
	docker build -t $(DOCKER_IMAGE)-test:$(DOCKER_TAG) -f test/integration/Dockerfile .
	@echo "Running integration tests..."
	docker run --rm $(DOCKER_IMAGE)-test:$(DOCKER_TAG)

.PHONY: integration-test-internal
integration-test-internal:
	@echo "Running integration tests..."
	$(GOTEST) -v -race -timeout 300s -tags=integration ./test/integration/...

.PHONY: integration-test-libp2p
integration-test-libp2p:
	@echo "Starting libp2p multi-node integration tests..."
	@echo "Building Docker images..."
	docker compose -f test/integration/libp2p/docker-compose.yml build
	@echo "Starting libp2p network with coordinator and 3 participants..."
	docker compose -f test/integration/libp2p/docker-compose.yml up --abort-on-container-exit --exit-code-from test-runner
	@echo "Cleaning up containers..."
	docker compose -f test/integration/libp2p/docker-compose.yml down -v

.PHONY: integration-test-pkcs11
integration-test-pkcs11:
	@echo "Running PKCS#11 integration tests..."
	$(GOTEST) -v -race -timeout 300s -tags="integration pkcs11" ./test/integration/pkcs11/...

.PHONY: integration-test-pkcs11-ed25519
integration-test-pkcs11-ed25519:
	@echo "Running Ed25519 PKCS#11 integration tests..."
	$(GOTEST) -v -race -timeout 120s -tags="integration pkcs11" -run "ED25519" ./test/integration/pkcs11/...

.PHONY: integration-test-pkcs11-secp256k1
integration-test-pkcs11-secp256k1:
	@echo "Running secp256k1 PKCS#11 integration tests..."
	$(GOTEST) -v -race -timeout 120s -tags="integration pkcs11" -run "secp256k1" ./test/integration/pkcs11/...

# =============================================================================
# Coverage Targets
# =============================================================================

.PHONY: coverage
coverage:
	@echo "Generating coverage report..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage report generated at $(COVERAGE_DIR)/coverage.html"

.PHONY: coverage-schnorr
coverage-schnorr:
	@echo "Generating coverage for schnorr package..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/schnorr.out -covermode=atomic ./pkg/schnorr
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/schnorr.out -o $(COVERAGE_DIR)/schnorr.html
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/schnorr.out

.PHONY: coverage-dkg
coverage-dkg:
	@echo "Generating coverage for dkg package..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/dkg.out -covermode=atomic ./pkg/dkg
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/dkg.out -o $(COVERAGE_DIR)/dkg.html
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/dkg.out

.PHONY: coverage-cli
coverage-cli:
	@echo "Generating coverage for CLI..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/cli.out -covermode=atomic ./cmd/frostdkg
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/cli.out -o $(COVERAGE_DIR)/cli.html
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/cli.out

.PHONY: coverage-tls
coverage-tls:
	@echo "Generating coverage for TLS package..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/tls.out -covermode=atomic ./pkg/transport/tls
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/tls.out -o $(COVERAGE_DIR)/tls.html
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/tls.out

.PHONY: coverage-libp2p
coverage-libp2p:
	@echo "Generating coverage for libp2p package..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/libp2p.out -covermode=atomic ./pkg/transport/libp2p
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/libp2p.out -o $(COVERAGE_DIR)/libp2p.html
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/libp2p.out

.PHONY: coverage-integration
coverage-integration:
	@echo "Generating coverage for integration tests (runs in Docker)..."
	docker build -t $(DOCKER_IMAGE)-coverage:$(DOCKER_TAG) -f test/integration/Dockerfile .
	docker run --rm -v $(PWD)/coverage:/coverage $(DOCKER_IMAGE)-coverage:$(DOCKER_TAG) \
		sh -c "mkdir -p /coverage && go test -v -race -coverprofile=/coverage/integration.out -covermode=atomic -tags=integration ./test/integration/... && go tool cover -func=/coverage/integration.out"
	@echo "Coverage report generated at $(COVERAGE_DIR)/integration.out"

.PHONY: coverage-pkcs11
coverage-pkcs11:
	@echo "Generating coverage for PKCS#11 integration tests..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/pkcs11.out -covermode=atomic -tags="integration pkcs11" ./test/integration/pkcs11/...
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/pkcs11.out -o $(COVERAGE_DIR)/pkcs11.html
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/pkcs11.out

# =============================================================================
# Benchmark Targets
# =============================================================================

.PHONY: bench
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

.PHONY: bench-schnorr
bench-schnorr:
	@echo "Running benchmarks for schnorr package..."
	$(GOTEST) -v -bench=. -benchmem ./pkg/schnorr

.PHONY: bench-dkg
bench-dkg:
	@echo "Running benchmarks for dkg package..."
	$(GOTEST) -v -bench=. -benchmem ./pkg/dkg

.PHONY: bench-tls
bench-tls:
	@echo "Running benchmarks for TLS package..."
	$(GOTEST) -v -bench=. -benchmem ./pkg/transport/tls

.PHONY: bench-libp2p
bench-libp2p:
	@echo "Running benchmarks for libp2p package..."
	$(GOTEST) -v -bench=. -benchmem ./pkg/transport/libp2p

# =============================================================================
# Code Quality Targets
# =============================================================================

.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

.PHONY: fmt-check
fmt-check:
	@echo "Checking code formatting..."
	@UNFORMATTED=$$(gofmt -l .); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "Code is not formatted:"; \
		echo "$$UNFORMATTED"; \
		echo "Run 'make fmt' to fix"; \
		exit 1; \
	fi
	@echo "Code formatting OK"

# actionlint validates .github/workflows (syntax, expressions, runner labels,
# shellcheck on run: blocks) before CI does — devops.md, the `make lint` row.
# actionlint is baked into the runner image (like golangci-lint): nothing is
# installed over the network, a missing or off-pin binary fails the target.
# Keep ACTIONLINT_VERSION identical to the actionlint steps in
# .github/workflows/ci.yml.
ACTIONLINT_VERSION := v1.7.13

.PHONY: lint
lint:
	@echo "Running linters..."
	$(GOVET) ./...
	@golangci-lint run --timeout=5m ./...
	@echo "Running actionlint on .github/workflows..."
	@command -v actionlint >/dev/null 2>&1 || { \
		echo "actionlint is not on PATH (baked into the runner image) — this is not a clean lint"; \
		exit 1; \
	}
	@GOT=$$(actionlint --version | sed -n '1s/^v\{0,1\}\([0-9.]*\).*/\1/p'); \
	if [ "$$GOT" != "$(ACTIONLINT_VERSION:v%=%)" ]; then \
		echo "actionlint on PATH is '$$GOT', pinned '$(ACTIONLINT_VERSION:v%=%)'"; \
		exit 1; \
	fi
	@actionlint

.PHONY: tidy
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

# =============================================================================
# Security Targets — devops.md §8, the mandatory analysis suite
# =============================================================================

# `security` is the contract: CI calls this target so the pipeline and a
# developer's machine run exactly the same checks. The container image is
# scanned by docker-build, which is where it exists.
.PHONY: security
security: gosec vulncheck mod-verify trivy
	@echo "Security suite passed"

# gosec exclusions. §8 requires a written justification beside every rule; keep
# this list identical to the one in .github/workflows/ci.yml.
#   G115 integer overflow on conversion: every site gosec flags is a deliberate
#        narrowing to byte — the big-endian serialization idiom
#        (byte(v >> 24), byte(v >> 16), …) in pkg/dkg/refresh.go and
#        pkg/dkg/frostdkg.go, and byte(participantIdx) where the index is a
#        small participant ordinal bounded by the DKG group size.
#        NOT a blanket "we accept overflow" — a NEW narrowing conversion
#        without a preceding bound is a real finding this exclusion will hide,
#        so review narrowing conversions by hand.
#   G118 goroutine with context.Background/TODO: the single site is
#        pkg/transport/quic/server.go's accept loop, which outlives the Start
#        call that spawns it and is terminated by Stop through shutdownChan.
#        Binding it to the caller's start-up context would cancel the listener.
GOSEC_EXCLUDE := G115,G118

.PHONY: gosec
gosec:
	@echo "Running security scan with gosec..."
	@gosec -exclude=$(GOSEC_EXCLUDE) -exclude-generated -severity medium -confidence medium -exclude-dir=test -exclude-dir=vendor ./...

# govulncheck is blocking (§8) and is also the §9 forcing function for toolchain
# currency. Two findings have NO fixed version published upstream and are
# allowlisted here by ID; every other finding — including a new one in these
# same modules — fails the target. Re-check on each dependency bump and delete
# an entry the day its fix ships.
#   GO-2024-3218 (allowlisted 2026-08-14) github.com/libp2p/go-libp2p-kad-dht:
#       no fixed version upstream. See docs/security.md.
#   GO-2026-4479 (allowlisted 2026-08-14) github.com/pion/dtls/v2, reached
#       indirectly through libp2p's WebRTC transport: no fixed version upstream.
GOVULN_ALLOW := GO-2024-3218 GO-2026-4479

.PHONY: vulncheck
vulncheck:
	@echo "Running vulnerability check with govulncheck..."
	@command -v govulncheck >/dev/null || { \
		echo "govulncheck is not on PATH (baked into the runner image) — this is not a clean scan"; \
		exit 1; \
	}; \
	set +e; OUT=$$(govulncheck ./... 2>&1); RC=$$?; set -e; \
	echo "$$OUT"; \
	if [ $$RC -ne 0 ] && [ $$RC -ne 3 ]; then \
		echo ""; \
		echo "govulncheck failed to RUN (exit $$RC) — a compile error, an unreachable vuln"; \
		echo "database or a changed output format all land here, not just findings."; \
		exit 1; \
	fi; \
	FOUND=$$(echo "$$OUT" | sed -n 's/^Vulnerability #[0-9]*: \(GO-[0-9][0-9-]*\).*/\1/p' | sort -u); \
	for id in $(GOVULN_ALLOW); do FOUND=$$(echo "$$FOUND" | grep -vx "$$id" || true); done; \
	FOUND=$$(echo "$$FOUND" | tr -d '[:space:]'); \
	if [ -n "$$FOUND" ]; then \
		echo ""; \
		echo "govulncheck: vulnerabilities outside the documented allowlist — fix them or record an exception in GOVULN_ALLOW"; \
		exit 1; \
	fi
	@echo "govulncheck passed (only allowlisted no-fix findings remain)"

.PHONY: mod-verify
mod-verify:
	@echo "Verifying module integrity against go.sum..."
	@go mod verify

# trivy and trivy-image fail closed. A missing scanner used to print "skipping"
# and return 0, so `make security` reported "Security suite passed" having
# scanned nothing — devops.md §8 makes both scans blocking.
.PHONY: trivy
trivy:
	@echo "Running Trivy filesystem scan..."
	@command -v trivy >/dev/null 2>&1 || { \
		echo "trivy is required by devops.md §8 (install: https://trivy.dev/docs/getting-started/installation/)"; \
		exit 1; \
	}
	@trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 .

.PHONY: trivy-image
trivy-image:
	@echo "Running Trivy image scan on $(DOCKER_IMAGE):$(DOCKER_TAG)..."
	@command -v trivy >/dev/null 2>&1 || { \
		echo "trivy is required by devops.md §8 (install: https://trivy.dev/docs/getting-started/installation/)"; \
		exit 1; \
	}
	@trivy image --scanners vuln --severity CRITICAL,HIGH --exit-code 1 $(DOCKER_IMAGE):$(DOCKER_TAG)

# =============================================================================
# Docker Targets
# =============================================================================

.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -f test/integration/Dockerfile .
	@$(MAKE) --no-print-directory trivy-image

.PHONY: docker-test
docker-test: docker-build
	@echo "Running tests in Docker..."
	docker run --rm $(DOCKER_IMAGE):$(DOCKER_TAG) make test

# =============================================================================
# Maintenance Targets
# =============================================================================

.PHONY: clean
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(COVERAGE_DIR)
	rm -rf $(BIN_DIR)
	rm -f coverage*.out coverage*.html *.log
	rm -f *.test *.out frostdkg

# =============================================================================
# CI Targets
# =============================================================================

.PHONY: ci
ci: tidy fmt-check lint security test check build-cli
	@echo "CI checks completed successfully"

# ci-fast: the subset that needs no Docker (devops.md §4).
.PHONY: ci-fast
ci-fast: fmt-check lint security test check build-cli
	@echo "Fast CI checks completed successfully"

.PHONY: ci-full
ci-full: ci integration-test
	@echo "Full CI completed successfully"

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help:
	@echo "Available targets:"
	@echo ""
	@echo "Build:"
	@echo "  all                    - Format, lint, test, and build CLI (default)"
	@echo "  build                  - Build frostdkg CLI binary (alias for build-cli)"
	@echo "  build-cli              - Build frostdkg CLI binary"
	@echo "  check                  - Verify all packages compile"
	@echo "  install                - Install frostdkg CLI to GOPATH/bin"
	@echo ""
	@echo "Unit Tests:"
	@echo "  test                   - Run all unit tests"
	@echo "  test-unit              - Run unit tests"
	@echo "  test-cli               - Run CLI tests"
	@echo "  test-schnorr           - Run schnorr package tests"
	@echo "  test-dkg               - Run DKG package tests"
	@echo "  test-tls               - Run TLS package tests"
	@echo "  test-libp2p            - Run libp2p unit tests (no network)"
	@echo "  test-libp2p-integration - Run libp2p integration tests"
	@echo ""
	@echo "Integration Tests:"
	@echo "  integration-test-local - Run all integration tests locally"
	@echo "  integration-test       - Run integration tests in Docker (recommended)"
	@echo "  integration-test-internal - Run integration tests (internal, Docker only)"
	@echo "  integration-test-libp2p - Run libp2p multi-node tests in Docker"
	@echo "  integration-test-pkcs11 - Run PKCS#11 integration tests"
	@echo "  integration-test-pkcs11-ed25519 - Run Ed25519 PKCS#11 tests"
	@echo "  integration-test-pkcs11-secp256k1 - Run secp256k1 PKCS#11 tests"
	@echo ""
	@echo "Coverage:"
	@echo "  coverage               - Generate coverage report"
	@echo "  coverage-cli           - Generate CLI coverage"
	@echo "  coverage-schnorr       - Generate schnorr coverage"
	@echo "  coverage-dkg           - Generate DKG coverage"
	@echo "  coverage-tls           - Generate TLS coverage"
	@echo "  coverage-libp2p        - Generate libp2p coverage"
	@echo "  coverage-integration   - Generate integration test coverage (Docker)"
	@echo "  coverage-pkcs11        - Generate PKCS#11 integration test coverage"
	@echo ""
	@echo "Benchmarks:"
	@echo "  bench                  - Run all benchmarks"
	@echo "  bench-schnorr          - Run schnorr benchmarks"
	@echo "  bench-dkg              - Run DKG benchmarks"
	@echo "  bench-tls              - Run TLS benchmarks"
	@echo "  bench-libp2p           - Run libp2p benchmarks"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt                    - Format code"
	@echo "  fmt-check              - Check code formatting (fails if not formatted)"
	@echo "  lint                   - Run linters (go vet, golangci-lint, actionlint)"
	@echo "  tidy                   - Tidy dependencies"
	@echo ""
	@echo "Security (devops.md §8):"
	@echo "  security               - Run the full suite: gosec, govulncheck, go mod verify, trivy fs"
	@echo "  gosec                  - Run security scan with gosec"
	@echo "  vulncheck              - Run vulnerability check with govulncheck"
	@echo "  mod-verify             - Verify module integrity against go.sum"
	@echo "  trivy                  - Trivy filesystem scan (dependency CVEs + secrets)"
	@echo "  trivy-image            - Trivy scan of the built container image"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build           - Build Docker image and scan it with Trivy"
	@echo "  docker-test            - Run tests in Docker"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean                  - Clean build artifacts"
	@echo ""
	@echo "CI:"
	@echo "  ci                     - Run CI checks (matches GitHub Actions workflow)"
	@echo "  ci-fast                - Run CI checks that need no Docker"
	@echo "  ci-full                - Run full CI with integration tests"

.DEFAULT_GOAL := help

AGENT_GIT ?= agent-git.sh
REPO_NAME ?= go-frostdkg
RELEASE_REMOTE ?= origin
# Builds never resolve through a workspace: modules come from Gitea tags
# (dependency-resolution.md §2). Immunizes against stray go.work files.
export GOWORK=off

# ---- dependency-resolution.md targets (2026-08-13 cutover) ----
# deps-latest runs before compiling in a consumer repo. It picks the highest
# tag INCLUDING -alpha prereleases — bare 'go get @latest' ignores
# prereleases and would downgrade to legacy v0.0.0.

# release-alpha is the handbook's template v2 (release-versioning.md):
#   make release-alpha VERSION=vX.Y.Z-alpha
# The recipe lives in mk/release-alpha.mk and mk/release-common.mk, copied
# verbatim from handbook software/templates/make/. The build version above is
# BUILD_VERSION so it cannot shadow the VERSION argument.
include mk/release-alpha.mk

.PHONY: deps-latest

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'
