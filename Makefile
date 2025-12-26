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
VERSION=$(shell cat VERSION 2>/dev/null || echo "dev")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)"

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
	@echo "Building frostdkg CLI $(VERSION)..."
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
	@echo "Installing frostdkg CLI $(VERSION)..."
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

.PHONY: lint
lint:
	@echo "Running linters..."
	$(GOVET) ./...
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run --timeout=5m ./...

.PHONY: tidy
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

# =============================================================================
# Security Targets
# =============================================================================

.PHONY: security
security:
	@echo "Running security scan with gosec..."
	@go run github.com/securego/gosec/v2/cmd/gosec@latest -exclude-generated -severity medium -confidence medium -exclude-dir=test -exclude-dir=vendor ./...

# NOTE: GO-2024-3218 (github.com/libp2p/go-libp2p-kad-dht) has no fix available as of 2025-01.
# This is tracked and will be updated when a fix is released.
# See: https://pkg.go.dev/vuln/GO-2024-3218
.PHONY: vulncheck
vulncheck:
	@echo "Running vulnerability check with govulncheck..."
	@go run golang.org/x/vuln/cmd/govulncheck@latest ./... || \
		(echo ""; echo "NOTE: GO-2024-3218 in libp2p-kad-dht has no fix available yet."; \
		 echo "See docs/security.md for details."; exit 0)

# =============================================================================
# Docker Targets
# =============================================================================

.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -f test/integration/Dockerfile .

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
ci: tidy fmt-check lint security vulncheck test check build-cli
	@echo "CI checks completed successfully"

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
	@echo "  lint                   - Run linters (go vet, golangci-lint)"
	@echo "  tidy                   - Tidy dependencies"
	@echo ""
	@echo "Security:"
	@echo "  security               - Run security scan with gosec"
	@echo "  vulncheck              - Run vulnerability check with govulncheck"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build           - Build Docker image"
	@echo "  docker-test            - Run tests in Docker"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean                  - Clean build artifacts"
	@echo ""
	@echo "CI:"
	@echo "  ci                     - Run CI checks (matches GitHub Actions workflow)"
	@echo "  ci-full                - Run full CI with integration tests"

.DEFAULT_GOAL := help
