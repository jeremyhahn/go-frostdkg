# syntax=docker/dockerfile:1.7
#
# Dockerfile for go-frostdkg integration tests
# This container runs comprehensive end-to-end integration tests
# in an isolated environment separate from the host OS.

FROM golang:1.26.7-alpine

# Install test dependencies. `apk upgrade` first: the base image's own
# packages lag alpine's security fixes (libcrypto3 3.5.7-r0, CVE-2026-14456,
# failed the image gate), and the gate scans what the image ships (#41).
RUN apk upgrade --no-cache && apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    bash

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum* ./

# go.mod pins first-party modules (github.com/jeremyhahn/go-frost, …) that are
# published to the internal Gitea instance, not to github.com. Resolving them
# needs GOPRIVATE plus git's insteadOf rewrite carrying a read-only token —
# conventions/dependency-resolution.md §6. Without it the build dies on
# `github.com/jeremyhahn/go-frost@v0.1.7-alpha: unknown revision`.
#
# The token arrives as a BuildKit secret, NOT a build arg or an ENV: a build arg
# is recorded in image metadata and readable with `docker history`, while a
# secret is mounted on tmpfs for this RUN alone and never becomes a layer. It is
# sourced rather than exported so the value never appears in a command line
# either (`ps` on the build host would show it).
#
# The mount is optional by design. On GitHub Actions no secret is supplied and
# these modules resolve from the public proxy once tags are mirrored (§7), so
# the same Dockerfile builds on both hosts.
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download

# Copy all source code
COPY . .

# Set environment for testing
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64

# Default command runs integration tests
CMD ["make", "integration-test-internal"]
