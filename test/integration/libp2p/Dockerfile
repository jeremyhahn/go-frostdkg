# syntax=docker/dockerfile:1.7
#
# Dockerfile for libp2p DKG node (coordinator or participant)
FROM golang:1.27.2-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./

# go.mod pins first-party modules published to the internal Gitea, not to
# github.com, so `go mod download` needs GOPRIVATE plus git's insteadOf rewrite
# carrying a read-only token (dependency-resolution.md §6). Without it this
# build dies on `github.com/jeremyhahn/go-frost@v0.1.7-alpha: unknown revision`.
#
# The token arrives as a BuildKit secret, never a build arg or ENV: an arg is
# recoverable with `docker history`, while a secret is mounted on tmpfs for this
# RUN alone. It is sourced rather than exported so it never reaches a command
# line either. The mount is optional, so the same Dockerfile builds on GitHub
# against the public proxy.
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download

# Copy source code
COPY . .

# Build the CLI
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /frostdkg ./cmd/frostdkg

# Runtime image
FROM alpine:3.24

RUN apk add --no-cache ca-certificates bash

COPY --from=builder /frostdkg /usr/local/bin/frostdkg

# Create data directory
RUN mkdir -p /data

# Copy entrypoint script
COPY test/integration/libp2p/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /data

ENTRYPOINT ["/entrypoint.sh"]
