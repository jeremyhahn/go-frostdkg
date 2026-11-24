# syntax=docker/dockerfile:1.7
#
# Dockerfile for libp2p DKG node (coordinator or participant)
FROM golang:1.27.3-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./

# Private first-party modules resolve through an optional BuildKit secret token (GOPRIVATE plus insteadOf), never a build arg.
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
