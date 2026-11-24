# syntax=docker/dockerfile:1.7
#
# Dockerfile for go-frostdkg integration tests
# This container runs comprehensive end-to-end integration tests
# in an isolated environment separate from the host OS.

FROM golang:1.27.3-alpine

# Upgrade base packages first so the image gate sees current security fixes.
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

# Private first-party modules resolve through an optional BuildKit secret token (GOPRIVATE plus insteadOf), never a build arg.
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
