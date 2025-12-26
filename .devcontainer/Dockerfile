# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2025 Jeremy Hahn
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    git \
    curl \
    wget \
    # SoftHSM2 and PKCS#11 support
    softhsm2 \
    opensc \
    libpkcs11-helper1-dev \
    p11-kit \
    p11-kit-modules \
    gnutls-bin \
    # OpenSSL development headers
    libssl-dev \
    # Protobuf compiler for gRPC
    protobuf-compiler \
    # Useful utilities
    jq \
    make \
    && rm -rf /var/lib/apt/lists/*

# Configure SoftHSM2
RUN mkdir -p /etc/softhsm /var/lib/softhsm/tokens && \
    chmod 755 /var/lib/softhsm/tokens

# Create SoftHSM2 configuration
RUN echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm/softhsm2.conf && \
    echo "objectstore.backend = file" >> /etc/softhsm/softhsm2.conf && \
    echo "log.level = INFO" >> /etc/softhsm/softhsm2.conf

# Set PKCS#11 environment variables
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

# Install Go (version will be managed by devcontainer feature)
# This is a fallback if the feature doesn't work
ARG GO_VERSION=1.23.4
RUN if ! command -v go &> /dev/null; then \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xzf - && \
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh; \
    fi

ENV PATH=$PATH:/usr/local/go/bin:/home/vscode/go/bin

# Install Go tools
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install pkcs11-tool for testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    opensc-pkcs11 \
    && rm -rf /var/lib/apt/lists/*

# Create a test token for development
RUN softhsm2-util --init-token --slot 0 --label "test-token" --pin 1234 --so-pin 12345678

# Set permissions for vscode user
RUN chown -R vscode:vscode /var/lib/softhsm

WORKDIR /workspace
