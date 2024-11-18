#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define installation directory for wolfSSL
INSTALL_DIR="/opt/wolfssl-rs"

# Navigate to the wolfcrypt-rs directory to build wolfSSL and generate bindings
echo "Building wolfSSL and generating bindings..."
cd wolfcrypt-rs/
make build

# Running fmt and clippy on wolfcrypt-rs
echo "Running fmt & clippy on wolfcrypt-rs..."
make fmt && make clippy

# Verify the wolfSSL installation
echo "Running tests to verify wolfSSL installation..."
make test

# Navigate to the rustls-wolfcrypt-provider directory
# to build Rustls with wolfCrypt provider
echo "Setting up Rustls with wolfCrypt provider..."
cd ../rustls-wolfcrypt-provider
make build

# Running fmt and clippy on wolfcrypt-rs
echo "Running fmt & clippy on rustls-wolfcrypt-provider..."
make fmt && make clippy

# Run Rustls tests
echo "Running Rustls tests..."
make test

echo "Build completed successfully!"
