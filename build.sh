#!/usr/bin/env bash -e

VERSION=$(cargo pkgid | cut -d# -f2 | cut -d: -f2)

echo "Running audit..."
cargo audit

echo "Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "Running tests..."
cargo test --release

echo "Building v${VERSION} for Mac OS..."
cargo build --release --target=x86_64-apple-darwin

echo "Building v${VERSION} for Linux AMD64..."
CROSS_COMPILE=x86_64-linux-musl- cargo build --release --target=x86_64-unknown-linux-musl
