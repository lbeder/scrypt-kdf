#!/usr/bin/env bash -e

VERSION=$(cargo pkgid | cut -d# -f2 | cut -d: -f2)

echo "Building v${VERSION} for Mac OS..."
APPLE_RELEASE="target/scrypt-kdf-${VERSION}-osx.tgz"
cargo build --release --target=x86_64-apple-darwin
tar zcvf ${APPLE_RELEASE} target/x86_64-apple-darwin/release/scrypt-kdf

echo "Building v${VERSION} for Linux AMD64..."
LINUX_RELEASE="target/scrypt-kdf-${VERSION}-linux-amd64.tgz"
CROSS_COMPILE=x86_64-linux-musl- cargo build --release --target=x86_64-unknown-linux-musl
tar zcvf ${LINUX_RELEASE} target/x86_64-unknown-linux-musl/release/scrypt-kdf

RELEASE_NOTES="target/release.md"
echo "Preparing release notes..."

cat <<EOF >$RELEASE_NOTES
# Release Notes v${VERSION}

## Mac OS

\`\`\`bash
shasum -a512 ${APPLE_RELEASE} $(shasum -a512 ${APPLE_RELEASE})
\`\`\`

## Linux AMD64

\`\`\`bash
shasum -a512 ${LINUX_RELEASE} $(shasum -a512 ${LINUX_RELEASE})
\`\`\`
EOF
