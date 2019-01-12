#!/usr/bin/env bash -e

VERSION=$(cargo pkgid | cut -d# -f2 | cut -d: -f2)

rm -rf target/*.tgz target/*.tgz.asc target/release.md

echo "Running tests..."
cargo test --release

echo "Building v${VERSION} for Mac OS..."
APPLE_RELEASE="target/scrypt-kdf-${VERSION}-osx.tgz"
cargo build --release --target=x86_64-apple-darwin
tar zcvf ${APPLE_RELEASE} target/x86_64-apple-darwin/release/scrypt-kdf
APPLE_RELEASE_SHA512=$(shasum -a512 ${APPLE_RELEASE})
APPLE_RELEASE_ASC=${APPLE_RELEASE}.asc

echo "Building v${VERSION} for Linux AMD64..."
LINUX_RELEASE="target/scrypt-kdf-${VERSION}-linux-amd64.tgz"
CROSS_COMPILE=x86_64-linux-musl- cargo build --release --target=x86_64-unknown-linux-musl
tar zcvf ${LINUX_RELEASE} target/x86_64-unknown-linux-musl/release/scrypt-kdf
LINUX_RELEASE_SHA512=$(shasum -a512 ${LINUX_RELEASE})
LINUX_RELEASE_ASC=${LINUX_RELEASE}.asc

keybase pgp sign --clearsign -m "${APPLE_RELEASE_SHA512}" > ${APPLE_RELEASE_ASC}
keybase pgp sign --clearsign -m "${LINUX_RELEASE_SHA512}" > ${LINUX_RELEASE_ASC}

RELEASE_NOTES="target/release.md"
echo "Preparing release notes..."

cat <<EOF >$RELEASE_NOTES
# Release Notes v${VERSION}

## Mac OS

### SHA512

\`\`\`bash
shasum -a512 ${APPLE_RELEASE} ${APPLE_RELEASE_SHA512}
\`\`\`

### Digital Signature

$(cat ${APPLE_RELEASE_ASC})

## Linux AMD64

### SHA512

\`\`\`bash
shasum -a512 ${LINUX_RELEASE} ${LINUX_RELEASE_SHA512}
\`\`\`

### Digital Signature

$(cat ${LINUX_RELEASE_ASC})
EOF
