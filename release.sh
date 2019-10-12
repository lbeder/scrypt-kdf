#!/usr/bin/env bash -e

VERSION=$(cargo pkgid | cut -d# -f2 | cut -d: -f2)

./build.sh

rm -rf target/*.tgz target/*.tgz.sig target/release.md

echo "Creating v${VERSION} bundle for Mac OS..."
APPLE_TARGET="scrypt-kdf-${VERSION}-osx.tgz"
APPLE_TARGET_SIG=${APPLE_TARGET}.sig
APPLE_RELEASE="target/${APPLE_TARGET}"
APPLE_RELEASE_SIG=${APPLE_RELEASE}.sig
tar zcvf ${APPLE_RELEASE} target/x86_64-apple-darwin/release/scrypt-kdf
APPLE_RELEASE_SHA512=$(shasum -a512 ${APPLE_RELEASE})
gpg --output ${APPLE_RELEASE_SIG} --detach-sig ${APPLE_RELEASE}

echo "Creating v${VERSION} bundle for Linux AMD64..."
LINUX_TARGET="scrypt-kdf-${VERSION}-linux-amd64.tgz"
LINUX_TARGET_SIG=${LINUX_TARGET}.sig
LINUX_RELEASE="target/${LINUX_TARGET}"
LINUX_RELEASE_SIG=${LINUX_RELEASE}.sig
tar zcvf ${LINUX_RELEASE} target/x86_64-unknown-linux-musl/release/scrypt-kdf
LINUX_RELEASE_SHA512=$(shasum -a512 ${LINUX_RELEASE})
gpg --output ${LINUX_RELEASE_SIG} --detach-sig ${LINUX_RELEASE}

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

\`\`\`bash
gpg --verify ${APPLE_TARGET_SIG} ${APPLE_TARGET}
\`\`\`

## Linux AMD64

### SHA512

\`\`\`bash
shasum -a512 ${LINUX_RELEASE} ${LINUX_RELEASE_SHA512}
\`\`\`

### Digital Signature

\`\`\`bash
gpg --verify ${LINUX_TARGET_SIG} ${LINUX_TARGET}
\`\`\`

EOF
