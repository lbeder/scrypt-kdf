#!/usr/bin/env sh -e

VERSION=$(cargo pkgid | cut -d# -f2 | cut -d: -f2)

./build.sh

rm -rf target/*.tgz target/*.tgz.sig target/release.md

echo "Creating v${VERSION} bundle for Mac OS ARM64..."
APPLE_ARM64_TARGET="scrypt-kdf-${VERSION}-osx-arm64.tgz"
APPLE_ARM64_TARGET_SIG=${APPLE_ARM64_TARGET}.sig
APPLE_ARM64_RELEASE="target/${APPLE_ARM64_TARGET}"
APPLE_ARM64_RELEASE_SIG=${APPLE_ARM64_RELEASE}.sig
tar zcvf ${APPLE_ARM64_RELEASE} target/aarch64-apple-darwin/release/scrypt-kdf
APPLE_ARM64_RELEASE_SHA512=$(shasum -a512 ${APPLE_ARM64_RELEASE})
gpg --output ${APPLE_ARM64_RELEASE_SIG} --detach-sig ${APPLE_ARM64_RELEASE}

echo "Creating v${VERSION} bundle for Mac OS x64..."
APPLE_X64_TARGET="scrypt-kdf-${VERSION}-osx-x64.tgz"
APPLE_X64_TARGET_SIG=${APPLE_X64_TARGET}.sig
APPLE_X64_RELEASE="target/${APPLE_X64_TARGET}"
APPLE_X64_RELEASE_SIG=${APPLE_X64_RELEASE}.sig
tar zcvf ${APPLE_X64_RELEASE} target/x86_64-apple-darwin/release/scrypt-kdf
APPLE_X64_RELEASE_SHA512=$(shasum -a512 ${APPLE_X64_RELEASE})
gpg --output ${APPLE_X64_RELEASE_SIG} --detach-sig ${APPLE_X64_RELEASE}

echo "Creating v${VERSION} bundle for Linux AMD64..."
LINUX_AMD64_TARGET="scrypt-kdf-${VERSION}-linux-amd64.tgz"
LINUX_AMD64_TARGET_SIG=${LINUX_AMD64_TARGET}.sig
LINUX_AMD64_RELEASE="target/${LINUX_AMD64_TARGET}"
LINUX_AMD64_RELEASE_SIG=${LINUX_AMD64_RELEASE}.sig
tar zcvf ${LINUX_AMD64_RELEASE} target/x86_64-unknown-linux-musl/release/scrypt-kdf
LINUX_AMD64_RELEASE_SHA512=$(shasum -a512 ${LINUX_AMD64_RELEASE})
gpg --output ${LINUX_AMD64_RELEASE_SIG} --detach-sig ${LINUX_AMD64_RELEASE}

echo "Creating v${VERSION} bundle for Windows x64..."
WINDOWS_X64_TARGET="scrypt-kdf-${VERSION}-windows-amd64.tgz"
WINDOWS_X64_TARGET_SIG=${WINDOWS_X64_TARGET}.sig
WINDOWS_X64_RELEASE="target/${WINDOWS_X64_TARGET}"
WINDOWS_X64_RELEASE_SIG=${WINDOWS_X64_RELEASE}.sig
tar zcvf ${WINDOWS_X64_RELEASE} target/x86_64-pc-windows-gnu/release/scrypt-kdf.exe
WINDOWS_X64_RELEASE_SHA512=$(shasum -a512 ${WINDOWS_X64_RELEASE})
gpg --output ${WINDOWS_X64_RELEASE_SIG} --detach-sig ${WINDOWS_X64_RELEASE}

RELEASE_NOTES="target/release.md"
echo "Preparing release notes..."

cat <<EOF >$RELEASE_NOTES
# Release Notes v${VERSION}

## Mac OS ARM64

Calculate the SHA512:

\`\`\`sh
shasum -a512 ${APPLE_ARM64_RELEASE} ${APPLE_ARM64_RELEASE_SHA512}
\`\`\`

Verify the digital signature:

\`\`\`sh
gpg --verify ${APPLE_ARM64_TARGET_SIG} ${APPLE_ARM64_TARGET}
\`\`\`

## Mac OS x64

Calculate the SHA512:

\`\`\`sh
shasum -a512 ${APPLE_X64_RELEASE} ${APPLE_X64_RELEASE_SHA512}
\`\`\`

Verify the digital signature:

\`\`\`sh
gpg --verify ${APPLE_X64_TARGET_SIG} ${APPLE_X64_TARGET}
\`\`\`

## Linux AMD64

Calculate the SHA512:

\`\`\`sh
shasum -a512 ${LINUX_AMD64_RELEASE} ${LINUX_AMD64_RELEASE_SHA512}
\`\`\`

Verify the digital signature:

\`\`\`sh
gpg --verify ${LINUX_AMD64_TARGET_SIG} ${LINUX_AMD64_TARGET}
\`\`\`

## Windows x64

Calculate the SHA512:

\`\`\`sh
shasum -a512 ${WINDOWS_X64_RELEASE} ${WINDOWS_X64_RELEASE_SHA512}
\`\`\`

Verify the digital signature:

\`\`\`sh
gpg --verify ${WINDOWS_X64_TARGET_SIG} ${WINDOWS_X64_TARGET}
\`\`\`

EOF
