#!/usr/bin/env bash
# Build, sign and package the standalone `safemaxxing` binary for the host architecture.
#
# Produces, under dist/:
#   safemaxxing-<version>-<arch>.tar.gz   the onedir bundle (what the Homebrew formula installs)
#   safemaxxing-<version>-<arch>.pkg      a signed installer (notarised and stapled by the caller)
#
# Code signing runs only when SIGN_IDENTITY is set, and the .pkg is built only when
# INSTALLER_IDENTITY is set, so the build and tarball steps also run locally without a
# Developer ID. The signing identities must already be in the default keychain (the release
# workflow imports them into an ephemeral one). Notarisation and stapling are the caller's job:
# they need App Store Connect credentials and apply to the .pkg.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' src/safemaxxing/__init__.py)"
arch="$(uname -m)"
entitlements="packaging/entitlements.plist"
identifier="com.github.carlobaratta.safemaxxing"
bundle="dist/safemaxxing"
tarball="dist/safemaxxing-${version}-${arch}.tar.gz"
pkg="dist/safemaxxing-${version}-${arch}.pkg"

echo "==> Building safemaxxing ${version} (${arch})"
uv run pyinstaller --clean --noconfirm packaging/safemaxxing.spec

if [[ -n "${SIGN_IDENTITY:-}" ]]; then
    echo "==> Code signing with hardened runtime"
    # Every embedded Mach-O must be signed before the main executable, inner ones first.
    find "$bundle" -type f \( -name "*.so" -o -name "*.dylib" \) -print0 \
        | while IFS= read -r -d '' lib; do
            codesign --force --options runtime --timestamp \
                --entitlements "$entitlements" --sign "$SIGN_IDENTITY" "$lib"
        done
    codesign --force --options runtime --timestamp \
        --entitlements "$entitlements" --sign "$SIGN_IDENTITY" "$bundle/safemaxxing"
    codesign --verify --deep --strict --verbose=2 "$bundle/safemaxxing"
else
    echo "==> SIGN_IDENTITY unset: skipping code signing (unsigned build)"
fi

echo "==> Creating ${tarball}"
tar -C dist -czf "$tarball" safemaxxing

if [[ -n "${INSTALLER_IDENTITY:-}" ]]; then
    echo "==> Building signed installer ${pkg}"
    stage="$(mktemp -d)"
    trap 'rm -rf "$stage"' EXIT
    install -d "$stage/payload/usr/local/libexec" "$stage/scripts"
    cp -R "$bundle" "$stage/payload/usr/local/libexec/safemaxxing"
    cat > "$stage/scripts/postinstall" <<'POST'
#!/bin/bash
set -e
mkdir -p /usr/local/bin
ln -sf /usr/local/libexec/safemaxxing/safemaxxing /usr/local/bin/safemaxxing
POST
    chmod +x "$stage/scripts/postinstall"
    pkgbuild --root "$stage/payload" --scripts "$stage/scripts" \
        --identifier "$identifier" --version "$version" --install-location / \
        --sign "$INSTALLER_IDENTITY" --timestamp "$pkg"
else
    echo "==> INSTALLER_IDENTITY unset: skipping .pkg build"
fi

echo "==> Done: $(ls -1 dist/safemaxxing-${version}-${arch}.* 2>/dev/null | tr '\n' ' ')"
