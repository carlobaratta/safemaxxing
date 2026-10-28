# Packaging & release

Builds a standalone, signed, notarized `safemaxxing` for macOS (one build per architecture)
and ships it via a GitHub release and a Homebrew tap.

## Pieces

| File | Role |
| --- | --- |
| `entrypoint.py` | PyInstaller entry point: runs the Typer CLI. |
| `safemaxxing.spec` | PyInstaller spec, onedir, host architecture (bundles Textual + its `.tcss` and psutil). |
| `entitlements.plist` | Hardened-runtime entitlements needed to notarize a Python build. |
| `build_release.sh` | Build → codesign → tarball → signed `.pkg`. |
| `../.github/workflows/release.yml` | Test matrix, keychain import, build, notarize, staple, publish. |
| `../Formula/safemaxxing.rb` | Homebrew formula (lives in the tap repo); installs the release tarball, with a `brew services` block. |

## Build locally (unsigned)

```sh
uv sync
uv pip install pyinstaller
./packaging/build_release.sh        # dist/safemaxxing-<version>-<arch>.tar.gz
```

With `SIGN_IDENTITY` (and `INSTALLER_IDENTITY`) set and the matching Developer ID keys in the
keychain, the same script signs the bundle and builds the `.pkg`.

## Release flow

Tag `vX.Y.Z` and push: `release.yml` runs the full gate on `macos-latest` and `macos-15-intel`
(Python 3.12/3.13), then on each architecture builds, signs with the hardened runtime,
packages a `.pkg`, submits it to Apple with `notarytool submit --wait`, staples the ticket, and
attaches the per-arch tarballs and `.pkg`s to the GitHub release. Update the tap's formula with
the version and the SHA-256s the build job prints to the run summary.

## Required repository secrets

| Secret | What |
| --- | --- |
| `MACOS_CERTIFICATE_P12` | base64 of the Developer ID Application **and** Installer certs (`.p12`). |
| `MACOS_CERTIFICATE_PASSWORD` | password for that `.p12`. |
| `KEYCHAIN_PASSWORD` | any password for the ephemeral build keychain. |
| `MACOS_SIGN_IDENTITY` | `Developer ID Application: Name (TEAMID)`. |
| `MACOS_INSTALLER_IDENTITY` | `Developer ID Installer: Name (TEAMID)`. |
| `AC_API_KEY_ID`, `AC_API_ISSUER_ID`, `AC_API_PRIVATE_KEY` | App Store Connect API key for `notarytool`. |

## Verified vs. not

- **Verified on macOS 27 (arm64):** the PyInstaller spec builds and the frozen binary runs
  (`version`, `--help`, `doctor` — psutil and the bundled `.tcss` load); `build_release.sh`
  builds and tars end to end unsigned; `entitlements.plist` passes `plutil -lint`;
  `release.yml` is valid YAML; `safemaxxing.rb` passes `ruby -c`.
- **Not verified here (needs a Developer ID and Apple credentials):** code signing,
  `.pkg` creation, notarization and stapling, and the end-to-end Actions run. These follow
  Apple's documented flow but should be dry-run on a real signing setup before the first tag.
