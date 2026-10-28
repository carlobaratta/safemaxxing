# PyInstaller spec for the standalone `safemaxxing` binary (one per architecture).
#
# Build:  uv run pyinstaller --clean --noconfirm packaging/safemaxxing.spec
# Output: dist/safemaxxing/ (a onedir bundle: the binary plus _internal/ dylibs). onedir, not
# onefile, so every Mach-O can be signed for notarization -- a onefile unpacks unsigned files
# at runtime and Gatekeeper rejects it. The host architecture is used, so CI builds arm64 on
# Apple Silicon and x86_64 on Intel and ships both.

import os

from PyInstaller.utils.hooks import collect_all, collect_submodules

root = os.path.dirname(os.path.dirname(os.path.abspath(SPEC)))

# Textual ships its own stylesheets and widgets as package data and loads widgets dynamically.
datas, binaries, hiddenimports = collect_all("textual")
# safemaxxing's own Textual stylesheet, loaded via `CSS_PATH = "safemaxxing.tcss"` relative to
# the tui package, so it must sit at the same path inside the bundle.
datas += [(os.path.join(root, "src/safemaxxing/tui/safemaxxing.tcss"), "safemaxxing/tui")]
hiddenimports += collect_submodules("safemaxxing")

a = Analysis(
    [os.path.join(root, "packaging/entrypoint.py")],
    pathex=[os.path.join(root, "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="safemaxxing",
    console=True,
    strip=False,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="safemaxxing")
