#!/usr/bin/env python3
"""Preview-package builder: explicit manifest in, deterministic zip out.

Two properties are the whole point, and both are tested:

* **the manifest is explicit** — a missing file is a failure (exit 1), never a
  silent skip.  A package that is one DLL short ships and then confuses a
  player; a package that fails loudly ships nothing.
* **the zip is deterministic** — fixed 1980-01-01 timestamps, entries sorted by
  arcname, mode 0644, `ZIP_DEFLATED` at level 9.  The same tree produces the
  same bytes, which is what makes the accompanying `SHA256SUMS` meaningful.

Interpretation traps (old tool name: none — this file has always been
`pack_preview.py`):

* **A missing manifest entry is an error, not a skip.**  `--dll`/`--inject`
  default to `zig-out/bin/…`, which only exists after `zig build`; `sdk/dist`
  only exists after `cd sdk && npm ci && npm run build`.  Missing those is the
  normal "you have not built yet" case, and it fails with the path it wanted.
* **The hashes are over the bytes that went into the zip**, so `SHA256SUMS`
  cannot drift from the archive by a later rebuild of the same tree.
* **Changing the compression parameters or the timestamp changes the hashes.**
  Nothing here reads the clock; do not add a "build time" field.

Usage:
    python3 scripts/pack_preview.py --version 0.1.0-preview.1 --out dist
    python3 scripts/pack_preview.py --version 9.9.9 --dll X --inject Y \
        --root <tree> --out <dir>
"""

import argparse
import hashlib
import pathlib
import sys
import zipfile

REPO = pathlib.Path(__file__).resolve().parent.parent

#: Files that must exist, by path relative to ``--root``.  ``sdk/package-lock.json``
#: is here because the author flow documented on the site starts with
#: ``cd sdk && npm ci``; ``libs/quickjs/LICENSE`` because the DLL embeds QuickJS
#: and `THIRD-PARTY-NOTICES.md` promises that licence travels with the bytes.
REQUIRED_FILES = (
    "README.md",
    "LICENSE",
    "THIRD-PARTY-NOTICES.md",
    "sdk/api.def",
    "sdk/package.json",
    "sdk/package-lock.json",
    "libs/quickjs/LICENSE",
)

#: Directories copied wholesale (files only, one level of recursion), by path
#: relative to ``--root``.
REQUIRED_DIRS = (
    "sdk/src",
    "sdk/dist",
    "sdk/templates",
    "examples/neo_events",
    "examples/neo_opinion",
)

#: Generated at pack time from the docs site, not committed.
INSTALL_SOURCE = "site/guide/install.md"
INSTALL_ENTRY = "INSTALL.md"

DEFAULT_DLL = "zig-out/bin/stellaris_quickjs.dll"
DEFAULT_INJECT = "zig-out/bin/inject.exe"
DEFAULT_OUT = "dist"

ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

#: Build residue that must never reach the archive.  ``dist`` is skipped because
#: it is a *staging* tree inside a mod project; ``sdk/dist`` is a required
#: directory and is walked from itself, so its own top level is unaffected.
SKIP_PARTS = {"node_modules", ".vitepress", "__pycache__", "dist", ".git"}


def _write_entry(zf, arcname, data):
    info = zipfile.ZipInfo(arcname, ZIP_EPOCH)
    info.external_attr = (0o644 & 0xFFFF) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, data, compresslevel=9)


def _resolve(root, value):
    path = pathlib.Path(value)
    return path if path.is_absolute() else root / path


def _iter_dir_files(root, rel_dir):
    base = root / rel_dir
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(base)
        if any(part in SKIP_PARTS for part in rel.parts[:-1]):
            continue
        yield f"{rel_dir}/{rel.as_posix()}", path.read_bytes()


def collect(root, dll, inject, version):
    """Return ``(entries, missing)`` — ``entries`` is arcname -> bytes."""
    entries = {}
    missing = []

    for rel in REQUIRED_FILES:
        path = root / rel
        if path.is_file():
            entries[rel] = path.read_bytes()
        else:
            missing.append(rel)

    for rel in REQUIRED_DIRS:
        if (root / rel).is_dir():
            for arcname, data in _iter_dir_files(root, rel):
                entries[arcname] = data
        else:
            missing.append(rel + "/")

    for path in (dll, inject):
        if path.is_file():
            entries[path.name] = path.read_bytes()
        else:
            missing.append(str(path))

    install = root / INSTALL_SOURCE
    if install.is_file():
        header = f"<!-- preview {version} -->\n".encode()
        entries[INSTALL_ENTRY] = header + install.read_bytes()
    else:
        missing.append(INSTALL_SOURCE)

    return entries, missing


def write_zip(zip_path, entries):
    with zipfile.ZipFile(zip_path, "w") as zf:
        for arcname in sorted(entries):
            _write_entry(zf, arcname, entries[arcname])


def write_sums(sums_path, binaries, zip_path):
    lines = [(hashlib.sha256(data).hexdigest(), name)
             for name, data in binaries.items()]
    lines.append((hashlib.sha256(zip_path.read_bytes()).hexdigest(), zip_path.name))
    body = "".join(f"{digest}  {name}\n"
                   for digest, name in sorted(lines, key=lambda item: item[1]))
    sums_path.write_text(body, encoding="utf-8")


def build(root, dll, inject, out_dir, version):
    """Assemble the package; returns the zip path, or ``None`` if the manifest is short."""
    entries, missing = collect(root, dll, inject, version)
    if missing:
        print("pack_preview: missing from the manifest:", file=sys.stderr)
        for item in missing:
            print(f"  {item}", file=sys.stderr)
        return None

    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"neo-stellaris-preview-{version}.zip"
    sums_path = out_dir / "SHA256SUMS"
    for stale in (zip_path, sums_path):
        if stale.exists():
            stale.unlink()

    write_zip(zip_path, entries)
    # Only the two binaries and the archive itself are hashed: they are what a
    # player copies out of the package.  Everything else is checked by the zip.
    binaries = {name: data for name, data in entries.items()
                if name in (dll.name, inject.name)}
    write_sums(sums_path, binaries, zip_path)
    return zip_path


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True,
                        help="打包版本;必须与 tag 一致(v0.1.0-preview.1 -> 0.1.0-preview.1)")
    parser.add_argument("--dll", default=DEFAULT_DLL,
                        help=f"注入宿主 DLL(默认 {DEFAULT_DLL},相对 --root)")
    parser.add_argument("--inject", default=DEFAULT_INJECT,
                        help=f"注入器可执行文件(默认 {DEFAULT_INJECT},相对 --root)")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help=f"输出目录(默认 {DEFAULT_OUT},相对 --root)")
    parser.add_argument("--root", default=str(REPO),
                        help="清单的根目录(默认本仓库根)")
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root).resolve()
    out_dir = _resolve(root, args.out)
    version = args.version.strip()
    if not version or "/" in version or "\\" in version:
        print(f"pack_preview: invalid --version {args.version!r}", file=sys.stderr)
        return 1

    zip_path = build(root, _resolve(root, args.dll), _resolve(root, args.inject),
                     out_dir, version)
    if zip_path is None:
        return 1
    print(f"PREVIEW_PACK ok zip={zip_path} version={version}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
