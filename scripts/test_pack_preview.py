"""Fences for `scripts/pack_preview.py` (the developer-preview builder).

Three properties, each one a way the package has actually failed or could fail
silently:

* a short manifest must fail loudly instead of producing a package that is one
  file short (exit 1, no zip written);
* two runs over the same tree must produce byte-identical zips — otherwise
  `SHA256SUMS` is decoration;
* `SHA256SUMS` must cover exactly the two binaries and the archive, sorted.

`_fake_tree` builds every path the manifest names, so a test that wants a
failure asks for exactly one of them to be absent.
"""
import hashlib
import pathlib
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pack_preview

VERSION = "9.9.9"
ZIP_NAME = f"neo-stellaris-preview-{VERSION}.zip"


def _fake_tree(tmp_path, skip=None):
    """Materialise the manifest under ``tmp_path/root``; ``skip`` omits one path."""
    root = tmp_path / "root"
    root.mkdir()

    for rel in pack_preview.REQUIRED_FILES:
        if skip == rel:
            continue
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"contents of {rel}\n".encode())

    for rel in pack_preview.REQUIRED_DIRS:
        path = root / rel
        path.mkdir(parents=True, exist_ok=True)
        (path / "example.txt").write_bytes(f"contents of {rel}\n".encode())

    if skip != pack_preview.INSTALL_SOURCE:
        install = root / pack_preview.INSTALL_SOURCE
        install.parent.mkdir(parents=True, exist_ok=True)
        install.write_bytes(b"# Install\n")

    dll = root / "zig-out" / "bin" / "stellaris_quickjs.dll"
    dll.parent.mkdir(parents=True, exist_ok=True)
    dll.write_bytes(b"MZ fake dll\n")
    inject = root / "zig-out" / "bin" / "inject.exe"
    inject.write_bytes(b"MZ fake injector\n")

    out = tmp_path / "out"
    return {"root": str(root), "dll": str(dll), "inject": str(inject), "out": str(out)}


def _args(tree, version=VERSION):
    return ["--version", version, "--dll", tree["dll"], "--inject", tree["inject"],
            "--root", tree["root"], "--out", tree["out"]]


def test_missing_manifest_file_fails(tmp_path, capsys):
    # 只建一半树：LICENSE 故意不建
    tree = _fake_tree(tmp_path, skip="LICENSE")
    rc = pack_preview.main(_args(tree))
    assert rc == 1
    assert "LICENSE" in capsys.readouterr().err
    assert not list(pathlib.Path(tree["out"]).glob("*.zip"))


def test_missing_install_source_fails(tmp_path, capsys):
    tree = _fake_tree(tmp_path, skip=pack_preview.INSTALL_SOURCE)
    rc = pack_preview.main(_args(tree))
    assert rc == 1
    assert pack_preview.INSTALL_SOURCE in capsys.readouterr().err
    assert not list(pathlib.Path(tree["out"]).glob("*.zip"))


def test_pack_is_deterministic(tmp_path):
    tree = _fake_tree(tmp_path)
    args = _args(tree)
    assert pack_preview.main(args) == 0
    first = (pathlib.Path(tree["out"]) / ZIP_NAME).read_bytes()
    assert pack_preview.main(args) == 0
    second = (pathlib.Path(tree["out"]) / ZIP_NAME).read_bytes()
    assert hashlib.sha256(first).digest() == hashlib.sha256(second).digest()


def test_sha256sums_lists_three_entries(tmp_path):
    tree = _fake_tree(tmp_path)
    assert pack_preview.main(_args(tree)) == 0
    lines = (pathlib.Path(tree["out"]) / "SHA256SUMS").read_text().splitlines()
    assert [line.split("  ")[1] for line in lines] == [
        "inject.exe", ZIP_NAME, "stellaris_quickjs.dll"]


def test_install_md_carries_the_version(tmp_path):
    tree = _fake_tree(tmp_path)
    assert pack_preview.main(_args(tree)) == 0
    with zipfile.ZipFile(pathlib.Path(tree["out"]) / ZIP_NAME) as zf:
        names = zf.namelist()
        assert pack_preview.INSTALL_ENTRY in names
        assert zf.read(pack_preview.INSTALL_ENTRY).startswith(
            f"<!-- preview {VERSION} -->".encode())


def test_zip_entries_are_sorted_and_stamped(tmp_path):
    tree = _fake_tree(tmp_path)
    assert pack_preview.main(_args(tree)) == 0
    with zipfile.ZipFile(pathlib.Path(tree["out"]) / ZIP_NAME) as zf:
        infos = zf.infolist()
    names = [info.filename for info in infos]
    assert names == sorted(names)
    assert {info.date_time for info in infos} == {pack_preview.ZIP_EPOCH}
    assert {info.compress_type for info in infos} == {zipfile.ZIP_DEFLATED}


def test_the_flag_gate_table_ships(tmp_path):
    """`neo check`'s flag-name gate reads the keyword TSV from the package root.

    Without it, an unpacked package cannot check any bundle that writes a star
    flag — the check fails with the path it looked for.
    """
    tree = _fake_tree(tmp_path)
    assert pack_preview.main(_args(tree)) == 0
    with zipfile.ZipFile(pathlib.Path(tree["out"]) / ZIP_NAME) as zf:
        names = zf.namelist()
    assert "evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv" in names
