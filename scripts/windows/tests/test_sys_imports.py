"""The gate's refusal path must be able to *say* why it refused.

2026-10-29: `world_probe.py` printed the refusal with `file=sys.stderr` but never
imported `sys`, so a refusal died with `NameError: name 'sys' is not defined`
instead of the reason — and the shot driver showed a traceback rather than the
premise it had failed on.  The reason is the whole point of the gate, so this is
pinned for every module of the family, not just that one file.
"""
import ast
import pathlib

WINDOWS_DIR = pathlib.Path(__file__).resolve().parent.parent


def _imports_sys(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == "sys" for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module == "sys":
                return True
    return False


def test_every_windows_module_that_uses_sys_imports_it():
    offenders = []
    for path in sorted(WINDOWS_DIR.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        if "sys." not in source:
            continue
        if not _imports_sys(ast.parse(source)):
            offenders.append(path.name)
    assert not offenders, f"these modules use sys. without importing it: {offenders}"
