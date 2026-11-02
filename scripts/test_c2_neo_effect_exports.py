"""test_c2_neo_effect_exports.py — C5-ADD 的导出契约围栏(零游戏、零 Windows API)。

契约来自 spec `docs/superpowers/specs/2026-11-02-c5-add-effect-keyword-design.md` 与
plan 的 Task 2 Interfaces:四个导出、一个固定的 stats 键序、以及 `neoAction` 的
实现槽位。驱动(`scripts/c2_boot_inject.py`)与 §93 的读数都照这些字面量解析,
任何一边改了都会红。
"""
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
EXPORTS = REPO / "src/dll/exports.zig"
NEO_DISPATCH = REPO / "src/dll/c2/neo_dispatch.zig"

STATS_KEYS = (
    "calls",
    "matched",
    "log_calls",
    "last_id",
    "rule_hits",
    "installed",
    "verify",
)


def test_the_four_exports_exist_in_the_zig_source():
    src = EXPORTS.read_text(encoding="utf-8")
    for name in ("C2NeoInstall", "C2NeoUninstall", "C2NeoVerify", "C2NeoStatsInto"):
        assert f"export fn {name}" in src


def test_the_stats_line_keeps_the_drivers_key_order():
    src = NEO_DISPATCH.read_text(encoding="utf-8")
    body = src.split("fn statsInto", 1)[1]
    # The driver splits on '=' and ' '; a reordered line would silently relabel
    # every column of §93, so the order is pinned, not just the key set.
    positions = [body.index(f"{key}={{d}}") for key in STATS_KEYS + ("dispatched", "null_scope", "mask_odd")]
    assert positions == sorted(positions)
