"""test_c2_neo_state_exports.py — C5-WRITE 的导出/键序围栏(零游戏、零 Windows)。

驱动 `c2_boot_inject.py` 要能选「只写日志」还是「日志 + 写系统变量」,stats 行要能
分开读 `writes` 与 `skipped` —— 前者是「我们调了官方 body」,后者是「body 地址没解析到」。
这三条都是字节层的契约,能在 Linux 上判;真跑留给实机窗口。
"""
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent


def test_set_act_export_exists():
    src = (REPO / "src/dll/exports.zig").read_text(encoding="utf-8")
    assert "export fn C2NeoSetAct" in src


def test_set_act_is_listed_in_the_drivers_needed_tuple():
    src = (REPO / "scripts/c2_boot_inject.py").read_text(encoding="utf-8")
    assert '"C2NeoSetAct"' in src.split("NEEDED = (", 1)[1].split(")", 1)[0]


def test_stats_line_orders_the_write_counters():
    src = (REPO / "src/dll/c2/neo_dispatch.zig").read_text(encoding="utf-8")
    body = src.split("fn statsInto", 1)[1]
    assert body.index("writes={d}") < body.index("skipped={d}")


def test_the_driver_exposes_act_log_and_write():
    src = (REPO / "scripts/c2_boot_inject.py").read_text(encoding="utf-8")
    assert '"--act"' in src
    assert '"log"' in src and '"write"' in src


def test_the_export_documents_the_action_codes():
    src = (REPO / "src/dll/exports.zig").read_text(encoding="utf-8")
    block = src.split("export fn C2NeoSetAct", 1)[1].split("}", 1)[0]
    assert "c2_neo_vtable.setAct" in block


# --- Part A Task 4: verify 通路的两个计数 -------------------------------------


def test_verify_stats_export_exists():
    src = (REPO / "src/dll/exports.zig").read_text(encoding="utf-8")
    assert "export fn C2NeoVerifyStatsInto" in src


def test_verify_stats_is_listed_in_the_drivers_needed_tuple():
    src = (REPO / "scripts/c2_boot_inject.py").read_text(encoding="utf-8")
    assert '"C2NeoVerifyStatsInto"' in src.split("NEEDED = (", 1)[1].split(")", 1)[0]


def test_the_verify_line_prints_both_counters_in_order():
    src = (REPO / "scripts/c2_boot_inject.py").read_text(encoding="utf-8")
    body = src.split("def verify_line", 1)[1]
    assert body.index("verified={") < body.index("verify_failed={")
