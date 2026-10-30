#!/usr/bin/env python3
"""test_c2_per_system_probe.py — 第七把 guard 的离线围栏(零游戏、零 Windows API)。

围栏分三层:
  * 契约层:Entry/Stats 的尺寸与字段序、stats 行的键序、layout 六词 —— 直接读 Zig 源码,
    任何一边改了字面量都会红;
  * 判读层:`verdict` 的十二档、容器解码、meta/artifact;
  * 门序层:安装码表、drain 容量、路径与命令通道的拒绝。

Task 3 先建契约层的两条;判读层在 Task 4 长全。
"""
from __future__ import annotations

import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_entry_size_matches_the_zig_module():
    src = (REPO_ROOT / "src/dll/c2/per_system_probe.zig").read_text()
    assert "@sizeOf(Entry) != 32" in src   # comptime 断言在源码里
    assert "@sizeOf(Stats) != 56" in src


def test_the_eight_exports_exist_in_the_zig_source():
    src = (REPO_ROOT / "src/dll/exports.zig").read_text()
    for name in ("C5PerSystemInstall", "C5PerSystemUninstall", "C5PerSystemVerify",
                 "C5PerSystemLayout", "C5PerSystemStatsInto", "C5PerSystemSetDrainCap",
                 "C5PerSystemDrainInto", "C5PerSystemReset"):
        assert f"export fn {name}" in src, f"missing export fn {name}"
