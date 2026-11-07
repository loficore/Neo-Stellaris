"""Runtime JS SDK 合同围栏：`sdk/api.def` ↔ `src/dll/c2/neo_js_host.zig`。

Phase 1 的 native 名字是冻结合同。TS 包、Zig host 和 mock host 三边只要有一边
改名/少一个，构建期检查就会绿着跑错 API。这里只做纯文本/JSON 检查，不起进程。
"""
import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
API_DEF = REPO / "sdk/api.def"
HOST = REPO / "src/dll/c2/neo_js_host.zig"
RUNTIME = REPO / "sdk/src/runtime.ts"

NAME_RE = re.compile(r'\.name = "(__neo_[a-z_]+)"')


def api_names():
    data = json.loads(API_DEF.read_text(encoding="utf-8"))
    assert data["version"] == 1
    return [fn["name"] for fn in data["functions"]]


def host_names():
    return NAME_RE.findall(HOST.read_text(encoding="utf-8"))


def test_api_def_and_host_native_names_match_in_order():
    assert api_names() == host_names()


def test_api_def_is_the_frozen_seven_function_v1():
    names = api_names()
    assert len(names) == 7
    assert names[0] == "__neo_register_system"
    assert names[-1] == "__neo_api_version"


def test_ts_runtime_exports_the_frozen_surface():
    text = RUNTIME.read_text(encoding="utf-8")
    for needle in (
        "export const API_VERSION = 1;",
        "export function onSystem",
        "export const graph",
        "export function log",
        "export function apiVersion",
        "betweenness",
        "isChokepoint",
        "setVariable",
        "get degree",
    ):
        assert needle in text, needle
