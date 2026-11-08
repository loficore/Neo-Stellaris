"""Runtime JS SDK 合同围栏：`sdk/api.def` ↔ `src/dll/c2/neo_js_host.zig`。

Phase 1 的 native 名字是冻结合同。TS 包、Zig host 和 mock host 三边只要有一边
改名/少一个，构建期检查就会绿着跑错 API。这里只做纯文本/JSON 检查，不起进程。

Phase 2 的 v1.1 是**加法**：`api.def` 的头部仍是 v1 的七项，之后按 host 的注册顺序
追加（neighbors → set_flag → has_flag → register_country → country_opinion →
country_their_opinion）。围栏读 host 的两张表——冻结的
`native_table`（`.name =`）与加法的 `additive_native_table`（`.js_name =`）——
要求 `api.def == FROZEN_V1 + ADDITIVE`，且两侧逐项同序。

Phase 2 并行期间曾有 `PENDING_HOST` 允许声明先于实现；C1 合并后已清空，
本文件恢复「全等」强度（见 `test_api_def_and_host_native_names_match_in_order`）。
"""
import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
API_DEF = REPO / "sdk/api.def"
HOST = REPO / "src/dll/c2/neo_js_host.zig"
RUNTIME = REPO / "sdk/src/runtime.ts"

CONTRACT_RE = re.compile(r'\.name = "(__neo_[a-z_]+)"')
ADDITIVE_RE = re.compile(r'\.js_name = "(__neo_[a-z_]+)"')

# v1 的七个名字：头部顺序被钉死。
FROZEN_V1 = [
    "__neo_register_system",
    "__neo_system_degree",
    "__neo_system_set_var",
    "__neo_graph_betweenness",
    "__neo_graph_is_chokepoint",
    "__neo_log",
    "__neo_api_version",
]

# v1.1 的追加尾部：顺序同样被钉死（v1 七项之后）。
ADDITIVE = [
    "__neo_system_neighbors",
    "__neo_system_set_flag",
    "__neo_system_has_flag",
    "__neo_register_country",
    "__neo_country_opinion",
    "__neo_country_their_opinion",
]


def api_names():
    data = json.loads(API_DEF.read_text(encoding="utf-8"))
    assert data["version"] == 1
    return [fn["name"] for fn in data["functions"]]


def host_names():
    """host 的两张表：冻结七项 + 加法三项，按各自的注册顺序。"""
    text = HOST.read_text(encoding="utf-8")
    return CONTRACT_RE.findall(text), ADDITIVE_RE.findall(text)


def test_api_def_and_host_native_names_match_in_order():
    declared = api_names()
    contract, additive = host_names()
    assert contract == FROZEN_V1
    assert additive == ADDITIVE
    assert declared == contract + additive


def test_v1_is_the_head_and_the_additive_tail_keeps_host_order():
    names = api_names()
    assert names[: len(FROZEN_V1)] == FROZEN_V1
    assert names[len(FROZEN_V1) :] == ADDITIVE
    assert len(set(names)) == len(names)


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
        "get neighbors",
        "setStarFlag",
        "hasStarFlag",
    ):
        assert needle in text, needle
