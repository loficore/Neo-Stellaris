"""Runtime JS SDK 合同围栏：`sdk/api.def` ↔ `src/dll/c2/neo_js_host.zig`。

Phase 1 的 native 名字是冻结合同。TS 包、Zig host 和 mock host 三边只要有一边
改名/少一个，构建期检查就会绿着跑错 API。这里只做纯文本/JSON 检查，不起进程。

Phase 2 的两条 track 分开落地（Track B 先加声明，Track A 再实现），所以围栏允许
`PENDING_HOST` 里的名字暂时只有 `api.def` 一侧；除这些之外 host 必须逐项同序实现。
`ADDITIVE` 同时钉住追加尾部的**顺序**（v1 七项之后：neighbors → set_flag →
has_flag），A2 实现时若插错位置这里会指出来。C1 清空 `PENDING_HOST`、把最后一条
改成 `FROZEN_V1 + ADDITIVE` 全等，即恢复 phase 1 的强度。
"""
import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
API_DEF = REPO / "sdk/api.def"
HOST = REPO / "src/dll/c2/neo_js_host.zig"
RUNTIME = REPO / "sdk/src/runtime.ts"

NAME_RE = re.compile(r'\.name = "(__neo_[a-z_]+)"')

# v1.1 的追加尾部：`api.def` 已声明，A2 尚未实现（本分支的 host 仍是 v1 的七项）。
ADDITIVE = [
    "__neo_system_neighbors",
    "__neo_system_set_flag",
    "__neo_system_has_flag",
]
PENDING_HOST = set(ADDITIVE)

# v1 的七个名字：哪怕有 pending，它们的相对顺序也不许动（旧 bundle 按位置无关，
# 但 host 的 NATIVE_FUNCTIONS 与 api.def 同序是「逐项同序」这条规则的本体）。
FROZEN_V1 = [
    "__neo_register_system",
    "__neo_system_degree",
    "__neo_system_set_var",
    "__neo_graph_betweenness",
    "__neo_graph_is_chokepoint",
    "__neo_log",
    "__neo_api_version",
]


def api_names():
    data = json.loads(API_DEF.read_text(encoding="utf-8"))
    assert data["version"] == 1
    return [fn["name"] for fn in data["functions"]]


def host_names():
    return NAME_RE.findall(HOST.read_text(encoding="utf-8"))


def test_api_def_and_host_native_names_match_in_order():
    declared = api_names()
    implemented = [name for name in declared if name not in PENDING_HOST]
    assert implemented == host_names()
    # A pending name that is no longer declared is a stale exception, not slack.
    assert [name for name in PENDING_HOST if name not in declared] == []


def test_v1_is_the_head_and_the_additive_tail_keeps_host_order():
    names = api_names()
    assert [name for name in names if name not in PENDING_HOST] == FROZEN_V1
    assert [name for name in names if name in PENDING_HOST] == ADDITIVE
    assert names[: len(FROZEN_V1)] == FROZEN_V1
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
