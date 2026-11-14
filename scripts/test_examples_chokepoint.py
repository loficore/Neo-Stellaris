"""`examples/chokepoint/mod/` 的文本围栏:外壳必须能直接装,且名字与目录对得上。

只钉两件事(计划 Review Focus:围栏不要锁死实现):
  1. `descriptor.mod` 的 `path=` 与目录同名(`mod/neo_chokepoint`);
  2. 事件文件真的用我们的 effect(`neo_action`)并且落两个官方 flag。
文件全文、注释、flag 的具体名字都不钉 —— 那些是会随每一发改的。
"""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "examples/chokepoint/mod"


def test_the_descriptor_path_matches_the_directory_name():
    text = (ROOT / "descriptor.mod").read_text(encoding="utf-8")
    assert 'path="mod/neo_chokepoint"' in text


def test_the_event_uses_our_effect_and_two_star_flags():
    text = (ROOT / "events/neo_chokepoint_events.txt").read_text(encoding="utf-8")
    assert "neo_action = { }" in text
    assert "check_variable" in text
    assert text.count("set_star_flag") == 2
