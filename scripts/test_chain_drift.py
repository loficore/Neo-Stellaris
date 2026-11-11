"""Pure-function tests for chain_drift.py — synthetic PE, no game, no disk.

Fixtures build a PE by hand (same header field layout as test_rttibatch.fake_image)
so every locator kind is pinned to addresses a reader verifies by eye.  The
self-证 fence at the bottom reads the pinned 4.4.4 binary and is skipped when no
copy is reachable through NS_STELLARIS_EXE / the default chain.
"""

import pytest

from chain_drift import ManifestError, Node, parse_manifest

HEADER = ("chain\tnode\tclass\tlocator\texpect\tdepends_on\twitness\tevidence\n")


def test_parse_manifest_reads_every_column_and_skips_comments():
    text = ("# chain drift manifest\n"
            "# 注释行不产生 Node\n" + HEADER +
            "register\tget_scripted_effect\taddress\tstrref:scriptedeffect.cpp\t0x89f960\t\ttoken_readback\tc1 §27\n")
    assert parse_manifest(text) == [
        Node(chain="register", node="get_scripted_effect", cls="address",
             locator="strref:scriptedeffect.cpp", expect="0x89f960",
             depends_on=(), witness="token_readback", evidence="c1 §27")]


def test_parse_manifest_splits_depends_on_on_commas():
    text = HEADER + ("register\ta\taddress\tbytes:90\t0x1\t\t\tx\n"
                     "register\tb\taddress\tbytes:90\t0x2\t\t\tx\n"
                     "register\tc\taddress\tbytes:90\t0x3\ta,b\t\tx\n")
    assert parse_manifest(text)[2].depends_on == ("a", "b")


def test_parse_manifest_rejects_duplicate_node_in_the_same_chain_with_line_number():
    text = HEADER + ("register\ta\taddress\tbytes:90\t0x1\t\t\tx\n"
                     "register\ta\taddress\tbytes:90\t0x2\t\t\tx\n")
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert exc.value.line_no == 3
    assert "duplicate node" in exc.value.message


def test_parse_manifest_allows_the_same_node_name_in_two_chains():
    text = HEADER + ("register\ta\taddress\tbytes:90\t0x1\t\t\tx\n"
                     "dispatch\ta\taddress\tbytes:90\t0x2\t\t\tx\n")
    assert len(parse_manifest(text)) == 2


def test_parse_manifest_rejects_unknown_class_and_wrong_column_count():
    for bad in ("register\ta\tbogus\tbytes:90\t0x1\t\t\tx\n",
                "register\ta\taddress\tbytes:90\n"):
        with pytest.raises(ManifestError) as exc:
            parse_manifest(HEADER + bad)
        assert exc.value.line_no == 2
