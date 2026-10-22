"""Contract tests for ``scripts/save_hypergraph.py`` — save file -> hyperlane graph.

Every fixture here is a synthetic ZIP written into ``tmp_path``.  The real 4.4.4
save never enters the repository and is not needed to test the parser.

The tests pin the five input classes from the plan's Review Focus: text vs binary
``gamestate``, escaping/comments, repeated keys, anonymous blocks, and the graph
invariants (asymmetry and length conflicts are hard errors; self-loops are counted
and excluded).
"""
import pathlib
import sys
import zipfile

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import save_hypergraph
from save_hypergraph import Block, extract_hypergraph, parse_clausewitz, read_gamestate

GAMESTATE = '''version="Pegasus v4.4.4"
galactic_object=
{
\t0=
\t{
\t\tname={ key="A" }
\t\thyperlane=
\t\t{
\t\t\t{ to=1 length=10 }
\t\t}
\t}
\t1=
\t{
\t\tname={ key="B" }
\t\thyperlane=
\t\t{
\t\t\t{ to=0 length=10 }
\t\t\t{ to=2 length=5 }
\t\t}
\t}
\t2=
\t{
\t\tname={ key="C" }
\t\thyperlane=
\t\t{
\t\t\t{ to=1 length=5 }
\t\t}
\t}
}
'''


def _save(tmp_path, payload, name="mini.sav", entry="gamestate"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(entry, payload)
    return path


def _graph(text=GAMESTATE):
    return extract_hypergraph(parse_clausewitz(text))


def test_read_gamestate_from_zip(tmp_path):
    text, replacements = read_gamestate(_save(tmp_path, GAMESTATE))
    assert text.startswith('version="Pegasus v4.4.4"')
    assert replacements == 0

    broken = GAMESTATE.encode("utf-8").replace(b'key="A"', b'key="A\xff"')
    text, replacements = read_gamestate(_save(tmp_path, broken, name="broken.sav"))
    assert replacements == 1
    assert "\ufffd" in text


def test_parse_quoted_strings_and_comments():
    root = parse_clausewitz(
        'name="a b \\"c\\"" # note "ignored"\n'
        "planet=162\n"
        'required_dlcs=\n{\n\t"Horizon Signal"\n}\n'
    )
    assert [(key, value) for key, value in root.entries if key == "name"] == [
        ("name", 'a b "c"')
    ]
    assert ("planet", "162") in root.entries
    dlcs = [value for key, value in root.entries if key == "required_dlcs"][0]
    assert dlcs.entries == [(None, "Horizon Signal")]


def test_parse_repeated_keys_preserved():
    root = parse_clausewitz("planet=162\nplanet=163\n")
    assert [value for key, value in root.entries if key == "planet"] == ["162", "163"]


def test_parse_anonymous_blocks():
    root = parse_clausewitz("hyperlane={ { to=0 length=1 } { to=1 length=2 } }")
    hyperlane = [value for key, value in root.entries if key == "hyperlane"][0]
    assert isinstance(hyperlane, Block)
    anonymous = [value for key, value in hyperlane.entries if key is None]
    assert len(anonymous) == 2
    assert all(isinstance(block, Block) for block in anonymous)
    assert dict(anonymous[0].entries) == {"to": "0", "length": "1"}
    assert dict(anonymous[1].entries) == {"to": "1", "length": "2"}


def test_extract_hypergraph_from_synthetic_save(tmp_path):
    text, replacements = read_gamestate(_save(tmp_path, GAMESTATE))
    adjacency, stats = extract_hypergraph(parse_clausewitz(text), replacements)
    assert adjacency == {0: {1: 10.0}, 1: {0: 10.0, 2: 5.0}, 2: {1: 5.0}}
    assert stats["systems"] == 3
    assert stats["directed_entries"] == 4
    assert stats["undirected_edges"] == 2
    assert stats["components"] == 1
    assert stats["isolates"] == 0
    assert stats["self_loops"] == 0
    assert stats["asymmetric_edges"] == 0
    assert stats["conflicting_edges"] == 0
    assert stats["replacement_chars"] == 0

    empty = parse_clausewitz('version="Pegasus v4.4.4"\ngalactic_object=\n{\n}\n')
    with pytest.raises(ValueError, match="empty hyperlane graph"):
        extract_hypergraph(empty)


def test_asymmetric_edge_is_hard_error():
    text = GAMESTATE.replace("\t\t\t{ to=0 length=10 }\n", "")
    with pytest.raises(ValueError, match="asymmetric"):
        extract_hypergraph(parse_clausewitz(text))


def test_conflicting_lengths_is_hard_error():
    text = GAMESTATE.replace("{ to=0 length=10 }", "{ to=0 length=11 }")
    with pytest.raises(ValueError, match="length"):
        extract_hypergraph(parse_clausewitz(text))


def test_self_loop_counted_and_excluded():
    text = GAMESTATE.replace(
        "\t\t{\n\t\t\t{ to=1 length=10 }",
        "\t\t{\n\t\t\t{ to=0 length=1 }\n\t\t\t{ to=1 length=10 }",
        1,
    )
    text = text.replace(
        "\t\t\t{ to=1 length=10 }\n\t\t}",
        "\t\t\t{ to=1 length=10 }\n\t\t\t{ to=1 length=10 }\n\t\t}",
        1,
    )
    adjacency, stats = _graph(text)
    assert stats["self_loops"] == 1
    assert stats["duplicate_entries"] == 1
    assert adjacency[0] == {1: 10.0}


def test_binary_gamestate_is_hard_error(tmp_path):
    with pytest.raises(ValueError, match="binary"):
        read_gamestate(_save(tmp_path, b"\x00" * 64, name="binary.sav"))


def test_cli_rejects_non_zip(tmp_path, capsys):
    path = tmp_path / "not-a-zip.sav"
    path.write_bytes(b"definitely not a zip")
    with pytest.raises(SystemExit) as excinfo:
        save_hypergraph.main([str(path), "--edges", str(tmp_path / "out.tsv")])
    assert excinfo.value.code == 2
    assert capsys.readouterr().err.strip()


def test_cli_rejects_missing_gamestate(tmp_path, capsys):
    path = _save(tmp_path, "not the gamestate", name="meta-only.sav", entry="meta")
    with pytest.raises(SystemExit) as excinfo:
        save_hypergraph.main([str(path), "--edges", str(tmp_path / "out.tsv")])
    assert excinfo.value.code == 2
    assert capsys.readouterr().err.strip()

    isolated = (
        'version="Pegasus v4.4.4"\n'
        "galactic_object=\n{\n"
        "\t0=\n\t{\n\t\thyperlane={ { to=1 length=1 } }\n\t}\n"
        "\t1=\n\t{\n\t\thyperlane={ { to=0 length=1 } }\n\t}\n"
        '\t2=\n\t{\n\t\tname={ key="C" }\n\t}\n'
        "}\n"
    )
    path = _save(tmp_path, isolated, name="isolated.sav")
    out = tmp_path / "isolated.tsv"
    assert save_hypergraph.main([str(path), "--edges", str(out)]) == 0
    assert "isolated" in capsys.readouterr().err
    assert out.read_text(encoding="utf-8") == "0\t1\t1\n"
