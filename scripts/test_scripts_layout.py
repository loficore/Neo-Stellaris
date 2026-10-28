"""Executable fence for the scripts/ naming-and-directory convention.

The rule text lives in ``AGENTS.md`` section「scripts/ 命名与目录约定」; the
inventory this fence must agree with is ``scripts/README.md``.  Every rule is a
pure function that takes a directory/file list and returns violation strings
shaped ``"<basename>: <reason>"``.  Each rule is tested twice: once against a
synthetic violating tree (proves the fence bites) and once against the real
repo (proves today's tree is clean).

Pure Python, host-only: nothing here imports a live-channel module or touches
``ctypes.WinDLL`` at import (ruling P3).  ``evidence/`` is never scanned.

Exemptions are added by naming the file in the rule function's docstring,
never by ``xfail`` — xfail hides the drift that motivated the fence.
"""

import importlib
import os
import pathlib
import re
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = pathlib.Path(__file__).resolve().parent
REPO = SCRIPTS.parent

def _read(path):
    return path.read_text(encoding="utf-8", errors="replace")

def top_level_scripts(root):
    """``scripts/*.py`` + ``scripts/*.js``, excluding ``scratch/`` and ``windows/``.

    The maintained top-level inventory per ``scripts/README.md``.
    """
    return sorted(p for p in list(root.glob("*.py")) + list(root.glob("*.js")))

_EXE_READER_RE = re.compile(r"(open|read_bytes|Path)\(.*stellaris\.exe")

def offline_exe_readers(files):
    """Files that read the game exe *from disk*: an exe-opening call or a
    ``SteamLibrary`` literal, and not a live-channel script (no
    ``CreateRemoteThread``) — the rule keys on what a script does, not its family.
    """
    out = []
    for f in files:
        src = _read(f)
        if (_EXE_READER_RE.search(src) or "SteamLibrary" in src) \
                and "CreateRemoteThread" not in src:
            out.append(f)
    return out

def violates_env_var(files):
    """R-env: an offline exe reader must carry a ``NS_STELLARIS_EXE`` candidate;
    a hard-coded ``D:\\SteamLibrary\\...`` fallback next to one is compliant.
    """
    return [f"{f.name}: reads stellaris.exe from disk with no NS_STELLARIS_EXE candidate"
            for f in offline_exe_readers(files)
            if "NS_STELLARIS_EXE" not in _read(f)]

GAME_VERSION_TOKENS = {"444"}
_BANNED_STEMS = {"final", "new", "misc", "old", "tmp"}

def violates_version_suffix(files):
    """R-suffix: no ``2``/``final``/``new``/``misc``-style version suffix on
    maintained script names — version belongs in git, not in filenames.  A
    trailing digit run is only allowed when it is a game-version token
    (``444`` in ``scan444.py`` / ``anchor444.js``).
    """
    out = []
    for f in files:
        digits = re.search(r"\d+$", f.stem)
        if f.stem in _BANNED_STEMS:
            out.append(f"{f.name}: banned placeholder-style stem (version belongs in git)")
        elif digits and digits.group() not in GAME_VERSION_TOKENS:
            out.append(f"{f.name}: trailing digit run '{digits.group()}' is a tool "
                       "version suffix, not a game version token")
    return out

def violates_pairing(scripts_dir):
    """R-pair: every ``.js`` directly in the given directory must have its stem
    appear in the text of some ``.py`` in that same directory.

    Substring-of-text is deliberate: ``dis.js`` is carried by ``fridadis.py``
    and ``anchor444.js`` by ``scan444.py:15``, cross-named on purpose because
    ``C:\\ns\\...`` is a wire path.  Only the directory it is given is scanned —
    called with ``SCRIPTS``, never with ``scratch/`` (frozen history such as
    ``2026-09_frida_hot_site_spies/body.js`` is explained by its own README).
    """
    out = []
    # A guard that discusses its subjects must not vouch for them: test_* files
    # are excluded from the driver set, else this fence's own docstring would
    # pair an orphaned .js after its real driver is renamed or moved.
    drivers = [_read(p) for p in sorted(scripts_dir.glob("*.py"))
               if not p.name.startswith("test_")]
    for js in sorted(scripts_dir.glob("*.js")):
        if not any(js.stem in src for src in drivers):
            out.append(f"{js.name}: no .py in this directory references it "
                       "(.py driver and .js script are a pair)")
    return out

FAMILY_PREFIXES = ("c1_", "c2_")

def violates_family_depth(root):
    """R-depth: a ``c1_*``/``c2_*``/``test_c2_harness.py`` ``.py`` must sit
    exactly at ``scripts/<name>`` — bare-name imports and the ``C:/temp`` scp
    contract (ruling P5) locate it by that path.  ``windows/`` is out of scope:
    the launcher family is a separate package with its own ``PYTHONPATH=.``.
    """
    out = []
    for p in sorted(root.rglob("*.py")):
        if p.parent == root:
            continue
        if "windows" in p.relative_to(root).parts:
            continue
        if p.name == "test_c2_harness.py" or p.name.startswith(FAMILY_PREFIXES):
            out.append(f"{p.name}: must sit directly under scripts/ "
                       "(bare-name imports + C:/temp wire contract)")
    return out

_SCRIPT_REF_RE = re.compile(r"(?:^|[\s`(])scripts/([A-Za-z0-9_./-]+\.(?:py|js|sh|bat)\b)",
                            re.MULTILINE)

# The living docs named by the convention (``AGENTS.md`` 「scripts/ 命名与目录约定」,
# R-refs).  Single source of truth: both the R-refs scan and
# test_named_living_docs_exist read this constant, so retiring a named doc is a
# one-line change *here* and the existence assertion follows — a test that pinned
# the doc's path in its own body would block that deletion.
LIVING_DOCS_NAMED = [REPO / "AGENTS.md", REPO / "justfile"]

def dangling_script_refs(doc_paths):
    """R-refs: every ``scripts/<path>`` token written in a living doc must
    resolve — literally under ``REPO`` first, else as the basename of a file
    anywhere under ``scripts/`` (scratch basenames are cited by evidence-style
    history and may be referenced shallowly).  Violation strings name the
    *doc* basename, so ``docs/superpowers/`` (private) must be filtered out by
    the caller.  ``evidence/`` is immutable and never scanned.
    """
    basenames = {p.name for p in SCRIPTS.rglob("*") if p.is_file()}
    out = []
    for doc in doc_paths:
        for m in _SCRIPT_REF_RE.finditer(_read(doc)):
            ref = m.group(1)
            if (REPO / ref).exists() or pathlib.PurePosixPath(ref).name in basenames:
                continue
            out.append(f"{doc.name}: dangling reference scripts/{ref}")
    return out

_WIRE_SCRIPT_RE = re.compile(r"C:[\\/]temp[\\/]([A-Za-z0-9_.-]+\.py)")

def violates_remote_script_refs(justfile_path):
    """R-wire: every ``C:/temp/<name>.py`` token in the justfile must have a
    source under ``scripts/``.  The wire contract is basename-based (P5), so a
    rename that forgets the justfile would otherwise leave an ssh command that
    runs yesterday's file — or nothing.  ``scratch/`` is excluded on purpose:
    the justfile deploys maintained tools only.
    """
    name = justfile_path.name
    out = []
    for m in _WIRE_SCRIPT_RE.finditer(_read(justfile_path)):
        wire = m.group(1)
        hits = [p for p in SCRIPTS.rglob(wire) if "scratch" not in p.parts]
        if not hits:
            out.append(f"{name}: C:/temp/{wire} has no source under scripts/")
    return out

ROADMAP_MAX_LINES = 140
_ROADMAP_COLUMNS = ("阶段", "状态", "证据", "计划", "第一前置")
_ROADMAP_STATUSES = {"done", "blocked", "in-progress", "planned"}
_ROADMAP_PLAN_RE = re.compile(r"\d{4}-\d{2}-\d{2}-[a-z0-9-]+\.md")
_ROADMAP_VOLUME_RE = re.compile(r"(structures|pipeline|c1_validation)")
_ROADMAP_SECTION_RE = re.compile(r"§\d")
_ROADMAP_SEP_RE = re.compile(r"^:?-+:?$")

def _roadmap_cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]

def violates_roadmap_shape(roadmap_path):
    """R-roadmap: ``docs/roadmap.md`` must stay a slim index, not re-inflate into
    a second narrative roadmap document.  Total line count is capped; the 阶段状态表 (the one table whose
    header carries all five column names — located *by header name, not position*,
    so a differently-shaped sibling table above it is not policed) must use a
    status from the vocabulary and fill its evidence/plan cell per status; no
    ``docs/superpowers/`` path may appear.  Violation strings are
    ``"<label>: <reason>"`` — the file basename for doc-level hits, the row's
    阶段 value for per-row hits — matching the neighboring-rule shape.
    """
    name = roadmap_path.name
    text = _read(roadmap_path)
    lines = text.splitlines()
    out = []
    if len(lines) > ROADMAP_MAX_LINES:
        out.append(f"{name}: lines > {ROADMAP_MAX_LINES} ({len(lines)} lines)")
    if "docs/superpowers/" in text:
        out.append(f"{name}: references private plan path docs/superpowers/")

    header_index = None
    col = {}
    for i, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        cells = _roadmap_cells(line)
        if all(c in cells for c in _ROADMAP_COLUMNS):
            header_index = i
            col = {c: cells.index(c) for c in _ROADMAP_COLUMNS}
            break
    if header_index is None:
        return out

    def evidence_ok(value):
        return bool(_ROADMAP_VOLUME_RE.search(value) and _ROADMAP_SECTION_RE.search(value))

    for line in lines[header_index + 1:]:
        if not line.strip().startswith("|"):
            break
        cells = _roadmap_cells(line)
        if cells and all(_ROADMAP_SEP_RE.match(c) for c in cells):
            continue
        if len(cells) <= max(col.values()):
            continue
        label = cells[col["阶段"]]
        status = cells[col["状态"]]
        evidence = cells[col["证据"]]
        plan = cells[col["计划"]]
        if status not in _ROADMAP_STATUSES:
            out.append(f"{label}: unknown status '{status}' "
                       f"(allowed: {sorted(_ROADMAP_STATUSES)})")
            continue
        if status in ("blocked", "in-progress") and not evidence_ok(evidence):
            out.append(f"{label}: {status} row needs evidence — a volume alias "
                       "(structures|pipeline|c1_validation) plus §<number>")
        if status == "planned" and not _ROADMAP_PLAN_RE.search(plan):
            out.append(f"{label}: planned row needs a plan filename matching "
                       "YYYY-MM-DD-<topic>.md")
        if status == "done" and not (evidence_ok(evidence) or _ROADMAP_PLAN_RE.search(plan)):
            out.append(f"{label}: done row needs evidence (§ + volume alias) "
                       "or a plan filename")
    return out

def violates_missing_roadmap_header(roadmap_path):
    """R-header: the companion of R-roadmap that closes its defeat vector.
    ``violates_roadmap_shape`` locates the 阶段状态表 by the five column names;
    renaming or dropping one header word makes it find no table, silently
    un-policing every per-row evidence/plan check while the real-tree test
    stays green.  This fence pins that a header line carrying all five names
    exists at all, so degrading the header fails loudly.  Violation strings
    match the rule shape ``"<basename>: <reason>"``.
    """
    name = roadmap_path.name
    for line in _read(roadmap_path).splitlines():
        if line.strip().startswith("|") and \
                all(c in _roadmap_cells(line) for c in _ROADMAP_COLUMNS):
            return []
    return [(f"{name}: no table header carries all five column names "
             f"{'|'.join(_ROADMAP_COLUMNS)} — the per-row checks of "
             "violates_roadmap_shape would silently not run")]

def violates_hardcoded_rvas(files):
    """R-rva: no hard-coded module-level ``RVAS`` dict literal in a maintained
    script — every RVA must be re-parsed from the injected copy via
    ``list_exports`` (ruling P10).
    """
    # armed by test_no_hardcoded_rva_dict_anywhere_in_the_maintained_tree
    # (Task 2); the pattern lives only in this compiled regex, so the guard
    # file itself stays clean and the real-tree test names only genuine
    # violators — P10 has no exemption, not even for the fence.
    rvas_re = re.compile(r"\bRVAS\s*=\s*\{")
    return [f"{f.name}: hard-coded RVAS dict (ruling P10 — re-parse with list_exports)"
            for f in files if rvas_re.search(_read(f))]

def stray_windows_literal_paths(scripts_dir):
    """Files whose basename is a Windows path (``C:\\temp\\x.jsonl``).

    ``game_supervisor`` reads ``LOG_PATH``/``STATUS_PATH`` from module globals,
    so a host test that calls ``_handle_command`` without redirecting them
    creates these under ``scripts/windows/`` on Linux.
    """
    out = []
    for path in sorted(scripts_dir.rglob("*")):
        if path.is_file() and ("\\" in path.name or ":" in path.name):
            out.append(path.relative_to(scripts_dir).as_posix())
    return out

def test_env_var_rule_names_a_disk_reader_without_the_var(tmp_path):
    bad = tmp_path / "peek.py"
    bad.write_text('EXE = r"D:\\SteamLibrary\\steamapps\\common\\Stellaris\\stellaris.exe"\n'
                   "f = open(EXE, 'rb').read()\n")
    good = tmp_path / "ok.py"
    good.write_text("_cands = [os.environ.get('NS_STELLARIS_EXE'),\n"
                    "  r'D:\\SteamLibrary\\steamapps\\common\\Stellaris\\stellaris.exe']\n"
                    "f = open(next(c for c in _cands if os.path.exists(c)), 'rb')\n")
    # regex branch: the exe-opening call itself matches, no SteamLibrary literal
    regex_bad = tmp_path / "regex_peek.py"
    regex_bad.write_text("f = open('/opt/game/stellaris.exe', 'rb')\n")
    # exclusion branch: a live-channel script (CreateRemoteThread) is out of scope
    live_ok = tmp_path / "live.py"
    live_ok.write_text("f = open('/opt/game/stellaris.exe', 'rb')\n"
                       "kernel32.CreateRemoteThread(pid, None, 0, addr, None, 0, None)\n")
    assert violates_env_var([bad, good, regex_bad, live_ok]) == [
        "peek.py: reads stellaris.exe from disk with no NS_STELLARIS_EXE candidate",
        "regex_peek.py: reads stellaris.exe from disk with no NS_STELLARIS_EXE candidate"]

def test_real_tree_has_no_env_var_violation():
    assert violates_env_var(top_level_scripts(SCRIPTS)) == []

def test_live_scripts_are_out_of_scope_for_the_env_var_rule():
    offenders = {v.split(":")[0] for v in violates_env_var(top_level_scripts(SCRIPTS))}
    for live in ("c1_remote.py", "c1_verify_bst.py", "c1_verify_reverse.py",
                 "c2_control_sleep.py", "c2_harness.py", "execspy.py", "fridadis.py",
                 "frida-test.py", "test_c2_harness.py"):
        assert live not in offenders

def test_version_suffix_rule_accepts_game_version_tokens_only(tmp_path):
    for name in ("body2.py", "fs3.py", "spy7.js", "misc.py",
                 "scan444.py", "anchor444.js", "thunkarrays.py"):
        (tmp_path / name).write_text("")
    hits = {v.split(":")[0] for v in violates_version_suffix(sorted(tmp_path.glob("*.*")))}
    assert hits == {"body2.py", "fs3.py", "spy7.js", "misc.py"}

def test_real_top_level_tree_is_suffix_clean():
    assert violates_version_suffix(top_level_scripts(SCRIPTS)) == []

def test_pairing_rule_flags_an_orphan_js_at_top_level(tmp_path):
    (tmp_path / "driver.py").write_text('JS = r"C:\\ns\\partner.js"\n')
    (tmp_path / "partner.js").write_text("")
    (tmp_path / "orphan.js").write_text("")
    (tmp_path / "scratch").mkdir()
    (tmp_path / "scratch" / "frozen.js").write_text("")   # out of scope
    assert [v.split(":")[0] for v in violates_pairing(tmp_path)] == ["orphan.js"]

def test_real_top_level_js_files_all_have_a_driver():
    assert violates_pairing(SCRIPTS) == []

def test_family_depth_rule_flags_a_nested_c2_script(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "c2_harness.py").write_text("")
    (tmp_path / "c2_task5_init.py").write_text("")
    (tmp_path / "windows").mkdir()
    (tmp_path / "windows" / "launch_stellaris.py").write_text("")
    # Family-named file under windows/: pins the exclusion itself — without
    # it, deleting the windows skip in violates_family_depth changes nothing
    # anyone can observe (a mutation-surviving branch).
    (tmp_path / "windows" / "c2_helper.py").write_text("")
    assert violates_family_depth(tmp_path) == [
        ("c2_harness.py: must sit directly under scripts/ "
         "(bare-name imports + C:/temp wire contract)")]

def test_real_family_is_at_depth_one():
    assert violates_family_depth(SCRIPTS) == []

def test_living_docs_script_references_resolve():
    docs = LIVING_DOCS_NAMED + list((REPO / "docs").rglob("*.md"))
    docs = [d for d in docs if "superpowers" not in str(d)]
    assert dangling_script_refs(docs) == []

def test_dangling_rule_fires_on_a_moved_script(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "gone.py").touch()
    (tmp_path / "docs" / "a.md").write_text("run `python3 scripts/nowhere.py`\n")
    hits = dangling_script_refs([tmp_path / "docs" / "a.md"])
    assert len(hits) == 1 and hits[0].startswith("a.md:")

def test_a_json_reference_is_not_read_as_a_js_script(tmp_path):
    # The extension alternation used to match the ".js" inside ".json", so a
    # living-doc pointer to scripts/windows/popup_allowlist.example.json was
    # reported as a dangling "popup_allowlist.example.js".
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("template: `scripts/windows/x.example.json`\n")
    assert dangling_script_refs([tmp_path / "docs" / "a.md"]) == []

def test_hardcoded_rva_rule_flags_a_rvas_dict(tmp_path):
    bad = tmp_path / "some_tool.py"
    # The offending dict text is assembled at runtime so this guard file never
    # contains the literal pattern the rule scans for; the armed real-tree test
    # must name exactly the genuine violators, and P10 has no exemption for
    # the fence's own fixture strings.
    bad.write_text("RVAS " + "= " + "{\n    'C2Sanity': 0x1234,\n}\n")
    good = tmp_path / "clean.py"
    good.write_text("exports = list_exports(dll_path)\n")
    assert violates_hardcoded_rvas([bad, good]) == [
        "some_tool.py: hard-coded RVAS dict (ruling P10 — re-parse with list_exports)"]

def test_no_hardcoded_rva_dict_anywhere_in_the_maintained_tree():
    assert violates_hardcoded_rvas(top_level_scripts(SCRIPTS)) == []

def test_c2_test_sanity_resolves_rvas_from_the_reparsed_table():
    m = importlib.import_module("c2_test_sanity")
    exports = {"C2Sanity": 0x1234, "C2Init": 0x5678}
    assert m.resolve_targets(exports, ("C2Sanity", "C2Init")) == exports
    try:
        m.resolve_targets(exports, ("C2Sanity", "C2Gone"))
        raise AssertionError(
            "a stale export name must raise, not dispatch a guessed address")
    except KeyError as exc:
        assert "C2Gone" in str(exc)

def test_c2_test_sanity_refuses_dispatch_when_sanity_is_not_42():
    m = importlib.import_module("c2_test_sanity")
    assert m.sanity_gate(42) is True
    for rc in (0, 3, 259, 41):
        assert m.sanity_gate(rc) is False

WORKTREE_ONLY = {"dispatch_watching_buffer", "_gle", "kernel32_call_address", "_prime_buffer"}

def test_c2_test_sanity_keeps_its_cli_shape():
    src = (SCRIPTS / "c2_test_sanity.py").read_text()
    assert "argv[1]" in src and "argv[2]" in src

def test_c2_test_sanity_does_not_reach_into_the_other_plan():
    import ast
    tree = ast.parse((SCRIPTS / "c2_test_sanity.py").read_text())
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not (names | attrs) & WORKTREE_ONLY, \
        "these symbols exist only in the uncommitted worktree copy of c2_harness.py"

# --- living-docs input existence + roadmap shape fence (plan-decomposition Task 1) ---

def test_named_living_docs_exist():
    missing = [str(p) for p in LIVING_DOCS_NAMED if not p.exists()]
    assert missing == []

def test_remote_script_rule_flags_a_wire_name_without_a_source(tmp_path):
    jf = tmp_path / "justfile"
    jf.write_text(
        "deploy:\n"
        "    scp scripts/windows/game_supervisor.py host:C:/temp/game_supervisor.py\n"
        "game:\n"
        '    ssh host "python C:/temp/gone.py status"\n',
        encoding="utf-8")
    assert violates_remote_script_refs(jf) == [
        "justfile: C:/temp/gone.py has no source under scripts/"]

def test_real_justfile_wire_names_resolve():
    assert violates_remote_script_refs(REPO / "justfile") == []

def test_roadmap_rule_flags_bloat_and_missing_pointers(tmp_path):
    bad = tmp_path / "roadmap.md"
    bad.write_text(
        "## 3. 阶段状态表\n"
        "| 阶段 | 状态 | 证据 | 计划 | 第一前置 |\n"
        "|---|---|---|---|---|\n"
        "| C2 | blocked | 无 | x.md | 重开游戏 |\n"
        "| B3 | planned |  |  | 上传 dis.js |\n"
        "| A | done | pipeline §17 |  |  |\n")
    hits = violates_roadmap_shape(bad)
    assert any("C2" in h and "evidence" in h for h in hits)
    assert any("B3" in h and "plan filename" in h for h in hits)
    assert not any("A:" in h for h in hits)          # done 行有 § 就够,不逼它再交计划名

def test_roadmap_rule_flags_an_oversized_doc(tmp_path):
    big = tmp_path / "roadmap.md"
    big.write_text("\n".join(["| 阶段 | 状态 | 证据 | 计划 | 第一前置 |"] +
                             ["| Cx | done | pipeline §17 |  |  |"] * (ROADMAP_MAX_LINES + 1)))
    assert any("lines > 140" in h for h in violates_roadmap_shape(big))

def test_roadmap_rule_flags_a_private_plan_path_and_unknown_status(tmp_path):
    p = tmp_path / "roadmap.md"
    p.write_text("see docs/superpowers/plans/2026-10-22-x.md\n"
                 "| 阶段 | 状态 | 证据 | 计划 | 第一前置 |\n|---|---|---|---|---|\n"
                 "| Q | open | pipeline §17 |  |  |\n")
    hits = violates_roadmap_shape(p)
    assert any("private plan path" in h for h in hits)
    assert any("Q" in h and "status" in h for h in hits)

def test_real_roadmap_matches_shape():
    assert violates_roadmap_shape(REPO / "docs" / "roadmap.md") == []

def test_roadmap_header_fence_bites_and_the_real_header_is_policied(tmp_path):
    p = tmp_path / "roadmap.md"
    p.write_text("| 阶段 | status | 证据 | 计划 | 第一前置 |\n|---|---|---|---|---|\n"
                 "| C2 | blocked | 无 | x.md | 重开游戏 |\n")
    # Renaming one header word silences the per-row checks of the main rule —
    # exactly the defeat vector the companion fence exists to close — so this
    # test pins both halves: the fixture blinds violates_roadmap_shape and the
    # header rule bites it; the real roadmap carries the five-name header.
    assert violates_roadmap_shape(p) == []
    assert violates_missing_roadmap_header(p) == [
        ("roadmap.md: no table header carries all five column names "
         "阶段|状态|证据|计划|第一前置 — the per-row checks of "
         "violates_roadmap_shape would silently not run")]
    assert violates_missing_roadmap_header(REPO / "docs" / "roadmap.md") == []

def test_stray_rule_flags_a_backslash_named_file(tmp_path):
    (tmp_path / "C:\\temp\\ns_game_log.jsonl").write_text("")
    assert stray_windows_literal_paths(tmp_path)


def test_real_scripts_tree_has_no_stray_windows_paths():
    assert stray_windows_literal_paths(SCRIPTS) == []


# ---------------------------------------------------------------------------
# Review Focus 2 (window plan 2026-10-27-live-window-out-of-family-witness):
# the B2 census must run LAST in a window, because it arms the base-Execute
# detour and every later [self+0] join reading would come from a process whose
# hot path we own.  The statement lives in the tool's own doc section — this
# fence keeps it from being deleted by a later tidy-up.
# ---------------------------------------------------------------------------

def test_census_runs_last_ordering_note():
    text = (REPO / "docs" / "offline-tooling.md").read_text(encoding="utf-8")
    heading = next((ln for ln in text.splitlines()
                    if ln.startswith("### ") and "scripts/execspy.py" in ln), None)
    assert heading is not None, "execspy 没有文档节(AGENTS 要求每个维护中工具有一节)"
    start = text.index(heading)
    end = text.find("\n### ", start + len(heading))
    section = text[start:] if end < 0 else text[start:end]
    assert "顺序" in section, "文档节必须写顺序声明"
    assert "压最后" in section or "最后" in section
    assert "hist_overflow" in section, "文档节必须写 hist_overflow==0 硬门"
    # The DLL module NAME is baked into execspy.js too — a driver that only
    # parameterized the Python path would load one file and look for another.
    assert "execspy.js" in section and "模块名" in section


# ---------------------------------------------------------------------------
# Task 6: the two fences that keep the world-state gate from being bypassed.
#
# spec §1's judgement criterion is 「在 IN_GAME_RUNNING 之外(或无有效租约)执行
# 任何 guard 的 Install,gate_module 必须拒绝」.  A gate that only *some* shots
# call is not that criterion — it is a habit.  The first fence counts the
# `inject_dll(` call sites and the ones behind a gate, and fails when the two
# disagree, so a new injector cannot be written without one.
#
# The second fence is spec §12(a) point 5: 「justfile 里凡是改变世界的动词,必须出现
# 在状态机的 ACTIONS 表里;新增动词而不登记即红」.
# ---------------------------------------------------------------------------

def _modules():
    """The two files the fences read their vocabulary from."""
    import world_state
    return world_state


def _scope_spans(src: str) -> list[tuple[str, int, int]]:
    """Every ``(name, start_line, end_line)`` scope in ``src``, 1-based.

    The unit of "behind a gate" is the **scope** (a function body, or the
    module body), not the file: a gate in ``main`` does not protect an
    injection in ``helper``.  Line ranges rather than an AST walk because the
    check is textual by nature ("does the gate call appear *before* the
    injection in the same scope") and a parser would have to re-derive the
    ordering anyway.
    """
    import ast
    spans: list[tuple[str, int, int]] = []
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            spans.append((node.name, node.lineno,
                          max(getattr(node, "end_lineno", node.lineno), node.lineno)))
    spans.append(("<module>", 1, len(src.splitlines())))
    return spans


def _scope_of(spans, line: int) -> str:
    """The innermost scope containing ``line``."""
    best = ("<module>", 1, 10 ** 9)
    for name, start, end in spans:
        if start <= line <= end and (start, -end) > (best[1], -best[2]):
            best = (name, start, end)
    return best[0]


def violates_ungated_injections(scripts_dir):
    """R-inject: every ``inject_dll(`` call site must be behind a gate.

    A **call site** is a call to ``inject_dll`` (bare or as an attribute, so
    ``harness.inject_dll(...)`` counts too) in a maintained top-level script —
    not the ``def inject_dll`` in ``c2_harness.py``, which is the machinery.

    "Behind a gate" means: in the same scope, a call to one of
    ``world_state.GATE_ENTRY_POINTS`` appears **before** the injection, so the
    refusal happens before the DLL is loaded.  A gate after the injection is
    the failure mode this rule exists for (「注入了再发现前提不成立」), so the
    order is part of the rule, not a detail.

    Violation strings are ``"<basename>: <scope> injects without a gate"``.
    """
    import ast
    ws = _modules()
    gates = set(ws.GATE_ENTRY_POINTS)
    out = []
    for path in sorted(scripts_dir.glob("*.py")):
        src = path.read_text(encoding="utf-8", errors="replace")
        if "inject_dll" not in src:
            continue
        spans = _scope_spans(src)
        tree = ast.parse(src)
        injections: list[int] = []
        gates_at: dict[str, list[int]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = None
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name == "inject_dll":
                injections.append(node.lineno)
            elif name in gates:
                gates_at.setdefault(_scope_of(spans, node.lineno), []).append(node.lineno)
        for line in injections:
            scope = _scope_of(spans, line)
            if not any(gate_line < line for gate_line in gates_at.get(scope, ())):
                out.append(f"{path.name}: {scope} injects without a gate "
                           "(no gate call before inject_dll in that scope)")
    return out


def test_ungated_rule_flags_an_injection_without_a_gate(tmp_path):
    """The fence bites: a gate in another scope does not protect this one."""
    (tmp_path / "ungated.py").write_text(
        "def helper():\n"
        "    inject_dll(1, 'x')\n"
        "\n"
        "def main():\n"
        "    assert_ready('install', guard='g')\n"
        "    helper()\n", encoding="utf-8")
    (tmp_path / "gated.py").write_text(
        "def main():\n"
        "    assert_ready('install', guard='g')\n"
        "    inject_dll(1, 'x')\n", encoding="utf-8")
    (tmp_path / "after.py").write_text(
        "def main():\n"
        "    inject_dll(1, 'x')\n"
        "    assert_ready('install', guard='g')\n", encoding="utf-8")
    (tmp_path / "attribute.py").write_text(
        "def run(h):\n"
        "    gate_install('g')\n"
        "    h.inject_dll(1, 'x')\n", encoding="utf-8")
    hits = [v.split(":")[0] for v in violates_ungated_injections(tmp_path)]
    assert hits == ["after.py", "ungated.py"], hits


def test_every_inject_call_site_is_gated():
    """The real tree: every maintained injection is behind a gate."""
    assert violates_ungated_injections(SCRIPTS) == []


#: The justfile verbs the plan's seed whitelist names, verbatim.  Anything the
#: daemon grows beyond this plus ``UNGATED_VERBS`` has to be registered.
PLAN_UNGAITED_SEED = ("status", "shot", "want", "policy", "choose", "console",
                      "console_sync", "speed")

_GAME_RECIPE_RE = re.compile(r"^game\b[^:]*:")
_JUSTFILE_RECIPE_RE = re.compile(r"^([a-z][a-z0-9_]*)(?:\s+[a-z*].*)?:", re.MULTILINE)


def justfile_game_verbs(justfile_path):
    """The verbs the justfile advertises for the game, read off its comment.

    The ``game`` recipe's usage line is the documentation an operator reads,
    so it is also the list a new verb is most likely to be added to without a
    registry change.  Parsed as ``a | b | c`` tokens; a token with arguments
    (``click 1400 861``) contributes its first word.
    """
    text = _read(justfile_path)
    lines = text.splitlines()
    block: list[str] = []
    # The usage comment is the run of "#" lines immediately above the `game`
    # recipe.  Anchoring on the recipe (not on the word "start") is what makes
    # the rule bite for a verb list that was rewritten wholesale.
    for index, line in enumerate(lines):
        if not _GAME_RECIPE_RE.match(line):
            continue
        above = []
        for candidate in reversed(lines[:index]):
            stripped = candidate.strip()
            if not stripped.startswith("#"):
                break
            above.append(stripped.lstrip("# "))
        block = list(reversed(above))
        break
    # Split on " | " with the spaces: a verb's own alternatives are written
    # without them (``console_sync open|closed|auto``), so the separator is
    # unambiguous and ``closed`` is not mistaken for a verb.
    verbs = []
    for chunk in " ".join(block).split(" | "):
        words = chunk.split()
        if not words:
            continue
        verb = words[0].strip()
        if verb and verb not in verbs:
            verbs.append(verb)
    return tuple(verbs)


def violates_unregistered_verbs(justfile_path):
    """R-verbs: every advertised world-changing verb must be registered.

    spec §12(a) point 5 binds this: a verb that changes the world and is not
    in the state machine's registry is a way to change the world without a
    lease.  The fence checks three things and reports each separately:

    * the verb is **registered** in ``world_state.VERB_ACTIONS``;
    * a registered verb that claims to change the world names an entry that
      **is** in ``world_state.ACTIONS`` (a typo would silently ungate it);
    * a verb that claims *not* to change the world is listed in
      ``world_state.UNGATED_VERBS`` — otherwise "no budget entry" would be a
      claim nobody can check.

    ``UNGATED_VERBS`` may only hold the plan's seed plus the session-ending
    verbs and the daemon's own lifecycle verbs; anything else is a new claim
    about the world and has to be made deliberately, in that constant.
    """
    ws = _modules()
    out = []
    for verb in justfile_game_verbs(justfile_path):
        if verb not in ws.VERB_ACTIONS:
            out.append(f"{justfile_path.name}: verb {verb!r} is not registered "
                       "in world_state.VERB_ACTIONS")
            continue
        action = ws.VERB_ACTIONS[verb]
        if action is None:
            if verb not in ws.UNGATED_VERBS:
                out.append(f"{justfile_path.name}: verb {verb!r} claims not to "
                           "change the world but is not in "
                           "world_state.UNGATED_VERBS")
        elif action not in ws.ACTIONS:
            out.append(f"{justfile_path.name}: verb {verb!r} is registered "
                       f"against {action!r}, which is not one of world_state.ACTIONS")
    return out


def test_unregistered_verb_rule_flags_an_unknown_and_a_mistyped_verb(
        tmp_path, monkeypatch):
    """The fence bites on each of the three failures it claims to catch."""
    ws = _modules()
    jf = tmp_path / "justfile"
    jf.write_text(
        "# start | status | nuke | pause | console_sync open|closed|auto\n"
        "game verb *args:\n"
        "    ssh host python game_supervisor.py\n", encoding="utf-8")

    # 1) a verb nobody registered
    hits = violates_unregistered_verbs(jf)
    assert any("'nuke'" in h and "not registered" in h for h in hits), hits
    # registered verbs raise nothing; ``pause`` maps onto the unpause budget,
    # and an argument alternative (``closed``) is not read as a verb at all.
    assert not any("'status'" in h for h in hits), hits
    assert not any("'pause'" in h for h in hits), hits
    assert not any("'closed'" in h for h in hits), hits
    assert ws.VERB_ACTIONS["pause"] in ws.ACTIONS

    # 2) registered as "does not change the world" without being on the list
    monkeypatch.setitem(ws.VERB_ACTIONS, "nuke", None)
    hits = violates_unregistered_verbs(jf)
    assert any("'nuke'" in h and "UNGATED_VERBS" in h for h in hits), hits

    # 3) registered against something that is not one of the five actions
    monkeypatch.setitem(ws.VERB_ACTIONS, "nuke", "detonate")
    hits = violates_unregistered_verbs(jf)
    assert any("'nuke'" in h and "not one of world_state.ACTIONS" in h
               for h in hits), hits


def test_real_justfile_verbs_are_registered():
    """The real justfile: every advertised verb is registered and consistent."""
    assert violates_unregistered_verbs(REPO / "justfile") == []


def test_ungated_verbs_is_the_seed_plus_the_named_extensions():
    """The whitelist cannot grow silently.

    Its content IS the claim "these verbs do not change the world".  Growing
    it is a decision about scope, so the fence pins the exact set: the plan's
    seed, plus the two session-ending verbs §1's D3 keeps apart from the
    budgeted actions, plus the daemon's own lifecycle verbs.
    """
    ws = _modules()
    allowed = set(PLAN_UNGAITED_SEED) | {"close", "quit", "start", "stop"}
    assert set(ws.UNGATED_VERBS) == allowed
    assert set(ws.UNGATED_VERBS).isdisjoint(ws.ACTIONS)


# ---------------------------------------------------------------------------
# Task 6 follow-up: R-gate-symbol.
#
# R-inject proves a gate *call* precedes every injection.  It cannot prove the
# gate exists — and for a while it did not: `gate_install` was written for the
# drivers, then lost in a revert that also removed unrelated lint churn, while
# all fourteen drivers kept importing it.  Every fence stayed green and every
# shot died on line one with ImportError, which only a live run revealed.
# A textual check cannot close that; this one resolves the symbol.
# ---------------------------------------------------------------------------

_GATE_IMPORT_RE = re.compile(
    r"^from (world_probe|world_state) import (\([^)]*\)|[^\n(]+)", re.MULTILINE)


def _gate_modules():
    """The two modules a driver may import a gate from, imported for real."""
    import sys as _sys
    for path in (SCRIPTS / "windows", SCRIPTS):
        if str(path) not in _sys.path:
            _sys.path.append(str(path))
    import world_probe  # pyright: ignore[reportMissingImports]
    import world_state
    return {"world_probe": world_probe, "world_state": world_state}


def violates_missing_gate_symbols(scripts_dir):
    """R-gate-symbol: a driver must not import a gate name that does not exist.

    Only names in ``world_state.GATE_ENTRY_POINTS`` are policed, so this rule
    stays about the gate rather than about every import a driver makes.  A
    missing name is reported with the module it was asked for, because "which
    one is wrong" is the first question the reader has.
    """
    modules = _gate_modules()
    gates = set(modules["world_state"].GATE_ENTRY_POINTS)
    out = []
    for path in sorted(scripts_dir.glob("*.py")):
        src = path.read_text(encoding="utf-8", errors="replace")
        for match in _GATE_IMPORT_RE.finditer(src):
            module_name, names = match.group(1), match.group(2)
            names = names.strip().strip("()")
            for name in (n.strip().split(" as ")[0].strip()
                         for n in names.split(",")):
                if not name or name not in gates:
                    continue
                if not hasattr(modules[module_name], name):
                    out.append(f"{path.name}: imports gate {name!r} from "
                               f"{module_name}, which does not define it")
    return out


def test_gate_symbol_rule_flags_an_import_the_module_cannot_answer(
        tmp_path, monkeypatch):
    """The fence bites on exactly the bug a live run found.

    The bug was ``gate_install`` imported from ``world_probe`` while that module
    did not define it.  Every real gate name exists today, so the missing one is
    invented here and added to the policed set — that keeps the rule's own test
    honest instead of weakening the rule to match a happy tree.
    """
    world_state = _gate_modules()["world_state"]
    monkeypatch.setattr(world_state, "GATE_ENTRY_POINTS",
                        tuple(world_state.GATE_ENTRY_POINTS) + ("gate_ghost",))
    (tmp_path / "shot.py").write_text(
        "from world_probe import gate_install\n"
        "from world_state import assert_ready\n"
        "from world_probe import gate_ghost\n", encoding="utf-8")
    hits = violates_missing_gate_symbols(tmp_path)
    assert len(hits) == 1, hits
    assert "gate_ghost" in hits[0] and "world_probe" in hits[0]
    # the two that DO exist must not be reported.
    assert not any("gate_install" in h for h in hits), hits
    assert not any("assert_ready" in h for h in hits), hits


def test_every_driver_gate_import_resolves():
    """The real tree: every gate a driver imports is actually defined."""
    assert violates_missing_gate_symbols(SCRIPTS) == []


# ---------------------------------------------------------------------------
# R-deploy: a window-side script that is not deployed cannot run, and the
# omission is invisible.
#
# This class of defect bit three times in one plan: the world-state trio
# (world_state/world_probe/ns_world) was never deployed, and `session_bridge`
# was missed in the same way a day later.  R-wire cannot catch either — it
# checks that every `C:/temp/<name>.py` *written in* the justfile has a source,
# and an omitted file writes nothing.  So this rule goes the other way: every
# maintained `scripts/windows/*.py` must appear in the deploy recipe, unless it
# is named here as deliberately host-absent.
# ---------------------------------------------------------------------------

#: Window-side modules that are deliberately NOT deployed to ``C:/temp``.
#: Each entry needs a reason: "it is not on the box because <why>".
NOT_DEPLOYED: dict[str, str] = {
    "__init__.py": "package marker; the wire is bare-name scripts, not a package",
}


def violates_undeployed_windows_scripts(scripts_dir, justfile_path):
    """R-deploy: every window-side module must travel with ``just deploy``.

    Compares ``scripts/windows/*.py`` against the basenames the ``deploy``
    recipe copies.  A script that is missing from the recipe is reported by
    name — "which file did I forget" is the question the reader has, and the
    answer must not require diffing two lists by eye.
    """
    windows = scripts_dir / "windows"
    if not windows.is_dir():
        return []
    # A recipe is its head line PLUS the indented body: the scp lives on the
    # body line, so reading only "deploy:" yields an empty set and every script
    # looks undeployed (which is how this rule's own test caught it).
    recipe_lines: list[str] = []
    collecting = False
    for line in _read(justfile_path).splitlines():
        if line.startswith("deploy:"):
            collecting = True
            continue
        if collecting:
            if line[:1].isspace():
                recipe_lines.append(line)
            elif line.strip():
                break
    deployed = set(re.findall(r"[A-Za-z0-9_./-]+/([A-Za-z0-9_]+\.py)",
                              "\n".join(recipe_lines)))
    out = []
    for path in sorted(windows.glob("*.py")):
        if path.name in NOT_DEPLOYED:
            continue
        if path.name not in deployed:
            out.append(f"{path.name}: shipped by no deploy recipe — it cannot "
                       "run on the host (add it to `just deploy`, or name it in "
                       "NOT_DEPLOYED with a reason)")
    return out


def test_deploy_rule_flags_a_window_script_nothing_ships(tmp_path):
    """The fence bites on exactly the omission that bit three times."""
    windows = tmp_path / "scripts" / "windows"
    windows.mkdir(parents=True)
    (windows / "__init__.py").write_text("", encoding="utf-8")
    (windows / "shipped.py").write_text("", encoding="utf-8")
    (windows / "forgotten.py").write_text("", encoding="utf-8")
    jf = tmp_path / "justfile"
    jf.write_text("deploy:\n"
                  "    scp scripts/windows/shipped.py host:C:/temp/\n",
                  encoding="utf-8")
    hits = violates_undeployed_windows_scripts(tmp_path / "scripts", jf)
    assert len(hits) == 1 and hits[0].startswith("forgotten.py:"), hits


def test_every_window_script_is_deployed():
    """The real tree: nothing on the window side is left behind."""
    assert violates_undeployed_windows_scripts(SCRIPTS, REPO / "justfile") == []
