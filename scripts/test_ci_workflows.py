"""Fences for the two CI workflow files.

There are two copies of the gate on purpose (`.github/workflows/ci.yml` runs on
GitHub-hosted runners, `.gitea/workflows/ci.yml` is the manual local-runner
copy), and two copies of anything drift.  The command list itself is already
single-sourced in the justfile (`just check-full`), so what is left to pin is:

* both copies still call that one recipe (a copy that quietly stops running the
  gate is worse than no copy);
* the Gitea copy never becomes automatic — it is a fallback for when GitHub is
  unreachable, and a fallback that also fires on push means every push runs the
  gate twice for no added signal.  (Measured 2026-11-05 on Gitea 28.2.0: a push
  carrying `.github/workflows/ci.yml` with `on: push:` produced no run, i.e. the
  compat path is not active there.  The rule is kept anyway, so the property
  does not depend on that measurement staying true.)
* neither copy wires in a live-channel tool.  `docs/roadmap.md` §2 makes the
  real-machine detour gate 「只在点名时」 with a per-plan shot budget; a workflow
  is exactly the wrong place to forget that, because it would fire unattended.

Pure text checks, no network, no YAML parser (the repo has no PyYAML dependency
and this file must stay importable on a bare runner).
"""
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
GITHUB_WORKFLOW = REPO / ".github/workflows/ci.yml"
GITEA_WORKFLOW = REPO / ".gitea/workflows/ci.yml"
WORKFLOWS = (GITHUB_WORKFLOW, GITEA_WORKFLOW)

# Every script family that needs a running game, a live process, or a human in
# the loop.  Naming one of these in a workflow is the failure mode this fence
# exists for — not a style preference.
LIVE_CHANNEL = re.compile(
    r"\b(?:c1_[a-z_]+|c2_[a-z0-9_]+|c4_[a-z_]+|game_supervisor|launch_stellaris"
    r"|session_bridge|ns_world|world_probe|keep_awake|popup_ocr|popup_guard"
    r"|c2_harness)\.(?:py|js)\b"
)


def _read(path):
    return path.read_text(encoding="utf-8")


def _executable(text):
    """Workflow text with comments removed.

    The header comments in both files *name* the live-channel tools on purpose
    ("these stay out"), so scanning raw text would make the fence fire on its own
    documentation.  Only what the runner would actually execute counts.
    """
    kept = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    return "\n".join(re.sub(r"\s#.*$", "", line) for line in kept)


def _trigger_block(text):
    """The body of the top-level ``on:`` key, up to the next top-level key."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.rstrip() == "on:")
    body = []
    for line in lines[start + 1:]:
        if line and not line[0].isspace():      # next top-level key
            break
        body.append(line)
    return "\n".join(body)


def workflows_share_the_gate():
    """F: both copies must run the one recipe; the command list lives in the justfile."""
    return [p.name for p in WORKFLOWS if "just check-full" not in _read(p)]


def live_channel_mentions():
    """F: no workflow may name a real-machine script (roadmap §2「只在点名时」)."""
    out = []
    for p in WORKFLOWS:
        for m in LIVE_CHANNEL.finditer(_executable(_read(p))):
            out.append(f"{p.parent.parent.name}/{p.name}: names live-channel {m.group()}")
    return out


def gitea_trigger_names(text):
    """F: the Gitea copy is manual-only, so its trigger block is dispatch alone.

    A fallback pipeline that also fires on push runs every gate twice for no
    added signal, and leaves the single `capacity: 1` local runner slot
    competing with itself.  Measured 2026-11-05: Gitea 28.2.0 does not pick up
    `.github/workflows/`, so today the duplicate would have to come from someone
    copying the trigger block over — which is exactly the edit this catches.
    """
    events = re.findall(r"^\s{2}([a-z_]+):", _trigger_block(text), re.MULTILINE)
    if events == ["workflow_dispatch"]:
        return []
    return [f"gitea trigger is {events}, expected ['workflow_dispatch']"]


def test_both_copies_run_the_gate():
    assert workflows_share_the_gate() == []


def test_no_copy_wires_in_a_live_channel_script():
    assert live_channel_mentions() == []


def test_gitea_copy_is_dispatch_only():
    assert gitea_trigger_names(_read(GITEA_WORKFLOW)) == []


def test_github_copy_is_the_primary_one():
    """The automatic triggers must live on the GitHub copy (push + pull_request)."""
    text = _read(GITHUB_WORKFLOW)
    assert "pull_request" in _trigger_block(text)
    assert re.search(r"^\s{2}push:", _trigger_block(text), re.MULTILINE)


def test_fence_bites_on_a_live_mention():
    """The rule above must actually bite: a positive control, not just a green."""
    caught = LIVE_CHANNEL.findall("run: python scripts/c2_trigger_eval_probe.py --mask 0")
    assert caught == ["c2_trigger_eval_probe.py"]


def test_fence_bites_on_an_automatic_gitea_trigger():
    sample = "on:\n  push:\n    branches: [main]\n  workflow_dispatch:\n\njobs:\n"
    assert gitea_trigger_names(sample) != []


# --- Part C Task 8: tag 上先跑完整门再发 release ------------------------------


def test_release_is_tag_only():
    """A release is the one side effect that must never fire on a branch push.

    The `if:` has to be in the job header (before `steps:`), so a tag push is the
    only event that reaches the publish step.
    """
    text = _read(GITHUB_WORKFLOW)
    job = text.split("  release:", 1)[1]
    assert "startsWith(github.ref, 'refs/tags/')" in job.split("steps:", 1)[0]


def test_the_gate_still_runs_on_tags():
    """Tags must go through the same gate: `release` only `needs: gate`."""
    assert "tags:" in _trigger_block(_read(GITHUB_WORKFLOW))
