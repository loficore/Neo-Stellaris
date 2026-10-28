"""Collect one row of the minimal golden set (spec §13).  Scratch-grade.

    python collect_labels.py --frame C:/temp/ns_game_shot.png \
        --label playing --source human --raw red_px=61,green_px=40

The golden set is 20 frames of **classifier output against a human verdict**
(spec §13.2): it exists so that a future threshold change has something to be
measured against.  Its whole value is that the rows are honest — a guessed
label makes the set worthless and worse than absent, because it looks like
evidence.  So this collector:

* refuses a row with no ``crop_sha256`` (a label of a frame has to name *that*
  frame's pixels — spec §13.2 makes the hash mandatory);
* refuses a label outside the three classifiers' vocabularies, so "looks fine"
  cannot enter as a verdict;
* refuses ``--source`` outside the three tiers (§13.4: ``human`` + ``agent``
  confirmed today, ``engine`` reserved);
* writes the **raw counts** it was given, unchanged — the counts are what a
  later calibration re-grades (spec §10), and re-deriving them from a verdict
  is exactly what cannot be done.

Deliberately not here: any model.  The golden set is the *reference* the model
work would be measured against (spec §13.1 and the plan's Global Constraints:
「状态判定与黄金集不使用任何模型」).
"""

from __future__ import annotations

import hashlib
import json
import pathlib

#: The three classifiers' vocabularies (spec §13.2).  A label outside these is
#: not a verdict about this machine's window state.
LABELS = (
    "playing",
    "paused",
    "unknown",  # pause
    "console_open",
    "console_closed",
    "console_undecided",  # console
    "choice",
    "dialog",
    "none",  # window
)

#: Where a row's verdict came from (spec §13.4).  ``engine`` is reserved and
#: accepted so a future engine-labelled row has a name, but today's minimum is
#: the other two.
SOURCES = ("human", "agent", "engine")

#: The raw counts a row may carry (spec §10).  Unknown keys are refused: a
#: typo in a count name would silently become a count nobody reads.
RAW_KEYS = ("red_px", "green_px", "bright_px", "gold_px", "row_count", "option_count")


def crop_sha256(path) -> str:
    """The sha256 of the frame's bytes — the row's identity."""
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def parse_raw(pairs) -> dict:
    """``["red_px=61", "green_px=40"]`` → ``{"red_px": 61, ...}``.

    A count that cannot be read as an integer is refused rather than dropped:
    a silently missing count turns "measured zero" and "never measured" into
    the same thing, which is the mistake the evidence rules exist to prevent.
    """
    out = {}
    for pair in pairs or ():
        if "=" not in pair:
            raise ValueError(f"raw count {pair!r} is not key=value")
        key, _, value = pair.partition("=")
        key = key.strip()
        if key not in RAW_KEYS:
            raise ValueError(
                f"unknown raw count {key!r} (known: {', '.join(RAW_KEYS)})"
            )
        text = value.strip()
        try:
            out[key] = int(text)
        except ValueError:
            raise ValueError(f"raw count {key}={text!r} is not an integer") from None
    return out


def build_row(
    *,
    frame: str,
    label: str,
    source: str,
    raw: dict,
    classifier: str = "",
    note: str = "",
    t: float | None = None,
) -> dict:
    """Assemble one golden-set row, refusing a row that cannot be evidence.

    The refusals are the feature: they are what stops a rushed run from
    producing twenty plausible-looking lines that a later calibration would
    trust.
    """
    if label not in LABELS:
        raise ValueError(
            f"label {label!r} is not one of the classifiers' "
            f"verdicts ({', '.join(LABELS)})"
        )
    if source not in SOURCES:
        raise ValueError(f"source {source!r} is not one of ({', '.join(SOURCES)})")
    path = pathlib.Path(frame)
    if not path.is_file():
        raise ValueError(f"frame not found: {frame}")
    digest = crop_sha256(path)
    if not digest:
        raise ValueError("the frame produced no crop_sha256")
    unknown = set(raw) - set(RAW_KEYS)
    if unknown:
        raise ValueError(f"unknown raw counts: {sorted(unknown)}")
    return {
        "t": t,
        "frame": path.name,
        "crop_sha256": digest,
        "source": source,
        "raw": {k: int(v) for k, v in raw.items()},
        "classifier": classifier,
        "label": label,
        "note": note,
    }


def append_row(row: dict, path) -> None:
    """Append one row to the golden set.  Append-only, one row per line."""
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


#: Which classifier field each label is a verdict about, and the value that
#: field would have to carry for the two to agree.  Written as a table rather
#: than a substring test: ``"console_open" in "console=open"`` is **False**, so
#: a substring check would score a correct console verdict as a disagreement.
LABEL_VERDICT: dict[str, tuple[str, str]] = {
    "playing": ("pause", "playing"),
    "paused": ("pause", "paused"),
    "unknown": ("pause", "unknown"),
    "console_open": ("console", "open"),
    "console_closed": ("console", "closed"),
    "console_undecided": ("console", "undecided"),
    "choice": ("window", "choice"),
    "dialog": ("window", "dialog"),
    "none": ("window", "none"),
}

#: The verdicts that mean "I cannot tell" — an abstention, not a disagreement.
ABSTAIN_LABELS = ("unknown", "console_undecided")


def _classifier_value(text: str, field: str) -> str | None:
    """The value ``text`` reports for ``field``, or ``None`` if it says nothing.

    The classifier string is the shape the plan fixes: ``pause=…;console=…;
    window=…`` (Task 9's row format), so splitting on ``;`` and then on ``=``
    is the whole parse.
    """
    for chunk in (text or "").split(";"):
        key, _, value = chunk.partition("=")
        if key.strip() == field:
            return value.strip()
    return None


def agreement(rows) -> dict:
    """The reading spec §13.3 asks for: agree / abstain, with console singled out.

    ``abstain`` is the ``unknown`` / ``undecided`` verdicts — a classifier that
    said "I cannot tell" has not disagreed with the human, and folding the two
    together would let a cautious classifier look wrong and a confident wrong
    one look right.

    ``console_open`` is reported **separately** because that is the failure the
    plan's Review Focus 2 names: a bright console panel read as a choice window
    (the suspected cause of ``choice_1_of_16``) would otherwise disappear into
    the overall rate.
    """
    agree = disagree = abstain = 0
    console = {"total": 0, "agree": 0}
    for row in rows:
        label = row.get("label", "")
        said = row.get("classifier", "")
        field, want = LABEL_VERDICT.get(label, ("", ""))
        if label in ABSTAIN_LABELS:
            abstain += 1
        elif field and _classifier_value(said, field) == want:
            agree += 1
        else:
            disagree += 1
        if label == "console_open":
            console["total"] += 1
            if _classifier_value(said, "console") == "open":
                console["agree"] += 1
    total = agree + disagree + abstain
    return {
        "total": total,
        "agree": agree,
        "disagree": disagree,
        "abstain": abstain,
        "rate": (agree / total) if total else 0.0,
        "console_open": console,
    }


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frame", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--source", default="human")
    parser.add_argument("--classifier", default="")
    parser.add_argument("--note", default="")
    parser.add_argument("--raw", nargs="*", default=[])
    parser.add_argument(
        "--out",
        default=str(
            pathlib.Path("evidence") / "logs" / "world_state_labels_4_4_4.jsonl"
        ),
    )
    args = parser.parse_args(argv)
    row = build_row(
        frame=args.frame,
        label=args.label,
        source=args.source,
        raw=parse_raw(args.raw),
        classifier=args.classifier,
        note=args.note,
    )
    append_row(row, args.out)
    print(f"LABEL={row['label']} SHA={row['crop_sha256'][:12]} OUT={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
