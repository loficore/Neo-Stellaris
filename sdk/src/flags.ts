// flags.ts — the build-time flag-name gate for `neo check`.
//
// Why this reads the author's `setStarFlag(...)` call sites and not the native
// `__neo_system_set_flag(id, name)` call: the SDK shim always forwards its own
// parameter, so the native call is dynamic in *every* bundle and a scan of it
// would reject all projects.  The literal only survives where the author wrote
// it, which is exactly the place a build-time check can answer.
//
// Two rules, both from the Phase 1 `Add_Modifier` incident (AGENTS.md 约束 4):
//   1. v1 accepts a string literal only — a computed name has no build-time
//      answer, so it fails instead of shipping an unchecked name;
//   2. the name must not collide, case-insensitively, with an official keyword.
//      `0x1D13270` looks names up case-insensitively, so a flag named like a
//      keyword would address engine behaviour rather than a flag.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export interface FlagCheck {
  /** Literal names the author wrote, in bundle order (duplicates kept). */
  names: string[];
  /** Author-facing one-liners; empty means the bundle is shippable. */
  problems: string[];
}

/** `s.setStarFlag(` — a dot is required so the shim's method key does not match. */
const CALL_RE = /\.\s*setStarFlag\s*\(/g;

/** The keyword table `scripts/thunkarrays.py` emits (3,900 behaviour rows). */
export const KEYWORDS_TSV = fileURLToPath(
  new URL("../../evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv", import.meta.url),
);

function clip(text: string): string {
  const flat = text.trim().replace(/\s+/g, " ");
  return flat.length > 60 ? `${flat.slice(0, 57)}...` : flat;
}

/** The first argument's source text, scanning for the matching `,`/`)`. */
function firstArgument(bundle: string, open: number): string | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < bundle.length; i++) {
    const ch = bundle[i];
    if (quote !== null) {
      if (ch === "\\") i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) return bundle.slice(open, i);
      depth -= 1;
    } else if (ch === "," && depth === 0) {
      return bundle.slice(open, i);
    }
  }
  return null;
}

/** The value of a single string literal, or `null` when the expression is not one. */
function literalValue(text: string): string | null {
  const t = text.trim();
  if (t.length < 2) return null;
  const quote = t[0];
  if ((quote !== '"' && quote !== "'" && quote !== "`") || t[t.length - 1] !== quote) return null;
  const inner = t.slice(1, -1);
  if (quote === "`" && inner.includes("${")) return null;
  if (quote === '"') {
    try {
      return JSON.parse(t) as string;
    } catch {
      return null;
    }
  }
  return inner.replace(/\\'/g, "'").replace(/\\\\/g, "\\");
}

export function checkFlagNames(bundle: string, keywords: ReadonlySet<string>): FlagCheck {
  const names: string[] = [];
  const problems: string[] = [];
  for (const match of bundle.matchAll(CALL_RE)) {
    const text = firstArgument(bundle, match.index + match[0].length);
    if (text === null) {
      problems.push("flags: unterminated setStarFlag(...) call in the bundle");
      continue;
    }
    const value = literalValue(text);
    if (value === null) {
      problems.push(
        `flags: setStarFlag(${clip(text)}) is a dynamic name; v1 only supports string literal flag names`,
      );
      continue;
    }
    names.push(value);
    if (keywords.has(value.toLowerCase())) {
      problems.push(
        `flags: ${JSON.stringify(value)} collides with an official keyword (case-insensitive); ` +
          "that name would address engine behaviour instead of a flag",
      );
    }
  }
  return { names, problems };
}

/** Read the `keywords` column (case-folded) out of the registration TSV. */
export function loadKeywordNames(tsvPath: string = KEYWORDS_TSV): Set<string> {
  let text: string;
  try {
    text = readFileSync(tsvPath, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? (error as Error).message;
    throw new Error(
      `flags: cannot read the keyword table at ${tsvPath} (${code}); ` +
        "neo check needs the repository's evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv",
    );
  }
  const lines = text.split(/\r?\n/).filter((line) => line.length > 0);
  if (lines.length === 0) throw new Error(`flags: keyword table ${tsvPath} is empty`);
  const header = lines[0].split("\t").map((cell) => cell.replace(/^#\s*/, "").trim());
  const index = header.includes("keywords") ? header.indexOf("keywords") : header.indexOf("keyword");
  if (index < 0) throw new Error(`flags: keyword table ${tsvPath} has no 'keywords' column`);
  const out = new Set<string>();
  for (const line of lines.slice(1)) {
    const cell = line.split("\t")[index];
    if (cell !== undefined && cell.length > 0) out.add(cell.trim().toLowerCase());
  }
  return out;
}
