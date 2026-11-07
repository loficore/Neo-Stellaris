// check.ts — `neo check`: the build-time gate that runs the bundle in a REAL
// QuickJS (quickjs-emscripten, the same engine family the host embeds) with the
// v1 native contract mocked out.
//
// Three layers, cheapest first:
//   1. tsc + esbuild (shared with `neo build`) — type and bundle errors;
//   2. a static scan of the bundle — no `require(`, `process.`, `window.`,
//      `document.`, `import(` (none of those exist in the host context), and the
//      flag-name gate (literal names only, no official-keyword collisions);
//   3. eval in QuickJS with the mock host — registration, handler execution
//      with a fake system id, and the API version.
//
// The check exits 0/2 and prints exactly one line; the author-facing detail is
// collapsed onto that line so a CI log cannot hide the reason.

import { readFileSync } from "node:fs";

import { getQuickJS, type QuickJSContext } from "quickjs-emscripten";

import { bundleProject } from "./build.js";
import { checkFlagNames, loadKeywordNames } from "./flags.js";
import { mockHostSource, type MockCall } from "./mock-host.js";

export interface CheckOptions {
  /** Authoring project directory (tsconfig.json + src/main.ts). */
  dir: string;
  /** Override the injected mock host (tests omit a native function on purpose). */
  hostSource?: string;
  /** Override the keyword table used by the flag-name gate (tests pass a missing path). */
  keywordsTsv?: string;
}

export interface CheckResult {
  ok: boolean;
  dir: string;
  registrations: number;
  apiVersion: number;
  calls: MockCall[];
  error?: string;
}

/** The fake system id the smoke test drives the handler with. */
export const CHECK_SYSTEM_ID = 7;

/** Context limits mirrored from the host contract (Track A). */
export const CONTEXT_MEMORY_LIMIT = 16 * 1024 * 1024;
export const CONTEXT_STACK_LIMIT = 1024 * 1024;

const FORBIDDEN: ReadonlyArray<{ label: string; pattern: RegExp }> = [
  { label: "require(", pattern: /\brequire\s*\(/ },
  { label: "process.", pattern: /\bprocess\s*\./ },
  { label: "window.", pattern: /\bwindow\s*\./ },
  { label: "document.", pattern: /\bdocument\s*\./ },
  { label: "import(", pattern: /\bimport\s*\(/ },
];

/** Locate Node/browser escapes in the bundle text. */
export function scanBundle(text: string): string[] {
  const out: string[] = [];
  for (const { label, pattern } of FORBIDDEN) {
    const match = pattern.exec(text);
    if (!match) continue;
    const line = text.slice(0, match.index).split("\n").length;
    out.push(`${label} at bundle line ${line}`);
  }
  return out;
}

/** The `version` of the frozen contract (`sdk/api.def`). */
export function contractVersion(): number {
  const def = JSON.parse(readFileSync(new URL("../api.def", import.meta.url), "utf8")) as {
    version: number;
  };
  return def.version;
}

/** One line, no embedded newlines — the check's whole output contract. */
export function oneLine(message: string): string {
  return message.replace(/\s+/g, " ").trim();
}

function evalIn(vm: QuickJSContext, code: string, label: string): unknown {
  const result = vm.evalCode(code, label);
  if (result.error) {
    const dumped = vm.dump(result.error);
    result.error.dispose();
    const detail =
      dumped && typeof dumped === "object" && "message" in dumped
        ? String((dumped as { message: unknown }).message)
        : String(dumped);
    throw new Error(`${label}: ${detail}`);
  }
  const value = vm.dump(result.value);
  result.value.dispose();
  return value;
}

const PROBE = `
(function () {
  var m = globalThis.__neo_mock;
  var id = ${CHECK_SYSTEM_ID};
  if (!m || typeof m.handler !== "function") {
    return JSON.stringify({ error: "no handler registered (onSystem was never called)" });
  }
  try {
    m.handler(id);
  } catch (e) {
    return JSON.stringify({ error: "handler threw: " + (e && e.message ? e.message : String(e)) });
  }
  var version = __neo_api_version();
  return JSON.stringify({
    registrations: m.registers,
    calls: m.calls,
    apiVersion: version
  });
})()
`;

interface Probe {
  error?: string;
  registrations?: number;
  calls?: MockCall[];
  apiVersion?: number;
}

export async function runCheck(options: CheckOptions): Promise<CheckResult> {
  const dir = options.dir;
  const base: CheckResult = { ok: false, dir, registrations: 0, apiVersion: 0, calls: [] };
  const fail = (error: string): CheckResult => ({ ...base, error: oneLine(error) });

  let text: string;
  let resolvedDir: string;
  try {
    const bundle = await bundleProject(dir);
    resolvedDir = bundle.dir;
    text = bundle.text;
  } catch (error) {
    return fail((error as Error).message);
  }
  base.dir = resolvedDir;

  const forbidden = scanBundle(text);
  if (forbidden.length > 0) {
    return fail(`forbidden global(s): ${forbidden.join("; ")}`);
  }

  // B5: flag names are checked before the bundle runs, because a name that
  // collides with an official keyword resolves in the token DB, not in a flag
  // map (AGENTS.md 约束 4 is the same hazard one layer down).
  let keywords: Set<string>;
  try {
    keywords = loadKeywordNames(options.keywordsTsv);
  } catch (error) {
    return fail((error as Error).message);
  }
  const flags = checkFlagNames(text, keywords);
  if (flags.problems.length > 0) {
    return fail(flags.problems.join("; "));
  }

  const expectedVersion = contractVersion();
  const QuickJS = await getQuickJS();
  const runtime = QuickJS.newRuntime();
  runtime.setMemoryLimit(CONTEXT_MEMORY_LIMIT);
  runtime.setMaxStackSize(CONTEXT_STACK_LIMIT);
  const vm = runtime.newContext();
  try {
    try {
      evalIn(vm, options.hostSource ?? mockHostSource(), "mock-host.js");
      evalIn(vm, text, "main.js");
    } catch (error) {
      return fail((error as Error).message);
    }

    let probe: Probe;
    try {
      probe = JSON.parse(String(evalIn(vm, PROBE, "neo-check-probe.js"))) as Probe;
    } catch (error) {
      return fail((error as Error).message);
    }
    if (probe.error) return fail(probe.error);

    const registrations = Number(probe.registrations ?? 0);
    const calls = probe.calls ?? [];
    const apiVersion = Number(probe.apiVersion ?? 0);
    if (registrations !== 1) {
      return fail(`expected exactly one onSystem handler, got ${registrations}`);
    }
    if (apiVersion !== expectedVersion) {
      return fail(`api version mismatch: native returned ${apiVersion}, contract is ${expectedVersion}`);
    }
    return { ok: true, dir: resolvedDir, registrations, apiVersion, calls };
  } finally {
    vm.dispose();
    runtime.dispose();
  }
}
